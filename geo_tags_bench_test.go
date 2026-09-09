package myssh

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildSyntheticGeoFile 生成接近真实规模的 geosite/geoip 文件：
// numTags 个 entry，每个 entry 附带 numDomains 个域名大字段。
// 写入临时目录并返回路径；b.TempDir 在基准结束时自动清理。
func buildSyntheticGeoFile(b *testing.B, numTags, numDomains int) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "synthetic.dat")

	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	var entry []byte
	var top []byte
	write := func(chunk []byte) {
		if _, err := f.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	for i := 0; i < numTags; i++ {
		entry = entry[:0]
		entry = protowire.AppendTag(entry, 1, protowire.BytesType)
		entry = protowire.AppendString(entry, fmt.Sprintf("category-%04d", i))
		for j := 0; j < numDomains; j++ {
			var domain []byte
			domain = protowire.AppendTag(domain, 1, protowire.VarintType)
			domain = protowire.AppendVarint(domain, 2)
			domain = protowire.AppendTag(domain, 2, protowire.BytesType)
			domain = protowire.AppendString(domain, fmt.Sprintf("sub%06d.example-category%04d.com", j, i))
			entry = protowire.AppendTag(entry, 2, protowire.BytesType)
			entry = protowire.AppendBytes(entry, domain)
		}
		top = protowire.AppendTag(top[:0], 1, protowire.BytesType)
		top = protowire.AppendBytes(top, entry)
		write(top)
	}
	return path
}

// BenchmarkGeoTagScan 量化 tag 扫描器吞吐：约 numTags*numDomains 条规则
// 的合成文件（默认 6000×50 ≈ 10MB 量级，接近真实 geosite.dat）。
func BenchmarkGeoTagScan(b *testing.B) {
	for _, tc := range []struct {
		name              string
		numTags, numDomns int
	}{
		{"small-1MB", 1000, 20},
		{"geosite-like-10MB", 6000, 50},
	} {
		b.Run(tc.name, func(b *testing.B) {
			path := buildSyntheticGeoFile(b, tc.numTags, tc.numDomns)
			info, err := os.Stat(path)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tags, err := extractGeoFileTags(path)
				if err != nil {
					b.Fatal(err)
				}
				if len(tags) != tc.numTags {
					b.Fatalf("tags = %d, want %d", len(tags), tc.numTags)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(info.Size())/(1<<20)/b.Elapsed().Seconds(), "MB/s")
		})
	}
}
