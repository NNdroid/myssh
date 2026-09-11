package myssh

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildTestGeoFile 构造一个最小 geosite/geoip 格式的测试文件：
// 顶层 repeated entry(field 1)，entry.country_code(field 1)，
// 附带一个 domains(field 2) 大字段验证跳过逻辑。
func buildTestGeoFile(t *testing.T, tags []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.dat")
	var buf []byte

	appendField := func(dst []byte, num protowire.Number, wire protowire.Type, payload []byte) []byte {
		dst = protowire.AppendTag(dst, num, wire)
		return protowire.AppendBytes(dst, payload)
	}

	for i, tag := range tags {
		var entry []byte
		entry = protowire.AppendTag(entry, 1, protowire.BytesType)
		entry = protowire.AppendString(entry, tag)
		if i%2 == 0 { // 一半 entry 带大字段，验证 tag 扫描只取 field 1
			var domain []byte
			domain = protowire.AppendTag(domain, 1, protowire.VarintType)
			domain = protowire.AppendVarint(domain, 2) // RootDomain
			domain = protowire.AppendTag(domain, 2, protowire.BytesType)
			domain = protowire.AppendString(domain, "example-domain-"+tag+".com")
			entry = appendField(entry, 2, protowire.BytesType, domain)
		}
		buf = protowire.AppendTag(buf, 1, protowire.BytesType)
		buf = protowire.AppendBytes(buf, entry)
	}
	// 顶层塞一个未知 field（field 9 varint），验证顶层跳过逻辑
	buf = protowire.AppendTag(buf, 9, protowire.VarintType)
	buf = protowire.AppendVarint(buf, 42)

	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractGeoFileTags(t *testing.T) {
	want := []string{"apple@cn", "cn", "geolocation-!cn", "private", "telegram"}
	path := buildTestGeoFile(t, []string{"cn", "geolocation-!cn", "private", "apple@cn", "cn", "telegram"})

	got, truncated, err := extractGeoFileTags(path)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("well-formed file must not be flagged truncated")
	}
	if len(got) != len(want) {
		t.Fatalf("tags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tags = %v, want %v", got, want)
		}
	}
}

// TestExtractGeoFileTagsTruncated 验证下载不完整（文件在 record 中间被截断）
// 的文件：返回已解析的部分 tag 且 truncated=true，提示宿主重新下载。
func TestExtractGeoFileTagsTruncated(t *testing.T) {
	path := buildTestGeoFile(t, []string{"cn", "private", "telegram"})
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) < 20 {
		t.Fatalf("test file too small: %d", len(full))
	}
	// 从尾部截掉一大块，制造"最后一条 entry 不完整"的文件
	if err := os.WriteFile(path, full[:len(full)-12], 0o644); err != nil {
		t.Fatal(err)
	}

	got, truncated, err := extractGeoFileTags(path)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("truncated file must set the truncated flag")
	}
	if len(got) == 0 {
		t.Fatal("expected partial tags before the truncation point")
	}
}

func TestGetGeoSiteTagsJSONCacheAndInvalidation(t *testing.T) {
	tags1 := []string{"cn", "private"}
	path := buildTestGeoFile(t, tags1)

	// 测试结束后清掉本测试写入的缓存项，避免污染其他用例
	t.Cleanup(func() {
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		geoTagsMu.Lock()
		delete(geoTagsCache, abs)
		geoTagsMu.Unlock()
	})

	if got := getGeoTagsJSON(path); got != `["cn","private"]` {
		t.Fatalf("first call = %s", got)
	}

	// 内容变化 → 新文件重扫
	tags2 := []string{"cn", "google", "private"}
	newPath := filepath.Join(filepath.Dir(path), "test2.dat")
	if err := os.WriteFile(newPath, mustBuildGeo(t, tags2), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := getGeoTagsJSON(newPath); got != `["cn","google","private"]` {
		t.Fatalf("second file = %s", got)
	}

	// mtime 失效路径：同一路径重写为更多 tag，mtime/size 变化后应重扫
	updated := []string{"cn", "private", "telegram"}
	if err := os.WriteFile(path, mustBuildGeo(t, updated), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := getGeoTagsJSON(path); got != `["cn","private","telegram"]` {
		t.Fatalf("after rewrite = %s", got)
	}
}

func mustBuildGeo(t *testing.T, tags []string) []byte {
	t.Helper()
	path := buildTestGeoFile(t, tags)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
