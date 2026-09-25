package myssh

import (
	"net"
	"regexp"
	"testing"

	"github.com/cloudflare/ahocorasick"
)

// setupTestRouter 构造带典型规则集的测试路由器
func setupTestRouter() *GeoRouter {
	r := newGeoRouter()

	// 规则 1: Full Domain 精确匹配
	r.fullDomains["www.v2ex.com"] = struct{}{}

	// 规则 2: Sub Domain 后缀匹配
	r.subDomains["google.com"] = struct{}{}
	r.subDomains["youtube.com"] = struct{}{}

	// 规则 3: Keyword 关键词，启用 AC 自动机
	r.keywordList = []string{"adservice", "analytics", "tracker"}
	r.keywordAC = ahocorasick.NewStringMatcher(r.keywordList)

	// 规则 4: Regex 正则 (分组形态)
	re := regexp.MustCompile("^.*\\.blocked\\.com$")
	r.regexGrouped = append(r.regexGrouped, re)

	// 规则 5: IP 段 (CIDR Trie)
	r.ipTrie.Insert([]byte{8, 8, 8, 8}, 32)
	r.ipTrie.Insert(net.ParseIP("192.168.0.0").To4(), 16)

	return r
}

// ==========================================
// MatchDomain 基准 (绕过 L1 缓存，测纯匹配)
// ==========================================

func BenchmarkMatchDomain_Full(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("www.v2ex.com") // 命中 O(1) 哈希
	}
}

func BenchmarkMatchDomain_Sub(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("api.video.youtube.com") // 后缀上溯 0 次
	}
}

func BenchmarkMatchDomain_Keyword_AC(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("s1.adservice.google.com") // 命中 AC 自动机分支
	}
}

func BenchmarkMatchDomain_Regex(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("test1.test2.blocked.com") // 命中正则
	}
}

func BenchmarkMatchDomain_MissAll(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("www.normal-website.com") // 全部未命中：最坏路径
	}
}

// ==========================================
// L1 缓存基准 (并发读)
// ==========================================

func BenchmarkMatchDomain_L1Cache(b *testing.B) {
	r := setupTestRouter()
	// 预热一次，填充 domainCache 条目
	r.MatchDomain("api.video.youtube.com")
	b.ResetTimer()

	// b.RunParallel 度量 sync.Map 并发读性能
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.MatchDomain("api.video.youtube.com") // 命中 L1 缓存
		}
	})
}

// ==========================================
// ShouldDirect 基准 (IP 直连路径)
// ==========================================

func BenchmarkShouldDirect_IPRoute(b *testing.B) {
	r := setupTestRouter()
	// 静默基准
	Debug = false
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.ShouldDirect("8.8.8.8") // 直接走 IP 匹配 CIDR 查询
	}
}
