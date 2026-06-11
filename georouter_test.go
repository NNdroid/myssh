package myssh

import (
	"net"
	"regexp"
	"testing"

	"github.com/cloudflare/ahocorasick"
)

// setupTestRouter 初始化一个包含模拟规则的路由器
func setupTestRouter() *GeoRouter {
	r := newGeoRouter()

	// 模拟 Full Domain 规则
	r.fullDomains["www.v2ex.com"] = struct{}{}

	// 模拟 Sub Domain 规则
	r.subDomains["google.com"] = struct{}{}
	r.subDomains["youtube.com"] = struct{}{}

	// 模拟 Keyword 规则并构建 AC 自动机
	r.keywordList = []string{"adservice", "analytics", "tracker"}
	r.keywordAC = ahocorasick.NewStringMatcher(r.keywordList)

	// 模拟 Regex 规则 (合并组)
	re := regexp.MustCompile("^.*\\.blocked\\.com$")
	r.regexGrouped = append(r.regexGrouped, re)

	// 模拟 IP 规则 (CIDR Trie)
	r.ipTrie.Insert([]byte{8, 8, 8, 8}, 32)
	r.ipTrie.Insert(net.ParseIP("192.168.0.0").To4(), 16)

	return r
}

// ==========================================
// MatchDomain 核心算法基准测试 (绕过 L1 缓存，直测底层算法)
// ==========================================

func BenchmarkMatchDomain_Full(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("www.v2ex.com") // 预期极速 O(1) 命中
	}
}

func BenchmarkMatchDomain_Sub(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("api.video.youtube.com") // 测试 0 分配原位切割循环
	}
}

func BenchmarkMatchDomain_Keyword_AC(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("s1.adservice.google.com") // 测试 AC 自动机多模式扫描
	}
}

func BenchmarkMatchDomain_Regex(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("test1.test2.blocked.com") // 测试正则兜底
	}
}

func BenchmarkMatchDomain_MissAll(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("www.normal-website.com") // 最差情况：走完所有检查均未命中
	}
}

// ==========================================
// L1 路由并发缓存基准测试 (极速捷径)
// ==========================================

func BenchmarkMatchDomain_L1Cache(b *testing.B) {
	r := setupTestRouter()
	// 提前执行一次，将结果预热进 domainCache 中
	r.MatchDomain("api.video.youtube.com") 
	b.ResetTimer()
	
	// b.RunParallel 可以测试在高并发协程下的 sync.Map 读取性能
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.MatchDomain("api.video.youtube.com") // 测试 L1 无锁并发短路性能
		}
	})
}

// ==========================================
// ShouldDirect 快速路径基准测试 (IP 直判)
// ==========================================

func BenchmarkShouldDirect_IPRoute(b *testing.B) {
	r := setupTestRouter()
	// 屏蔽日志以防止拖慢基准测试
	Debug = false 
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.ShouldDirect("8.8.8.8") // 测试纯 IP 字符串查 CIDR 前缀树性能
	}
}