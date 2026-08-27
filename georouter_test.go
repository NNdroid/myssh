package myssh

import (
	"net"
	"regexp"
	"testing"

	"github.com/cloudflare/ahocorasick"
)

// setupTestRouter  info
func setupTestRouter() *GeoRouter {
	r := newGeoRouter()

	//  info  Full Domain  info
	r.fullDomains["www.v2ex.com"] = struct{}{}

	//  info  Sub Domain  info
	r.subDomains["google.com"] = struct{}{}
	r.subDomains["youtube.com"] = struct{}{}

	//  info  Keyword  info  AC  info
	r.keywordList = []string{"adservice", "analytics", "tracker"}
	r.keywordAC = ahocorasick.NewStringMatcher(r.keywordList)

	//  info  Regex  info  ( info )
	re := regexp.MustCompile("^.*\\.blocked\\.com$")
	r.regexGrouped = append(r.regexGrouped, re)

	//  info  IP  info  (CIDR Trie)
	r.ipTrie.Insert([]byte{8, 8, 8, 8}, 32)
	r.ipTrie.Insert(net.ParseIP("192.168.0.0").To4(), 16)

	return r
}

// ==========================================
// MatchDomain  info  ( info  L1  info ， info )
// ==========================================

func BenchmarkMatchDomain_Full(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("www.v2ex.com") //  info  O(1)  info
	}
}

func BenchmarkMatchDomain_Sub(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("api.video.youtube.com") //  info  0  info
	}
}

func BenchmarkMatchDomain_Keyword_AC(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("s1.adservice.google.com") //  info  AC  info mode info
	}
}

func BenchmarkMatchDomain_Regex(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("test1.test2.blocked.com") //  info
	}
}

func BenchmarkMatchDomain_MissAll(b *testing.B) {
	r := setupTestRouter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.doMatchDomain("www.normal-website.com") //  info ： info
	}
}

// ==========================================
// L1  info  ( info )
// ==========================================

func BenchmarkMatchDomain_L1Cache(b *testing.B) {
	r := setupTestRouter()
	//  info ， info  domainCache  info
	r.MatchDomain("api.video.youtube.com")
	b.ResetTimer()

	// b.RunParallel  info  sync.Map  info
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.MatchDomain("api.video.youtube.com") //  info  L1  info
		}
	})
}

// ==========================================
// ShouldDirect  info  (IP  info )
// ==========================================

func BenchmarkShouldDirect_IPRoute(b *testing.B) {
	r := setupTestRouter()
	//  info
	Debug = false
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.ShouldDirect("8.8.8.8") //  info  IP  info  CIDR  info
	}
}
