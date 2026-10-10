package myssh

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func aAnswer(name string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP("93.184.216.34").To4(),
	}
}

func newTTLServer() *LocalDnsServer { return &LocalDnsServer{} }

// 回归：否定结果不能再被缓存一整小时。
// 修复前 TTL 0 与「无 Answer 段」都会落到 DefaultMaxTTL——一条瞬时 NXDOMAIN 会被钉满
// 一小时，域名恢复解析后用户仍看到它不通。
func TestCalculateOptimalTTLNegativeResultsUseShortTTL(t *testing.T) {
	server := newTTLServer()
	cases := []struct {
		name  string
		reply *dns.Msg
	}{
		{"all_zero_ttl", &dns.Msg{Answer: []dns.RR{aAnswer("a.example.", 0), aAnswer("b.example.", 0)}}},
		{"nxdomain_no_answer", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
		{"no_data_no_answer", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
		{"empty_msg", &dns.Msg{}},
	}
	for _, tc := range cases {
		if got := server.calculateOptimalTTL(tc.reply); got != uint32(DefaultMinTTL) {
			t.Fatalf("%s: want %d, got %d", tc.name, DefaultMinTTL, got)
		}
	}
}

func TestCalculateOptimalTTLMinOfPositiveAnswers(t *testing.T) {
	if got := newTTLServer().calculateOptimalTTL(&dns.Msg{Answer: []dns.RR{aAnswer("a.", 300), aAnswer("b.", 1200)}}); got != 300 {
		t.Fatalf("want 300, got %d", got)
	}
}

func TestCalculateOptimalTTLZeroIsIgnoredWhenAPositiveExists(t *testing.T) {
	if got := newTTLServer().calculateOptimalTTL(&dns.Msg{Answer: []dns.RR{aAnswer("a.", 0), aAnswer("b.", 900)}}); got != 900 {
		t.Fatalf("want 900, got %d", got)
	}
}

func TestCalculateOptimalTTLClampedToConfiguredBounds(t *testing.T) {
	server := newTTLServer()
	if got := server.calculateOptimalTTL(&dns.Msg{Answer: []dns.RR{aAnswer("a.", 1)}}); got != uint32(DefaultMinTTL) {
		t.Fatalf("below floor: want %d, got %d", DefaultMinTTL, got)
	}
	if got := server.calculateOptimalTTL(&dns.Msg{Answer: []dns.RR{aAnswer("a.", 7200)}}); got != uint32(DefaultMaxTTL) {
		t.Fatalf("above ceiling: want %d, got %d", DefaultMaxTTL, got)
	}
}

// 恰好等于上限的合法 TTL 不能被误判成「无应答」——用 !sawPositiveTTL 而非
// minTTL == DefaultMaxTTL 兜底，就是为了保住这条。
func TestCalculateOptimalTTLExactMaxIsKept(t *testing.T) {
	if got := newTTLServer().calculateOptimalTTL(&dns.Msg{Answer: []dns.RR{aAnswer("a.", uint32(DefaultMaxTTL))}}); got != uint32(DefaultMaxTTL) {
		t.Fatalf("want %d, got %d", DefaultMaxTTL, got)
	}
}
