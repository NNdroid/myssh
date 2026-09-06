package myssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/cloudflare/ahocorasick"
	"github.com/miekg/dns"
)

// ---------- 中继吞吐（回环 TCP） ----------

// benchTCPair 建立一对回环 TCP 连接。
func benchTCPair(b *testing.B) (client, server net.Conn, stop func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		b.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		client.Close()
		ln.Close()
		b.Fatal(r.err)
	}
	return client, r.c, func() {
		client.Close()
		r.c.Close()
		ln.Close()
	}
}

// benchmarkRelay 测量 tcpRelay 中继 b.N 个 64KB 数据块的吞吐：
// writer --(connA)--> tcpRelay --(connB)--> sink。
// wrapSrc/wrapDst 用于叠加 TrackedConn 统计层，量化其开销。
func benchmarkRelay(b *testing.B, wrapSrc, wrapDst func(net.Conn) net.Conn) {
	b.Helper()
	const chunk = 64 * 1024

	w, a, stop1 := benchTCPair(b)
	defer stop1()
	bc, sink, stop2 := benchTCPair(b)
	defer stop2()

	var s, d net.Conn = a, bc
	if wrapSrc != nil {
		s = wrapSrc(s)
	}
	if wrapDst != nil {
		d = wrapDst(d)
	}
	defer s.Close()
	defer d.Close()

	deadline := time.Now().Add(2 * time.Minute)
	w.SetDeadline(deadline)
	sink.SetDeadline(deadline)

	relayDone := make(chan error, 1)
	go func() {
		_, err := tcpRelay(d, s)
		relayDone <- err
	}()

	total := int64(b.N) * chunk
	sinkDone := make(chan int64, 1)
	go func() {
		buf := make([]byte, chunk)
		var got int64
		for got < total {
			n, err := sink.Read(buf)
			if err != nil {
				sinkDone <- got
				return
			}
			got += int64(n)
		}
		sinkDone <- got
	}()

	payload := make([]byte, chunk)
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	// 关闭写入端触发 EOF，中继在冲刷完所有数据后退出。
	w.Close()
	if err := <-relayDone; err != nil {
		b.Fatalf("relay: %v", err)
	}
	if got := <-sinkDone; got != total {
		b.Fatalf("short read: got %d want %d", got, total)
	}
}

func BenchmarkTCPRelay(b *testing.B) {
	b.Run("raw", func(b *testing.B) {
		benchmarkRelay(b, nil, nil)
	})
	b.Run("tracked-src", func(b *testing.B) {
		benchmarkRelay(b, func(c net.Conn) net.Conn { return WrapConn(c, "bench.example.com") }, nil)
	})
	b.Run("tracked-both", func(b *testing.B) {
		benchmarkRelay(b,
			func(c net.Conn) net.Conn { return WrapConn(c, "bench.example.com") },
			func(c net.Conn) net.Conn { return WrapConn(c, "10.0.0.1:443") })
	})
}

// ---------- WebSocket 隧道回显吞吐 ----------

// BenchmarkWSEcho 测量 ws/wss 隧道数据路径的回显往返吞吐（gws + wsStream 适配层）。
func BenchmarkWSEcho(b *testing.B) {
	addr, stop := startWSEchoServer(b)
	defer stop()

	cfg := ProxyConfig{
		ProxyAddr:  addr,
		CustomHost: "proxy.test",
		CustomPath: "/",
		SshAddr:    "127.0.0.1:22",
		ServerName: "proxy.test",
	}
	proto, err := GetTunnel("ws")
	if err != nil {
		b.Fatal(err)
	}
	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	payload := make([]byte, 64*1024)
	buf := make([]byte, 64*1024)
	b.SetBytes(64 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------- GeoRouter 域名匹配 ----------

func benchGeoRouter(b *testing.B) *GeoRouter {
	b.Helper()
	r := newGeoRouter()
	for i := 0; i < 500; i++ {
		r.fullDomains[fmt.Sprintf("full%d.example.com", i)] = struct{}{}
	}
	for i := 0; i < 2000; i++ {
		r.subDomains[fmt.Sprintf("site%d.cn", i)] = struct{}{}
	}
	for i := 0; i < 2000; i++ {
		r.keywordList = append(r.keywordList, fmt.Sprintf("brand%d-shop", i))
	}
	r.keywordAC = ahocorasick.NewStringMatcher(r.keywordList)
	for i := 0; i < 50; i++ {
		if re, err := regexp.Compile(fmt.Sprintf(`^ad%d-[a-z0-9]+\.tracker\.example$`, i)); err == nil {
			r.regexList = append(r.regexList, re)
		}
	}
	r.combineRegexPatterns()
	return r
}

func BenchmarkGeoRouterMatchDomain(b *testing.B) {
	r := benchGeoRouter(b)
	bench := func(name, domain string, hit bool) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if got := r.doMatchDomain(domain); got != hit {
					b.Fatalf("match %q = %v, want %v", domain, got, hit)
				}
			}
		})
	}
	bench("full-hit", "full0.example.com", true)
	bench("subdomain-hit", "www.site123.cn", true)
	bench("keyword-miss", "www.nothing-matches-here-example.org", false)
	bench("regex-miss", "plain-news.example.org", false)

	b.Run("l1-cache-hit", func(b *testing.B) {
		// 预热 L1 缓存后测量命中路径。注意必须选一个规则命中的域名：
		// 缓存条目达到阈值会被异步整体清空，之后重新计算必须仍返回 true。
		r.MatchDomain("full0.example.com")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !r.MatchDomain("full0.example.com") {
				b.Fatal("expected cached hit")
			}
		}
	})
}

// ---------- IP Trie ----------

func BenchmarkIPTrie(b *testing.B) {
	t := newIPTrie()
	for i := 0; i < 4096; i++ {
		ip := net.IPv4(10, byte(i>>8), byte(i&0xff), 0).To4()
		t.Insert(ip, 24)
	}
	t.Insert(net.ParseIP("192.168.0.0").To4(), 16)

	hit := net.ParseIP("10.1.244.7")
	miss4 := net.ParseIP("8.8.8.8")
	miss6 := net.ParseIP("2001:db8::1")

	b.Run("v4-hit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !t.Contains(hit) {
				b.Fatal("expected hit")
			}
		}
	})
	b.Run("v4-miss", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t.Contains(miss4) {
				b.Fatal("expected miss")
			}
		}
	})
	b.Run("v6-miss", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t.Contains(miss6) {
				b.Fatal("expected miss")
			}
		}
	})
}

// ---------- DNS 缓存命中（消息拷贝 + TTL 衰减） ----------

func BenchmarkDNSCacheHitCopy(b *testing.B) {
	lds := &LocalDnsServer{}
	question := new(dns.Msg)
	question.SetQuestion("cached.example.com.", dns.TypeA)
	reply := question.Copy()
	for i := 0; i < 4; i++ {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "cached.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, byte(i+1)),
		})
	}
	entry := dnsCacheEntry{msg: reply, cachedAt: time.Now().Add(-time.Second), expiresAt: time.Now().Add(time.Hour)}
	req := new(dns.Msg)
	req.SetQuestion("cached.example.com.", dns.TypeA)
	req.Id = 4242

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lds.copyAndAdjustTTL(entry, req.Id)
	}
}

// TestDNSPackedCacheRoundTrip 验证预打包缓存路径的端到端正确性：
// TTL 偏移扫描覆盖 answer/extra 各节、事务 ID 改写、TTL 按流逝时间衰减。
func TestDNSPackedCacheRoundTrip(t *testing.T) {
	lds := &LocalDnsServer{}
	question := new(dns.Msg)
	question.SetQuestion("rt.example.com.", dns.TypeA)
	reply := question.Copy()
	reply.Id = 9999
	for i := 0; i < 2; i++ {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "rt.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.IPv4(1, 2, 3, byte(i+1)),
		})
	}
	reply.Extra = append(reply.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.IPv4(9, 9, 9, 9),
	})

	packed, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	offs := scanWireTTLOffsets(packed)
	if offs == nil {
		t.Fatal("TTL offset scan failed")
	}
	if len(offs) != 3 {
		t.Fatalf("offsets = %v, want 3 entries", offs)
	}

	entry := dnsCacheEntry{
		packed:    packed,
		ttlOffset: offs,
		cachedAt:  time.Now().Add(-10 * time.Second),
		expiresAt: time.Now().Add(time.Hour),
	}
	got, ok := lds.patchPacked(entry, 4242)
	if !ok {
		t.Fatal("patch failed")
	}

	m := new(dns.Msg)
	if err := m.Unpack(got); err != nil {
		t.Fatalf("unpack patched message: %v", err)
	}
	if m.Id != 4242 {
		t.Fatalf("id = %d, want 4242", m.Id)
	}
	if len(m.Answer) != 2 || len(m.Extra) != 1 {
		t.Fatalf("records = %d/%d, want 2/1", len(m.Answer), len(m.Extra))
	}
	for _, ans := range m.Answer {
		if ans.Header().Ttl != 110 {
			t.Fatalf("answer ttl = %d, want 110 (120 - 10s elapsed)", ans.Header().Ttl)
		}
	}
	if m.Extra[0].Header().Ttl != 3590 {
		t.Fatalf("extra ttl = %d, want 3590", m.Extra[0].Header().Ttl)
	}
}

// BenchmarkDNSCacheHitPacked 测量预打包缓存命中路径（拷贝 + 事务 ID + TTL 偏移补丁），
// 与 BenchmarkDNSCacheHitCopy（消息深拷贝回退路径）对比。
func BenchmarkDNSCacheHitPacked(b *testing.B) {
	lds := &LocalDnsServer{}
	question := new(dns.Msg)
	question.SetQuestion("cached.example.com.", dns.TypeA)
	reply := question.Copy()
	for i := 0; i < 4; i++ {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "cached.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(93, 184, 216, byte(i+1)),
		})
	}
	packed, err := reply.Pack()
	if err != nil {
		b.Fatal(err)
	}
	offs := scanWireTTLOffsets(packed)
	if offs == nil {
		b.Fatal("TTL offset scan failed")
	}
	entry := dnsCacheEntry{
		packed:    packed,
		ttlOffset: offs,
		cachedAt:  time.Now().Add(-time.Second),
		expiresAt: time.Now().Add(time.Hour),
	}
	req := new(dns.Msg)
	req.SetQuestion("cached.example.com.", dns.TypeA)
	req.Id = 4242

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if buf, ok := lds.patchPacked(entry, req.Id); !ok || len(buf) != len(packed) {
			b.Fatal("patch failed")
		}
	}
}
