package myssh

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// startQUICIP4PServer 起一个只负责完成 QUIC 握手的本地服务端，供 IP4P
// 证书探测与 SDK QUIC 拨号回归测试使用。收到的连接统一在 Cleanup 里关闭，
// 避免 quic-go 的收发 goroutine 拖到 goleak 检查之后。
func startQUICIP4PServer(t *testing.T) string {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", newTestQUICTLSConfig(t), &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}

	var mu sync.Mutex
	var conns []*quic.Conn
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.CloseWithError(0, "test cleanup")
		}
	})
	return ln.Addr().String()
}

// TestDialUDPReturnsUnconnectedPacketConnForIP4P 钉住两件事：
//   - dialUDP 必须解开 IP4P，把真实 IPv4:port 交给 handler；
//   - 返回的 socket 必须是未连接的 net.PacketConn。quic-go / kcp-go 逐包
//     WriteTo/ReadFrom，而 net.Dialer.DialContext("udp") 返回的连接型 socket
//     会报 "use of WriteTo with pre-connected connection"，一个包都发不出去。
func TestDialUDPReturnsUnconnectedPacketConnForIP4P(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	port := server.LocalAddr().(*net.UDPAddr).Port
	target := ip4POf(t, net.IPv4(127, 0, 0, 1), port)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, resolved, err := dialUDP(ctx, ProxyConfig{}, target)
	if err != nil {
		t.Fatalf("dialUDP(%s): %v", target, err)
	}
	defer conn.Close()

	if want := server.LocalAddr().String(); resolved != want {
		t.Fatalf("resolved address = %q, want %q", resolved, want)
	}
	if conn.RemoteAddr() != nil {
		t.Fatalf("UDP socket must be unconnected, got RemoteAddr=%v", conn.RemoteAddr())
	}
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatalf("dialUDP returned %T, want net.PacketConn", conn)
	}

	remote, err := net.ResolveUDPAddr("udp", resolved)
	if err != nil {
		t.Fatalf("resolve %q: %v", resolved, err)
	}
	if _, err := pc.WriteTo([]byte("ip4p-ok"), remote); err != nil {
		t.Fatalf("WriteTo on the tunnel UDP socket: %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, from, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom: %v", err)
	}
	if string(buf[:n]) != "ip4p-ok" {
		t.Fatalf("server got %q, want %q", buf[:n], "ip4p-ok")
	}
	// 未连接 socket 默认绑在双栈 [::] 上，源地址字符串可能与 IPv4 目标不同；
	// 只需确认包确实从我们创建的那个端口发出。
	fromUDP, ok := from.(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected source address type %T", from)
	}
	localUDP, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected local address type %T", conn.LocalAddr())
	}
	if fromUDP.Port != localUDP.Port {
		t.Errorf("packet from port %d, want %d", fromUDP.Port, localUDP.Port)
	}
}

// TestDialTunnelHandsResolvedIP4PToUDPHandler 保证 quic / kcptun handler
// 拿到的 cfg.ProxyAddr 是解开的 IPv4:port，而不是 2001::... 加占位端口 0。
func TestDialTunnelHandsResolvedIP4PToUDPHandler(t *testing.T) {
	const name = "test_ip4p_udp_handler"
	var seen string
	RegisterTunnel(name, "udp", func(_ context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		seen = cfg.ProxyAddr
		_ = baseConn.Close() // 让 watchEngineCtx 的监视 goroutine 立即退出
		return nil, errors.New("stop after capture")
	})
	defer delete(tunnelRegistry, name)

	target := ip4POf(t, net.IPv4(127, 0, 0, 1), 12345)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = dialTunnel(ctx, ProxyConfig{TunnelType: name, ProxyAddr: target})

	if want := "127.0.0.1:12345"; seen != want {
		t.Fatalf("handler saw cfg.ProxyAddr=%q, want %q", seen, want)
	}
}

// TestFetchCertInfoQUICResolvesIP4P 是 FetchCertInfo(useQUIC=true) 的端到端
// 回归：修复前连接型 UDP socket 直接 WriteTo 失败，且 udpAddr 仍是 IP4P
// 字面量 + 端口 0，探测必然超时。
func TestFetchCertInfoQUICResolvesIP4P(t *testing.T) {
	addr := startQUICIP4PServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	target := ip4POf(t, net.ParseIP(host), port)

	info, err := FetchCertInfo(target, true, "localhost", "")
	if err != nil {
		t.Fatalf("FetchCertInfo(%s, QUIC): %v", target, err)
	}
	if info.Protocol != "QUIC" {
		t.Errorf("protocol = %q, want QUIC", info.Protocol)
	}
	if len(info.Raw) == 0 {
		t.Error("empty DER certificate")
	}
}

// TestSDKQUICDialerResolvesIP4P 钉住 h3 / webtransport / masque / xhttp 走
// sdkQUICDialer 时的 IP4P 解析：这条链路绕过 dialSocket，必须单独解开地址。
func TestSDKQUICDialerResolvesIP4P(t *testing.T) {
	addr := startQUICIP4PServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	target := ip4POf(t, net.ParseIP(host), port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := sdkQUICDialer(ProxyConfig{})
	conn, err := dial(ctx, target, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         quicALPN,
	}, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("sdkQUICDialer(%s): %v", target, err)
	}
	_ = conn.CloseWithError(0, "test done")
}

// TestSDKTCPDialerResolvesIP4P 钉住 h2 / grpc / xhttp 走 sdkTCPDialer 时的
// IP4P 解析：SDK 隧道是自拨型（custom network），不经过 dialSocket。
func TestSDKTCPDialerResolvesIP4P(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	target := ip4POf(t, net.IPv4(127, 0, 0, 1), port)

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		accepted <- struct{}{}
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := sdkTCPDialer(ProxyConfig{})(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("sdkTCPDialer(%s): %v", target, err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("server never accepted the IP4P-resolved connection")
	}
	if want := ln.Addr().String(); conn.RemoteAddr().String() != want {
		t.Errorf("connected to %s, want %s", conn.RemoteAddr(), want)
	}
}

// serveIP4PAAAAFakeDNS 起一个真实 UDP DNS 服务端（配合 Resolver 的自定义 Dial
// 使用；net.Pipe 在 PreferGo 下存在 TCP/UDP 帧格式歧义，不用）。每收到一条
// 查询 queries +1，并回复固定的 IP4P AAAA 记录。
func serveIP4PAAAAFakeDNS(t *testing.T, queries *atomic.Int32, fqdn, aaaa string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake dns listen: %v", err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dns.Msg
			if err := query.Unpack(buf[:n]); err != nil {
				continue
			}
			queries.Add(1)
			resp := new(dns.Msg)
			resp.SetReply(&query)
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(aaaa),
			})
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// TestLookupIP6CachedHitsDNSOnce 钉住 AAAA 探测缓存的三条行为：
//   - TTL 内的重复探测只打一次上游 DNS（消除 SDK 热路径翻倍的 DNS 流量）；
//   - 缓存的应答可正常解出 IP4P；
//   - 过期后重新查询；查询失败不写缓存（保持逐次重试语义）。
func TestLookupIP6CachedHitsDNSOnce(t *testing.T) {
	const host = "ip4p-cache.test"
	const aaaa = "2001::3039:102:304" // 1.2.3.4:12345

	var queries atomic.Int32
	server := serveIP4PAAAAFakeDNS(t, &queries, host+".", aaaa)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, server.LocalAddr().String())
		},
	}

	// 隔离全局缓存：该键只属于本测试
	ip4pAAAACacheMu.Lock()
	delete(ip4pAAAACache, host)
	ip4pAAAACacheMu.Unlock()
	t.Cleanup(func() {
		ip4pAAAACacheMu.Lock()
		delete(ip4pAAAACache, host)
		ip4pAAAACacheMu.Unlock()
	})

	ctx := context.Background()
	ips, err := lookupIP6Cached(ctx, resolver, host)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if queries.Load() != 1 {
		t.Fatalf("first lookup made %d queries, want 1", queries.Load())
	}
	if len(ips) != 1 {
		t.Fatalf("got %d answers, want 1", len(ips))
	}
	if v4, port, ok := decodeIP4PIP(ips[0]); !ok || v4.String() != "1.2.3.4" || port != 12345 {
		t.Fatalf("decoded = (%v, %d, %v), want (1.2.3.4, 12345, true)", v4, port, ok)
	}

	// TTL 内第二次查询：必须命中缓存，不打上游
	ips2, err := lookupIP6Cached(ctx, resolver, host)
	if err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if queries.Load() != 1 {
		t.Fatalf("cached lookup made a new query (total %d), want 1", queries.Load())
	}
	if len(ips2) != 1 || !ips2[0].Equal(ips[0]) {
		t.Fatalf("cached answer changed: %v != %v", ips2, ips)
	}

	// 过期后：重新查询
	ip4pAAAACacheMu.Lock()
	ip4pAAAACache[host] = ip4pAAAAEntry{ips: ips, expiresAt: time.Now().Add(-time.Second)}
	ip4pAAAACacheMu.Unlock()
	if _, err := lookupIP6Cached(ctx, resolver, host); err != nil {
		t.Fatalf("requery after expiry: %v", err)
	}
	if queries.Load() != 2 {
		t.Fatalf("expired lookup made %d queries total, want 2", queries.Load())
	}
}

// TestLookupIP6CachedDoesNotCacheFailure 验证查询失败不写缓存：失败后紧接的
// 探测仍会再次打上游，DNS 恢复后能立即拿到结果。
func TestLookupIP6CachedDoesNotCacheFailure(t *testing.T) {
	const host = "ip4p-fail.test"

	server := serveIP4PAAAAFakeDNS(t, &atomic.Int32{}, host+".", "2001::3039:102:304")

	// 故障开关：置位期间 Dial 直接报错（等价于 DNS 上游不可达，且完全确定——
	// 黑洞端口的 refused 依赖 ICMP 时序，不适合做断言），恢复后指向假服务端。
	var failUpstream atomic.Bool
	failUpstream.Store(true)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if failUpstream.Load() {
				return nil, errors.New("fake upstream down")
			}
			return net.Dial(network, server.LocalAddr().String())
		},
	}

	ip4pAAAACacheMu.Lock()
	delete(ip4pAAAACache, host)
	ip4pAAAACacheMu.Unlock()
	t.Cleanup(func() {
		ip4pAAAACacheMu.Lock()
		delete(ip4pAAAACache, host)
		ip4pAAAACacheMu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := lookupIP6Cached(ctx, resolver, host); err == nil {
		t.Fatal("lookup against dead upstream should fail")
	}
	// 失败不写缓存：恢复上游后，紧接的查询必须重新打到上游并成功
	failUpstream.Store(false)
	ips, err := lookupIP6Cached(ctx, resolver, host)
	if err != nil {
		t.Fatalf("recovery lookup: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("recovery lookup returned no answers")
	}
}
