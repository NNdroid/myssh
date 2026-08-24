package myssh

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDnsServer 在 loopback UDP 上启动一个隧道权威 DNS 服务端，返回服务端实例、DNS Server 与可达地址。
func startTestDnsServer(t *testing.T) (*DNSTunnelServer, *dns.Server, string) {
	t.Helper()
	srv := NewDNSTunnelServer("tunnel.test.")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	dnsSrv := &dns.Server{PacketConn: pc, Handler: srv}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	return srv, dnsSrv, addr
}

func stopTestDnsServer(t *testing.T, dnsSrv *dns.Server) {
	t.Helper()
	_ = dnsSrv.Shutdown()
	time.Sleep(30 * time.Millisecond) // 等待 serve 协程退出，避免 goleak 误报
}

// readSessionN 从隧道服务端精确读取 n 字节（后端视角）。
func readSessionN(t *testing.T, srv *DNSTunnelServer, sess string, n int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	for len(out) < n {
		chunk, err := srv.ReadSession(sess, n-len(out)+64)
		if err != nil {
			t.Fatalf("ReadSession: %v", err)
		}
		out = append(out, chunk...)
	}
	return out
}

// readConnN 从 net.Conn 精确读取 n 字节（客户端视角）。
func readConnN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	off := 0
	for off < n {
		m, err := c.Read(buf[off:])
		if err != nil {
			t.Fatalf("conn read: %v", err)
		}
		off += m
	}
	return buf
}

func TestDNSTunnelRoundTrip(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sess1")
	defer tunnel.Close()

	// 客户端 -> 服务端
	msg := []byte("client-hello-over-dns")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("client->server mismatch: got %q want %q", got, msg)
	}

	// 服务端 -> 客户端
	reply := []byte("server-world-over-dns-0123456789")
	srv.WriteSession(sess, reply)
	buf := make([]byte, 256)
	n, err := tunnel.Read(buf)
	if err != nil {
		t.Fatalf("tunnel read: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Fatalf("server->client mismatch: got %q want %q", buf[:n], reply)
	}
}

func TestDNSTunnelLargePayload(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessBig")
	defer tunnel.Close()

	payload := bytes.Repeat([]byte("Z"), 500)
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, 500); !bytes.Equal(got, payload) {
		t.Fatalf("large client->server mismatch (len got=%d)", len(got))
	}

	back := bytes.Repeat([]byte("Y"), 500)
	srv.WriteSession(sess, back)
	if got := readConnN(t, tunnel, 500); !bytes.Equal(got, back) {
		t.Fatalf("large server->client mismatch (len got=%d)", len(got))
	}
}

func TestDNSTunnelFailover(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	// 第一个上游不可达，应自动故障转移到真实 addr
	servers := []string{"127.0.0.1:1", addr}
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, servers, "tunnel.test.", dns.TypeTXT, "sessF")
	defer tunnel.Close()

	msg := []byte("failover-test-ok")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("tunnel write (failover): %v", err)
	}
	sess, err := srv.WaitForSession(5 * time.Second)
	if err != nil {
		t.Fatalf("wait session (failover): %v", err)
	}
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("failover client->server mismatch: got %q want %q", got, msg)
	}
}

func TestDNSTunnelConfigError(t *testing.T) {
	if _, err := NewDNSTunnel(context.Background(), ProxyConfig{}); err == nil {
		t.Fatal("expected error for missing dns_tunnel_domain/servers")
	}
}

func TestDNSTunnelTypeA(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	// A 记录仅能承载 4 字节，验证最小可用通路
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeA, "sessA")
	defer tunnel.Close()

	msg := []byte("abcd") // 恰好 4 字节，可完整放进 A 记录
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("tunnel write (A): %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session (A): %v", err)
	}
	// 服务端回的数据同样是 A(4 字节)，这里仅验证上行落地
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("A client->server mismatch: got %q want %q", got, msg)
	}
}
