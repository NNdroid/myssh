package myssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// =============================================================
// tunnel_dns.go 的边缘场景与错误路径测试
//
// 本文件补充 tunnel_dns_test.go 未覆盖的分支：空写入、读超时/截止时间、
// 关闭后行为、服务端关闭会话→EOF、NULL/CNAME 记录类型双向、并发读写、
// TCP 传输，以及 NewDNSTunnel 的配置错误分支。
// 复用同包内的 startTestDnsServer / readSessionN / readConnN / stopTestDnsServer。
// =============================================================

// startTestDnsServerTCP 在 loopback TCP 上启动隧道权威 DNS 服务端，
// 返回服务端实例、DNS Server 与带 tcp:// 前缀的可达地址（供 dns_tunnel_servers 使用）。
func startTestDnsServerTCP(t *testing.T) (*DNSTunnelServer, *dns.Server, string) {
	t.Helper()
	srv := NewDNSTunnelServer("tunnel.test.")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr := "tcp://" + ln.Addr().String()
	dnsSrv := &dns.Server{Listener: ln, Handler: srv}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	return srv, dnsSrv, addr
}

// TestDNSTunnelEmptyWrite 验证写入空切片时不发送任何查询、不报错，且隧道仍可正常使用。
func TestDNSTunnelEmptyWrite(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessEmpty")
	defer tunnel.Close()

	// 空写入：循环体不执行，应直接返回 (0, nil)，不触发任何上行查询
	n, err := tunnel.Write(nil)
	if err != nil {
		t.Fatalf("empty write should not error: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty write should return 0 bytes, got %d", n)
	}

	// 隧道仍可用：随后写入应正常落地
	msg := []byte("after-empty-ok")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("write after empty: %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("after-empty client->server mismatch: got %q want %q", got, msg)
	}
}

// TestDNSTunnelReadDeadline 验证 SetReadDeadline 到过去时间时，Read 立即返回截止错误。
func TestDNSTunnelReadDeadline(t *testing.T) {
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{"127.0.0.1:1"}, "tunnel.test.", dns.TypeTXT, "sessDL")
	defer tunnel.Close()

	// 截止时间设在过去，Read 不应阻塞或上行任何查询
	tunnel.SetReadDeadline(time.Now().Add(-time.Second))

	buf := make([]byte, 16)
	_, err := tunnel.Read(buf)
	if err == nil {
		t.Fatal("expected deadline exceeded error, got nil")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", err)
	}
}

// TestDNSTunnelReadAfterClose 验证关闭后 Read/Write 立即返回 net.ErrClosed，不触发上行。
func TestDNSTunnelReadAfterClose(t *testing.T) {
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{"127.0.0.1:1"}, "tunnel.test.", dns.TypeTXT, "sessRC")
	// 先关闭（内部 attempt 关闭查询被忽略错误）
	if err := tunnel.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	buf := make([]byte, 16)
	if _, err := tunnel.Read(buf); err != net.ErrClosed {
		t.Fatalf("read after close: expected net.ErrClosed, got %v", err)
	}
	if n, err := tunnel.Write([]byte("x")); err != net.ErrClosed || n != 0 {
		t.Fatalf("write after close: expected (0, net.ErrClosed), got (%d, %v)", n, err)
	}
}

// TestDNSTunnelServerCloseEOF 验证客户端关闭后，服务端 ReadSession 返回 io.EOF。
func TestDNSTunnelServerCloseEOF(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessSCE")
	defer tunnel.Close()

	msg := []byte("client-data-before-close")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("client->server mismatch: got %q want %q", got, msg)
	}

	// 客户端关闭会话（同步发送关闭查询，服务端 markClosed 后才返回）
	if err := tunnel.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// 服务端后续读取应得到 EOF
	if _, err := srv.ReadSession(sess, 8); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after close, got %v", err)
	}
}

// TestDNSTunnelTypeNULL 验证 NULL 记录类型双向传输（含多片分块：300 字节）。
func TestDNSTunnelTypeNULL(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeNULL, "sessNULL")
	defer tunnel.Close()

	payload := bytes.Repeat([]byte("N"), 300)
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, 300); !bytes.Equal(got, payload) {
		t.Fatalf("NULL client->server mismatch (len got=%d)", len(got))
	}

	back := bytes.Repeat([]byte("M"), 300)
	srv.WriteSession(sess, back)
	if got := readConnN(t, tunnel, 300); !bytes.Equal(got, back) {
		t.Fatalf("NULL server->client mismatch (len got=%d)", len(got))
	}
}

// TestDNSTunnelTypeCNAME 验证 CNAME 记录类型双向传输（小负载，因单标签上限 ~39 字节）。
func TestDNSTunnelTypeCNAME(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeCNAME, "sessCNAME")
	defer tunnel.Close()

	payload := bytes.Repeat([]byte("C"), 20) // 20 字节 < 39 字节上限
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("CNAME client->server mismatch: got %q want %q", got, payload)
	}

	back := bytes.Repeat([]byte("X"), 20)
	srv.WriteSession(sess, back)
	if got := readConnN(t, tunnel, len(back)); !bytes.Equal(got, back) {
		t.Fatalf("CNAME server->client mismatch: got %q want %q", got, back)
	}
}

// TestDNSTunnelConcurrentRW 验证同一隧道上客户端「并发写 + 并发读（回显）」不丢数据、不死锁。
func TestDNSTunnelConcurrentRW(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessConc")
	defer tunnel.Close()

	payload := bytes.Repeat([]byte("Q"), 800)

	// 服务端：等会话、收全量、原样回显
	go func() {
		sess, err := srv.WaitForSession(5 * time.Second)
		if err != nil {
			t.Errorf("wait session: %v", err)
			return
		}
		data := readSessionN(t, srv, sess, len(payload))
		srv.WriteSession(sess, data)
	}()

	// 客户端：写与读并发进行（Write 发数据查询，Read 发轮询查询，共享 exchangeMu 串行化上行）
	writeDone := make(chan error, 1)
	go func() {
		_, e := tunnel.Write(payload)
		writeDone <- e
	}()

	if got := readConnN(t, tunnel, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("concurrent echo mismatch (len got=%d)", len(got))
	}
	if e := <-writeDone; e != nil {
		t.Fatalf("concurrent write: %v", e)
	}
}

// TestDNSTunnelTCPTransport 验证通过 tcp:// 上游（而非默认 udp）完成完整往返。
func TestDNSTunnelTCPTransport(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServerTCP(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessTCP")
	defer tunnel.Close()

	msg := []byte("tcp-transport-ok")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	sess, err := srv.WaitForSession(5 * time.Second)
	if err != nil {
		t.Fatalf("wait session: %v", err)
	}
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("tcp client->server mismatch: got %q want %q", got, msg)
	}

	reply := []byte("tcp-reply-ok-0123456789")
	srv.WriteSession(sess, reply)
	if got := readConnN(t, tunnel, len(reply)); !bytes.Equal(got, reply) {
		t.Fatalf("tcp server->client mismatch: got %q want %q", got, reply)
	}
}

// TestDNSTunnelConfigErrors 覆盖 NewDNSTunnel 的配置校验与 dnsTypeToQType 的 default 分支。
func TestDNSTunnelConfigErrors(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ProxyConfig
		wantErr bool
	}{
		{
			name:    "missing domain",
			cfg:     ProxyConfig{DnsTunnelServers: []string{"127.0.0.1:53"}},
			wantErr: true,
		},
		{
			name:    "missing servers",
			cfg:     ProxyConfig{DnsTunnelDomain: "tunnel.test."},
			wantErr: true,
		},
		{
			name:    "unsupported type",
			cfg:     ProxyConfig{DnsTunnelDomain: "tunnel.test.", DnsTunnelServers: []string{"127.0.0.1:53"}, DnsTunnelType: "soa"},
			wantErr: true,
		},
		{
			name:    "valid config",
			cfg:     ProxyConfig{DnsTunnelDomain: "tunnel.test.", DnsTunnelServers: []string{"127.0.0.1:53"}, DnsTunnelType: "txt"},
			wantErr: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, err := NewDNSTunnel(context.Background(), c.cfg)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", c.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", c.name, err)
			}
			if conn == nil {
				t.Fatalf("expected non-nil conn for %s", c.name)
			}
			_ = conn.Close()
		})
	}
}
