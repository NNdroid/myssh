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
// tunnel_dns_custom.go  info
//
//  info  tunnel_dns_test.go  info ： info 、 info timeout/ info 、
// closed info 、 info closed info →EOF、NULL/CNAME  info bidirectional、 info 、
// TCP  info ， info  NewDNSTunnel  info config info 。
//  info  startTestDnsServer / readSessionN / readConnN / stopTestDnsServer。
// =============================================================

// startTestDnsServerTCP  info  loopback TCP  info tunnel info  DNS  info ，
//
//	info 、DNS Server  info  tcp://  info address（ info  dns_tunnel_servers  info ）。
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

// TestDNSTunnelEmptyWrite  info send info 、 info ， info tunnel info 。
func TestDNSTunnelEmptyWrite(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessEmpty")
	defer tunnel.Close()

	//  info ： info ， info  (0, nil)， info uplink info
	n, err := tunnel.Write(nil)
	if err != nil {
		t.Fatalf("empty write should not error: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty write should return 0 bytes, got %d", n)
	}

	// tunnel info ： info
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

// TestDNSTunnelReadDeadline  info  SetReadDeadline  info ，Read  info 。
func TestDNSTunnelReadDeadline(t *testing.T) {
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{"127.0.0.1:1"}, "tunnel.test.", dns.TypeTXT, "sessDL")
	defer tunnel.Close()

	//  info ，Read  info uplink info
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

// TestDNSTunnelReadAfterClose  info closed info  Read/Write  info  net.ErrClosed， info uplink。
func TestDNSTunnelReadAfterClose(t *testing.T) {
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{"127.0.0.1:1"}, "tunnel.test.", dns.TypeTXT, "sessRC")
	//  info closed（ info  attempt closed info ignored info ）
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

// TestDNSTunnelServerCloseEOF  info clientclosed info ， info  ReadSession  info  io.EOF。
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

	// clientclosed info （ info sendclosed info ， info  markClosed  info ）
	if err := tunnel.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	//  info  EOF
	if _, err := srv.ReadSession(sess, 8); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after close, got %v", err)
	}
}

// TestDNSTunnelTypeNULL  info  NULL  info bidirectional info （ info ：300 bytes）。
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

// TestDNSTunnelTypeCNAME  info  CNAME  info bidirectional info （ info ， info  ~39 bytes）。
func TestDNSTunnelTypeCNAME(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeCNAME, "sessCNAME")
	defer tunnel.Close()

	payload := bytes.Repeat([]byte("C"), 20) // 20 bytes < 39 bytes info
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

// TestDNSTunnelConcurrentRW  info tunnel info client「 info  +  info （ info ）」 info 、 info 。
func TestDNSTunnelConcurrentRW(t *testing.T) {
	srv, dnsSrv, addr := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeTXT, "sessConc")
	defer tunnel.Close()

	payload := bytes.Repeat([]byte("Q"), 800)

	//  info ： info 、 info 、 info
	go func() {
		sess, err := srv.WaitForSession(5 * time.Second)
		if err != nil {
			t.Errorf("wait session: %v", err)
			return
		}
		data := readSessionN(t, srv, sess, len(payload))
		srv.WriteSession(sess, data)
	}()

	// client： info （Write  info ，Read  info ， info  exchangeMu  info uplink）
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

// TestDNSTunnelTCPTransport  info  tcp://  info （ info default udp）completed info 。
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

// TestDNSTunnelConfigErrors  info  NewDNSTunnel  info config info  dnsTypeToQType  info  default  info 。
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
