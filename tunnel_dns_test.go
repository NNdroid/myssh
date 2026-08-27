package myssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDnsServer  info  loopback UDP  info tunnel info  DNS  info ， info 、DNS Server  info address。
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
	time.Sleep(30 * time.Millisecond) //  info  serve  info ， info  goleak  info
}

// readSessionN  info tunnel info  n bytes（ info ）。
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

// readConnN  info  net.Conn  info  n bytes（client info ）。
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

	// client ->  info
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

	//  info  -> client
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

	//  info ， info  addr
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

	// A  info  4 bytes， info
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{addr}, "tunnel.test.", dns.TypeA, "sessA")
	defer tunnel.Close()

	msg := []byte("abcd") //  info  4 bytes， info  A  info
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("tunnel write (A): %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session (A): %v", err)
	}
	//  info  A(4 bytes)， info uplink info
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("A client->server mismatch: got %q want %q", got, msg)
	}
}

func TestDNSTunnelDoHTransport(t *testing.T) {
	srv, dnsSrv, _ := startTestDnsServer(t)
	defer stopTestDnsServer(t, dnsSrv)

	//  info  DoH  info server info  srv
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen doh: %v", err)
	}
	defer ln.Close()

	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			reqMsg := new(dns.Msg)
			if err := reqMsg.Unpack(body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			respWriter := &dohTestResponseWriter{msgChan: make(chan *dns.Msg, 1)}
			srv.ServeDNS(respWriter, reqMsg)
			reply := <-respWriter.msgChan
			replyBytes, _ := reply.Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(http.StatusOK)
			w.Write(replyBytes)
		}),
	}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	dohURL := "http://" + ln.Addr().String() + "/dns-query"
	tunnel := newDNSTunnel(context.Background(), ProxyConfig{}, []string{dohURL}, "tunnel.test.", dns.TypeTXT, "sessDoH")
	defer tunnel.Close()

	msg := []byte("doh-test-payload")
	if _, err := tunnel.Write(msg); err != nil {
		t.Fatalf("tunnel write (DoH): %v", err)
	}
	sess, err := srv.WaitForSession(3 * time.Second)
	if err != nil {
		t.Fatalf("wait session (DoH): %v", err)
	}
	if got := readSessionN(t, srv, sess, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("DoH client->server mismatch: got %q want %q", got, msg)
	}
}

type dohTestResponseWriter struct {
	msgChan chan *dns.Msg
}

func (w *dohTestResponseWriter) LocalAddr() net.Addr       { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *dohTestResponseWriter) RemoteAddr() net.Addr      { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *dohTestResponseWriter) WriteMsg(m *dns.Msg) error { w.msgChan <- m; return nil }
func (w *dohTestResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *dohTestResponseWriter) Close() error              { return nil }
func (w *dohTestResponseWriter) TsigStatus() error         { return nil }
func (w *dohTestResponseWriter) TsigTimersOnly(bool)       {}
func (w *dohTestResponseWriter) Hijack()                   {}
