package myssh

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startRawEchoServer  info 「 info  TCP tunnel」 info ：
//   - info client info （ info ）， info  onHandshake  info ；
//   - info  rejectStatus>0  info ， info  200  info bytes info 。
func startRawEchoServer(t *testing.T, rejectStatus int, onHandshake func([]byte)) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("http listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var req []byte
				//  info 。
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					req = append(req, []byte(line)...)
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				if onHandshake != nil {
					onHandshake(req)
				}
				if rejectStatus > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 " + itoa(rejectStatus) + " Rejected\r\n\r\n"))
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				//  info ： info 。
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// TestHTTPTunnelEchoRoundTrip  info  http  info tunnel：send HttpPayload completed info ，
//
//	info bytestunnel， info bidirectional info 。
func TestHTTPTunnelEchoRoundTrip(t *testing.T) {
	addr, stop := startRawEchoServer(t, 0, nil)
	defer stop()

	cfg := ProxyConfig{
		ProxyAddr:  addr,
		CustomHost: "proxy.test",
		SshAddr:    "127.0.0.1:22",
		HttpPayload: "CONNECT [host_and_port] HTTP/1.1\r\n" +
			"Host: [host]\r\n" +
			"User-Agent: [user_agent]\r\n" +
			"\r\n",
	}
	proto, err := GetTunnel("http")
	if err != nil {
		t.Fatalf("GetTunnel(http): %v", err)
	}

	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		t.Fatalf("http handler: %v", err)
	}
	defer conn.Close()

	want := []byte("SSH-2.0-myssh-http-roundtrip-PAYLOAD-1122334455")
	go func() {
		if _, werr := conn.Write(want); werr != nil {
			t.Logf("http write: %v", werr)
		}
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

// TestHTTPTunnelPayloadSubstitution  info  HttpPayload  info ，
//
//	info （[auth]） info 。
func TestHTTPTunnelPayloadSubstitution(t *testing.T) {
	type result struct {
		raw []byte
		ok  bool
	}
	resCh := make(chan result, 1)

	addr, stop := startRawEchoServer(t, 0, func(raw []byte) {
		resCh <- result{raw: raw, ok: true}
	})
	defer stop()

	cfg := ProxyConfig{
		ProxyAddr:         addr,
		CustomHost:        "real-host.example.com",
		SshAddr:           "10.0.0.9:2222",
		ProxyAuthRequired: true,
		ProxyAuthUser:     "alice",
		ProxyAuthPass:     "secret",
		HttpPayload: "CONNECT [host_and_port] HTTP/1.1\r\n" +
			"Host: [host]\r\n" +
			"[auth]" +
			"\r\n",
	}
	proto, err := GetTunnel("http")
	if err != nil {
		t.Fatalf("GetTunnel(http): %v", err)
	}

	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		t.Fatalf("http handler: %v", err)
	}
	defer conn.Close()

	select {
	case r := <-resCh:
		s := string(r.raw)
		if !strings.Contains(s, "CONNECT 10.0.0.9:2222 HTTP/1.1") {
			t.Errorf("host_and_port not substituted: %q", s)
		}
		if !strings.Contains(s, "Host: real-host.example.com") {
			t.Errorf("host not substituted: %q", s)
		}
		if !strings.Contains(s, "Proxy-Authorization: Basic ") {
			t.Errorf("[auth] not injected: %q", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handshake capture")
	}
}

// TestHTTPTunnelEmptyPayload  info  HttpPayload  info closed info 。
func TestHTTPTunnelEmptyPayload(t *testing.T) {
	cfg := ProxyConfig{ProxyAddr: "127.0.0.1:1"}
	proto, err := GetTunnel("http")
	if err != nil {
		t.Fatalf("GetTunnel(http): %v", err)
	}
	// fakeConn  info ，handler  info  payload  info 。
	conn, err := proto.Handler(context.Background(), cfg, &fakeConn{})
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected error for empty HttpPayload, got nil")
	}
}

// TestHTTPTunnelNonHTTPResponse  info  HTTP  info ，handler  info 。
func TestHTTPTunnelNonHTTPResponse(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		//  info  handler  info  HttpPayload。
		_, _ = serverPipe.Read(buf)
		//  info  HTTP  info 。
		_, _ = serverPipe.Write([]byte("GARBAGE-PROTOCOL-RESPONSE\r\n"))
	}()

	cfg := ProxyConfig{
		ProxyAddr:  "127.0.0.1:1",
		CustomHost: "proxy.test",
		HttpPayload: "CONNECT [host_and_port] HTTP/1.1\r\n" +
			"Host: [host]\r\n\r\n",
	}
	proto, _ := GetTunnel("http")
	conn, err := proto.Handler(context.Background(), cfg, clientPipe)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected error for non-HTTP response, got nil")
	}
}

// TestHTTPTunnelAuthRejected  info  407  info ，handler  info Authentication failed info 。
func TestHTTPTunnelAuthRejected(t *testing.T) {
	addr, stop := startRawEchoServer(t, 407, nil)
	defer stop()

	cfg := ProxyConfig{
		ProxyAddr:         addr,
		CustomHost:        "proxy.test",
		SshAddr:           "127.0.0.1:22",
		ProxyAuthRequired: true,
		ProxyAuthUser:     "u",
		ProxyAuthPass:     "p",
		HttpPayload:       "CONNECT [host_and_port] HTTP/1.1\r\nHost: [host]\r\n[auth]\r\n",
	}
	proto, _ := GetTunnel("http")
	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected auth-rejected error (407), got nil")
	}
}
