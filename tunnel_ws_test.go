package myssh

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// startWSEchoServer  info  WebSocket  info ， info  ws tunnel info bidirectional info 。
func startWSEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
				Subprotocols:       []string{"binary"},
				InsecureSkipVerify: true,
				OriginPatterns:     []string{"*"},
			})
			if err != nil {
				return
			}
			defer c.Close(websocket.StatusNormalClosure, "")
			//  info  WS  info  net.Conn  info ， info 。
			nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
			_, _ = io.Copy(nc, nc)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close(); _ = ln.Close() }
}

// TestWebSocketEchoRoundTrip  info  ws（ info ）tunnel info completed info bytes。
func TestWebSocketEchoRoundTrip(t *testing.T) {
	addr, stop := startWSEchoServer(t)
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
		t.Fatalf("GetTunnel(ws): %v", err)
	}

	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		t.Fatalf("ws handler: %v", err)
	}
	defer conn.Close()

	want := []byte("SSH-2.0-myssh-ws-roundtrip-PAYLOAD-0987654321")
	go func() {
		if _, werr := conn.Write(want); werr != nil {
			t.Logf("ws write: %v", werr)
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

// TestWebSocketAuthFailure  info  401  info ，ws tunnel info 。
func TestWebSocketAuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//  info ， info client 401 Authentication failed info 。
			w.WriteHeader(http.StatusUnauthorized)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close(); _ = ln.Close() }()

	cfg := ProxyConfig{
		ProxyAddr:         ln.Addr().String(),
		CustomHost:        "proxy.test",
		CustomPath:        "/",
		SshAddr:           "127.0.0.1:22",
		ServerName:        "proxy.test",
		ProxyAuthRequired: true,
		ProxyAuthUser:     "u",
		ProxyAuthPass:     "p",
	}
	proto, err := GetTunnel("ws")
	if err != nil {
		t.Fatalf("GetTunnel(ws): %v", err)
	}

	baseConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected ws auth failure (401), got nil error")
	}
}

// TestWebSocketRegistration  info  ws/wss  info  init  info 。
func TestWebSocketRegistration(t *testing.T) {
	for _, name := range []string{"ws", "wss"} {
		proto, err := GetTunnel(name)
		if err != nil {
			t.Fatalf("GetTunnel(%q): %v", name, err)
		}
		if proto.Network != "tcp" {
			t.Errorf("GetTunnel(%q).Network = %q, want tcp", name, proto.Network)
		}
		if proto.Handler == nil {
			t.Errorf("GetTunnel(%q).Handler is nil", name)
		}
	}
}
