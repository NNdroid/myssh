package myssh

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lxzan/gws"
)

// startWSEchoServer 启动本地 WebSocket 回显服务端，供 ws tunnel 测试双向传输。
// 接受 testing.TB 以便普通测试与基准测试共用。
func startWSEchoServer(t testing.TB) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws listen: %v", err)
	}
	upgrader := gws.NewUpgrader(gws.BuiltinEventHandler{}, &gws.ServerOption{
		SubProtocols: []string{"binary"},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := upgrader.Upgrade(w, r)
			if err != nil {
				return
			}
			defer func() { _ = c.WriteClose(1000, nil) }()
			// 用 WS 适配层 wsStream 包装 net.Conn 后回显。
			nc := &wsStream{conn: c}
			_, _ = io.Copy(nc, nc)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close(); _ = ln.Close() }
}

// TestWebSocketEchoRoundTrip 验证 ws（明文）隧道握手完成后的字节回显链路。
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
	proto, err := GetTunnel("websocket")
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

// TestWebSocketAuthFailure 验证收到 401 响应时，ws 隧道握手报错退出。
func TestWebSocketAuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 不升级，直接给 client 回 401 Authentication failed 响应。
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
	proto, err := GetTunnel("websocket")
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

// TestWebSocketRegistration 验证 websocket 已在 init 中按约定注册。
func TestWebSocketRegistration(t *testing.T) {
	proto, err := GetTunnel("websocket")
	if err != nil {
		t.Fatalf("GetTunnel(websocket): %v", err)
	}
	if proto.Network != "tcp" {
		t.Errorf("GetTunnel(websocket).Network = %q, want tcp", proto.Network)
	}
	if proto.Handler == nil {
		t.Error("GetTunnel(websocket).Handler is nil")
	}
}
