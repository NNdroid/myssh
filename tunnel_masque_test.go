package myssh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMasqueTunnel_Registration(t *testing.T) {
	proto, err := GetTunnel("masque")
	if err != nil {
		t.Fatalf("Expected masque tunnel to be registered, got error: %v", err)
	}
	if proto.Network != "custom" {
		t.Errorf("Expected network to be 'custom', got '%s'", proto.Network)
	}
	if proto.Handler == nil {
		t.Fatal("Expected handler to be non-nil")
	}
}

func TestMasqueTunnel_H2_Success(t *testing.T) {
	// 启动一个本地的 HTTP/2 测试服务器
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("Expected CONNECT method, got %s", r.Method)
		}
		if r.Header.Get("Protocol") != "connect-tcp" {
			t.Errorf("Expected Protocol: connect-tcp, got %s", r.Header.Get("Protocol"))
		}

		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		// 读写一些数据模拟隧道，并手动 Flush 保证客户端能及时收到数据
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				break
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	// 提取出地址
	proxyAddr := strings.TrimPrefix(server.URL, "https://")

	proto, _ := GetTunnel("masque")

	cfg := ProxyConfig{
		Alpn:       "h2",
		ProxyAddr:  proxyAddr,
		SshAddr:    "10.0.0.1:2222",
		CustomPath: "/.well-known/masque/tcp",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("MASQUE H2 handler failed: %v", err)
	}
	defer conn.Close()

	// 测试读写
	go func() {
		conn.Write([]byte("ping"))
	}()

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from masque conn: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Errorf("Expected 'ping', got '%s'", string(buf[:n]))
	}
}

func TestMasqueTunnel_H2_Reject(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	proxyAddr := strings.TrimPrefix(server.URL, "https://")
	proto, _ := GetTunnel("masque")

	cfg := ProxyConfig{
		Alpn:      "h2",
		ProxyAddr: proxyAddr,
		SshAddr:   "10.0.0.1:22",
	}

	ctx := context.Background()
	_, err := proto.Handler(ctx, cfg, nil)
	if err == nil {
		t.Fatal("Expected error on rejected masque connection, got nil")
	}
	if !strings.Contains(err.Error(), "masque proxy returned status 403") {
		t.Errorf("Unexpected error message: %v", err)
	}
}
