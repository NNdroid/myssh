package myssh

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestWTRegistration 验证 wt（WebTransport）协议已注册且底层网络类型为 custom。
func TestWTRegistration(t *testing.T) {
	proto, err := GetTunnel("wt")
	if err != nil {
		t.Fatalf("GetTunnel(wt): %v", err)
	}
	if proto.Network != "custom" {
		t.Fatalf("wt network = %q, want \"custom\"", proto.Network)
	}
}

// TestWTConnAddrs 验证 wtConn 的地址方法行为：远端地址来自配置，本地为零值 UDP。
// wtConn 内嵌 *webtransport.Stream，但地址方法不依赖 Stream，可安全单独构造测试。
func TestWTConnAddrs(t *testing.T) {
	w := &wtConn{remoteAddr: "203.0.113.9:443"}
	remote := w.RemoteAddr()
	if ua, ok := remote.(*net.UDPAddr); !ok || ua.IP.String() != "203.0.113.9" || ua.Port != 443 {
		t.Fatalf("RemoteAddr = %v, want 203.0.113.9:443", remote)
	}
	local := w.LocalAddr()
	if ua, ok := local.(*net.UDPAddr); !ok || !ua.IP.IsUnspecified() || ua.Port != 0 {
		t.Fatalf("LocalAddr = %v, want unspecified:0", local)
	}
}

// TestWTHandshakeError 验证 wt 隧道在底层 UDP 拨号失败（非法地址）时快速返回错误。
func TestWTHandshakeError(t *testing.T) {
	wtSessionCache = sync.Map{}
	defer func() { wtSessionCache = sync.Map{} }()

	proto, err := GetTunnel("wt")
	if err != nil {
		t.Fatalf("GetTunnel(wt): %v", err)
	}
	cfg := ProxyConfig{ProxyAddr: "127.0.0.1:notaport", ServerName: "localhost"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := proto.Handler(ctx, cfg, nil); err == nil {
		t.Fatal("expected wt handshake to fail on invalid proxy addr, got nil")
	}
}
