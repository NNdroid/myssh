package myssh

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestH3Registration 验证 h3 协议已注册且底层网络类型为 custom（自行接管 socket）。
func TestH3Registration(t *testing.T) {
	proto, err := GetTunnel("h3")
	if err != nil {
		t.Fatalf("GetTunnel(h3): %v", err)
	}
	if proto.Network != "custom" {
		t.Fatalf("h3 network = %q, want \"custom\"", proto.Network)
	}
}

// TestH3ConnAddrs 验证 h3Conn 的地址方法行为符合预期：远端地址来自配置，
// 本地地址为零值 UDP（QUIC 隧道不暴露真实 TCP 地址）。
func TestH3ConnAddrs(t *testing.T) {
	s := &h3Conn{remoteAddr: "198.51.100.7:443"}
	remote := s.RemoteAddr()
	if ua, ok := remote.(*net.UDPAddr); !ok || ua.IP.String() != "198.51.100.7" || ua.Port != 443 {
		t.Fatalf("RemoteAddr = %v, want 198.51.100.7:443", remote)
	}
	local := s.LocalAddr()
	if ua, ok := local.(*net.UDPAddr); !ok || !ua.IP.IsUnspecified() || ua.Port != 0 {
		t.Fatalf("LocalAddr = %v, want unspecified:0", local)
	}
}

// TestH3HandshakeError 验证 h3 隧道在底层 UDP 拨号失败（非法地址）时快速返回错误，而非挂死。
func TestH3HandshakeError(t *testing.T) {
	h3TransportCache = sync.Map{}
	defer func() { h3TransportCache = sync.Map{} }()

	proto, err := GetTunnel("h3")
	if err != nil {
		t.Fatalf("GetTunnel(h3): %v", err)
	}
	cfg := ProxyConfig{ProxyAddr: "127.0.0.1:notaport", ServerName: "localhost"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// h3 协议 network=custom，由协议自行建连，baseConn 传 nil 即可。
	if _, err := proto.Handler(ctx, cfg, nil); err == nil {
		t.Fatal("expected h3 handshake to fail on invalid proxy addr, got nil")
	}
}
