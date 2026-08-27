package myssh

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestWTRegistration  info  wt（WebTransport） info  custom。
func TestWTRegistration(t *testing.T) {
	proto, err := GetTunnel("wt")
	if err != nil {
		t.Fatalf("GetTunnel(wt): %v", err)
	}
	if proto.Network != "custom" {
		t.Fatalf("wt network = %q, want \"custom\"", proto.Network)
	}
}

// TestWTConnAddrs  info  wtConn  info address info ： info address info config， info  UDP。
// wtConn  info  *webtransport.Stream， info address info  Stream， info 。
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

// TestWTHandshakeError  info  wt tunnel info  UDP  info failed（ info address） info 。
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
