package myssh

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestH3Registration  info  h3  info  custom（ info  socket）。
func TestH3Registration(t *testing.T) {
	proto, err := GetTunnel("h3")
	if err != nil {
		t.Fatalf("GetTunnel(h3): %v", err)
	}
	if proto.Network != "custom" {
		t.Fatalf("h3 network = %q, want \"custom\"", proto.Network)
	}
}

// TestH3ConnAddrs  info  h3Conn  info address info ： info address info config，
//
//	info address info  UDP（QUIC tunnel info  TCP address）。
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

// TestH3HandshakeError  info  h3 tunnel info  UDP  info failed（ info address） info ， info 。
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
	// h3  info  network=custom， info ，baseConn  info  nil  info 。
	if _, err := proto.Handler(ctx, cfg, nil); err == nil {
		t.Fatal("expected h3 handshake to fail on invalid proxy addr, got nil")
	}
}
