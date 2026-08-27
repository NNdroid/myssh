package myssh

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConn  info  net.Conn  info 。
// tunnel info ， info  Close  info （ info closed）。
type fakeConn struct {
	closed bool
}

func (c *fakeConn) Read([]byte) (int, error)           { return 0, nil }
func (c *fakeConn) Write([]byte) (int, error)          { return 0, nil }
func (c *fakeConn) Close() error                       { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// TestTunnelRegistry  info tunnel info  init  info ，
//
//	info  network  info  handler；unknown info 。
func TestTunnelRegistry(t *testing.T) {
	tests := []struct {
		key         string
		wantNetwork string
		wantErr     bool
	}{
		{"h2", "tcp", false},
		{"h2c", "tcp", false},
		{"grpc", "tcp", false},
		{"grpcc", "tcp", false},
		{"masque", "custom", false},
		{"kcp", "udp", false},
		{"udp_custom", "udp", false},
		{"nonexistent-proto", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			proto, err := GetTunnel(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetTunnel(%q): expected error, got nil", tt.key)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetTunnel(%q) error: %v", tt.key, err)
			}
			if proto.Network != tt.wantNetwork {
				t.Errorf("GetTunnel(%q).Network = %q, want %q", tt.key, proto.Network, tt.wantNetwork)
			}
			if proto.Handler == nil {
				t.Errorf("GetTunnel(%q).Handler is nil", tt.key)
			}
		})
	}
}

// TestAcquireH2Transport  info  H2/gRPC  info channel info ：
//   - info （ info ） info  *http.Client；
//   - info  key  info ， info closed info  baseConn。
func TestAcquireH2Transport(t *testing.T) {
	tests := []struct {
		name  string
		isTLS bool
	}{
		{"h2c_cache_miss_then_hit", false},
		{"h2_cache_miss_then_hit", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//  info ， info 。
			h2TransportCache = sync.Map{}
			cacheKey := "proxy.example.com:443|" + tt.name
			cfg := ProxyConfig{
				ProxyAddr:  "proxy.example.com:443",
				ServerName: "proxy.example.com",
			}

			base1 := &fakeConn{}
			client1, err := acquireH2Transport(context.Background(), cacheKey, tt.isTLS, cfg, base1)
			if err != nil {
				t.Fatalf("first acquire failed: %v", err)
			}
			if client1 == nil || client1.Transport == nil {
				t.Fatal("expected non-nil client with a Transport")
			}

			//  info  key  info ， info  client， info closed info  baseConn。
			base2 := &fakeConn{}
			client2, err := acquireH2Transport(context.Background(), cacheKey, tt.isTLS, cfg, base2)
			if err != nil {
				t.Fatalf("second acquire failed: %v", err)
			}
			if client2 != client1 {
				t.Error("expected cached client to be reused (same pointer)")
			}
			if !base2.closed {
				t.Error("expected baseConn to be closed on cache hit")
			}
		})
	}
}

// TestBuildUTLSConfig  info  uTLS config info ：ServerName、InsecureSkipVerify、
// ALPN（NextProtos） info 。
func TestBuildUTLSConfig(t *testing.T) {
	tests := []struct {
		name       string
		cfg        ProxyConfig
		alpn       []string
		wantServer string
		wantProtos []string
	}{
		{
			name:       "with_alpn_and_pinning",
			cfg:        ProxyConfig{ServerName: "example.com", VerifyCertificateFingerprint: true, ServerCertificateFingerprint: "sha256/abc"},
			alpn:       []string{"h2", "http/1.1"},
			wantServer: "example.com",
			wantProtos: []string{"h2", "http/1.1"},
		},
		{
			name:       "no_alpn",
			cfg:        ProxyConfig{ServerName: "example.org"},
			alpn:       nil,
			wantServer: "example.org",
			wantProtos: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := buildUTLSConfig(tt.cfg, tt.alpn)
			if c == nil {
				t.Fatal("buildUTLSConfig returned nil")
			}
			if c.ServerName != tt.wantServer {
				t.Errorf("ServerName = %q, want %q", c.ServerName, tt.wantServer)
			}
			if !c.InsecureSkipVerify {
				t.Error("expected InsecureSkipVerify = true")
			}
			if len(c.NextProtos) != len(tt.wantProtos) {
				t.Errorf("NextProtos = %v, want %v", c.NextProtos, tt.wantProtos)
			}
			if c.VerifyPeerCertificate == nil {
				t.Error("expected VerifyPeerCertificate to be set")
			}
		})
	}
}

// TestGRPCFramingRoundTrip  info  gRPC  info / info ，
//
//	info 、 info 、32KB  info 、 info ， info 。
func TestGRPCFramingRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"small", []byte("hello world")},
		{"medium", bytes.Repeat([]byte("a"), 1000)},
		{"boundary_32k", bytes.Repeat([]byte("b"), 32*1024)},
		{"large_40k", bytes.Repeat([]byte("c"), 40*1024)},
		{"binary", []byte{0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			gw := &grpcWriter{w: buf}
			n, err := gw.Write(tt.payload)
			if err != nil {
				t.Fatalf("Write error: %v", err)
			}
			if n != len(tt.payload) {
				t.Fatalf("Write returned %d, want %d", n, len(tt.payload))
			}

			gr := &grpcReader{r: buf}
			out := make([]byte, len(tt.payload))
			got := 0
			for got < len(tt.payload) {
				m, rerr := gr.Read(out[got:])
				got += m
				if rerr != nil {
					t.Fatalf("Read error after %d bytes: %v", got, rerr)
				}
				if m == 0 {
					t.Fatal("Read returned 0 with no error (possible stall)")
				}
			}
			if !bytes.Equal(out, tt.payload) {
				t.Errorf("round-trip mismatch: got %q, want %q", out, tt.payload)
			}
		})
	}
}

// TestStreamConnAddr  info  streamConn  info address info ：
//
//	info address info  *net.TCPAddr； info address info default 443 port。
func TestStreamConnAddr(t *testing.T) {
	tests := []struct {
		name      string
		remote    string
		wantPort  int
		wantValid bool
	}{
		{"ipv4", "1.2.3.4:443", 443, true},
		{"ipv6", "[::1]:8080", 8080, true},
		{"unparseable_fallback_443", "not a valid addr", 443, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &streamConn{remote: tt.remote}
			addr := s.RemoteAddr()
			tcp, ok := addr.(*net.TCPAddr)
			if !ok {
				t.Fatalf("RemoteAddr() = %T, want *net.TCPAddr", addr)
			}
			if tcp.Port != tt.wantPort {
				t.Errorf("RemoteAddr().Port = %d, want %d", tcp.Port, tt.wantPort)
			}

			// LocalAddr  info address。
			la := s.LocalAddr()
			if la.String() != (&net.TCPAddr{IP: net.IPv4zero, Port: 0}).String() {
				t.Errorf("LocalAddr() = %v, want zero TCP addr", la)
			}
		})
	}
}
