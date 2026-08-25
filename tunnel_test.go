package myssh

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConn 是一个仅用于测试的 net.Conn 桩实现。
// 隧道层测试不需要真实网络，只关心 Close 的副作用（缓存命中时应被关闭）。
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

// TestTunnelRegistry 验证核心隧道协议均在 init 阶段正确注册，
// 并返回预期的 network 与非空 handler；未知协议应报错。
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

// TestAcquireH2Transport 验证 H2/gRPC 传输通道的缓存语义：
//   - 首次调用（缓存未命中）返回非空的 *http.Client；
//   - 同 key 第二次调用应命中缓存并返回同一指针，同时关闭新传入的 baseConn。
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
			// 重置全局缓存，保证用例相互独立。
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

			// 第二次同 key 应命中缓存，复用同一 client，并关闭新传入的 baseConn。
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

// TestBuildUTLSConfig 验证 uTLS 配置构造正确：ServerName、InsecureSkipVerify、
// ALPN（NextProtos）以及证书校验回调均按预期设置。
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

// TestGRPCFramingRoundTrip 对 gRPC 数据帧封装/解封装做表驱动往返测试，
// 覆盖小包、中包、32KB 边界、超大包与二进制数据，验证零拷贝帧格式正确还原。
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

// TestStreamConnAddr 验证 streamConn 的地址解析：
// 合法地址应解析为对应 *net.TCPAddr；非法地址应回退到默认 443 端口。
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

			// LocalAddr 应始终返回零值地址。
			la := s.LocalAddr()
			if la.String() != (&net.TCPAddr{IP: net.IPv4zero, Port: 0}).String() {
				t.Errorf("LocalAddr() = %v, want zero TCP addr", la)
			}
		})
	}
}
