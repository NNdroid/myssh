package myssh

import (
	"net"
	"testing"
)

func TestSDKTunnelRegistrationsOwnDialing(t *testing.T) {
	for _, name := range []string{"xhttp", "xhttpc", "h2", "h2c", "h3", "wt", "masque", "grpc", "grpcc", "udp_custom", "dns_custom", "icmp_custom"} {
		proto, err := GetTunnel(name)
		if err != nil {
			t.Fatalf("GetTunnel(%q): %v", name, err)
		}
		if proto.Network != "custom" {
			t.Errorf("GetTunnel(%q).Network = %q, want custom", name, proto.Network)
		}
	}
}

func TestSDKProxyEndpoint(t *testing.T) {
	endpoint, path, err := sdkProxyEndpoint(ProxyConfig{TunnelType: "h2", ProxyAddr: "proxy.example:443", CustomPath: "edge"}, "https", "/tunnel")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://proxy.example:443" || path != "/edge" {
		t.Fatalf("endpoint=%q path=%q", endpoint, path)
	}
	endpoint, path, err = sdkProxyEndpoint(ProxyConfig{TunnelType: "xhttp", ProxyAddr: "https://proxy.example/custom"}, "https", "/stream")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://proxy.example" || path != "/custom" {
		t.Fatalf("endpoint=%q path=%q", endpoint, path)
	}
}

func TestNormalizeXHTTPALPN(t *testing.T) {
	tests := map[string]string{
		"":                 "auto",
		"h3,h2,http/1.1":   "auto",
		"h2,http/1.1":      "h2",
		"http/1.1":         "h1",
		"unexpected-value": "auto",
	}
	for input, want := range tests {
		if got := normalizeXHTTPALPN(input); got != want {
			t.Errorf("normalizeXHTTPALPN(%q)=%q want %q", input, got, want)
		}
	}
}

func TestParseUDPCMagicSDK(t *testing.T) {
	got, err := parseUDPCMagicSDK("UDPC")
	if err != nil || got != 0x55445043 {
		t.Fatalf("got=%08x err=%v", got, err)
	}
	if _, err := parseUDPCMagicSDK("bad"); err == nil {
		t.Fatal("expected invalid magic error")
	}
}

func TestOwnedSDKConnClosesOwnerOnce(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	closed := 0
	conn := ownSDKConn(left, func() error { closed++; return nil })
	_ = conn.Close()
	_ = conn.Close()
	if closed != 1 {
		t.Fatalf("owner closed %d times", closed)
	}
}

func TestSDKConfigValidationBeforeDial(t *testing.T) {
	if _, err := dialUDPCustomSDK(t.Context(), ProxyConfig{ProxyAddr: "127.0.0.1:1", SshAddr: "127.0.0.1:22"}); err == nil {
		t.Fatal("udp_custom accepted missing PSK")
	}
	if _, err := NewDNSTunnel(t.Context(), ProxyConfig{SshAddr: "127.0.0.1:22"}); err == nil {
		t.Fatal("dns_custom accepted missing domain and servers")
	}
	if _, err := dialXHTTPSDK(t.Context(), ProxyConfig{TunnelType: "xhttp", ProxyAddr: "http://127.0.0.1:1", SshAddr: "127.0.0.1:22"}, true); err == nil {
		t.Fatal("xhttp accepted an http endpoint for TLS mode")
	}
	if _, err := dialICMPCustomSDK(t.Context(), ProxyConfig{SshAddr: "127.0.0.1:22"}); err == nil {
		t.Fatal("icmp_custom accepted missing server address")
	}
	if _, err := dialICMPCustomSDK(t.Context(), ProxyConfig{ProxyAddr: "203.0.113.7", SshAddr: "127.0.0.1:22"}); err == nil {
		t.Fatal("icmp_custom accepted missing PSK")
	}
}

// TestResolveTunnelTLS 验证合并型隧道的 TLS 开关语义：
// 显式设置优先；旧配置（nil）沿用类型的历史 TLS 语义。
func TestResolveTunnelTLS(t *testing.T) {
	on, off := true, false

	// grpc 历史上是 TLS：nil → true
	if !resolveTunnelTLS(ProxyConfig{TunnelType: "grpc"}, true) {
		t.Fatal("legacy grpc must default to TLS on")
	}
	if resolveTunnelTLS(ProxyConfig{TunnelType: "grpc", TunnelTLSEnabled: &off}, true) {
		t.Fatal("explicit off must win over legacy default")
	}
	// websocket 是新类型：nil → false
	if resolveTunnelTLS(ProxyConfig{TunnelType: "websocket"}, false) {
		t.Fatal("websocket must default to cleartext")
	}
	if !resolveTunnelTLS(ProxyConfig{TunnelType: "websocket", TunnelTLSEnabled: &on}, false) {
		t.Fatal("explicit on must enable TLS")
	}
}

// TestWebsocketRegistration 新统一类型的网络声明。
func TestWebsocketRegistration(t *testing.T) {
	proto, err := GetTunnel("websocket")
	if err != nil {
		t.Fatalf("GetTunnel(websocket): %v", err)
	}
	if proto.Network != "tcp" || proto.Handler == nil {
		t.Fatalf("websocket: network=%q handler=%v", proto.Network, proto.Handler)
	}
	// 旧类型别名仍然可解析
	for _, name := range []string{"ws", "wss"} {
		if _, err := GetTunnel(name); err != nil {
			t.Fatalf("legacy alias %q missing: %v", name, err)
		}
	}
}
