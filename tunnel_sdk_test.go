package myssh

import (
	"net"
	"testing"
)

func TestSDKTunnelRegistrationsOwnDialing(t *testing.T) {
	for _, name := range []string{"xhttp", "xhttpc", "h2", "h2c", "h3", "wt", "masque", "grpc", "grpcc", "udp_custom", "dns_custom"} {
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
}
