package myssh

import (
	"context"
	"net"
	"testing"
)

// TestRawFixedChromeALPN 固化 raw 隧道的 ALPN 契约：TLS 模式恒用 Chrome 标准
// "h2,http/1.1"（不随配置变化），以维持 Chrome ClientHello 画像。
func TestRawFixedChromeALPN(t *testing.T) {
	c := buildUTLSConfig(ProxyConfig{ServerName: "example.com"}, []string{"h2", "http/1.1"})
	if len(c.NextProtos) != 2 || c.NextProtos[0] != "h2" || c.NextProtos[1] != "http/1.1" {
		t.Fatalf("raw must present Chrome-standard ALPN, got %v", c.NextProtos)
	}
}

// TestRawCleartextPassthrough 验证 TLS 开关关闭时 raw 直通 baseConn（明文），
// 开启逻辑由 cfg.TunnelTLSEnabled 决定。
func TestRawCleartextPassthrough(t *testing.T) {
	proto, err := GetTunnel("raw")
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	out, err := proto.Handler(context.Background(), ProxyConfig{TunnelType: "raw"}, a)
	if err != nil {
		t.Fatal(err)
	}
	if out != a {
		t.Fatal("cleartext raw must return the base conn unchanged")
	}
}
