package myssh

import (
	"testing"
)

// TestEffectiveServerName 固化 SNI 解析契约：trim 后原样透传，空即空。
//
// 关键断言是最后两条——空值**不**被替换成连接目标。这条规则是探测与运行时
// 握手到同一张证书的前提（见 effectiveServerName 注释）：server_name 留空
// 且目标是域名时，回落 host 会让「获取」探到 host 匹配的证书、而运行时不发
// SNI 拿到默认证书，写下的 pin 随即在真连接时校验失败。
func TestEffectiveServerName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"   example.com\t", "example.com"},
		{"cdn.example.com:443", "cdn.example.com:443"},
		{"", ""},
		{"   ", ""},
	}
	for _, tt := range tests {
		if got := effectiveServerName(tt.in); got != tt.want {
			t.Errorf("effectiveServerName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestBuildUTLSConfigServerNameResolution 锁定运行时不给空 server_name 补 host：
// 运行时是 pin 的判读方，它拿到什么证书，「获取」就必须探到什么证书。
func TestBuildUTLSConfigServerNameResolution(t *testing.T) {
	for _, in := range []string{"", "   ", "example.com", "  cdn.example.com "} {
		c := buildUTLSConfig(ProxyConfig{ServerName: in}, []string{"h2", "http/1.1"})
		if c.ServerName != effectiveServerName(in) {
			t.Errorf("ServerName for %q = %q, want %q", in, c.ServerName, effectiveServerName(in))
		}
	}

	if c := buildUTLSConfig(ProxyConfig{ServerName: ""}, nil); c.ServerName != "" {
		t.Fatalf("empty server_name must stay empty (no host fallback), got %q", c.ServerName)
	}
}
