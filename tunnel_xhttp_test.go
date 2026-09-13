package myssh

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestXHTTPStreamModeValidation 验证 xhttp_stream_mode 配置的归一化与校验：
// 空/auto 保持 SDK 自适应，stream/poll 强制指定，非法值直接拒绝。
func TestXHTTPStreamModeValidation(t *testing.T) {
	cases := map[string]struct {
		want    string
		wantErr bool
	}{
		"":            {want: "", wantErr: false}, // 默认 auto（SDK 端空值等同自适应）
		"auto":        {want: "auto", wantErr: false},
		"  AUTO  ":    {want: "auto", wantErr: false},
		"stream":      {want: "stream", wantErr: false},
		"poll":        {want: "poll", wantErr: false},
		"bogus":       {wantErr: true},
		"auto,stream": {wantErr: true},
	}

	for mode, tc := range cases {
		got, err := normalizeXHTTPStreamMode(mode)
		if tc.wantErr {
			if err == nil {
				t.Errorf("XhttpStreamMode %q: expected error, got %q", mode, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("XhttpStreamMode %q: unexpected error: %v", mode, err)
		} else if got != tc.want {
			t.Errorf("XhttpStreamMode %q: got %q, want %q", mode, got, tc.want)
		}
	}
}

// TestXhttpStreamModeJSONTag 防止 JSON 标签被意外改动（DB/API round-trip 依赖它）。
func TestXhttpStreamModeJSONTag(t *testing.T) {
	b, err := json.Marshal(ProxyConfig{XhttpStreamMode: "poll"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"xhttp_stream_mode":"poll"`) {
		t.Fatalf("json tag mismatch: %s", b)
	}
}

// TestDialXHTTPSDKEmptyFingerprintFailClosed 保证 xhttp 与其他 TLS 隧道一致：
// 开启 verify_certificate_finger_print 却没填 server_certificate_finger_print 时，
// TLS 拨号必须在建连前 fail-closed——否则 SDK 侧 verifyFingerprint("") 会退化为
// 接受任意证书（中间人风险）。校验在 NewClient/拨号之前触发，故不触网。
func TestDialXHTTPSDKEmptyFingerprintFailClosed(t *testing.T) {
	cfg := ProxyConfig{
		TunnelType:                   "xhttp",
		ProxyAddr:                    "127.0.0.1:8443",
		SshAddr:                      "127.0.0.1:22",
		VerifyCertificateFingerprint: true,
		ServerCertificateFingerprint: "",
	}
	_, err := dialXHTTPSDK(context.Background(), cfg, true)
	if err == nil || !strings.Contains(err.Error(), "server_certificate_finger_print is empty") {
		t.Fatalf("expected fail-closed empty-fingerprint error, got %v", err)
	}
}

// TestDialXHTTPSDKGuardIsTLSTrueOnly 证明该 guard 只在启用 TLS 时生效：明文 xhttp
// 即便 verify=true 且指纹为空也不该触发它。这里用 guard 之后的“需要 token 却没给”
// 确定性错误来验证执行流已越过指纹校验，同样在 NewClient 之前返回、不触网。
func TestDialXHTTPSDKGuardIsTLSTrueOnly(t *testing.T) {
	cfg := ProxyConfig{
		TunnelType:                   "xhttp",
		ProxyAddr:                    "127.0.0.1:8080",
		SshAddr:                      "127.0.0.1:22",
		VerifyCertificateFingerprint: true,
		ProxyAuthRequired:            true, // 空 token → guard 之后的确定性错误
	}
	_, err := dialXHTTPSDK(context.Background(), cfg, false)
	if err == nil {
		t.Fatal("expected proxy_auth_token error after passing the TLS-gated guard")
	}
	if strings.Contains(err.Error(), "server_certificate_finger_print") {
		t.Fatalf("plaintext xhttp must not trip the TLS fingerprint guard: %v", err)
	}
	if !strings.Contains(err.Error(), "proxy_auth_token") {
		t.Fatalf("expected to reach the token check, got: %v", err)
	}
}
