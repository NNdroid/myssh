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

// TestXhttpTuningJSONTags pins the JSON keys the Android host writes when
// passing the xhttp tuning options through Start(configJson).
func TestXhttpTuningJSONTags(t *testing.T) {
	b, err := json.Marshal(ProxyConfig{
		XhttpPadding:      "400-600",
		XhttpWindowSizeMB: 16,
		XhttpMaxConns:     64,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"xhttp_padding":"400-600"`,
		`"xhttp_window_size_mb":16`,
		`"xhttp_max_conns":64`,
	} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %s in %s", want, b)
		}
	}
}

// TestDialXHTTPSDKRequiresPSKWithoutAuthFlag: the SDK removed open mode, so a
// PSK is mandatory for xhttp even when proxy_auth_required is false. The check
// happens before any dial, so an empty token must fail deterministically.
func TestDialXHTTPSDKRequiresPSKWithoutAuthFlag(t *testing.T) {
	cfg := ProxyConfig{
		TunnelType:        "xhttp",
		ProxyAddr:         "127.0.0.1:8080",
		SshAddr:           "127.0.0.1:22",
		ProxyAuthRequired: false,
	}
	_, err := dialXHTTPSDK(context.Background(), cfg, false)
	if err == nil || !strings.Contains(err.Error(), "proxy_auth_token") {
		t.Fatalf("expected a PSK-required error, got %v", err)
	}
}

// TestDialXHTTPSDKTuningRejectedBeforeDial proves the new fields reach the
// SDK: an invalid padding rule and an out-of-range window are both rejected
// before any network I/O, with the field name in the error.
func TestDialXHTTPSDKTuningRejectedBeforeDial(t *testing.T) {
	base := ProxyConfig{
		TunnelType:     "xhttp",
		ProxyAddr:      "127.0.0.1:8080",
		SshAddr:        "127.0.0.1:22",
		ProxyAuthToken: "test-psk",
	}
	cases := []struct {
		name   string
		mutate func(*ProxyConfig)
		want   string
	}{
		{"padding", func(c *ProxyConfig) { c.XhttpPadding = "not-a-padding-rule" }, "xhttp_padding"},
		{"window", func(c *ProxyConfig) { c.XhttpWindowSizeMB = 65 }, "window_size_mb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			_, err := dialXHTTPSDK(context.Background(), cfg, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
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
