package myssh

import (
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
