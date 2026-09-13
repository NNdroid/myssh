package myssh

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeMasqueALPN(t *testing.T) {
	cases := map[string]string{
		"":        "", // auto
		"auto":    "", // auto
		"h3,h2":   "", // 用户书写“两者皆可”=> SDK auto
		"H2, H3 ": "", // 大小写/空格归一后仍是 auto
		"h3":      "h3",
		"H3":      "h3",
		"h2":      "h2",
		"bogus":   "bogus", // 原样返回，交 SDK 校验拒绝
	}
	for in, want := range cases {
		if got := normalizeMasqueALPN(in); got != want {
			t.Errorf("normalizeMasqueALPN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeUdpMtuProbe(t *testing.T) {
	// ""/auto => nil（SDK 默认开启）
	for _, v := range []string{"", "auto", "AUTO", "  "} {
		p, err := normalizeUdpMtuProbe(v)
		if err != nil {
			t.Fatalf("normalizeUdpMtuProbe(%q) unexpected err %v", v, err)
		}
		if p != nil {
			t.Errorf("normalizeUdpMtuProbe(%q) = %v, want nil (SDK default)", v, *p)
		}
	}
	// on/true/1 => &true
	for _, v := range []string{"on", "TRUE", "1"} {
		p, err := normalizeUdpMtuProbe(v)
		if err != nil || p == nil || !*p {
			t.Errorf("normalizeUdpMtuProbe(%q) = (%v,%v), want ptr(true)", v, pBool(p), err)
		}
	}
	// off/false/0 => &false
	for _, v := range []string{"off", "FALSE", "0"} {
		p, err := normalizeUdpMtuProbe(v)
		if err != nil || p == nil || *p {
			t.Errorf("normalizeUdpMtuProbe(%q) = (%v,%v), want ptr(false)", v, pBool(p), err)
		}
	}
	// 非法值报错
	if _, err := normalizeUdpMtuProbe("maybe"); err == nil {
		t.Fatal("expected error for invalid udp_custom_mtu_probe value")
	}
}

func pBool(p *bool) bool { return p != nil && *p }

// TestNewTransportParamJSONTags 锁定 4 个新字段的 JSON key（web/Android/API round-trip 依赖）。
func TestNewTransportParamJSONTags(t *testing.T) {
	cfg := ProxyConfig{
		MasqueAlpn:        "h3,h2",
		PaddingMinBytes:   1200,
		UdpCustomMaxPkt:   1400,
		UdpCustomMtuProbe: "off",
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"masque_alpn":"h3,h2"`,
		`"padding_min_bytes":1200`,
		`"udp_custom_max_pkt":1400`,
		`"udp_custom_mtu_probe":"off"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshalled ProxyConfig missing %q: %s", want, s)
		}
	}
}

// TestResolveH2PaddingMin 锁定 padding_min_bytes 的翻译：0(未配置)=>1420，
// 正数原样、负数原样（关闭）。防止有人把 myssh 默认误退回 SDK 的 900。
func TestResolveH2PaddingMin(t *testing.T) {
	cases := map[int]int{0: 1420, 1: 1, 900: 900, 1420: 1420, -1: -1, -900: -900}
	for in, want := range cases {
		if got := resolveH2PaddingMin(in); got != want {
			t.Errorf("resolveH2PaddingMin(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestH2UtlxFingerprintGate 锁定 h2/grpc Chrome 伪装的安全门控：只有“TLS 开 +
// 非 QUIC + 未启用证书指纹校验”才伪装；尤其是开启指纹校验时**绝不**返回 "chrome"，
// 否则 h2tunnel uTLS 路径会绕过 VerifyPeerCertificate 使 pinning 失效（MITM）。
// TestH2UtlxFingerprintGate 锁定 h2/grpc Chrome 伪装的门控：仅“TLS 开 + 非 QUIC”
// 时伪装为 chrome，其余（明文 / QUIC 承载）不伪装。注意：自 h2tunnel 7c6d201 起伪装
// 路径会搬运 VerifyPeerCertificate，证书指纹 pinning 与伪装可共存，故不再因校验而关闭伪装。
func TestH2UtlxFingerprintGate(t *testing.T) {
	cases := []struct {
		tls, quic bool
		want      string
	}{
		{true, false, "chrome"}, // TCP-TLS（h2/grpc）=> 伪装
		{true, true, ""},        // QUIC（h3/wt/masque）=> 不伪装
		{false, false, ""},      // 明文 => 不伪装
		{false, true, ""},       // 无 TLS 且 QUIC => 不伪装
	}
	for _, c := range cases {
		if got := h2UtlxFingerprint(c.tls, c.quic); got != c.want {
			t.Errorf("h2UtlxFingerprint(tls=%v,quic=%v)=%q want %q", c.tls, c.quic, got, c.want)
		}
	}
}
func TestProxyConfigHasNoIcmpFamily(t *testing.T) {
	b, err := json.Marshal(ProxyConfig{
		TunnelType:    "icmp_custom",
		IcmpCustomPsk: "x", IcmpCustomMtuMode: "probe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "icmp_custom_family") || strings.Contains(string(b), "IcmpCustomFamily") {
		t.Fatalf("ProxyConfig must not carry icmp_custom_family anymore: %s", b)
	}
}
