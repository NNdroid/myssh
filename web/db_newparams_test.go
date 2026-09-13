package main

import (
	"encoding/json"
	"testing"

	"myssh"
)

// TestNewTransportParamsRoundTrip 权威验证 4 个新列（masqueAlpn/paddingMinBytes/
// udpCustomMaxPkt/udpCustomMtuProbe）在 Add→Get→Update→Get→ToProxyConfig 全链路对齐：
// 任何 SELECT/Scan/INSERT/UPDATE 的列数或占位符错位都会在此暴露。paddingMinBytes
// 取负值以覆盖“负数=关闭填充”的有符号往返。
func TestNewTransportParamsRoundTrip(t *testing.T) {
	newTestDB(t)

	p := Profile{
		Name:              "newparams",
		SshAddr:           "127.0.0.1:22",
		User:              "u",
		AuthType:          "password",
		Pass:              "pw",
		TunnelType:        "h2",
		ProxyAddr:         "https://127.0.0.1:443",
		MasqueAlpn:        "h3",
		PaddingMinBytes:   -1,
		UdpCustomMaxPkt:   1400,
		UdpCustomMtuProbe: "off",
	}
	id, err := AddProfile(p)
	if err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	assertNewParams(t, "after Add", id, "h3", -1, 1400, "off")

	// Update 改值再读回，验证 UPDATE 的 SET 与值参对齐。
	got, err := GetProfile(id)
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	got.MasqueAlpn = "h2"
	got.PaddingMinBytes = 900
	got.UdpCustomMaxPkt = 1280
	got.UdpCustomMtuProbe = "on"
	if err := UpdateProfile(id, *got); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	assertNewParams(t, "after Update", id, "h2", 900, 1280, "on")

	// 最终经 ToProxyConfig 序列化，确认核心 ProxyConfig 拿到同样的值。
	cfgJSON, err := BuildProxyConfigJSON(id)
	if err != nil {
		t.Fatalf("BuildProxyConfigJSON: %v", err)
	}
	var cfg myssh.ProxyConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal ProxyConfig: %v", err)
	}
	if cfg.MasqueAlpn != "h2" || cfg.PaddingMinBytes != 900 || cfg.UdpCustomMaxPkt != 1280 || cfg.UdpCustomMtuProbe != "on" {
		t.Fatalf("ToProxyConfig mismatch: masque=%q pad=%d maxpkt=%d probe=%q",
			cfg.MasqueAlpn, cfg.PaddingMinBytes, cfg.UdpCustomMaxPkt, cfg.UdpCustomMtuProbe)
	}
}

func assertNewParams(t *testing.T, phase, id, wantMasque string, wantPad, wantMaxPkt int, wantProbe string) {
	t.Helper()
	g, err := GetProfile(id)
	if err != nil {
		t.Fatalf("GetProfile %s: %v", phase, err)
	}
	if g.MasqueAlpn != wantMasque || g.PaddingMinBytes != wantPad || g.UdpCustomMaxPkt != wantMaxPkt || g.UdpCustomMtuProbe != wantProbe {
		t.Fatalf("%s: got masque=%q pad=%d maxpkt=%d probe=%q, want %q/%d/%d/%q",
			phase, g.MasqueAlpn, g.PaddingMinBytes, g.UdpCustomMaxPkt, g.UdpCustomMtuProbe,
			wantMasque, wantPad, wantMaxPkt, wantProbe)
	}
}
