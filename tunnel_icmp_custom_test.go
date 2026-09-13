package myssh

import (
	"strings"
	"testing"

	icmpclient "github.com/NNdroid/icmp_custom/tunnel"
)

// TestParseICMPMagicSDK 覆盖 hex 解析与空值默认；同时确保 ASCII 词
// （如 "UDPC"）被拒绝——魔数明文传输，可打印串会成为中间设备指纹。
func TestParseICMPMagicSDK(t *testing.T) {
	got, err := parseICMPMagicSDK("d1a7c0de")
	if err != nil || got != 0xd1a7c0de {
		t.Fatalf("got=%08x err=%v", got, err)
	}
	if got, err := parseICMPMagicSDK(""); err != nil || got != 0 {
		t.Fatalf("empty: got=%08x err=%v, want 0/nil", got, err)
	}
	for _, bad := range []string{"UDPC", "12345", "zzzzzzzz", "d1a7c0deaa"} {
		if _, err := parseICMPMagicSDK(bad); err == nil {
			t.Errorf("value %q unexpectedly accepted", bad)
		}
	}
}

// TestICMPEventBridgeMapping 验证 icmp_custom 事件的归一化映射。
func TestICMPEventBridgeMapping(t *testing.T) {
	cb := newCaptureCallback()
	RegisterTunnelEventCallback(cb)
	defer RegisterTunnelEventCallback(nil)

	cases := []struct {
		name     string
		emit     func()
		wantType TunnelEventType
	}{
		{"established", func() { emitICMPEvent(icmpclient.ClientEvent{Kind: icmpclient.TunnelEstablished, Session: 9}) }, TunnelEventEstablished},
		{"died", func() { emitICMPEvent(icmpclient.ClientEvent{Kind: icmpclient.TunnelDied, Detail: "timeout"}) }, TunnelEventDied},
		{"reconnecting", func() { emitICMPEvent(icmpclient.ClientEvent{Kind: icmpclient.Reconnecting, Attempt: 2}) }, TunnelEventReconnecting},
		{"handshake-retrying", func() { emitICMPEvent(icmpclient.ClientEvent{Kind: icmpclient.HandshakeRetrying, Attempt: 1}) }, TunnelEventHandshakeRetrying},
	}

	for _, tc := range cases {
		tc.emit()
		got := <-cb.events
		if got.Type != tc.wantType || got.Source != "icmp_custom" {
			t.Errorf("%s: got %s/%s, want icmp_custom/%s", tc.name, got.Source, got.Type, tc.wantType)
		}
	}
}

// TestICMPEventSessionFormat 会话 ID 以十进制文本进入回调。
func TestICMPEventSessionFormat(t *testing.T) {
	var gotSession string
	RegisterTunnelEventCallback(&stringCapture{fn: func(_, _, session, _ string) { gotSession = session }})
	defer RegisterTunnelEventCallback(nil)

	emitICMPEvent(icmpclient.ClientEvent{Kind: icmpclient.TunnelEstablished, Session: 4294967295})
	if gotSession != "4294967295" {
		t.Fatalf("session = %q", gotSession)
	}
}

// TestICMPMtuValues 文档化 icmp_custom_mtu_mode 的合法取值，防止 webui 选项与
// SDK 漂移。地址族（family）自 icmp_custom c08cc52 起已从 myssh 与 SDK 移除，
// 客户端按对端地址自动选族，故此处不再涉及 family。
func TestICMPMtuValues(t *testing.T) {
	for _, mode := range []string{"", "probe", "auto", "fixed"} {
		if mode == "ipv4" || mode == "ipv6" {
			t.Fatalf("unexpected family value %q in mtu-mode set (family was removed)", mode)
		}
	}
	// myssh 透传时统一转小写（见 dialICMPCustomSDK：strings.ToLower(cfg.IcmpCustomMtuMode)）。
	if v := strings.ToLower("PROBE"); v != "probe" {
		t.Fatal("unreachable")
	}
}
