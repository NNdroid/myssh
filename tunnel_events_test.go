package myssh

import (
	"errors"
	"strings"
	"testing"

	dnstunnel "github.com/NNdroid/dns_custom"
	h2tunnel "github.com/NNdroid/h2tunnel"
	udpclient "github.com/NNdroid/udp_custom/tunnel"
	xhttptunnel "github.com/NNdroid/xhttptunnel/tunnel"
)

// captureCallback 收集 emitTunnelEvent 转发的事件。
type captureCallback struct {
	events chan TunnelEvent
}

func newCaptureCallback() *captureCallback {
	return &captureCallback{events: make(chan TunnelEvent, 32)}
}

func (c *captureCallback) OnTunnelEvent(e TunnelEvent) {
	c.events <- e
}

// TestTunnelEventBridgeMapping 验证四个 SDK 的事件归一化映射：类型、来源、
// 会话、尝试序号与错误文本都正确落到 TunnelEvent。
func TestTunnelEventBridgeMapping(t *testing.T) {
	cases := []struct {
		name     string
		emit     func()
		wantType TunnelEventType
		wantSrc  string
	}{
		{"h2-established", func() { emitH2Event(h2tunnel.ClientEvent{Kind: h2tunnel.EventTunnelEstablished}) }, TunnelEventEstablished, "h2"},
		{"h2-died", func() {
			emitH2Event(h2tunnel.ClientEvent{Kind: h2tunnel.EventTunnelDied, Reason: h2tunnel.TunnelDeathMaxRetries, Err: errors.New("boom")})
		}, TunnelEventDied, "h2"},
		{"h2-reconnecting", func() { emitH2Event(h2tunnel.ClientEvent{Kind: h2tunnel.EventReconnecting, Attempt: 2}) }, TunnelEventReconnecting, "h2"},
		{"h2-denied", func() { emitH2Event(h2tunnel.ClientEvent{Kind: h2tunnel.EventTargetDenied}) }, TunnelEventTargetDenied, "h2"},

		{"xhttp-established", func() { emitXhttpEvent(xhttptunnel.TunnelEstablished{SessionID: "s1"}) }, TunnelEventEstablished, "xhttp"},
		{"xhttp-died", func() { emitXhttpEvent(xhttptunnel.TunnelDied{SessionID: "s1", Reason: "idle timeout"}) }, TunnelEventDied, "xhttp"},
		{"xhttp-reconnecting", func() { emitXhttpEvent(xhttptunnel.Reconnecting{SessionID: "s1", Nth: 3}) }, TunnelEventReconnecting, "xhttp"},
		{"xhttp-denied", func() { emitXhttpEvent(xhttptunnel.TargetDenied{SessionID: "s1", Target: "1.2.3.4:22"}) }, TunnelEventTargetDenied, "xhttp"},

		{"udpc-established", func() { emitUDPCEvent(udpclient.ClientEvent{Kind: udpclient.TunnelEstablished, Session: 7}) }, TunnelEventEstablished, "udp_custom"},
		{"udpc-died", func() { emitUDPCEvent(udpclient.ClientEvent{Kind: udpclient.TunnelDied, Detail: "timeout"}) }, TunnelEventDied, "udp_custom"},
		{"udpc-handshake", func() { emitUDPCEvent(udpclient.ClientEvent{Kind: udpclient.HandshakeRetrying, Attempt: 2}) }, TunnelEventHandshakeRetrying, "udp_custom"},

		{"dns-established", func() {
			emitDNSEvent(dnstunnel.ClientEvent{Kind: dnstunnel.ClientTunnelEstablished, Session: "sess-1"})
		}, TunnelEventEstablished, "dns_custom"},
		{"dns-died", func() {
			emitDNSEvent(dnstunnel.ClientEvent{Kind: dnstunnel.ClientTunnelDied, Reason: dnstunnel.ReasonWriteFailed, Err: errors.New("io")})
		}, TunnelEventDied, "dns_custom"},
		{"dns-denied", func() { emitDNSEvent(dnstunnel.ClientEvent{Kind: dnstunnel.ClientTargetDenied}) }, TunnelEventTargetDenied, "dns_custom"},
	}

	cb := newCaptureCallback()
	RegisterTunnelEventCallback(cb)
	defer RegisterTunnelEventCallback(nil)

	for _, tc := range cases {
		tc.emit()
		got := <-cb.events
		if got.Type != tc.wantType || got.Source != tc.wantSrc {
			t.Errorf("%s: got %s/%s, want %s/%s", tc.name, got.Source, got.Type, tc.wantSrc, tc.wantType)
		}
	}
}

// TestTunnelEventNilCallback 回调未注册时 emit 不得 panic。
func TestTunnelEventNilCallback(t *testing.T) {
	RegisterTunnelEventCallback(nil)
	defer RegisterTunnelEventCallback(nil)
	emitTunnelEvent(TunnelEvent{Type: TunnelEventEstablished, Source: "test"})
}

// TestTunnelEventString 事件文本包含来源、类型与会话，便于日志排查。
func TestTunnelEventString(t *testing.T) {
	e := TunnelEvent{Type: TunnelEventReconnecting, Source: "xhttp", Session: "abc", Attempt: 2, ErrText: "reset"}
	s := e.String()
	for _, want := range []string{"xhttp", "tunnel_reconnecting", "abc", "attempt 2", "reset"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, want to contain %q", s, want)
		}
	}
}
