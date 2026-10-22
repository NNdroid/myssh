package myssh

import (
	"errors"
	"strings"
	"testing"

	dnstunnel "github.com/NNdroid/dns_custom"
	h2tunnel "github.com/NNdroid/h2tunnel"
	udpclient "github.com/NNdroid/udp_custom/tunnel"
	xhttptunnel "github.com/NNdroid/xhttptunnel/tunnel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	zaptestobserver "go.uber.org/zap/zaptest/observer"
)

// captureCallback 收集 emitTunnelEvent 转发的事件。
type captureCallback struct {
	events chan TunnelEvent
}

func newCaptureCallback() *captureCallback {
	return &captureCallback{events: make(chan TunnelEvent, 32)}
}

func (c *captureCallback) OnTunnelEvent(tunnel, kind, session, detail string) {
	c.events <- TunnelEvent{Source: tunnel, Type: TunnelEventType(kind), Session: session, Detail: detail}
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
		{"h2-established", func() { emitH2EventAs("h2")(h2tunnel.ClientEvent{Kind: h2tunnel.EventTunnelEstablished}) }, TunnelEventEstablished, "h2"},
		{"h2-died", func() {
			emitH2EventAs("h2")(h2tunnel.ClientEvent{Kind: h2tunnel.EventTunnelDied, Reason: h2tunnel.TunnelDeathMaxRetries, Err: errors.New("boom")})
		}, TunnelEventDied, "h2"},
		{"h2-reconnecting", func() { emitH2EventAs("h2")(h2tunnel.ClientEvent{Kind: h2tunnel.EventReconnecting, Attempt: 2}) }, TunnelEventReconnecting, "h2"},
		{"h2-denied", func() { emitH2EventAs("h2")(h2tunnel.ClientEvent{Kind: h2tunnel.EventTargetDenied}) }, TunnelEventTargetDenied, "h2"},
		{"h3-source-attributed", func() { emitH2EventAs("h3")(h2tunnel.ClientEvent{Kind: h2tunnel.EventTunnelEstablished}) }, TunnelEventEstablished, "h3"},

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

	// gomobile 绑定形态：回调收到的是全 string 参数，字段完整。
	var gotTunnel, gotKind, gotSession, gotDetail string
	RegisterTunnelEventCallback(&stringCapture{fn: func(tunnel, kind, session, detail string) {
		gotTunnel, gotKind, gotSession, gotDetail = tunnel, kind, session, detail
	}})
	defer RegisterTunnelEventCallback(nil)
	emitXhttpEvent(xhttptunnel.Reconnecting{SessionID: "s9", Nth: 3, Reason: "transport broke"})
	if gotTunnel != "xhttp" || gotKind != string(TunnelEventReconnecting) || gotSession != "s9" ||
		!strings.Contains(gotDetail, "(attempt 3)") || !strings.Contains(gotDetail, "transport broke") {
		t.Errorf("callback args: tunnel=%q kind=%q session=%q detail=%q", gotTunnel, gotKind, gotSession, gotDetail)
	}
}

// stringCapture 适配 string 形态的宿主回调（即 gomobile 绑定的签名）。
type stringCapture struct {
	fn func(tunnel, kind, session, detail string)
}

func (c *stringCapture) OnTunnelEvent(tunnel, kind, session, detail string) {
	c.fn(tunnel, kind, session, detail)
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

// TestTunnelEventSeverity 定级要区分故障与主动拆除：本机关连接（延迟探针测完即
// 拆）是预期行为，不该以 ERROR 计入告警；真实断连与策略拒绝仍然是 ERROR。
func TestTunnelEventSeverity(t *testing.T) {
	cases := []struct {
		name string
		ev   TunnelEvent
		want int
	}{
		{"established", TunnelEvent{Type: TunnelEventEstablished}, 1},
		{"reconnecting", TunnelEvent{Type: TunnelEventReconnecting}, 2},
		{"handshake_retrying", TunnelEvent{Type: TunnelEventHandshakeRetrying}, 2},

		// 本机主动拆除：各 SDK 的措辞都要覆盖，漏一个就还会每轮探针打一条 ERROR。
		{"died_xhttp_local_close", TunnelEvent{Type: TunnelEventDied, Source: "xhttp", Detail: "reason=local close"}, 1},
		{"died_xhttp_local_close_upper", TunnelEvent{Type: TunnelEventDied, Source: "xhttp", Detail: "LOCAL CLOSE"}, 1},
		{"died_h2_canceled", TunnelEvent{Type: TunnelEventDied, Source: "h2", Detail: "canceled"}, 1},
		{"died_dns_caller_closed", TunnelEvent{Type: TunnelEventDied, Source: "dns_custom",
			Detail: "target=8.8.8.8:53 transport=udp reason=closed by caller"}, 1},
		{"died_dns_ctx_cancelled", TunnelEvent{Type: TunnelEventDied, Source: "dns_custom", Detail: "reason=context cancelled"}, 1},
		{"died_ctx_canceled", TunnelEvent{Type: TunnelEventDied, Source: "xhttp", Detail: "context canceled"}, 1},
		{"died_udp_bare_closed", TunnelEvent{Type: TunnelEventDied, Source: "udp_custom", Detail: "closed"}, 1},
		{"died_icmp_bare_closed", TunnelEvent{Type: TunnelEventDied, Source: "icmp_custom", Detail: "closed"}, 1},

		// 真实断连与策略拒绝仍然是 ERROR。
		{"died_peer_reset", TunnelEvent{Type: TunnelEventDied, Source: "xhttp", Detail: "reason=peer reset"}, 3},
		// "peer closed" 含 closed 但是服务端收尾，不能被裸 closed 规则误降级。
		{"died_xhttp_peer_closed", TunnelEvent{Type: TunnelEventDied, Source: "xhttp", Detail: "reason=peer closed"}, 3},
		// 裸 "closed" 只对 udp/icmp_custom 生效，别处仍是异常。
		{"died_bare_closed_other_source", TunnelEvent{Type: TunnelEventDied, Source: "xhttp", Detail: "closed"}, 3},
		{"died_udp_read_failed", TunnelEvent{Type: TunnelEventDied, Source: "udp_custom", Detail: "local conn read failed"}, 3},
		{"died_udp_idle_timeout", TunnelEvent{Type: TunnelEventDied, Source: "udp_custom", Detail: "idle timeout"}, 3},
		{"died_dns_write_failed", TunnelEvent{Type: TunnelEventDied, Source: "dns_custom", Detail: "reason=write failed"}, 3},
		{"died_h2_data_gap", TunnelEvent{Type: TunnelEventDied, Source: "h2", Detail: "data gap"}, 3},
		{"died_empty_detail", TunnelEvent{Type: TunnelEventDied}, 3},
		{"target_denied", TunnelEvent{Type: TunnelEventTargetDenied, Detail: "allowed targets"}, 3},

		// 非死亡事件即使提到 local close 也不应被降级：降级只对隧道死亡生效。
		{"reconnecting_mentions_local_close", TunnelEvent{Type: TunnelEventReconnecting, Detail: "previous round ended: local close"}, 2},
	}
	for _, tc := range cases {
		if got := tc.ev.severity(); got != tc.want {
			t.Errorf("%s: severity() = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestEmitTunnelEventLocalCloseIsNotError 探针式拆除走 info，真断连走 error，
// 且两路的文本内容与降级前完全一致（不影响宿主解析与既有告警关键字）。
func TestEmitTunnelEventLocalCloseIsNotError(t *testing.T) {
	core, obs := zaptestobserver.New(zapcore.InfoLevel)
	prev := zlog
	zlog = zap.New(core).Sugar()
	defer func() { zlog = prev }()

	emitTunnelEvent(TunnelEvent{
		Type: TunnelEventDied, Source: "xhttp",
		Session: "probe", Detail: "reason=local close",
	})
	if obs.Len() != 1 {
		t.Fatalf("local close: want 1 log entry, got %d", obs.Len())
	}
	if lvl := obs.All()[0].Level; lvl != zapcore.InfoLevel {
		t.Errorf("local close logged at %s, want info", lvl)
	}
	if !strings.Contains(obs.All()[0].Message, "[xhttp] tunnel_died session=probe reason=local close") {
		t.Errorf("event text changed unexpectedly: %q", obs.All()[0].Message)
	}

	emitTunnelEvent(TunnelEvent{
		Type: TunnelEventDied, Source: "xhttp",
		Session: "main", Detail: "reason=peer reset",
	})
	if obs.Len() != 2 {
		t.Fatalf("unexpected death: want 2 log entries, got %d", obs.Len())
	}
	if lvl := obs.All()[1].Level; lvl != zapcore.ErrorLevel {
		t.Errorf("unexpected death logged at %s, want error", lvl)
	}

	// 非 xhttptunnel 的本机拆除措辞同样要走 info。
	for _, tc := range []struct {
		src    string
		detail string
	}{
		{"h2", "canceled"},
		{"udp_custom", "closed"},
		{"dns_custom", "target=1.1.1.1:53 reason=closed by caller"},
	} {
		emitTunnelEvent(TunnelEvent{
			Type: TunnelEventDied, Source: tc.src,
			Session: "probe", Detail: tc.detail,
		})
		if lvl := obs.All()[obs.Len()-1].Level; lvl != zapcore.InfoLevel {
			t.Errorf("%s %q logged at %s, want info", tc.src, tc.detail, lvl)
		}
	}
}
