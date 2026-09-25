package myssh

import (
	"fmt"
	"sync"
)

// ==========================================
// SDK 事件桥接
//
// 各客户端 SDK（h2tunnel/xhttptunnel/udp_custom/dns_custom/icmp_custom）
// 各自提供事件回调。这里把 SDK 生命周期事件归一化为 TunnelEvent 统一转发：
//
//	1) 按级别写入 zlog，SDK 关键状态与本程序日志一致输出；
//	2) 转发给宿主注册的 TunnelEventCallback（Android/gomobile 可据此
//	   驱动连接状态 UI、断线提示等）。
//
// 日志桥接适配器见 sdk_log.go。
//
// 事件派发是通知语义：SDK 内部已做 panic 隔离与异步派发，宿主回调必须
// 快速返回；SDK 在过载时会丢事件（各自有 dropped 计数），可靠性要求高的
// 状态判断请以数据面实际结果为准。
// ==========================================

// TunnelEventType 归一化的隧道事件类型。字符串值即事件线上的稳定标识，
// 宿主（Android/Web UI）可直接按值分发。
type TunnelEventType string

const (
	// TunnelEventEstablished 隧道会话就绪（握手完成、数据可流动）。
	TunnelEventEstablished TunnelEventType = "tunnel_established"
	// TunnelEventDied 隧道会话死亡（含原因）。宿主通常应触发整体重连评估。
	TunnelEventDied TunnelEventType = "tunnel_died"
	// TunnelEventReconnecting 会话内重连/重试（SDK 断线续传层）。
	TunnelEventReconnecting TunnelEventType = "tunnel_reconnecting"
	// TunnelEventHandshakeRetrying 握手重试（尚未建立）。
	TunnelEventHandshakeRetrying TunnelEventType = "tunnel_handshake_retrying"
	// TunnelEventTargetDenied 服务端拒绝目标（allowlist/策略）。
	TunnelEventTargetDenied TunnelEventType = "tunnel_target_denied"
)

// TunnelEvent 归一化的隧道生命周期事件。
type TunnelEvent struct {
	Type    TunnelEventType // 事件类型
	Source  string          // 来源隧道类型："h2"/"grpc"/"h3"/"masque"/"webtransport"/"xhttp"/"udp_custom"/"icmp_custom"/"dns_custom"
	Session string          // SDK 侧会话标识（格式随 SDK 而异，可为空）
	Detail  string          // 人类可读上下文（原因/目标等）
	Attempt int             // 重连/重试序号（1 起；仅重试类事件有意义）
	ErrText string          // 底层错误文本（可为空）
}

func (e TunnelEvent) String() string {
	s := fmt.Sprintf("[%s] %s", e.Source, e.Type)
	if e.Session != "" {
		s += " session=" + e.Session
	}
	if e.Detail != "" {
		s += " " + e.Detail
	}
	if e.Attempt > 0 {
		s += fmt.Sprintf(" (attempt %d)", e.Attempt)
	}
	if e.ErrText != "" {
		s += " err=" + e.ErrText
	}
	return s
}

// severity 按事件类型给出日志级别：死亡/拒绝为错误，建立为提示，
// 重连与握手重试为警告。
func (e TunnelEvent) severity() int {
	switch e.Type {
	case TunnelEventDied, TunnelEventTargetDenied:
		return 3 // error
	case TunnelEventEstablished:
		return 1 // info
	default:
		return 2 // warn
	}
}

var tunnelEventMu sync.RWMutex

// TunnelEventCallback 宿主事件回调（gomobile 绑定安全：全 string 参数）。
// 在 SDK 的派发 goroutine 中调用，panic 由 SDK 恢复；实现必须快速返回，
// 阻塞逻辑请自行异步化。Android 侧通过 myssh.Myssh.registerTunnelEventCallback
// 注册，与本程序内部日志同源。
type TunnelEventCallback interface {
	OnTunnelEvent(tunnel string, kind string, session string, detail string)
}

// RegisterTunnelEventCallback 注册宿主隧道事件回调（可传 nil 注销）。
func RegisterTunnelEventCallback(cb TunnelEventCallback) {
	tunnelEventMu.Lock()
	tunnelEventCb = cb
	tunnelEventMu.Unlock()
}

var tunnelEventCb TunnelEventCallback

// emitTunnelEvent 将归一化事件写入日志并转发给宿主回调。
func emitTunnelEvent(e TunnelEvent) {
	// 1) 统一日志输出：SDK 侧关键状态与本程序日志一致。
	msg := fmt.Sprintf("%s [Tunnel-Event] %s", TAG, e.String())
	switch e.severity() {
	case 3:
		zlog.Error(msg)
	case 2:
		zlog.Warn(msg)
	default:
		zlog.Info(msg)
	}

	// 2) 转发宿主回调（未注册则跳过）。detail 由结构化字段组装，
	//    宿主无需解析日志文本即可拿到全部信息。
	tunnelEventMu.RLock()
	cb := tunnelEventCb
	tunnelEventMu.RUnlock()
	if cb != nil {
		detail := e.Detail
		if e.Attempt > 0 {
			detail = joinSpace(detail, fmt.Sprintf("(attempt %d)", e.Attempt))
		}
		if e.ErrText != "" {
			detail = joinSpace(detail, "err="+e.ErrText)
		}
		cb.OnTunnelEvent(e.Source, string(e.Type), e.Session, detail)
	}
}

func joinSpace(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}
