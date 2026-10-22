package myssh

import (
	"fmt"
	"strings"
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
// 重连与握手重试为警告。本机主动拆除是例外（延迟探针每轮新建隧道、测完即关，
// 属于预期的生命周期而不是故障）。这些死亡仍会照常打出来（内容不变），只是
// 不再用 ERROR 惊动告警——否则每轮探针会产生两条 ERROR，把真实断连淹没掉。
func (e TunnelEvent) severity() int {
	if e.Type == TunnelEventDied && isLocalCloseDeath(e) {
		return 1 // info
	}
	switch e.Type {
	case TunnelEventDied, TunnelEventTargetDenied:
		return 3 // error
	case TunnelEventEstablished:
		return 1 // info
	default:
		return 2 // warn
	}
}

// localCloseSubstrings 本机主动拆除的各 SDK 措辞，按子串匹配。子串而不是精确
// 相等，是因为 Detail 的包装格式各 SDK 不统一（xhttptunnel 是 "reason=..."，
// dns_custom 是 "target=... reason=..."，h2/udp/icmp 直接放原因），且某个 SDK
// 改写措辞时精确匹配会静默回退到 ERROR。
var localCloseSubstrings = []string{
	"local close",  // xhttptunnel：本机 Close() 或 ctx 取消
	"local_closed", // 其他 SDK 可能用的下划线写法
	"local closed",
	"cancel",           // h2tunnel "canceled"、dns_custom "context cancelled"（英式）、ctx "context canceled"
	"closed by caller", // dns_custom ReasonCallerClosed
}

// localCloseBareClosed udp_custom/icmp_custom 在本机 Close() 且无具体原因时写的
// 就是裸 "closed"。这两个 SDK 的其余原因都不含 closed，但 xhttptunnel 的
// "peer closed"（服务端收尾，仍算异常）含这个词，所以只能限定来源后精确匹配。
var localCloseBareClosed = map[string]bool{
	"udp_custom":  true,
	"icmp_custom": true,
}

// isLocalCloseDeath 判断死亡原因是不是本机主动关连接。各 SDK 的表述完全不同
// （xhttptunnel "local close"、h2tunnel "canceled"、dns_custom "closed by
// caller"/"context cancelled"、udp/icmp_custom "closed"），同一个动作要全覆盖，
// 漏一个就会继续每轮探针打一条 ERROR。
func isLocalCloseDeath(e TunnelEvent) bool {
	d := strings.ToLower(e.Detail)
	if localCloseBareClosed[e.Source] && d == "closed" {
		return true
	}
	for _, r := range localCloseSubstrings {
		if strings.Contains(d, r) {
			return true
		}
	}
	return false
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
