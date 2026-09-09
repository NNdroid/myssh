package myssh

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"

	"go.uber.org/zap"
)

// ==========================================
// SDK 日志/事件桥接
//
// 四个客户端 SDK（h2tunnel/xhttptunnel/udp_custom/dns_custom）各自提供
// 原生日志接口与事件回调。这里把它们归一化并入本程序：
//
//	日志：SDK 输出统一桥接到 zlog，级别跟随全局 atomicLogLevel
//	     （InitLogger/调试开关切换后，新建连接即生效）。
//	事件：SDK 生命周期事件归一化为 TunnelEvent 统一转发——
//	     1) 按级别写入 zlog，SDK 关键状态与本程序日志一致输出；
//	     2) 转发给宿主注册的 TunnelEventCallback（Android/gomobile 可据此
//	        驱动连接状态 UI、断线提示等）。
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
	Source  string          // 来源 SDK："h2"/"xhttp"/"udp_custom"/"dns_custom"
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

// TunnelEventCallback 宿主事件回调。在 SDK 的派发 goroutine 中调用，
// panic 由 SDK 恢复；实现必须快速返回，阻塞逻辑请自行异步化。
type TunnelEventCallback interface {
	OnTunnelEvent(event TunnelEvent)
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

	// 2) 转发宿主回调（未注册则跳过）。
	tunnelEventMu.RLock()
	cb := tunnelEventCb
	tunnelEventMu.RUnlock()
	if cb != nil {
		cb.OnTunnelEvent(e)
	}
}

// ---- 日志适配器 ----

// sdkSugared 返回命名子 logger（SugaredLogger 形态），供 dns_custom 注入。
// 从全局 zap.L() 派生，跟随 InitLogger 的重建与级别切换。
func sdkSugared(name string) *zap.SugaredLogger {
	return zap.L().Named(name).Sugar()
}

// sdkZap 返回命名子 logger（原生 *zap.Logger），供 xhttptunnel 注入。
func sdkZap(name string) *zap.Logger {
	// SDK 日志的 caller 会指向桥接层，无信息量，关闭。
	return zap.L().Named(name).WithOptions(zap.WithCaller(false))
}

// sdkLogAdapter 把 zap SugaredLogger 适配为 udp_custom 要求的四方法
// Logger 接口。
type sdkLogAdapter struct {
	log *zap.SugaredLogger
}

func (a sdkLogAdapter) Debugf(format string, args ...any) { a.log.Debugf(format, args...) }
func (a sdkLogAdapter) Infof(format string, args ...any)  { a.log.Infof(format, args...) }
func (a sdkLogAdapter) Warnf(format string, args ...any)  { a.log.Warnf(format, args...) }
func (a sdkLogAdapter) Errorf(format string, args ...any) { a.log.Errorf(format, args...) }

// sdkUDPLogger 供 udp_custom 注入。
func sdkUDPLogger(name string) sdkLogAdapter {
	return sdkLogAdapter{log: sdkSugared(name)}
}

// zapSlogHandler 把 slog 记录桥接到 zap，供 h2tunnel 注入
// (*slog.Logger)。级别由 zap core 裁决：SDK 的调试日志只在全局 debug
// 级别可见。
type zapSlogHandler struct {
	zap   *zap.Logger
	attrs []slog.Attr
}

func (h zapSlogHandler) Enabled(context.Context, slog.Level) bool {
	return true // 交给 zap core 裁决
}

func (h zapSlogHandler) Handle(_ context.Context, r slog.Record) error {
	buf := bytes.NewBuffer(nil)
	for _, a := range h.attrs {
		appendSlogAttr(buf, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendSlogAttr(buf, a)
		return true
	})
	msg := r.Message
	if buf.Len() > 0 {
		msg += " " + buf.String()
	}
	switch r.Level {
	case slog.LevelDebug:
		h.zap.Debug(msg)
	case slog.LevelWarn:
		h.zap.Warn(msg)
	case slog.LevelError:
		h.zap.Error(msg)
	default:
		h.zap.Info(msg)
	}
	return nil
}

func (h zapSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return zapSlogHandler{zap: h.zap, attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h zapSlogHandler) WithGroup(string) slog.Handler { return h } // 组扁平化

func appendSlogAttr(buf *bytes.Buffer, a slog.Attr) {
	a.Value = a.Value.Resolve()
	fmt.Fprintf(buf, " %s=%s", a.Key, a.Value.String())
}

// sdkSlog 供 h2tunnel 注入。
func sdkSlog(name string) *slog.Logger {
	return slog.New(zapSlogHandler{zap: sdkZap(name)})
}
