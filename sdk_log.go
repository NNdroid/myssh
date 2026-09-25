package myssh

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"go.uber.org/zap"
)

// 本文件实现各客户端 SDK 的日志桥接适配器：把 h2tunnel（slog）、
// xhttptunnel（*zap.Logger）、udp_custom/icmp_custom（四方法 Logger 接口）、
// dns_custom（SugaredLogger）的原生日志接口统一桥接到 zlog。
// 所有适配器都从全局 zap.L() 派生命名子 logger，级别跟随全局
// atomicLogLevel（InitLogger/SetLogLevel 切换后即时生效）。
// 事件桥接见 tunnel_events.go。

// sdkSugared 返回命名子 logger（SugaredLogger 形态），供 dns_custom 注入。
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
