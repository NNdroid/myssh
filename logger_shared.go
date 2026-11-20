// 本文件刻意不带 //go:build 约束，对**所有**平台生效。
//
// logger_android.go（//go:build android）与 logger_generic.go（//go:build !android）
// 是两套平行的日志实现，二者必须对外暴露同一套「与平台无关」的公共 API。
// 历史上 SyncLogger 只写进了 !android 分支，而 cmd/main.go 无条件调用它，
// 于是 GOOS=android 构建直接报 undefined: myssh.SyncLogger。
//
// 约定：凡是「两套实现都必须有、且签名一致」的符号，一律放在本文件里；
// 真正需要分平台实现的部分（InitLogger 的 core 组装、SetLogReceiver 等）留在各自文件中。

package myssh

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// sugaredHolder 以 atomic.Pointer 持有全局 SugaredLogger。InitLogger 可被宿主
// 重复调用（Android 每次引擎 Start、web 每次 /log-clear），旧实现把裸全局指针
// 直接改写，而全包所有日志热路径无锁并发读它——对指针的无同步写读构成
// data race（logger_android.go 曾修过同类问题，但漏了 zlog 本身）。
// 方法集与 *zap.SugaredLogger 在本仓库实际用到的方法一致，调用点无需改动。
type sugaredHolder struct {
	p atomic.Pointer[zap.SugaredLogger]
}

// newNopSugaredHolder 返回一个已装入 Nop logger 的 holder，作为包级默认值：
// 未调用 InitLogger 前所有日志进 Nop，避免空指针 panic。atomic.Pointer 含
// noCopy，holder 一律以指针传递。
func newNopSugaredHolder() *sugaredHolder {
	var h sugaredHolder
	h.p.Store(zap.NewNop().Sugar())
	return &h
}

func (h *sugaredHolder) Store(l *zap.SugaredLogger) { h.p.Store(l) }

func (h *sugaredHolder) Debugf(format string, args ...any) { h.p.Load().Debugf(format, args...) }
func (h *sugaredHolder) Infof(format string, args ...any)  { h.p.Load().Infof(format, args...) }
func (h *sugaredHolder) Warnf(format string, args ...any)  { h.p.Load().Warnf(format, args...) }
func (h *sugaredHolder) Errorf(format string, args ...any) { h.p.Load().Errorf(format, args...) }
func (h *sugaredHolder) Info(args ...any)                  { h.p.Load().Info(args...) }
func (h *sugaredHolder) Warn(args ...any)                  { h.p.Load().Warn(args...) }
func (h *sugaredHolder) Error(args ...any)                 { h.p.Load().Error(args...) }
func (h *sugaredHolder) Sync() error                       { return h.p.Load().Sync() }

// zlog 是全局日志器；默认 Nop，由 InitLogger 以原子替换的方式更新。
var zlog = newNopSugaredHolder()

// SyncLogger 在程序退出前把缓冲区日志刷盘（对文件 core 触发 fsync）。
// zlog 恒可用（未初始化时为 Nop），无需判空。
func SyncLogger() {
	_ = zlog.Sync()
}

// activeLogFile 记录当前 file core 持有的日志文件。InitLogger 可被宿主重复
// 调用（Android 每次引擎 Start、web 每次 /log-clear），旧实现只换 logger、
// 从不关旧文件——fd 随调用次数泄漏。
var (
	logFileMu     sync.Mutex
	activeLogFile *os.File
)

// swapLogFile 在 zlog 替换后调用：记录新文件并关闭上一代文件。传 nil 表示
// 新 logger 不写文件（桌面端 logPath 为空），同样要关掉旧文件。
//
// 关闭瞬间，极少数已捕获旧 zlog 引用的在途写会得到一次写失败——可接受：
// 重开 logger 的场景（引擎启停、清日志）本就意味着旧日志流终结，新写入
// 在替换完成后立即落到新文件上。
func swapLogFile(f *os.File) {
	logFileMu.Lock()
	prev := activeLogFile
	activeLogFile = f
	logFileMu.Unlock()
	if prev != nil {
		_ = prev.Close()
	}
}

// parseLogLevel 把配置面的日志级别字符串解析为 zapcore.Level，
// 未识别取值回落 Info。两个平台实现共用，避免 switch 漂移。
func parseLogLevel(logLevelStr string) zapcore.Level {
	switch strings.ToUpper(strings.TrimSpace(logLevelStr)) {
	case "DEBUG":
		return zapcore.DebugLevel
	case "INFO":
		return zapcore.InfoLevel
	case "WARN", "WARNING":
		return zapcore.WarnLevel
	case "ERROR":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// 编译期契约：下列符号必须由 logger_android.go / logger_generic.go 在各自平台提供，
// 且签名一致。任一平台漏实现或签名字段变更，任意平台的构建都会在此处立刻失败，
// 而不是等到交叉编译某个 GOOS 时才暴露。
var (
	_ func(logPath string, logLevelStr string) int = InitLogger
	_ func(logLevelStr string)                     = SetLogLevel
	_ func() string                                = GetLogLevel
)
