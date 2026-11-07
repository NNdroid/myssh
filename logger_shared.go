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

	"go.uber.org/zap/zapcore"
)

// SyncLogger 在程序退出前把缓冲区日志刷盘（对文件 core 触发 fsync）。
// 平台中立：两个平台都将 zlog 初始化为 *zap.SugaredLogger（未初始化时为 Nop），
// 因此这里只需判空后 Sync 即可，无需分平台实现。
func SyncLogger() {
	if zlog != nil {
		_ = zlog.Sync()
	}
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
