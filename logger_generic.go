//go:build !android

package myssh

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// 全局可用的 SugarLogger，默认给一个 Nop 避免未初始化时引发空指针 Panic
	zlog *zap.SugaredLogger = zap.NewNop().Sugar()
)

// InitLogger 初始化通用日志记录器
// logPath: 日志文件存放路径，如果为空字符串 ""，则只输出到控制台
// logLevelStr: 日志级别 (DEBUG, INFO, WARN, ERROR)
func InitLogger(logPath string, logLevelStr string) int {
	var level zapcore.Level
	switch strings.ToUpper(logLevelStr) {
	case "DEBUG":
		level = zapcore.DebugLevel
	case "INFO":
		level = zapcore.InfoLevel
	case "WARN":
		level = zapcore.WarnLevel
	case "ERROR":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	// 统一的日志格式配置
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var cores []zapcore.Core

	// 1. 控制台输出配置 (附带颜色，方便在 Linux 终端查看)
	consoleEncoderConfig := encoderConfig
	consoleEncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)

	// 标准输出 (Stdout)，Systemd 等守护进程会自动捕获这里的内容
	consoleCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), level)
	cores = append(cores, consoleCore)

	// 2. 文件输出配置 (如果有传入路径)
	if logPath != "" {
		// 文件输出不需要颜色代码，否则用 tail/cat 看会出现乱码
		fileEncoderConfig := encoderConfig
		fileEncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		// 这里保留了你原代码中对文件的 Console 格式偏好，如果你喜欢 JSON 可以换成 NewJSONEncoder
		fileEncoder := zapcore.NewConsoleEncoder(fileEncoderConfig)

		// 使用 O_APPEND 追加模式，而不是 O_TRUNC 清空模式，防止程序重启丢失历史日志
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			// 文件打开失败返回错误码
			return -1
		}
		fileCore := zapcore.NewCore(fileEncoder, zapcore.AddSync(file), level)
		cores = append(cores, fileCore)
	}

	// 将多个输出核心组合在一起
	combinedCore := zapcore.NewTee(cores...)

	// 实例化 logger，开启调用者行号显示
	logger := zap.New(combinedCore, zap.AddCaller())
	zlog = logger.Sugar()

	zlog.Infof("[Logger] 通用日志系统初始化完成 | 级别: %s | 文件: %s", level.String(), logPath)

	return 0
}

// SyncLogger 暴露给 main 函数，在程序退出前确保缓冲区日志落盘
func SyncLogger() {
	if zlog != nil {
		_ = zlog.Sync()
	}
}
