//go:build !android

package myssh

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// 全局 SugarLogger，未调用 InitLogger 前默认为 Nop，避免空指针 Panic
	zlog           *zap.SugaredLogger = zap.NewNop().Sugar()
	atomicLogLevel                    = zap.NewAtomicLevelAt(zapcore.InfoLevel)
)

// SetLogLevel dynamically updates generic log level in real-time
func SetLogLevel(logLevelStr string) {
	level := parseLogLevel(logLevelStr)
	atomicLogLevel.SetLevel(level)
	if zlog != nil {
		zlog.Infof("[Logger] Generic log level updated to: %s", level.String())
	}
}

// GetLogLevel returns the current log level as a lowercase string (e.g. "debug", "info").
func GetLogLevel() string {
	return atomicLogLevel.Level().String()
}

// InitLogger 初始化桌面平台日志（stdout 彩色 console + 可选文件）。
// logPath: 日志文件路径；传 "" 则不写文件。
// logLevelStr: 日志级别 (DEBUG, INFO, WARN, ERROR)。
func InitLogger(logPath string, logLevelStr string) int {
	SetLogLevel(logLevelStr)

	// 基础 encoder config
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

	// 1. console encoder config（彩色级别，适合交互式 Linux 终端）
	consoleEncoderConfig := encoderConfig
	consoleEncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)

	// 输出到 Stdout（Systemd 下同样适用）
	consoleCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), atomicLogLevel)
	cores = append(cores, consoleCore)

	// 2. file encoder config（纯文本）
	if logPath != "" {
		// 纯文本格式，方便 tail/cat 查看
		fileEncoderConfig := encoderConfig
		fileEncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		// 与 Console 同构，非 JSON，故仍用 NewJSONEncoder 对应的 NewConsoleEncoder
		fileEncoder := zapcore.NewConsoleEncoder(fileEncoderConfig)

		// 用 O_APPEND 追加模式（桌面 CLI 单次启动；Android 侧用 O_TRUNC，
		// 差异为有意设计，理由见 logger_android.go InitLogger 注释）
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			// 文件打开失败
			return -1
		}
		fileCore := zapcore.NewCore(fileEncoder, zapcore.AddSync(file), atomicLogLevel)
		cores = append(cores, fileCore)
	}

	// 组合 core
	combinedCore := zapcore.NewTee(cores...)

	// 构造全局 logger，替换 zap 全局实例
	logger := zap.New(combinedCore, zap.AddCaller())
	zap.ReplaceGlobals(logger)
	zlog = logger.Sugar()

	zlog.Infof("[Logger] Generic log system initialization completed | Level: %s | File: %s", atomicLogLevel.Level().String(), logPath)

	return 0
}
