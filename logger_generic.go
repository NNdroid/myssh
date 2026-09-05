//go:build !android

package myssh

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	//  info  SugarLogger，default info  Nop  info  Panic
	zlog           *zap.SugaredLogger = zap.NewNop().Sugar()
	atomicLogLevel                    = zap.NewAtomicLevelAt(zapcore.InfoLevel)
)

// SetLogLevel dynamically updates generic log level in real-time
func SetLogLevel(logLevelStr string) {
	var level zapcore.Level
	switch strings.ToUpper(strings.TrimSpace(logLevelStr)) {
	case "DEBUG":
		level = zapcore.DebugLevel
	case "INFO":
		level = zapcore.InfoLevel
	case "WARN", "WARNING":
		level = zapcore.WarnLevel
	case "ERROR":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}
	atomicLogLevel.SetLevel(level)
	if zlog != nil {
		zlog.Infof("[Logger] Generic log level updated to: %s", level.String())
	}
}

// GetLogLevel returns the current log level as a lowercase string (e.g. "debug", "info").
func GetLogLevel() string {
	return atomicLogLevel.Level().String()
}

// InitLogger  info
// logPath:  info ， info  ""， info
// logLevelStr:  info  (DEBUG, INFO, WARN, ERROR)
func InitLogger(logPath string, logLevelStr string) int {
	SetLogLevel(logLevelStr)

	//  info config
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

	// 1.  info config ( info ， info  Linux  info )
	consoleEncoderConfig := encoderConfig
	consoleEncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)

	//  info  (Stdout)，Systemd  info
	consoleCore := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), atomicLogLevel)
	cores = append(cores, consoleCore)

	// 2.  info config ( info )
	if logPath != "" {
		//  info ， info  tail/cat  info
		fileEncoderConfig := encoderConfig
		fileEncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		//  info  Console  info ， info  JSON  info  NewJSONEncoder
		fileEncoder := zapcore.NewConsoleEncoder(fileEncoderConfig)

		//  info  O_APPEND  info mode， info  O_TRUNC  info mode， info
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			//  info failed info
			return -1
		}
		fileCore := zapcore.NewCore(fileEncoder, zapcore.AddSync(file), atomicLogLevel)
		cores = append(cores, fileCore)
	}

	//  info
	combinedCore := zapcore.NewTee(cores...)

	//  info  logger， info
	logger := zap.New(combinedCore, zap.AddCaller())
	zap.ReplaceGlobals(logger)
	zlog = logger.Sugar()

	zlog.Infof("[Logger] Generic log system initialization completed | Level: %s | File: %s", atomicLogLevel.Level().String(), logPath)

	return 0
}

// SyncLogger  info  main  info ， info
func SyncLogger() {
	if zlog != nil {
		_ = zlog.Sync()
	}
}
