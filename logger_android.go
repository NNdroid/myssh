package myssh

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"strings"
)

// --- 接口定义 ---

// LogReceiver 是由 Android 端实现的接口
type LogReceiver interface {
	Receive(level int, tag, msg string)
}

var (
	globalReceiver LogReceiver
	logChan        = make(chan logItem, 1000)
	zlog           *zap.SugaredLogger = zap.NewNop().Sugar()
)

// --- 常量与辅助函数 ---

const (
	AndroidLogDebug = 0
	AndroidLogInfo  = 1
	AndroidLogWarn  = 2
	AndroidLogError = 3
	AndroidLogPanic = 4
	AndroidLogFatal = 5
)

func zapToStunLevel(l zapcore.Level) int {
	switch l {
	case zapcore.DebugLevel:
		return AndroidLogDebug
	case zapcore.InfoLevel:
		return AndroidLogInfo
	case zapcore.WarnLevel:
		return AndroidLogWarn
	case zapcore.ErrorLevel:
		return AndroidLogError
	case zapcore.DPanicLevel, zapcore.PanicLevel:
		return AndroidLogPanic
	case zapcore.FatalLevel:
		return AndroidLogFatal
	default:
		return AndroidLogInfo
	}
}

type logItem struct {
	level int
	tag   string
	msg   string
}

// --- 核心逻辑 ---

// SetLogReceiver 由 Android 调用，传入实现接口的 Kotlin 对象
func SetLogReceiver(r LogReceiver) {
	globalReceiver = r
	// 启动异步日志消费泵
	go func() {
		for item := range logChan {
			if globalReceiver != nil {
				// gomobile 会自动处理线程切换和接口调用
				globalReceiver.Receive(item.level, item.tag, item.msg)
			}
		}
	}()
}

type stunCore struct {
	zapcore.LevelEnabler
	encoder zapcore.Encoder
	tag     string
}

func (c *stunCore) With(fields []zapcore.Field) zapcore.Core {
	clone := &stunCore{
		LevelEnabler: c.LevelEnabler,
		encoder:      c.encoder.Clone(),
		tag:          c.tag,
	}
	// 将 With 传入的字段提前写入 encoder，提高 Write 性能
	for i := range fields {
		fields[i].AddTo(clone.encoder)
	}
	return clone
}

func (c *stunCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *stunCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	// 1. 注入更多系统级参数
	additionalFields := []zapcore.Field{
		zap.Int("pid", os.Getpid()),              // 进程ID，排查多进程冲突
		zap.Int("uid", os.Getuid()),
		zap.String("version", Version),
	}
	
	// 合并 fields
	allFields := append(fields, additionalFields...)

	// 2. 编码条目
	buf, err := c.encoder.EncodeEntry(ent, allFields)
	if err != nil {
		return err
	}

	// 3. 异步丢入队列
	select {
	case logChan <- logItem{
		level: zapToStunLevel(ent.Level),
		tag:   c.tag,
		msg:   buf.String(),
	}:
	default:
		// 队列满则静默丢弃
	}
	buf.Free()
	return nil
}
func (c *stunCore) Sync() error { return nil }

// --- 初始化 ---

func InitLogger(logPath string, logLevelStr string) int {
	var level zapcore.Level
	switch strings.ToUpper(logLevelStr) {
	case "DEBUG": level = zapcore.DebugLevel
	case "INFO":  level = zapcore.InfoLevel
	case "WARN":  level = zapcore.WarnLevel
	case "ERROR": level = zapcore.ErrorLevel
	default:      level = zapcore.InfoLevel
	}

	zapEncoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "severity",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	consoleEncoder := zapcore.NewConsoleEncoder(zapEncoderConfig)
	jsonEncoder := zapcore.NewJSONEncoder(zapEncoderConfig)

	// 文件输出
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return -1
	}
	fileCore := zapcore.NewCore(consoleEncoder.Clone(), zapcore.AddSync(file), level)//使用控制台输出格式

	// 安卓 UI 输出
	androidCoreInstance := &stunCore{
		LevelEnabler: level,
		encoder:      jsonEncoder.Clone(),//使用json格式
		tag:          "Stun-Go",
	}

	combinedCore := zapcore.NewTee(fileCore, androidCoreInstance)
	logger := zap.New(combinedCore, zap.AddCaller())
	zlog = logger.Sugar()

	zlog.Infof("[Logger] 日志系统初始化完成 (LogReceiver 模式)")
	return 0
}