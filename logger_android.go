//go:build android

package myssh

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ---  info  ---

// LogReceiver  info  Android  info
type LogReceiver interface {
	Receive(level int, tag, msg string)
}

var (
	globalReceiverMu sync.RWMutex
	globalReceiver   LogReceiver
	// logConsumerOnce 保证转发 goroutine 全进程只启动一个。旧实现在每次
	// SetLogReceiver 里各起一个消费者，重复绑定（UI 重进/换 Activity）会
	// 叠加多个 goroutine 争抢同一 channel，同一条日志被多次投递。
	logConsumerOnce sync.Once
	logChan                            = make(chan logItem, 1000)
	zlog            *zap.SugaredLogger = zap.NewNop().Sugar()
	atomicLogLevel                     = zap.NewAtomicLevelAt(zapcore.InfoLevel)
)

// SetLogLevel dynamically updates Go engine log level in real-time
func SetLogLevel(logLevelStr string) {
	level := parseLogLevel(logLevelStr)
	atomicLogLevel.SetLevel(level)
	if zlog != nil {
		zlog.Infof("[Logger] Dynamic log level updated to: %s", level.String())
	}
}

// GetLogLevel returns the current log level as a lowercase string (e.g. "debug", "info").
func GetLogLevel() string {
	return atomicLogLevel.Level().String()
}

// ---  info  ---

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

// ---  info  ---

// SetLogReceiver 注册 Android 宿主的日志接收器（gomobile 由 Kotlin 实现）。
// 可重复调用以更换接收器；转发 goroutine 由首次调用触发，仅启动一次。
func SetLogReceiver(r LogReceiver) {
	logConsumerOnce.Do(func() { go drainLogChan() })
	globalReceiverMu.Lock()
	globalReceiver = r
	globalReceiverMu.Unlock()
}

// drainLogChan 是唯一的日志转发消费者：从 stunCore 的非阻塞 channel 取出
// 日志项投递给当前接收器。接收器引用全程持锁读写，旧实现的无锁读是数据竞争。
func drainLogChan() {
	for item := range logChan {
		globalReceiverMu.RLock()
		r := globalReceiver
		globalReceiverMu.RUnlock()
		if r != nil {
			r.Receive(item.level, item.tag, item.msg)
		}
	}
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
	//  info  With  info  encoder， info  Write  info
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
	// 1.  info
	additionalFields := []zapcore.Field{
		zap.Int("pid", os.Getpid()), //  info ID， info
		zap.Int("uid", os.Getuid()),
		zap.String("version", Version),
	}

	//  info  fields
	allFields := append(fields, additionalFields...)

	// 2.  info
	buf, err := c.encoder.EncodeEntry(ent, allFields)
	if err != nil {
		return err
	}

	// 3.  info
	select {
	case logChan <- logItem{
		level: zapToStunLevel(ent.Level),
		tag:   c.tag,
		msg:   buf.String(),
	}:
	default:
		//  info discarded
	}
	buf.Free()
	return nil
}
func (c *stunCore) Sync() error { return nil }

// ---  info  ---

func InitLogger(logPath string, logLevelStr string) int {
	SetLogLevel(logLevelStr)

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

	//  info
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return -1
	}
	fileCore := zapcore.NewCore(consoleEncoder.Clone(), zapcore.AddSync(file), atomicLogLevel)

	//  info  UI  info
	androidCoreInstance := &stunCore{
		LevelEnabler: atomicLogLevel,
		encoder:      jsonEncoder.Clone(), // info json info
		tag:          "Stun-Go",
	}

	combinedCore := zapcore.NewTee(fileCore, androidCoreInstance)
	logger := zap.New(combinedCore, zap.AddCaller())
	zap.ReplaceGlobals(logger)
	zlog = logger.Sugar()

	zlog.Infof("[Logger] Log system initialization completed (LogReceiver mode)")
	return 0
}
