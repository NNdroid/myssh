package myssh

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// EngineCallback defines the callback interface exported to Android.
type EngineCallback interface {
	OnState(state string, detail string)
	OnNodeEvent(nodeId string, event string, detail string)
	OnError(code int, msg string)
	OnCrash(crashReport string) // 🌟 Triggered when an unhandled panic or crash occurs
}

// State constants
const (
	StateStarting     = "starting"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateReconnecting = "reconnecting"
	StateStopped      = "stopped"
	StateError        = "error"
)

// Node event constants
const (
	NodeEventConnecting = "connecting"
	NodeEventConnected  = "connected"
	NodeEventFailed     = "failed"
)

var (
	engineCb   EngineCallback
	engineCbMu sync.RWMutex

	// 最近一次状态的快照。回调是异步派发的，宿主在回调之外（例如 Activity
	// 重建后重新注册回调）仍可通过 GetState/IsRunning 拿到真实状态。
	engineStateMu     sync.RWMutex
	engineState       = StateStopped
	engineStateDetail string

	engineErrMu   sync.RWMutex
	engineErrCode int
	engineErrMsg  string

	// 单消费者事件队列：emit* 只入队，绝不在调用方 goroutine 上跨 JNI 调用宿主。
	//
	// 旧实现是同步直调：AutoSSH 循环发 StateReconnecting 时，若宿主在
	// OnState 里调 Stop()，Stop 会等 <-engineDone 而那个 goroutine 正卡在
	// OnState 里等 Kotlin 返回 —— 死锁。Start 期间发 StateStarting 时更直接：
	// engineLifecycleMu 还没释放，回调里再 Start/Stop 就是非重入锁自锁。
	// 改为入队后，引擎线程永不等待宿主，慢回调也不会拖住重连。
	engineQueueMu      sync.Mutex
	engineQueueCond    = sync.NewCond(&engineQueueMu)
	engineQueue        []engineEvent
	engineDispatchOnce sync.Once
	engineEventsDrop   atomic.Uint64
)

const engineQueueCap = 512

type engineEventKind uint8

const (
	engineEventState engineEventKind = iota
	engineEventNode
	engineEventError
	engineEventCrash
)

type engineEvent struct {
	kind engineEventKind
	a, b string
	c    string
	code int
}

type engineError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// registerEngineCallback registers the Android callback receiver.
func registerEngineCallback(cb EngineCallback) {
	engineCbMu.Lock()
	engineCb = cb
	engineCbMu.Unlock()
}

// clearEngineCallback releases the host reference so a destroyed Activity can
// be garbage-collected instead of being kept alive by the Go global.
func clearEngineCallback() {
	registerEngineCallback(nil)
}

func emitState(state, detail string) {
	engineStateMu.Lock()
	engineState = state
	engineStateDetail = detail
	engineStateMu.Unlock()

	// 新的启动周期开始时清掉上一轮的错误，避免 GetLastError 读到陈旧原因。
	if state == StateStarting {
		engineErrMu.Lock()
		engineErrCode = 0
		engineErrMsg = ""
		engineErrMu.Unlock()
	}

	enqueueEngineEvent(engineEvent{kind: engineEventState, a: state, b: detail})
}

func emitNodeEvent(nodeId, event, detail string) {
	enqueueEngineEvent(engineEvent{kind: engineEventNode, a: nodeId, b: event, c: detail})
}

func emitError(code int, msg string) {
	engineErrMu.Lock()
	engineErrCode = code
	engineErrMsg = msg
	engineErrMu.Unlock()

	enqueueEngineEvent(engineEvent{kind: engineEventError, code: code, a: msg})
}

func emitCrash(report string) {
	enqueueEngineEvent(engineEvent{kind: engineEventCrash, a: report})
}

// enqueueEngineEvent 非阻塞入队。队列满时丢最旧的一条并计数（用
// GetDroppedEventCount 观测）；绝不让引擎等待宿主。
func enqueueEngineEvent(ev engineEvent) {
	engineDispatchOnce.Do(func() { go dispatchEngineEvents() })

	engineQueueMu.Lock()
	if len(engineQueue) >= engineQueueCap {
		copy(engineQueue, engineQueue[1:])
		engineQueue = engineQueue[:len(engineQueue)-1]
		engineEventsDrop.Add(1)
	}
	engineQueue = append(engineQueue, ev)
	engineQueueCond.Signal()
	engineQueueMu.Unlock()
}

// dispatchEngineEvents 是唯一的事件消费者。每个事件用 recover 包裹，宿主
// 回调抛异常（或 gomobile 把 Java 异常转成 panic）不会杀死派发 goroutine。
func dispatchEngineEvents() {
	for {
		engineQueueMu.Lock()
		for len(engineQueue) == 0 {
			engineQueueCond.Wait()
		}
		ev := engineQueue[0]
		copy(engineQueue, engineQueue[1:])
		engineQueue = engineQueue[:len(engineQueue)-1]
		engineQueueMu.Unlock()

		engineCbMu.RLock()
		cb := engineCb
		engineCbMu.RUnlock()
		if cb == nil {
			continue
		}
		deliverEngineEvent(cb, ev)
	}
}

func deliverEngineEvent(cb EngineCallback, ev engineEvent) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Errorf("[Callback] host callback panicked, event dropped: %v\n%s", r, debug.Stack())
		}
	}()

	switch ev.kind {
	case engineEventState:
		cb.OnState(ev.a, ev.b)
	case engineEventNode:
		cb.OnNodeEvent(ev.a, ev.b, ev.c)
	case engineEventError:
		cb.OnError(ev.code, ev.a)
	case engineEventCrash:
		cb.OnCrash(ev.a)
	}
}

// engineStateSnapshot returns the last emitted state and its detail.
func engineStateSnapshot() (string, string) {
	engineStateMu.RLock()
	defer engineStateMu.RUnlock()
	return engineState, engineStateDetail
}

// engineStateJSON returns {"state":..,"detail":..} for the last emitted state.
// A JSON object is used instead of two return values so the gomobile binding
// stays on the well-supported single-string ABI.
func engineStateJSON() string {
	state, detail := engineStateSnapshot()
	b, err := json.Marshal(struct {
		State  string `json:"state"`
		Detail string `json:"detail"`
	}{State: state, Detail: detail})
	if err != nil {
		return ""
	}
	return string(b)
}

// engineIsRunning reports whether a start/connect/reconnect cycle is in flight.
func engineIsRunning() bool {
	state, _ := engineStateSnapshot()
	switch state {
	case StateStarting, StateConnecting, StateConnected, StateReconnecting:
		return true
	default:
		return false
	}
}

// engineLastErrorJSON returns {"code":..,"message":..} for the most recent
// error, or "" when no error has been recorded in the current cycle.
func engineLastErrorJSON() string {
	engineErrMu.RLock()
	code, msg := engineErrCode, engineErrMsg
	engineErrMu.RUnlock()
	if msg == "" {
		return ""
	}
	b, err := json.Marshal(engineError{Code: code, Message: msg})
	if err != nil {
		return ""
	}
	return string(b)
}

// engineEventsDroppedCount exposes how many callback events were dropped
// because the host could not keep up.
func engineEventsDroppedCount() int64 {
	return int64(engineEventsDrop.Load())
}

// Protect executes fn with panic recovery, formatting the report and sending it to Android
func Protect(tag string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			report := fmt.Sprintf("💥 [%s] Panic Recovered: %v\nTime: %s\nVersion: %s\n\nCall Stack:\n%s",
				tag, r, time.Now().Format("2006-01-02 15:04:05"), Version, stack)
			zlog.Errorf("%s", report)
			emitCrash(report)
		}
	}()
	fn()
}

// SafeGo executes fn in a newly spawned goroutine protected against unhandled panics
func SafeGo(tag string, fn func()) {
	go func() {
		Protect(tag, fn)
	}()
}

// InitCrashOutput redirects unhandled runtime fatal crashes directly to logPath using debug.SetCrashOutput
func InitCrashOutput(logPath string) error {
	if logPath == "" {
		return nil
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	return debug.SetCrashOutput(f, debug.CrashOptions{})
}
