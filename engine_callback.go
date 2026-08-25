package myssh

import "sync"

// EngineCallback 由 Android 侧实现的引擎事件回调。
// 与现有 TrafficCallback / SysInfoCallback / LogReceiver 风格一致，
// 用于把引擎状态、节点事件、致命错误以结构化方式推送到主 UI，
// 而不再只依赖日志页（这正是“报错不知道”的根因之一）。
type EngineCallback interface {
	OnState(state string, detail string)
	OnNodeEvent(nodeId string, event string, detail string)
	OnError(code int, msg string)
}

// 引擎状态常量
const (
	StateStarting     = "starting"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateReconnecting = "reconnecting"
	StateStopped      = "stopped"
	StateError        = "error"
)

// 节点事件常量
const (
	NodeEventConnecting = "connecting"
	NodeEventConnected  = "connected"
	NodeEventFailed     = "failed"
)

var (
	engineCb   EngineCallback
	engineCbMu sync.RWMutex
)

// registerEngineCallback 注册引擎事件回调。底层引擎为单例，最后注册者生效。
func registerEngineCallback(cb EngineCallback) {
	engineCbMu.Lock()
	engineCb = cb
	engineCbMu.Unlock()
}

func emitState(state, detail string) {
	engineCbMu.RLock()
	cb := engineCb
	engineCbMu.RUnlock()
	if cb != nil {
		cb.OnState(state, detail)
	}
}

func emitNodeEvent(nodeId, event, detail string) {
	engineCbMu.RLock()
	cb := engineCb
	engineCbMu.RUnlock()
	if cb != nil {
		cb.OnNodeEvent(nodeId, event, detail)
	}
}

func emitError(code int, msg string) {
	engineCbMu.RLock()
	cb := engineCb
	engineCbMu.RUnlock()
	if cb != nil {
		cb.OnError(code, msg)
	}
}
