package myssh

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
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
)

// registerEngineCallback registers the Android callback receiver.
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

func emitCrash(report string) {
	engineCbMu.RLock()
	cb := engineCb
	engineCbMu.RUnlock()
	if cb != nil {
		cb.OnCrash(report)
	}
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
