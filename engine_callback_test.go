package myssh

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 回调派发器的核心契约：emit* 只入队，绝不在调用方 goroutine 上跨越 JNI
// 调用宿主。宿主在回调里阻塞或反调 emit*，都不能让引擎线程卡住。

// fakeEngineCallback 记录所有回调并可选地执行一段自定义逻辑。
type fakeEngineCallback struct {
	mu      sync.Mutex
	events  []string
	ch      chan string
	onState func(state, detail string)
}

func newFakeEngineCallback() *fakeEngineCallback {
	return &fakeEngineCallback{ch: make(chan string, 256)}
}

func (f *fakeEngineCallback) record(ev string) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
	select {
	case f.ch <- ev:
	default: // 存满就丢，避免测试自己把派发器堵死
	}
}

func (f *fakeEngineCallback) OnState(state, detail string) {
	if f.onState != nil {
		f.onState(state, detail)
	}
	f.record("state:" + state)
}

func (f *fakeEngineCallback) OnNodeEvent(nodeId, event, detail string) {
	f.record("node:" + event)
}

func (f *fakeEngineCallback) OnError(code int, msg string) {
	f.record(fmt.Sprintf("error:%d:%s", code, msg))
}

func (f *fakeEngineCallback) OnCrash(report string) { f.record("crash") }

func (f *fakeEngineCallback) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-f.ch:
			if got == want {
				return
			}
		case <-deadline:
			f.mu.Lock()
			seen := append([]string(nil), f.events...)
			f.mu.Unlock()
			t.Fatalf("event %q was not delivered, got %v", want, seen)
		}
	}
}

// TestEmitStateDoesNotBlockOnSlowHostCallback 钉住异步派发：宿主回调卡住时，
// emitState 必须立刻返回。旧实现是同步直调，AutoSSH 循环发 StateReconnecting
// 时若宿主在 OnState 里调 Stop()，Stop 等 <-engineDone 会直接死锁。
func TestEmitStateDoesNotBlockOnSlowHostCallback(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	cb := newFakeEngineCallback()
	cb.onState = func(string, string) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	registerEngineCallback(cb)
	defer registerEngineCallback(nil)

	done := make(chan struct{})
	go func() {
		emitState(StateConnecting, "slow-host")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("emitState blocked on the host callback")
	}

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback was never delivered")
	}
	close(release)
}

// TestCallbackReenterEmitDoesNotDeadlock 钉住重入：宿主在 OnState 里再次
// emitState 只是继续入队，不会与派发器互相等待。
func TestCallbackReenterEmitDoesNotDeadlock(t *testing.T) {
	cb := newFakeEngineCallback()
	var once sync.Once
	cb.onState = func(state, _ string) {
		if state != "outer" {
			return
		}
		once.Do(func() { emitState("inner", "reentered") })
	}
	registerEngineCallback(cb)
	defer registerEngineCallback(nil)

	emitState("outer", "start")
	cb.waitFor(t, "state:outer")
	emitState("inner", "from-test")
	cb.waitFor(t, "state:inner")
}

// TestPanickingCallbackDoesNotKillDispatcher 钉住 recover：宿主回调抛异常
// （或 gomobile 把 Java 异常转成 panic）后，派发器必须继续工作。
func TestPanickingCallbackDoesNotKillDispatcher(t *testing.T) {
	cb := &panickingCallback{delivered: make(chan string, 4)}
	registerEngineCallback(cb)
	defer registerEngineCallback(nil)

	emitNodeEvent("node-1", NodeEventFailed, "boom")
	emitNodeEvent("node-2", NodeEventConnected, "after-panic")

	select {
	case got := <-cb.delivered:
		if got != NodeEventConnected {
			t.Fatalf("unexpected event after panic: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher stopped delivering after a panicking callback")
	}
}

type panickingCallback struct {
	delivered chan string
	fired     bool
}

func (p *panickingCallback) OnState(string, string) {}
func (p *panickingCallback) OnError(int, string)    {}
func (p *panickingCallback) OnCrash(string)         {}

func (p *panickingCallback) OnNodeEvent(_, event, _ string) {
	if !p.fired {
		p.fired = true
		panic("host callback exploded")
	}
	p.delivered <- event
}

// TestEngineStateSnapshotAndLastError 覆盖异步派发后宿主仍可主动查询的状态。
func TestEngineStateSnapshotAndLastError(t *testing.T) {
	registerEngineCallback(nil)

	emitState(StateStarting, "boot")
	if !engineIsRunning() {
		t.Fatal("StateStarting should count as running")
	}
	if got := engineStateJSON(); got != `{"state":"starting","detail":"boot"}` {
		t.Fatalf("unexpected state JSON: %s", got)
	}

	emitError(-7, "auth failed")
	if got := engineLastErrorJSON(); got != `{"code":-7,"message":"auth failed"}` {
		t.Fatalf("unexpected last error JSON: %s", got)
	}

	// 新一轮启动必须清掉上一轮的错误，否则宿主会读到陈旧原因。
	emitState(StateStarting, "retry")
	if got := engineLastErrorJSON(); got != "" {
		t.Fatalf("last error should be cleared on a new start cycle, got %s", got)
	}

	emitState(StateStopped, "bye")
	if engineIsRunning() {
		t.Fatal("StateStopped must not count as running")
	}
}
