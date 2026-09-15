package myssh

import (
	"sync"
	"testing"
	"time"
)

// TestWgWaitReuseNoPanic reproduces the crash seen on Android via gobind:
// a Java thread blocked in WgWait while the engine restarts (new tasks
// tracked after the live count hit zero), with a second concurrent waiter.
// The old package-level sync.WaitGroup panicked with
// "sync: WaitGroup is reused before previous Wait has returned" in this
// interleaving; the mutex+Cond task counter must simply drain.
func TestWgWaitReuseNoPanic(t *testing.T) {
	// 父任务贯穿整个 churn 窗口，且必须在 waiter 启动前挂上：若没有它（或
	// 挂晚了），每轮 release 可能先于下一轮 track 落地、count 瞬间归零，
	// parked（或尚未进入循环）的 waiter 会在 churn 中途合法返回，随后的
	// 归零断言就会看到在途任务（flaky，CI -race 下必现）。
	taskTrack()

	var waiters sync.WaitGroup
	waiters.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer waiters.Done()
			wgWait()
		}()
	}

	// Engine-cycle churn: track/release around the zero boundary while the
	// waiters are parked — the exact window the WaitGroup rejected.
	for cycle := 0; cycle < 20; cycle++ {
		taskTrack()
		go func() {
			time.Sleep(time.Millisecond)
			taskRelease()
		}()
		time.Sleep(time.Millisecond)
	}
	taskRelease() // only now may the count reach zero

	done := make(chan struct{})
	go func() {
		waiters.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("wgWait did not return after all tasks drained")
	}

	if got := atomicLiveTasks(); got != 0 {
		t.Fatalf("liveTasks = %d, want 0", got)
	}
}

func atomicLiveTasks() int {
	taskMu.Lock()
	defer taskMu.Unlock()
	return liveTasks
}
