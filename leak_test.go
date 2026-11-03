package myssh

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain 用 goleak 检测测试结束后是否残留 goroutine 泄漏。
//
// IgnoreCurrent() 把「长生命周期」的后台 goroutine（主要是各 init
// 启动的：流量采样、DNS 缓存 cleanup、GeoRouter 清理等）登记为
// 「基线」，只对增量泄漏报错，避免误报。
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreCurrent(),
		// 引擎回调派发器是进程级单例（由 engineDispatchOnce 保证只启动一次），
		// 设计上就不退出。它在首次 emit 时才懒启动，因此不在 IgnoreCurrent 的
		// 基线里；且它阻塞在 Cond.Wait 时栈顶是 sync.runtime_notifyListWait，
		// 只能用 IgnoreAnyFunction 全栈匹配。
		goleak.IgnoreAnyFunction("myssh.dispatchEngineEvents"),
		goleak.IgnoreTopFunction("github.com/quic-go/quic-go.(*Transport).listen"),
		goleak.IgnoreTopFunction("github.com/quic-go/quic-go.(*Transport).runSendQueue"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
