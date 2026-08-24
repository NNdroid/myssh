package myssh

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain 在所有测试结束后通过 goleak 检测 goroutine 泄漏。
//
// IgnoreCurrent() 会快照「进入测试前」已经在运行的 goroutine（主要是包 init 阶段
// 启动的常驻后台协程：流量统计定时器、DNS 缓存清理循环、GeoRouter 后台循环等），
// 只检测「测试执行期间新引入」且未正确退出的协程，避免误报常驻服务协程。
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreCurrent())
}
