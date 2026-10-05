//go:build !android

package myssh

import (
	"net"
	"syscall"
)

// 非 Android 平台（linux 交叉编译、darwin 等）没有 tproxy 的 iptables 规则，
// 也就没有回环风险，SO_MARK 无用。这里提供空实现，让 dialer 的接线代码
// 在所有平台都能编译，且行为与"没有 helper"完全一致。

// RegisterSocketMarkHelper 在非 Android 上是空操作。
func RegisterSocketMarkHelper(exePath string, appPID int64, mark int64) {}

// ProbeSocketMark 在非 Android 上恒为 0（不可用）—— 与"没有 helper"一致。
func ProbeSocketMark() int64 { return 0 }

// markSocketFD 在非 Android 上是空操作。
func markSocketFD(fd uintptr) {}

// wrapSocketMark 在非 Android 上原样返回 dialer（不套任何 Control）。
func wrapSocketMark(dialer *net.Dialer) *net.Dialer { return dialer }

func androidMarkControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error { return nil }
}
