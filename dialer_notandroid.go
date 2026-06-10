//go:build !android

package myssh

import (
	"net"
)

// wrapAndroidProtect 在非 Android 平台上是一个空操作 (no-op)。
// 它直接返回原始的 dialer，不附加任何功能。
// 增加这条日志可以明确地告知开发者，当前编译的版本不包含 Socket 保护逻辑。
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("[Protect] STUB: 当前为非 Android 平台编译，Socket 保护功能被禁用。")
	return dialer
}
