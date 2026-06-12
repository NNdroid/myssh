//go:build linux && !android

package myssh

import (
	"net"
	"syscall"
)

// bindDevice 利用 Linux 的 SO_BINDTODEVICE 选项将 Socket 强行绑定到指定网卡
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName == "" {
		return
	}

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var operr error
		err := c.Control(func(fd uintptr) {
			// 将底层 Socket 描述符绑定到网卡名称
			operr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName)
		})
		if err != nil {
			return err
		}
		return operr
	}

	zlog.Infof("%s [Tunnel] 🔒 Underlying Socket configured to bind to specified interface: %s", TAG, ifaceName)
}

// wrapAndroidProtect is a no-op on Linux.
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("[Protect] STUB: Compiled for Linux platform, Socket protection is disabled.")
	return dialer
}
