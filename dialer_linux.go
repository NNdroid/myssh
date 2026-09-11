//go:build linux && !android

package myssh

import (
	"net"
	"syscall"
)

// bindDevice  info  Linux  info  SO_BINDTODEVICE  info  Socket  info
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName == "" {
		return
	}

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var operr error
		err := c.Control(func(fd uintptr) {
			//  info  Socket  info
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

// icmpProtectFD is a no-op on desktop Linux: raw-socket capabilities are
// governed by CAP_NET_RAW, and there is no VpnService to exempt from.
func icmpProtectFD() func(fd int) error { return nil }
