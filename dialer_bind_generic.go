//go:build !linux && !android

package myssh

import (
	"net"
	"runtime"
)

// 本文件覆盖除 Linux/Android 外的所有平台（darwin/windows/BSD 等）。
// 这些平台没有 SO_BINDTODEVICE，也不存在 Android VpnService，因此
// bindDevice 统一采用「取网卡首个非环回 IPv4 → dialer.LocalAddr」的
// 用户态绑法，wrapAndroidProtect / icmpProtectFD 均为 no-op。
// Linux 桌面（SO_BINDTODEVICE）与 Android（fd 级 protect）仍各自单独实现。

// bindDevice attempts to bind the dialer to a specific network interface by name.
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName == "" {
		return
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		zlog.Warnf("%s [Tunnel] ⚠️ Unable to find specified interface '%s': %v. Falling back to system default routing table.", TAG, ifaceName, err)
		return
	}

	addrs, err := iface.Addrs()
	if err != nil {
		zlog.Warnf("%s [Tunnel] ⚠️ Unable to get address for interface '%s': %v. Falling back to system default routing table.", TAG, ifaceName, err)
		return
	}

	var foundIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				foundIP = ipnet.IP
				break
			}
		}
	}

	if foundIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: foundIP}
		zlog.Infof("%s [Tunnel] Bound to local IP of interface '%s': %s (%s)", TAG, ifaceName, foundIP.String(), runtime.GOOS)
	} else {
		zlog.Warnf("%s [Tunnel] ⚠️ Failed to find a bindable non-loopback IP address on interface '%s'. Falling back to system default routing table.", TAG, ifaceName)
	}
}

// wrapAndroidProtect is a no-op outside Android.
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("[Protect] STUB: Compiled for %s platform, Socket protection is disabled.", runtime.GOOS)
	return dialer
}

// icmpProtectFD is a no-op outside Android: the ICMP carrier rejects
// unsupported platforms before any socket is created.
func icmpProtectFD() func(fd int) error { return nil }
