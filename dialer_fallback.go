//go:build !linux && !android && !windows && !darwin

package myssh

import (
	"net"
)

// bindDevice attempts to bind the dialer to a specific network interface by name.
// This is a generic fallback implementation for other OSes (FreeBSD, OpenBSD, etc.).
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
		zlog.Infof("%s [Tunnel] Bound to local IP of interface '%s': %s (Fallback)", TAG, ifaceName, foundIP.String())
	} else {
		zlog.Warnf("%s [Tunnel] ⚠️ Failed to find a bindable non-loopback IP address on interface '%s'. Falling back to system default routing table.", TAG, ifaceName)
	}
}

// wrapAndroidProtect is a no-op on fallback platforms.
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("[Protect] STUB: Socket protection feature is disabled on the current platform.")
	return dialer
}
