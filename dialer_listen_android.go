//go:build android

package myssh

import "net"

// rangeListenConfig returns a ListenConfig whose Control hook protects the
// freshly created (unconnected) UDP socket via VpnService.protect(), so the
// per-packet port-spreading tunnel traffic is excluded from the VPN routing
// loop. Mirrors wrapAndroidProtect but for listening sockets.
func rangeListenConfig(cfg ProxyConfig) *net.ListenConfig {
	lc := &net.ListenConfig{}
	lc.Control = androidProtectControl()
	return lc
}
