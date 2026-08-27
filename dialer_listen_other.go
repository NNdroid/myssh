//go:build !android

package myssh

import "net"

// rangeListenConfig returns a plain ListenConfig on non-Android platforms.
// On Linux/Darwin a BindInterface constraint is intentionally NOT applied to the
// unconnected range socket (it would pin the source and complicate the per-packet
// destination spread); the destination-port variation already provides the
// desired path diversity. VpnService protection is Android-only.
func rangeListenConfig(cfg ProxyConfig) *net.ListenConfig {
	return &net.ListenConfig{}
}
