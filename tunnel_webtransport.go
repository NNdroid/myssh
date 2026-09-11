package myssh

import (
	h2tunnel "github.com/NNdroid/h2tunnel"
)

func init() {
	// webtransport：h2tunnel 的 WebTransport 传输（基于 HTTP/3；
	// WebTransport-over-H2 仅是 IETF 草案，SDK 未实现）。
	registerH2SDK("webtransport", h2tunnel.TransportWebTransport, true)
}
