package myssh

import h2tunnel "github.com/NNdroid/h2tunnel"

func init() {
	registerH2SDK("wt", h2tunnel.TransportWebTransport, true)
}
