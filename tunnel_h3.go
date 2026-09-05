package myssh

import h2tunnel "github.com/NNdroid/h2tunnel"

func init() {
	registerH2SDK("h3", h2tunnel.TransportH3, true)
}
