package myssh

import h2tunnel "github.com/NNdroid/h2tunnel"

func init() {
	registerH2SDK("masque", h2tunnel.TransportMASQUE, true)
}
