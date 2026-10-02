package myssh

import (
	"context"
	"net"
)

// EOF closes only the sending direction. Errors and cancellation close both
// endpoints and wake the other copy before returning.
func relayBidirectional(ctx context.Context, local, remote net.Conn, direct bool) {
	stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
	defer stop()
	results := make(chan error, 2)
	copyDirection := func(dst, src net.Conn) {
		var err error
		if direct {
			_, err = relayStream(dst, src)
		} else {
			_, err = tcpRelay(dst, src)
		}
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				dst.Close()
			}
		}
		if err != nil {
			local.Close()
			remote.Close()
		}
		results <- err
	}
	go copyDirection(local, remote)
	go copyDirection(remote, local)
	<-results
	<-results
	local.Close()
	remote.Close()
}
