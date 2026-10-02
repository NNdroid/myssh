//go:build !linux && !android

package myssh

import (
	"net"
)

func trySplice(dst, src net.Conn) (int64, error, bool) {
	return 0, nil, false
}
