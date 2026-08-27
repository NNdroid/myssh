//go:build !linux && !android

package myssh

import (
	"errors"
	"net"
)

func trySplice(dst, src net.Conn) (int64, error) {
	return 0, errors.New("splice is only supported on linux and android")
}
