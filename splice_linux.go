//go:build linux || android

package myssh

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const spliceDefaultChunk = 64 * 1024

func getRawFd(c net.Conn) (int, error) {
	type unwrapper interface {
		Unwrap() net.Conn
	}
	current := c
	for {
		if u, ok := current.(unwrapper); ok {
			current = u.Unwrap()
		} else {
			break
		}
	}

	sc, ok := current.(syscall.Conn)
	if !ok {
		return -1, errors.New("connection does not implement syscall.Conn")
	}

	rawConn, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}

	var fd int = -1
	var sysErr error
	err = rawConn.Control(func(descriptor uintptr) {
		fd = int(descriptor)
	})
	if err != nil {
		return -1, err
	}
	if sysErr != nil {
		return -1, sysErr
	}
	if fd < 0 {
		return -1, errors.New("invalid file descriptor")
	}
	return fd, nil
}

func trySplice(dst, src net.Conn) (int64, error) {
	srcFd, err := getRawFd(src)
	if err != nil {
		return 0, err
	}
	dstFd, err := getRawFd(dst)
	if err != nil {
		return 0, err
	}

	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	pRead := pipeFds[0]
	pWrite := pipeFds[1]
	defer func() {
		_ = unix.Close(pRead)
		_ = unix.Close(pWrite)
	}()

	var total int64 = 0

	for {
		nIn, errIn := unix.Splice(srcFd, nil, pWrite, nil, spliceDefaultChunk, unix.SPLICE_F_MOVE)
		if nIn > 0 {
			var nOutLeft = nIn
			for nOutLeft > 0 {
				nOut, errOut := unix.Splice(pRead, nil, dstFd, nil, int(nOutLeft), unix.SPLICE_F_MOVE)
				if nOut > 0 {
					nOutLeft -= nOut
					total += int64(nOut)
				}
				if errOut != nil {
					if errOut == unix.EINTR {
						continue
					}
					return total, errOut
				}
			}
		}

		if errIn != nil {
			if errIn == unix.EINTR {
				continue
			}
			return total, errIn
		}

		if nIn == 0 {
			break
		}
	}

	return total, nil
}
