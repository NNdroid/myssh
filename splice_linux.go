//go:build linux || android

package myssh

import (
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

// Only unwrap our accounting layer over plain TCP. Never bypass TLS or SSH.
func spliceTCP(c net.Conn) (*net.TCPConn, *TrackedConn) {
	if tracked, ok := c.(*TrackedConn); ok {
		tcp, _ := tracked.Conn.(*net.TCPConn)
		return tcp, tracked
	}
	tcp, _ := c.(*net.TCPConn)
	return tcp, nil
}

func trySplice(dst, src net.Conn) (total int64, err error, handled bool) {
	s, sr := spliceTCP(src)
	d, dw := spliceTCP(dst)
	if s == nil || d == nil {
		return 0, nil, false
	}
	sraw, err := s.SyscallConn()
	if err != nil {
		return 0, err, false
	}
	draw, err := d.SyscallConn()
	if err != nil {
		return 0, err, false
	}
	var pipe [2]int
	if err = unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return 0, err, false
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	// RawConn retains fd ownership and uses Go's poller. Deadlines and Close
	// wake blocked operations without stale-fd races or blocking OS threads.
	for {
		var n int64
		var opErr error
		err = sraw.Read(func(fd uintptr) bool {
			for {
				n, opErr = unix.Splice(int(fd), nil, pipe[1], nil, 64*1024, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
				if opErr == syscall.EINTR {
					continue
				}
				return opErr != syscall.EAGAIN
			}
		})
		if err != nil {
			return total, err, true
		}
		if opErr != nil {
			if total == 0 && n == 0 && (opErr == syscall.EINVAL || opErr == syscall.ENOSYS || opErr == syscall.EOPNOTSUPP) {
				return 0, opErr, false
			}
			return total, opErr, true
		}
		if n == 0 {
			return total, nil, true
		}
		if sr != nil {
			sr.recordRead(int(n))
		}
		for n > 0 {
			var written int64
			err = draw.Write(func(fd uintptr) bool {
				for {
					written, opErr = unix.Splice(pipe[0], nil, int(fd), nil, int(n), unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
					if opErr == syscall.EINTR {
						continue
					}
					return opErr != syscall.EAGAIN
				}
			})
			if written > 0 {
				n -= written
				total += written
				if dw != nil {
					dw.recordWrite(int(written))
				}
			}
			if err != nil {
				return total, err, true
			}
			if opErr != nil {
				return total, opErr, true
			}
			if written == 0 {
				return total, syscall.EIO, true
			}
		}
	}
}
