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
	err = rawConn.Control(func(descriptor uintptr) {
		fd = int(descriptor)
	})
	if err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, errors.New("invalid file descriptor")
	}
	return fd, nil
}

// pollFd 等待 fd 就绪（Go 网络 fd 均为非阻塞，splice 返回 EAGAIN 时必须等待后再试）。
// 阻塞语义与 tcpRelay 的 conn.Read 一致：直到就绪、对端关闭（POLLHUP）或本连接被
// Close（fd 关闭后 poll 返回 POLLNVAL）。
func pollFd(fd int, events int16) error {
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(fds, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 &&
			fds[0].Revents&events == 0 {
			return syscall.ECONNRESET
		}
		return nil
	}
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
			// 关键：从 src 读入管道的字节必须全部送达 dst 后才能退出，
			// 否则 defer 关闭管道时会把残留字节连同数据流一起丢掉。
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
					if errOut == unix.EAGAIN {
						// dst 发送缓冲已满（背压）：等可写后继续排空管道。
						if werr := pollFd(dstFd, unix.POLLOUT); werr != nil {
							return total, werr
						}
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
			if errIn == unix.EAGAIN {
				// src 暂时无数据：等可读后继续走 splice 路径，
				// 而不是回退用户态拷贝（否则 splice 只能处理第一批数据）。
				if rerr := pollFd(srcFd, unix.POLLIN); rerr != nil {
					return total, rerr
				}
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
