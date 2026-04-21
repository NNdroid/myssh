package myssh

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
)

var (
	// 用于 TCP io.CopyBuffer 的 64KB 缓冲池
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64*1024)
			return &buf
		},
	}
	// 用于 UDP 读取的 64KB 缓冲池
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65536)
			return &buf
		},
	}
	// 用于 XHTTP io.CopyBuffer 的 990KB 缓冲池
	xhttpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 990*1000)
			return &buf
		},
	}
	// 全局复用的 bytes.Buffer 池，接收响应体
	bytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	// 填充池
	padPool    []byte
	padPoolLen = 64 * 1000
)

func init() {
	// 随机填充池初始化
	padPool = make([]byte, padPoolLen)
	io.ReadFull(rand.Reader, padPool)
}

func tcpRelay(dst io.Writer, src io.Reader) (int64, error) {
	// 1. 从池子里借一块内存
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr

	// 2. 确保在函数退出时还给池子
	defer tcpBufPool.Put(bufPtr)

	// 3. 使用 CopyBuffer，并传入我们复用的内存块
	// 它会一直使用这块内存直到 src 读到 EOF 或出错
	return io.CopyBuffer(dst, src, buf)
}
