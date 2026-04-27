package myssh

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

var paddingGarbage [4096]byte
var paddingWritePool = sync.Pool{
	New: func() interface{} {
		// 单次最大 chunk 为 1MB (1048576)
		// Header(6) + Padding(最大不到 512)
		// 分配 1048576 + 1024 = 1049600 字节，绝对安全且避免越界
		buf := make([]byte, 1049600)
		return &buf
	},
}

func init() {
	rand.Read(paddingGarbage[:])
}

// 快速获取随机数
func fastRand(max int) int {
	var b [1]byte
	rand.Read(b[:])
	return int(b[0]) % max
}

// calculatePadding 智能动态填充算法
// 核心思想：反比例填充 + 块边界对齐
func calculatePadding(dataLen int) int {
	var targetPad int

	// 阶梯式反比例基础填充
	switch {
	case dataLen < 128:
		// 极小包（握手包、心跳包）：重度混淆，随机填充 128 ~ 384 字节
		targetPad = 128 + fastRand(256)
	case dataLen < 512:
		// 小包（控制指令）：中度混淆，随机填充 64 ~ 192 字节
		targetPad = 64 + fastRand(128)
	case dataLen < 8192:
		// 中等包：轻度混淆，随机填充 16 ~ 64 字节
		targetPad = 16 + fastRand(48)
	default:
		// 大型数据流（高速下载）
		targetPad = 0
	}

	// 块对齐增强 (Block Alignment)
	// 强制让 (真实数据 + Padding) 的总长度对齐到 64 字节边界，
	// 这会让流量看起来非常像 AES/ChaCha20 这种标准块加密算法的输出特征。
	totalLen := dataLen + targetPad
	remainder := totalLen % 64
	if remainder != 0 {
		targetPad += (64 - remainder)
	}

	// 绝对安全边界拦截
	// 确保 Padding 永远不会超过我们预分配的 paddingGarbage 垃圾池大小
	if targetPad >= len(paddingGarbage) {
		targetPad = len(paddingGarbage) - 1
	}

	return targetPad
}

// ==========================================
// Padding 读写器核心
// ==========================================

// PaddingWriter 对标准 io.Writer 进行混淆包装
type PaddingWriter struct {
	w io.Writer
}

func (pw *PaddingWriter) Write(p []byte) (nTotal int, err error) {
	for len(p) > 0 {
		chunk := p
		// 控制单帧最大限制为 1MB
		if len(chunk) > 1048576 {
			chunk = chunk[:1048576]
		}

		// 智能计算 Padding 长度
		padLen := calculatePadding(len(chunk))
		totalLen := 6 + len(chunk) + padLen

		// 🌟 核心优化：从全局池子里“借”一块内存，坚决不用 make
		bufPtr := paddingWritePool.Get().(*[]byte)
		buf := *bufPtr

		// 写入 6 字节 Header
		binary.BigEndian.PutUint32(buf[0:4], uint32(len(chunk)))
		binary.BigEndian.PutUint16(buf[4:6], uint16(padLen))

		// 写入真实数据
		copy(buf[6:], chunk)

		// 写入垃圾 Padding
		if padLen > 0 {
			copy(buf[6+len(chunk):], paddingGarbage[:padLen])
		}

		// 🌟 提交给底层发送（切片截取到实际组装的 totalLen）
		_, errW := pw.w.Write(buf[:totalLen])

		// 🌟 用完立刻“还”回池子，供其他并发连接复用
		paddingWritePool.Put(bufPtr)

		if errW != nil {
			return nTotal, errW
		}

		nTotal += len(chunk)
		p = p[len(chunk):]
	}
	return nTotal, nil
}

// 傳遞關閉信號到底層 Writer
func (pw *PaddingWriter) Close() error {
	if closer, ok := pw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// PaddingReader 对应的解包器
type PaddingReader struct {
	r        io.Reader
	leftData uint32
	leftPad  uint16
}

func (pr *PaddingReader) Read(p []byte) (n int, err error) {
	for pr.leftData == 0 {
		// 消耗掉上一帧残留的 Padding (如果有的话)
		if pr.leftPad > 0 {
			_, err := io.CopyN(io.Discard, pr.r, int64(pr.leftPad))
			if err != nil {
				return 0, err
			}
			pr.leftPad = 0
		}

		// 读取新帧的 6 字节 Header
		var header [6]byte
		if _, err := io.ReadFull(pr.r, header[:]); err != nil {
			return 0, err
		}
		pr.leftData = binary.BigEndian.Uint32(header[0:4]) // 解析 4 字节数据长度
		pr.leftPad = binary.BigEndian.Uint16(header[4:6])
	}

	// 读取真实载荷
	toRead := pr.leftData
	if uint32(len(p)) < toRead {
		toRead = uint32(len(p)) // 防御性判断：不能超过用户传入的 slice 容量
	}
	n, err = pr.r.Read(p[:toRead])
	if err != nil && err != io.EOF {
		zlog.Debugf("[PaddingReader] 读取真实数据异常: %v", err)
	}
	pr.leftData -= uint32(n)
	return n, err
}

// 傳遞關閉信號到底層 Reader
func (pr *PaddingReader) Close() error {
	if closer, ok := pr.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// ==========================================
// PaddingConn 组合器 (让 Padding 变成一个 net.Conn)
// ==========================================

// paddingConn 将普通的 net.Conn 包装为带 Padding 混淆的 net.Conn
type paddingConn struct {
	net.Conn
	pr *PaddingReader
	pw *PaddingWriter
}

func (p *paddingConn) Read(b []byte) (n int, err error) {
	return p.pr.Read(b)
}

func (p *paddingConn) Write(b []byte) (n int, err error) {
	return p.pw.Write(b)
}

// WrapWithPadding 提供一个便捷方法来包裹底层的连接
func WrapWithPadding(base net.Conn) net.Conn {
	return &paddingConn{
		Conn: base,
		pr:   &PaddingReader{r: base},
		pw:   &PaddingWriter{w: base},
	}
}

// WrapWithPaddingForStreams 用于处理那种底层实现了 io.Reader 和 io.Writer，并且有一个关闭回调的场景
// (主要用于那些把读和写分开，但又需要聚合成 net.Conn 的特殊情况)
type customPaddingConn struct {
	pr         *PaddingReader
	pw         *PaddingWriter
	closer     func() error
	localAddr  func() net.Addr
	remoteAddr func() net.Addr
}

func (c *customPaddingConn) Read(b []byte) (n int, err error)   { return c.pr.Read(b) }
func (c *customPaddingConn) Write(b []byte) (n int, err error)  { return c.pw.Write(b) }
func (c *customPaddingConn) Close() error                       { return c.closer() }
func (c *customPaddingConn) LocalAddr() net.Addr                { return c.localAddr() }
func (c *customPaddingConn) RemoteAddr() net.Addr               { return c.remoteAddr() }
func (c *customPaddingConn) SetDeadline(t time.Time) error      { return nil }
func (c *customPaddingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *customPaddingConn) SetWriteDeadline(t time.Time) error { return nil }
