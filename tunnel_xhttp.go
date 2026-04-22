package myssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	//"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	xhttpHeaderSize     = 6   // 头部固定 6 字节 (4字节长度 + 2字节Padding长度)
	xhttpMaxPaddingSize = 65535 // 最大 padding
)

var (
	xhttpMaxsendBufSize = 900 * 1000 // 降低单次发送包的大小，避开 Nginx 1MB 拦截
	xhttpMaxframeSize   = xhttpMaxsendBufSize + xhttpMaxPaddingSize + xhttpHeaderSize
)

// ==========================================
// 1. 高性能可靠传输缓冲区 (Seq/Ack 机制)
// ==========================================

type reliableBuffer struct {
	mu         sync.RWMutex
	cond       *sync.Cond
	data       []byte // 必须改回单一切片 []byte
	baseOffset uint64
	maxSize    int
	closed     bool
}

func newReliableBuffer(maxSize int) *reliableBuffer {
	rb := &reliableBuffer{maxSize: maxSize}
	rb.cond = sync.NewCond(&sync.Mutex{}) // 独立一把锁用于唤醒
	return rb
}

func (rb *reliableBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	rb.cond.L.Lock()
	for len(rb.data) >= rb.maxSize && !rb.closed {
		rb.cond.Wait() // 满了就等
	}
	if rb.closed {
		rb.cond.L.Unlock()
		return 0, io.ErrClosedPipe
	}
	rb.cond.L.Unlock()

	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.data = append(rb.data, p...)
	return len(p), nil
}

// GetSlice 获取从指定偏移量开始的数据，并清理掉已被对端确认 (Ack) 的旧数据
func (rb *reliableBuffer) GetSlice(remoteAck uint64, dispatchSeq uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// 清理对端已经确认收到的数据
	freed := false
	if remoteAck > rb.baseOffset {
		skip := remoteAck - rb.baseOffset
		if skip <= uint64(len(rb.data)) {
			rb.data = rb.data[skip:]
			rb.baseOffset = remoteAck
			freed = true // 标记清理了内存
			// 【惰性緊縮】：如果底層陣列膨脹超過 4MB 且空間浪費過半，才真正釋放記憶體
			if cap(rb.data) > rb.maxSize && len(rb.data) < cap(rb.data)/2 {
				newData := make([]byte, len(rb.data))
				copy(newData, rb.data)
				rb.data = newData
			}
		} else {
			rb.data = nil
			rb.baseOffset = remoteAck
			freed = true
		}
	}

	// 如果清理了旧数据，腾出了空间，唤醒被阻塞的 Write
	if freed {
		rb.cond.Broadcast()
	}

	// 修正派发起点：如果派发指针落后于已确认位置（说明发生了重传重置），则从当前最老的数据开始
	if dispatchSeq < rb.baseOffset {
		dispatchSeq = rb.baseOffset
	}

	// 计算相对于当前缓冲区头部的偏移量
	offsetInBuf := dispatchSeq - rb.baseOffset
	if offsetInBuf >= uint64(len(rb.data)) {
		return nil, dispatchSeq, nil // 没有新数据可以派发
	}

	// 截取分片
	availLen := uint64(len(rb.data)) - offsetInBuf
	length := int(availLen)
	if length > maxLen {
		length = maxLen
	}

	// 使用内存池进行拷贝
	bufPtr := xhttpBufPool.Get().(*[]byte) // 确保 xhttpBufPool 已定义并能提供足够容量的切片
	res := (*bufPtr)[:length]
	copy(res, rb.data[offsetInBuf:offsetInBuf+uint64(length)])

	// 返回：数据切片, 本次实际使用的Seq, 内存池指针
	return res, dispatchSeq, bufPtr
}

func (rb *reliableBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.data)
}

// ==========================================
// 2. Meek 虚拟连接 (集成可靠传输)
// ==========================================

type meekVirtualConn struct {
	ctx       context.Context
	sessionID string
	local     net.Addr
	remote    net.Addr

	readCond    *sync.Cond
	readBuf     bytes.Buffer
	nextReadSeq uint64            // 我方期待收到的下一个 Seq
	oooBuf      map[uint64][]byte // 乱序缓存

	writeBuf *reliableBuffer // 替换原有的 bytes.Buffer 和 mutex

	closed bool
}

func newMeekVirtualConn(ctx context.Context, sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		ctx:       ctx,
		sessionID: sessionID,
		local:     local,
		remote:    remote,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeBuf:  newReliableBuffer(4 * 1024 * 1024),
		oooBuf:    make(map[uint64][]byte),
	}
}

func (c *meekVirtualConn) Read(p []byte) (int, error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	for c.readBuf.Len() == 0 && !c.closed {
		c.readCond.Wait() // 等待唤醒
	}
    
	// 醒来后第一时间检查是否是因为上下文取消或被 Close 唤醒的
	if c.ctx.Err() != nil || c.closed {
		c.closed = true
		return 0, io.EOF
	}
	
	// 正常读取数据
	n, err := c.readBuf.Read(p)

	// ==========================================
	// 【滞留内存释放】
	// ==========================================
	// 如果读取后缓冲区刚好空了，且底层容量撑得过大（比如超过了 1MB）
	if c.readBuf.Len() == 0 && c.readBuf.Cap() > 1024*1024 {
		// 直接赋予一个全新的空 Buffer。
		// 这样一来，原来那个长达 1MB+ 的底层数组失去了引用，会被 Go 的 GC 迅速回收，释放系统内存。
		c.readBuf = bytes.Buffer{} 
	}

	return n, err
}

func (c *meekVirtualConn) Write(p []byte) (int, error) {
	if c.closed {
			return 0, io.ErrClosedPipe
		}
	return c.writeBuf.Write(p)
}

// PutReadData 乱序重组
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	if len(data) > 0 {
		if seq == c.nextReadSeq {
			// 序號正好匹配，寫入緩衝區
			c.readBuf.Write(data)
			c.nextReadSeq += uint64(len(data))

			// 檢查暫存區有沒有「未來的包」現在可以接上了
			for {
				if nextData, ok := c.oooBuf[c.nextReadSeq]; ok {
					c.readBuf.Write(nextData)
					delete(c.oooBuf, c.nextReadSeq)
					c.nextReadSeq += uint64(len(nextData))
				} else {
					break
				}
			}
			c.readCond.Broadcast()
		} else if seq > c.nextReadSeq {
			// 序號太新了，先存進 map
			// 序列号跨度过大（例如超过了 5MB 的数据量），视为无效包/恶意包，直接抛弃
			// 假设你的一般包大小为 100KB，跨度超过 50 个包的距离就没必要缓存了
			if seq - c.nextReadSeq > 5 * 1024 * 1024 { 
				return c.nextReadSeq // 丢弃不合理的未来包
			}

			// 限制 Map 长度
			if len(c.oooBuf) < 128 { // 1024 太大了，128 个乱序包已经能应对 99% 的弱网环境
				dataCopy := make([]byte, len(data))
				copy(dataCopy, data)
				c.oooBuf[seq] = dataCopy
			}
		}
	}
	return c.nextReadSeq
}

func (c *meekVirtualConn) Close() error {
	c.readCond.L.Lock()
	c.closed = true
	// 释放乱序缓存，避免常驻内存导致泄露
	c.oooBuf = nil
	c.readCond.Broadcast()
	c.readCond.L.Unlock()
	return nil
}

func (c *meekVirtualConn) LocalAddr() net.Addr                { return c.local }
func (c *meekVirtualConn) RemoteAddr() net.Addr               { return c.remote }
func (c *meekVirtualConn) SetDeadline(t time.Time) error      { return nil }
func (c *meekVirtualConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *meekVirtualConn) SetWriteDeadline(t time.Time) error { return nil }

// ==========================================
// 3. 动态 Padding 与 0xFFFF 信令装甲
// ==========================================

// getBufFromPool 安全地从 sync.Pool 中获取 *[]byte
// 当池子为空时，根据传入的 defaultSize 动态分配内存，完美支持多尺寸复用
func getBufFromPool(pool *sync.Pool, defaultSize int) *[]byte {
	obj := pool.Get()
	
	if obj == nil {
		b := make([]byte, defaultSize)
		return &b
	}
	
	return obj.(*[]byte)
}

type xhttpFramedConn struct {
	r             io.Reader
	w             io.Writer
	closer        func() error
	local         net.Addr
	remote        net.Addr
	mu            sync.Mutex
	readBuf       []byte
	frameBufPtr   *[]byte // 使用指针便于池化回收
	hdrBuf        []byte
	payloadBufPtr *[]byte // 使用指针便于池化回收
	closeCh       chan struct{}
	closedFlag    int32
	lastWriteTime int64
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	// 最大的 Payload + 最大的 Padding + 6字节头部
	fBufPtr := getBufFromPool(&xhttpBufPool, xhttpMaxframeSize)
	
	pBufPtr := getBufFromPool(&xhttpBufPool, xhttpMaxsendBufSize)

	conn := &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		frameBufPtr:  fBufPtr,
		hdrBuf: make([]byte, 6), 
		payloadBufPtr: pBufPtr,
		closeCh:       make(chan struct{}),
		lastWriteTime: time.Now().Unix(),
	}
	go conn.heartbeatLoop()
	return conn
}

func (c *xhttpFramedConn) heartbeatLoop() {
	// 巡逻周期设为 10 秒（不用频繁唤醒）
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// 获取上次真实发送数据的时间
			last := atomic.LoadInt64(&c.lastWriteTime)

			// 如果距离上次发包已经过去了 60 秒，说明连接处于绝对空闲状态
			if time.Now().Unix()-last >= 60 {
				c.Write(nil) // 发送空帧，这会自动触发上面的 StoreInt64 刷新时间
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *xhttpFramedConn) writeSingleFrame(chunk []byte) error {
	chunkSize := len(chunk)
	var padLenInt int
	if chunkSize == 0 {
		padLenInt = 32 + mrand.IntN(128)
	} else if chunkSize < 512 {
		padLenInt = (600 + mrand.IntN(600)) - chunkSize
		if padLenInt < 0 {
			padLenInt = mrand.IntN(256)
		}
	} else {
		padLenInt = 16 + mrand.IntN(112)
	}

	frameLen := 6 + padLenInt + chunkSize
	fBuf := *c.frameBufPtr

	// 判断底层数组容量(cap)是否足够
	if frameLen > cap(fBuf) {
		// 如果不够，采用 2 倍扩容策略，避免频繁 make
		newCap := cap(fBuf) * 2
		if newCap < frameLen {
			newCap = frameLen
		}
		fBuf = make([]byte, frameLen, newCap)
		*c.frameBufPtr = fBuf
	} else {
		// 容量足够时，直接拉伸Slice
		fBuf = fBuf[:frameLen]
	}

	// 写入 Header
	binary.BigEndian.PutUint32(fBuf[0:4], uint32(chunkSize))
	binary.BigEndian.PutUint16(fBuf[4:6], uint16(padLenInt))

	// 极速 Padding 填充
	if padLenInt > 0 {
		offset := mrand.IntN(padPoolLen - padLenInt)
		copy(fBuf[6:6+padLenInt], padPool[offset:offset+padLenInt])
	}

	// 写入 Payload
	if chunkSize > 0 {
		copy(fBuf[6+padLenInt:], chunk)
	}

	// 单次系统调用发出
	_, err := c.w.Write(fBuf)
	return err
}

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	atomic.StoreInt64(&c.lastWriteTime, time.Now().Unix())
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, c.writeSingleFrame(nil)
	}

	written := 0
	maxPayload := xhttpMaxsendBufSize
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPayload {
			chunkSize = maxPayload
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]
		if err := c.writeSingleFrame(chunk); err != nil {
			return written, err
		}
		written += chunkSize
	}
	return written, nil
}

func (c *xhttpFramedConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 { // 没有len信息，所以readBuf有就直接返回
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		if _, err := io.ReadFull(c.r, c.hdrBuf); err != nil {
			return 0, err
		}
		rawPayloadLen := binary.BigEndian.Uint32(c.hdrBuf[0:4])
		padLen := int(binary.BigEndian.Uint16(c.hdrBuf[4:6]))

		pBuf := *c.payloadBufPtr

		// 直接复用 c.payloadBufPtr 当作“垃圾桶”来接收 padding
		if padLen > 0 {
			if padLen > cap(pBuf) {
				pBuf = make([]byte, padLen)
				*c.payloadBufPtr = pBuf
			} else {
				pBuf = pBuf[:padLen]
			}
			if _, err := io.ReadFull(c.r, pBuf); err != nil {
				return 0, err
			}
		}

		// 处理特殊信令和空帧
		if rawPayloadLen == uint32(0xFFFFFFFF) {
			return 0, io.EOF // 截获远端 0xFFFFFFFF 信令，立即切断上传通道
		}
		if rawPayloadLen == 0 {
			continue
		}

		payloadLen := int(rawPayloadLen)

		// 计算可以直接读入 buffer `p` 的长度
		readIntoP := payloadLen
		if readIntoP > len(p) {
			readIntoP = len(p) // buffer 容量有限，只能装下这么多了
		}

		// 数据直接从 io.Reader 灌入用户的 p
		if _, err := io.ReadFull(c.r, p[:readIntoP]); err != nil {
			return 0, err
		}

		// 如果用户的 p 太小，剩下的 payload 必须读入内部 buffer 暂存
		leftover := payloadLen - readIntoP
		if leftover > 0 {
			pBuf = *c.payloadBufPtr
			// 使用 cap 而不是 len 来判断，最大程度减少 make() 重新分配内存的次数
			if leftover > cap(pBuf) {
				pBuf = make([]byte, leftover)
				*c.payloadBufPtr = pBuf
			}
			leftoverBuf := pBuf[:leftover]

			if _, err := io.ReadFull(c.r, leftoverBuf); err != nil {
				// 如果前面给用户的 p 已经读了 readIntoP 字节，
				// 这里哪怕断开，也应该把已读到的长度返回给上层
				return readIntoP, err
			}
			// 保存这部分没被拿走的数据，供下一次 Read 消费
			c.readBuf = leftoverBuf
		}

		return readIntoP, nil
	}
}

func (c *xhttpFramedConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1) {
		c.mu.Lock()
		frame := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
		c.w.Write(frame)
		c.mu.Unlock()

		close(c.closeCh)

		// 回收缓存池
		if c.frameBufPtr != nil {
			// 如果容量没有因为异常而暴涨（设定一个合理阈值，比如 2 倍），才放入池中
			if cap(*c.frameBufPtr) <= xhttpMaxframeSize*2 {
				xhttpBufPool.Put(c.frameBufPtr)
			}
			c.frameBufPtr = nil
		}
		if c.payloadBufPtr != nil {
			if cap(*c.payloadBufPtr) <= xhttpMaxsendBufSize*2 {
				xhttpBufPool.Put(c.payloadBufPtr)
			}
			c.payloadBufPtr = nil
		}

		return c.closer()
	}
	return nil
}

func (c *xhttpFramedConn) LocalAddr() net.Addr                { return c.local }
func (c *xhttpFramedConn) RemoteAddr() net.Addr               { return c.remote }
func (c *xhttpFramedConn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpFramedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpFramedConn) SetWriteDeadline(t time.Time) error { return nil }

func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// VerifyAndHandshakeUTLS 执行 uTLS 握手并校验首个证书的 SHA-256 指纹
// expectedFingerprint 格式示例: "EE:21:43:..." (不区分大小写，支持冒号或空格分隔)
func VerifyAndHandshakeUTLS(ctx context.Context, tcpConn net.Conn, utlsConfig *utls.Config, tcpAlpns []string, verifyFingerprint bool, expectedFingerprint string) (*utls.UConn, string, string, error) {

	uConn := utls.UClient(tcpConn, utlsConfig, utls.HelloChrome_Auto)

	// 1. 提前构建握手状态
	if err := uConn.BuildHandshakeState(); err != nil {
		tcpConn.Close()
		return nil, "", "", fmt.Errorf("utls build handshake state failed: %w", err)
	}

	// 2. 修改 ALPN 扩展
	for _, ext := range uConn.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = tcpAlpns
			break
		}
	}

	// 3. 执行握手
	if err := uConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, "", "", fmt.Errorf("utls handshake failed: %w", err)
	}

	// 4. 获取连接状态并校验指纹
	state := uConn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		uConn.Close()
		return nil, "", "", fmt.Errorf("no certificates presented by peer")
	}

	negotiatedProtocol := state.NegotiatedProtocol

	// 计算当前证书指纹
	leafCert := certs[0]
	sha256Sum := sha256.Sum256(leafCert.Raw)
	actualFingerprint := fmt.Sprintf("%02X", sha256Sum[0])
	for i := 1; i < len(sha256Sum); i++ {
		actualFingerprint += ":" + fmt.Sprintf("%02X", sha256Sum[i])
	}

	// 如果传入了指纹限制，则进行比对
	if verifyFingerprint {
		// 标准化处理：转大写并移除常见的冒号/空格
		cleanExpected := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(expectedFingerprint, ":", ""), " ", ""))
		cleanActual := strings.ReplaceAll(actualFingerprint, ":", "")

		if cleanExpected != cleanActual {
			uConn.Close()
			return nil, negotiatedProtocol, actualFingerprint, fmt.Errorf("TLS certificate fingerprint mismatch! expected: %s, actual: %s", expectedFingerprint, actualFingerprint)
		}
	}
	return uConn, negotiatedProtocol, actualFingerprint, nil
}

func VerifyAndHandshakeQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, quicCfg *quic.Config, verifyFingerprint bool, expectedFingerprint string) (*quic.Conn, string, error) {
	// 使用 DialAddrEarly 以支持 0-RTT（如果服务器支持）
	conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, quicCfg)
	if err != nil {
		return nil, "", fmt.Errorf("quic dial failed: %w", err)
	}

	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		conn.CloseWithError(0, "timeout")
		return nil, "", ctx.Err()
	}

	// 提取证书并校验指纹
	cs := conn.ConnectionState()
	certs := cs.TLS.PeerCertificates
	if len(certs) == 0 {
		conn.CloseWithError(0, "no_certs")
		return nil, "", fmt.Errorf("server provided no certificates")
	}

	// 计算实际指纹
	sha256Sum := sha256.Sum256(certs[0].Raw)
	var actualFPBuilder strings.Builder
	for i, b := range sha256Sum {
		if i > 0 {
			actualFPBuilder.WriteString(":")
		}
		fmt.Fprintf(&actualFPBuilder, "%02X", b)
	}
	actualFP := actualFPBuilder.String()

	// 比对指纹
	if verifyFingerprint {
		cleanExpected := strings.ToUpper(strings.ReplaceAll(expectedFingerprint, ":", ""))
		cleanActual := strings.ReplaceAll(actualFP, ":", "")

		if cleanExpected != cleanActual {
			conn.CloseWithError(0, "fingerprint_mismatch")
			return nil, actualFP, fmt.Errorf("fingerprint mismatch! expected: %s, actual: %s", expectedFingerprint, actualFP)
		}
	}

	return conn, actualFP, nil
}

// ==========================================
// 注册
// ==========================================
func init() {

	xhttpHandler := func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn, isTLS bool, alpnList []string) (net.Conn, error) {
		if len(alpnList) == 0 {
			alpnList = []string{"h3", "h2", "http/1.1"}
		}
		scheme, protoName := "http", "XHTTPC"
		if isTLS {
			scheme, protoName = "https", "XHTTP"
		}

		zlog.Infof("%s [Tunnel] 准备握手%s, 伪装 Host: %s, 允许协议: %v", TAG, protoName, cfg.CustomHost, alpnList)

		path := cfg.CustomPath
		if path == "" {
			path = "/stream"
		}
		reqURL := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)
		sessionID := generateRandomHex(16)

		var client *http.Client
		var negotiatedProtocol string
		var certificateFingerprint string
		var err error
		var cleanupFuncs []func() // 存放必须在隧道关闭时释放的资源（防泄露）

		baseTlsConf := &tls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: true,
		}

		if isTLS {
			// ==========================================
			// 1. 优先探测 HTTP/3 (QUIC)
			// ==========================================
			if slices.Contains(alpnList, "h3") {
				h3Ctx, h3Cancel := context.WithTimeout(parentCtx, 2*time.Second)
				qconf := &quic.Config{MaxIdleTimeout: 10 * time.Second}
				h3TlsConf := baseTlsConf.Clone()
				h3TlsConf.NextProtos = []string{"h3"}

				var probeH3Conn *quic.Conn
				probeH3Conn, certificateFingerprint, err = VerifyAndHandshakeQUIC(h3Ctx, cfg.ProxyAddr, h3TlsConf, qconf, cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint)
				h3Cancel()

				if err == nil {
					// 探测成功，立即关闭探测连接以释放 UDP 端口和 Goroutine（内存泄露核心修复）
					if probeH3Conn != nil {
						(*probeH3Conn).CloseWithError(0, "probe_done")
					}

					zlog.Infof("%s [Tunnel] 证书指纹: %s", TAG, certificateFingerprint)
					zlog.Infof("%s [Tunnel] ⚡ 探测成功: HTTP/3 (QUIC)", TAG)
					negotiatedProtocol = "h3"

					tr3 := &http3.Transport{
						TLSClientConfig: h3TlsConf,
						Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
							qc, _, err := VerifyAndHandshakeQUIC(ctx, addr, tlsCfg, quicCfg, cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint)
							return qc, err
						},
					}
					client = &http.Client{
						Transport: tr3,
						Timeout:   90 * time.Second,
					}

					// 必须在隧道关闭时释放 http3.Transport，否则将泄露大量 UDP Goroutine
					cleanupFuncs = append(cleanupFuncs, func() {
						tr3.Close()
					})
				} else if probeH3Conn != nil {
					// 探测失败但如果连接未关闭，必须清理
					(*probeH3Conn).CloseWithError(0, "probe_failed")
				}
			}

			// ==========================================
			// 2. TCP ALPN 探测 (h2 / http/1.1)
			// ==========================================
			if client == nil {
				var d net.Dialer
				tcpConn, err := d.DialContext(parentCtx, "tcp", cfg.ProxyAddr)
				if err != nil {
					return nil, fmt.Errorf("probe tcp failed: %w", err)
				}

				// 剔除 h3，准备 uTLS 握手
				tcpAlpns := slices.DeleteFunc(slices.Clone(alpnList), func(s string) bool { return s == "h3" })
				utlsConfig := &utls.Config{
					ServerName:         cfg.ServerName,
					InsecureSkipVerify: true,
					NextProtos:         tcpAlpns,
				}

				var uConn *utls.UConn
				uConn, negotiatedProtocol, certificateFingerprint, err = VerifyAndHandshakeUTLS(parentCtx, tcpConn, utlsConfig, tcpAlpns, cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint)

				zlog.Infof("%s [Tunnel] 证书指纹: %s", TAG, certificateFingerprint)
				zlog.Infof("%s [Tunnel] 探测到 TCP ALPN: %s", TAG, negotiatedProtocol)

				if err != nil {
					tcpConn.Close() // 握手失败时必须主动关闭底层 TCP 连接，防止 FD 泄露
					return nil, fmt.Errorf("utls verify&handshake failed: %w", err)
				}

				// 缓存探路连接 (Zero-Waste)
				cachedConn := net.Conn(uConn)
				var connConsumed atomic.Bool

				// 防止未被消费的探测连接永久泄露 (内存/FD泄露修复)
				cleanupFuncs = append(cleanupFuncs, func() {
					if !connConsumed.Load() && cachedConn != nil {
						cachedConn.Close()
					}
				})

				dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
					if connConsumed.CompareAndSwap(false, true) {
						return cachedConn, nil
					}

					tc, err := d.DialContext(ctx, "tcp", cfg.ProxyAddr)
					if err != nil {
						return nil, fmt.Errorf("dial proxy tcp failed: %w", err)
					}

					uc, np, cf, err := VerifyAndHandshakeUTLS(ctx, tc, utlsConfig, tcpAlpns, cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint)
					zlog.Infof("%s [Tunnel] 证书指纹: %s", TAG, cf)
					zlog.Infof("%s [Tunnel] 探测到 TCP ALPN: %s", TAG, np)

					if err != nil {
						tc.Close() // 握手失败时必须主动关闭底层 TCP 连接，防止 FD 泄露
						return nil, fmt.Errorf("utls verify&handshake failed: %w", err)
					}

					return uc, nil
				}

				if negotiatedProtocol == "h2" && slices.Contains(alpnList, "h2") {
					tr2 := &http2.Transport{
						DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
							return dialTLS(ctx, network, addr)
						},
					}
					client = &http.Client{
						Transport: tr2,
						Timeout:   90 * time.Second,
					}
					cleanupFuncs = append(cleanupFuncs, func() {
						tr2.CloseIdleConnections()
					})
				} else {
					tr1 := &http.Transport{
						DialTLSContext:  dialTLS,
						TLSClientConfig: baseTlsConf,
					}
					client = &http.Client{
						Transport: tr1,
						Timeout:   90 * time.Second,
					}
					cleanupFuncs = append(cleanupFuncs, func() {
						tr1.CloseIdleConnections()
					})
				}
			}
		} else {
			// ==========================================
			// 3. 纯 TCP 模式 (h2c 探测)
			// ==========================================
			dialTCP := func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", cfg.ProxyAddr)
			}
			if probeH2C(parentCtx, cfg.ProxyAddr) && slices.Contains(alpnList, "h2") {
				zlog.Infof("%s [Tunnel] ⚡ 探测成功，启用 H2C (明文 HTTP/2) 引擎", TAG)
				t2 := &http2.Transport{
					AllowHTTP: true,
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
						return dialTCP(ctx, network, addr)
					},
				}
				client = &http.Client{Transport: t2, Timeout: 90 * time.Second}
				cleanupFuncs = append(cleanupFuncs, func() {
					t2.CloseIdleConnections()
				})
			} else {
				zlog.Infof("%s [Tunnel] 🐢 H2C 探测失败，平滑回退至纯 TCP HTTP/1.1 引擎", TAG)
				t1 := &http.Transport{
					DialContext:           dialTCP,
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   100,
					MaxConnsPerHost:       100,
					IdleConnTimeout:       90 * time.Second,
					ExpectContinueTimeout: 5 * time.Second,
				}
				client = &http.Client{Transport: t1, Timeout: 90 * time.Second}
				cleanupFuncs = append(cleanupFuncs, func() {
					t1.CloseIdleConnections()
				})
			}
		}

		// 虚拟连接与数据泵初始化
		proxyNetAddr, _ := net.ResolveTCPAddr("tcp", cfg.ProxyAddr)
		var localNetAddr net.Addr
		if proxyNetAddr.IP.To4() != nil {
			// 远程是 IPv4
			localNetAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
		} else {
			// 远程是 IPv6
			localNetAddr = &net.TCPAddr{IP: net.IPv6zero, Port: 0}
		}
		ctx, cancel := context.WithCancel(parentCtx)
		virtualConn := newMeekVirtualConn(ctx, sessionID, localNetAddr, proxyNetAddr)

		// 数据泵核心逻辑
		go func() {
			defer virtualConn.Close()
			defer cancel()

			var ackedByServer, dispatchSeq uint64
			var windowMu sync.Mutex
			var consecutiveErrors, triggerRetry, emptyPollers int32
			workerCount := 8
			var wg sync.WaitGroup

			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					idleTimer := time.NewTimer(50 * time.Millisecond)
					if !idleTimer.Stop() {
						<-idleTimer.C // 抽干初始化的时间
					}
					for !virtualConn.closed && ctx.Err() == nil {
						// 抢占任务：从写缓冲中划走一段数据
						windowMu.Lock()
						currAck := atomic.LoadUint64(&ackedByServer)
						// 如果派发游标落后（重传重置），强制对齐
						if dispatchSeq < currAck {
							dispatchSeq = currAck
						}

						// GetSlice 实现了核心的滑动窗口
						upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(currAck, dispatchSeq, xhttpMaxsendBufSize)

						// 空载限流策略
						if len(upData) == 0 {
							// 如果没有上行数据，只允许最多 1 个 Worker 去服务端进行长轮询
							if atomic.LoadInt32(&emptyPollers) >= 1 {
								windowMu.Unlock()
								// 用 select 替代单纯的 Sleep，一旦隧道被关闭，能瞬间退出而不是傻等
								idleTimer.Reset(100 * time.Millisecond)
								select {
								case <-idleTimer.C:
									// 等待完成
								case <-ctx.Done():
									idleTimer.Stop() // 清理资源
									return
								}
								continue
							}
							atomic.AddInt32(&emptyPollers, 1) // 登记为一个空载探子
							dispatchSeq = currentSeq          // 对齐游标
						} else {
							dispatchSeq = currentSeq + uint64(len(upData))
						}
						windowMu.Unlock()

						// 构造请求
						var method string
						var bodyReader io.Reader
						if len(upData) > 0 {
							method = http.MethodPost
							bodyReader = bytes.NewReader(upData)
						} else {
							method = http.MethodGet
							bodyReader = http.NoBody
						}
						req, _ := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
						req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
						req.Host = cfg.CustomHost

						// GET 防缓存
						if len(upData) == 0 {
							q := req.URL.Query()
							q.Set("t", strconv.FormatInt(time.Now().UnixNano(), 36))
							req.URL.RawQuery = q.Encode()
							req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
						} else {
							req.ContentLength = int64(len(upData))
							req.Header.Set("Content-Type", "application/octet-stream")
						}

						// 注入控制头
						req.Header.Set("Host", cfg.CustomHost)
						req.Header.Set("X-Target", cfg.SshAddr)
						req.Header.Set("X-Network", "tcp")
						req.Header.Set("X-Session-ID", sessionID)
						// 注入 Seq 和 Ack 校验头
						req.Header.Set("X-Seq", strconv.FormatUint(currentSeq, 10))
						req.Header.Set("X-Ack", strconv.FormatUint(atomic.LoadUint64(&virtualConn.nextReadSeq), 10))
						req.Header.Set("Content-Type", "application/octet-stream")

						if cfg.ProxyAuthRequired {
							req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
						}

						// 消费并清除重传信号
						if atomic.CompareAndSwapInt32(&triggerRetry, 1, 0) {
							req.Header.Set("X-Retry", "1")
						}

						resp, err := client.Do(req)

						// 请求结束，注销空载探子身份
						if len(upData) == 0 {
							atomic.AddInt32(&emptyPollers, -1)
						}

						if err != nil {
							// 归还pool
							if upBufPtr != nil {
								xhttpBufPool.Put(upBufPtr) // 假设 xhttpBufPool 在全局可用
							}

							zlog.Errorf("%s [Tunnel] HTTP 请求失败 (Seq: %d): %v", TAG, currentSeq, err)

							// 若上下文被取消，直接退出
							if errors.Is(err, context.Canceled) {
								break
							}

							// 【并发核心策略】：一旦出错，重置派发游标到已确认点，触发重传
							windowMu.Lock()
							dispatchSeq = atomic.LoadUint64(&ackedByServer)
							windowMu.Unlock()

							// 激活重传求救信号，通知服务端也回退下行游标
							atomic.StoreInt32(&triggerRetry, 1)

							if atomic.AddInt32(&consecutiveErrors, 1) > 20 {
								zlog.Errorf("%s [Tunnel] 连续网络通信失败，触发熔断，销毁隧道: %s", TAG, cfg.SshAddr)
								break
							}

							idleTimer.Reset(300 * time.Millisecond)
							select {
							case <-idleTimer.C:
								// 等待完成
							case <-ctx.Done():
								idleTimer.Stop() // 清理资源
								return
							}
							continue
						}

						// 2. 处理响应头的 Ack，推进清理线
						if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" {
							sAck, _ := strconv.ParseUint(sAckStr, 10, 64)
							for {
								old := atomic.LoadUint64(&ackedByServer)
								if sAck <= old || atomic.CompareAndSwapUint64(&ackedByServer, old, sAck) {
									break
								}
							}
						}

						// 拦截非 200 OK 的异常状态码！
						if resp.StatusCode != http.StatusOK {
							if upBufPtr != nil {
								xhttpBufPool.Put(upBufPtr)
							}

							downBuf := bytesBufPool.Get().(*bytes.Buffer) // 假设 bytesBufPool 全局可用
							downBuf.Reset()
							downBuf.ReadFrom(resp.Body)
							bodyErr := downBuf.Bytes()
							resp.Body.Close()
							bytesBufPool.Put(downBuf)

							zlog.Errorf("%s [Tunnel] ❌ 收到异常 HTTP 状态码: %d, body: %s", TAG, resp.StatusCode, string(bodyErr))

							// 同样触发重传
							windowMu.Lock()
							dispatchSeq = atomic.LoadUint64(&ackedByServer)
							windowMu.Unlock()
							atomic.StoreInt32(&triggerRetry, 1)

							if atomic.AddInt32(&consecutiveErrors, 1) > 20 {
								zlog.Errorf("%s [Tunnel] 连续异常，触发熔断", TAG)
								break
							}

							idleTimer.Reset(1 * time.Second)
							select {
							case <-idleTimer.C:
								// 等待完成
							case <-ctx.Done():
								idleTimer.Stop() // 清理资源
								return
							}
							continue
						}

						atomic.StoreInt32(&consecutiveErrors, 0)

						// 3. 处理 Body (下行数据)
						sSeqStr := resp.Header.Get("X-Seq")
						sSeq, _ := strconv.ParseUint(sSeqStr, 10, 64)

						downBuf := bytesBufPool.Get().(*bytes.Buffer)
						downBuf.Reset()
						_, errBody := downBuf.ReadFrom(resp.Body) // 严格检查 body 错误
						downData := downBuf.Bytes()
						resp.Body.Close()

						// 严格校验下行数据的完整性
						if errBody != nil {
							bytesBufPool.Put(downBuf)
							if upBufPtr != nil {
								xhttpBufPool.Put(upBufPtr)
							}

							zlog.Warnf("%s [Tunnel] 读取下行 Body 失败，触发安全重传: %v", TAG, errBody)

							windowMu.Lock()
							dispatchSeq = atomic.LoadUint64(&ackedByServer)
							windowMu.Unlock()
							atomic.StoreInt32(&triggerRetry, 1)

							idleTimer.Reset(300 * time.Millisecond)
							select {
							case <-idleTimer.C:
								// 等待完成
							case <-ctx.Done():
								idleTimer.Stop() // 清理资源
								return
							}
							continue
						}

						// 将校验通过的数据注入读缓冲 (PutReadData 支持乱序)
						if len(downData) > 0 || sSeqStr != "" {
							virtualConn.PutReadData(sSeq, downData)
						}

						// 归还 pool
						bytesBufPool.Put(downBuf)
						if upBufPtr != nil {
							xhttpBufPool.Put(upBufPtr)
						}

						// 智能退避：如果双向都没有数据流动，才进行休眠
						if len(upData) == 0 && len(downData) == 0 && virtualConn.writeBuf.Len() == 0 {

							idleTimer.Reset(50 * time.Millisecond)
							select {
							case <-idleTimer.C:
								// 等待完成
							case <-ctx.Done():
								idleTimer.Stop() // 清理资源
								return
							}
						}
					}
				}()
			}
			wg.Wait()
		}()

		return newXhttpFramedConn(virtualConn, virtualConn, func() error {
			cancel()
			// 依次执行安全清理
			for _, cleanup := range cleanupFuncs {
				cleanup()
			}
			return virtualConn.Close()
		}, localNetAddr, proxyNetAddr), nil
	}

	// 注册 Tunnel
	RegisterTunnel("xhttpc", "none", func(ctx context.Context, cfg ProxyConfig, base net.Conn) (net.Conn, error) {
		alpnList := strings.Split(cfg.Alpn, ",")
		return xhttpHandler(ctx, cfg, base, false, alpnList)
	})
	RegisterTunnel("xhttp", "none", func(ctx context.Context, cfg ProxyConfig, base net.Conn) (net.Conn, error) {
		alpnList := strings.Split(cfg.Alpn, ",")
		return xhttpHandler(ctx, cfg, base, true, alpnList)
	})
}

// 辅助工具函数：原子更新最大值
func updateUint64IfGreater(addr *uint64, newVal uint64) {
	for {
		old := atomic.LoadUint64(addr)
		if newVal <= old || atomic.CompareAndSwapUint64(addr, old, newVal) {
			break
		}
	}
}

// 辅助工具函数：轻量级 H2C 嗅探
func probeH2C(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := conn.Write([]byte(preface)); err != nil {
		return false
	}

	buf := make([]byte, 9)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return buf[3] == 0x04 // SETTINGS frame type
}
