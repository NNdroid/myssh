package myssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	maxsendBufSize = 900 * 1000
	maxframeSize = 990 * 1000
	padPoolLen = 64 * 1024
)

// ==========================================
// 1. 高性能可靠传输缓冲区 (Seq/Ack 机制)
// ==========================================

type reliableBuffer struct {
	mu         sync.RWMutex
	data       []byte // 原始数据缓冲区
	baseOffset uint64 // 当前 data[0] 对应的绝对偏移量 (Seq)
}

func (rb *reliableBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.data = append(rb.data, p...)
	return len(p), nil
}

// GetSlice 获取从指定偏移量开始的数据，并清理掉已被对端确认 (Ack) 的旧数据
func (rb *reliableBuffer) GetSlice(remoteAck uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// 1. 清理对端已经确认收到的数据
	if remoteAck > rb.baseOffset {
		skip := remoteAck - rb.baseOffset
		if skip <= uint64(len(rb.data)) {
			remain := uint64(len(rb.data)) - skip
			if remain == 0 {
				rb.data = nil // 释放底层数组
			} else {
				// 新建一个恰好大小的数组，彻底抛弃原来可能高达几十 MB 的底层旧数组
				newData := make([]byte, remain)
				copy(newData, rb.data[skip:])
				rb.data = newData
			}
			rb.baseOffset = remoteAck
		} else {
			rb.data = nil
			rb.baseOffset = remoteAck
		}
	}

	// 2. 如果没新数据发，返回空
	if len(rb.data) == 0 {
		return nil, rb.baseOffset, nil
	}

	// 3. 截取分片
	length := len(rb.data)
	if length > maxLen {
		length = maxLen
	}

	// 高性能拷贝：防止重传时底层 Transport 竞态修改切片
	bufPtr := tcpBufPool.Get().(*[]byte)
	res := (*bufPtr)[:length]
	copy(res, rb.data[:length])
	return res, rb.baseOffset, bufPtr
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
	sessionID   string
	local       net.Addr
	remote      net.Addr
	
	readCond    *sync.Cond
	readBuf     bytes.Buffer
	nextReadSeq uint64 // 我方期待收到的下一个 Seq
	
	writeBuf    *reliableBuffer // 替换原有的 bytes.Buffer 和 mutex
	
	closed      bool
}

func newMeekVirtualConn(sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		sessionID: sessionID,
		local:     local,
		remote:    remote,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeBuf:  &reliableBuffer{},
	}
}

func (c *meekVirtualConn) Read(p []byte) (int, error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	for c.readBuf.Len() == 0 && !c.closed {
		c.readCond.Wait()
	}
	if c.closed && c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *meekVirtualConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.writeBuf.Write(p)
}

// PutReadData 带有 Seq 校验的写入逻辑 (防止重传导致的数据重复)
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	// 严格按序接收：丢弃重传产生的重复包
	if seq == c.nextReadSeq && len(data) > 0 {
		c.readBuf.Write(data)
		c.nextReadSeq += uint64(len(data))
		c.readCond.Broadcast()
	}
	return c.nextReadSeq
}

func (c *meekVirtualConn) Close() error {
	c.readCond.L.Lock()
	c.closed = true
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
var padPool []byte

type xhttpFramedConn struct {
	r          io.Reader
	w          io.Writer
	closer     func() error
	local      net.Addr
	remote     net.Addr
	mu         sync.Mutex
	readBuf    []byte
	frameBuf   []byte
	hdrBuf     []byte
	payloadBuf []byte
	closeCh    chan struct{}
	closedFlag int32
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	conn := &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		frameBuf: make([]byte, maxframeSize), hdrBuf: make([]byte, 6), payloadBuf: make([]byte, maxsendBufSize),
		closeCh: make(chan struct{}),
	}
	go conn.heartbeatLoop()
	return conn
}

func (c *xhttpFramedConn) heartbeatLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.Write(nil)
		case <-c.closeCh:
			return
		}
	}
}

func (c *xhttpFramedConn) writeSingleFrame(chunk []byte) error {
	chunkSize := len(chunk)
	var padLenInt int
	if chunkSize == 0 {
		padLenInt = 32 + mrand.Intn(128)
	} else if chunkSize < 512 {
		padLenInt = (600 + mrand.Intn(600)) - chunkSize
		if padLenInt < 0 {
			padLenInt = mrand.Intn(256)
		}
	} else {
		padLenInt = 16 + mrand.Intn(112)
	}

	frameLen := 6 + padLenInt + chunkSize
	// 判断底层数组容量(cap)是否足够
	if frameLen > cap(c.frameBuf) {
		// 如果不够，采用 2 倍扩容策略，避免频繁 make
		newCap := cap(c.frameBuf) * 2
		if newCap < frameLen {
			newCap = frameLen
		}
		c.frameBuf = make([]byte, frameLen, newCap)
	} else {
		// 容量足够时，直接拉伸Slice
		c.frameBuf = c.frameBuf[:frameLen] 
	}

	// 写入 Header
	binary.BigEndian.PutUint32(c.frameBuf[0:4], uint32(chunkSize))
	binary.BigEndian.PutUint16(c.frameBuf[4:6], uint16(padLenInt))

	// 极速 Padding 填充
	if padLenInt > 0 {
		offset := mrand.Intn(padPoolLen - padLenInt)
		copy(c.frameBuf[6:6+padLenInt], padPool[offset:offset+padLenInt])
	}

	// 写入 Payload
	if chunkSize > 0 {
		copy(c.frameBuf[6+padLenInt:], chunk)
	}

	// 单次系统调用发出
	_, err := c.w.Write(c.frameBuf)
	return err
}

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, c.writeSingleFrame(nil)
	}

	written := 0
	maxPayload := maxframeSize
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
	if len(c.readBuf) > 0 {// 没有len信息，所以readBuf有就直接返回
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

		// 直接复用 c.payloadBuf 当作“垃圾桶”来接收 padding
		if padLen > 0 {
			if padLen > cap(c.payloadBuf) {
				c.payloadBuf = make([]byte, padLen)
			}
			if _, err := io.ReadFull(c.r, c.payloadBuf[:padLen]); err != nil {
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
			// 使用 cap 而不是 len 来判断，最大程度减少 make() 重新分配内存的次数
			if leftover > cap(c.payloadBuf) {
				c.payloadBuf = make([]byte, leftover)
			}
			leftoverBuf := c.payloadBuf[:leftover]
			
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

// ==========================================
// 4. Android 核心握手逻辑与注册
// ==========================================

func init() {
	// 随机填充池初始化
	padPool = make([]byte, padPoolLen)
	io.ReadFull(rand.Reader, padPool)

	xhttpHandler := func(cfg ProxyConfig, baseConn net.Conn, isTLS bool) (net.Conn, error) {
		scheme := "http"
		protoName := "XHTTPC"
		if isTLS {
			scheme = "https"
			protoName = "XHTTP"
		}

		zlog.Infof("%s [Tunnel] 2. 准备进行 %s 隧道握手, 伪装 Host: %s", TAG, protoName, cfg.CustomHost)

		var activeConn net.Conn = baseConn
		var negotiatedProtocol = "http/1.1"

		if isTLS {
			utlsConfig := &utls.Config{
				ServerName:         cfg.ServerName,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
			}
			uConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
			if err := uConn.Handshake(); err != nil {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ %s uTLS 握手失败: %v", TAG, protoName, err)
				return nil, err
			}
			activeConn = uConn
			negotiatedProtocol = uConn.ConnectionState().NegotiatedProtocol
		}

		zlog.Infof("%s [Tunnel] ✅ %s 底层握手成功 (协议: %s)", TAG, protoName, negotiatedProtocol)

		path := cfg.CustomPath
		if path == "" {
			path = "/stream"
		}
		reqURL := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)
		sessionID := generateRandomHex(16)

		var connUsed int32
		dialerFunc := func() (net.Conn, error) {
			if atomic.SwapInt32(&connUsed, 1) == 0 {
				return activeConn, nil
			}
			return nil, fmt.Errorf("physical connection exhausted")
		}

		var rt http.RoundTripper
		if negotiatedProtocol == "h2" {
			rt = &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
					return dialerFunc()
				},
			}
		} else {
			t1 := &http.Transport{ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 1, DisableKeepAlives: false}
			if isTLS {
				t1.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialerFunc() }
			} else {
				t1.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialerFunc() }
			}
			rt = t1
		}

		client := &http.Client{Transport: rt, Timeout: 30 * time.Second}
		virtualConn := newMeekVirtualConn(sessionID, activeConn.LocalAddr(), activeConn.RemoteAddr())

		// =====================================
		// 数据泵：带有滑动窗口 ARQ 的稳态轮询
		// =====================================
		go func() {
			defer virtualConn.Close()
			defer activeConn.Close() 

			var ackedByServer uint64
			consecutiveErrors := 0

			for !virtualConn.closed {
				// 依靠服务端的 Ack 来推进滑动窗口，安全取出需要发送或重传的切片
				upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(ackedByServer, 60000)//maxsendBufSize

				req, _ := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(upData))
				req.ContentLength = int64(len(upData))

				req.Host = cfg.CustomHost
				req.Header.Set("Host", cfg.CustomHost)
				req.Header.Set("X-Target", cfg.SshAddr)
				req.Header.Set("X-Network", "tcp")
				req.Header.Set("X-Session-ID", sessionID)
				
				// 注入 Seq 和 Ack 校验头
				req.Header.Set("X-Seq", strconv.FormatUint(currentSeq, 10))
				virtualConn.readCond.L.Lock()
				myAck := virtualConn.nextReadSeq
				virtualConn.readCond.L.Unlock()
				req.Header.Set("X-Ack", strconv.FormatUint(myAck, 10))
				
				req.Header.Set("Content-Type", "application/octet-stream")
				if cfg.ProxyAuthRequired {
					req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
				}

				resp, err := client.Do(req)

				if err != nil {
					// 归还pool
					if upBufPtr != nil {
						tcpBufPool.Put(upBufPtr)
					}
					// 不需要再手动执行 putWriteBufFront！
					// 由于 ackedByServer 没有推进，下一轮 GetSlice 会自动切割出原数据进行无缝重传。
					
					consecutiveErrors++
					if consecutiveErrors > 5 {
						zlog.Errorf("%s [Tunnel] 连续 5 次网络通信失败，触发熔断，销毁隧道: %s", TAG, cfg.SshAddr)
						break
					}

					time.Sleep(500 * time.Millisecond)
					continue
				}
				
				// 拦截非 200 OK 的异常状态码！
				if resp.StatusCode != http.StatusOK {
					if upBufPtr != nil {
						tcpBufPool.Put(upBufPtr)
					}
					
					downBuf := bytesBufPool.Get().(*bytes.Buffer)
					downBuf.Reset()
					downBuf.ReadFrom(resp.Body)
					bodyErr := downBuf.Bytes()
					resp.Body.Close()
					bytesBufPool.Put(downBuf)
					
					zlog.Errorf("%s [Tunnel] ❌ 收到异常 HTTP 状态码: %d, body: %s", TAG, resp.StatusCode, string(bodyErr))
					
					consecutiveErrors++
					if consecutiveErrors > 5 {
						zlog.Errorf("%s [Tunnel] 连续异常，触发熔断", TAG)
						break
					}
					
					time.Sleep(2 * time.Second) 
					continue
				}

				consecutiveErrors = 0

				// 解析服务端发来的 Ack，推进我们的发送窗口
				if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" {
					sAck, _ := strconv.ParseUint(sAckStr, 10, 64)
					if sAck > ackedByServer {
						ackedByServer = sAck
					}
				}

				// 解析服务端的数据 Seq
				sSeqStr := resp.Header.Get("X-Seq")
				sSeq, _ := strconv.ParseUint(sSeqStr, 10, 64)

				downBuf := bytesBufPool.Get().(*bytes.Buffer)
				downBuf.Reset()
				downBuf.ReadFrom(resp.Body)
				downData := downBuf.Bytes()
				resp.Body.Close()

				// 将校验通过的数据注入读缓冲
				if len(downData) > 0 || sSeqStr != "" {
					virtualConn.PutReadData(sSeq, downData)
				}
				
				// 归还 pool
				bytesBufPool.Put(downBuf)
				if upBufPtr != nil {
					tcpBufPool.Put(upBufPtr)
				}

				// 智能退避：如果双向都没有数据流动，才进行休眠
				if len(upData) == 0 && len(downData) == 0 && virtualConn.writeBuf.Len() == 0 {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()

		return newXhttpFramedConn(virtualConn, virtualConn, func() error {
			virtualConn.Close()
			return activeConn.Close()
		}, activeConn.LocalAddr(), activeConn.RemoteAddr()), nil
	}

	RegisterTunnel("xhttpc", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return xhttpHandler(cfg, baseConn, false)
	})
	RegisterTunnel("xhttp", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return xhttpHandler(cfg, baseConn, true)
	})
}