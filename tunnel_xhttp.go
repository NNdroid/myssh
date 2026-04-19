package myssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ==========================================
// 1. Meek 虚拟连接 (带数据抢救引擎)
// ==========================================

type meekVirtualConn struct {
	sessionID  string
	local      net.Addr
	remote     net.Addr
	readCond   *sync.Cond
	readBuf    bytes.Buffer
	writeMutex sync.Mutex
	writeBuf   bytes.Buffer
	closed     bool
}

func newMeekVirtualConn(sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		sessionID: sessionID,
		local:     local,
		remote:    remote,
		readCond:  sync.NewCond(&sync.Mutex{}),
	}
}

func (c *meekVirtualConn) Read(p []byte) (int, error) {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()
	for c.readBuf.Len() == 0 && !c.closed {
		c.readCond.Wait()
	}
	if c.closed && c.readBuf.Len() == 0 { return 0, io.EOF }
	return c.readBuf.Read(p)
}

func (c *meekVirtualConn) Write(p []byte) (int, error) {
	if c.closed { return 0, io.ErrClosedPipe }
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeBuf.Write(p)
}

func (c *meekVirtualConn) HasWriteData() bool {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeBuf.Len() > 0
}

func (c *meekVirtualConn) takeWriteBuf(max int) []byte {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBuf.Len() == 0 { return nil }
	takeLen := c.writeBuf.Len()
	if takeLen > max { takeLen = max }
	data := make([]byte, takeLen)
	c.writeBuf.Read(data)
	return data
}

// 核心特性：数据抢救！将发送失败的数据塞回队列头部，实现 0 丢包
func (c *meekVirtualConn) putWriteBufFront(data []byte) {
	if len(data) == 0 { return }
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	newData := make([]byte, len(data)+c.writeBuf.Len())
	copy(newData, data)
	copy(newData[len(data):], c.writeBuf.Bytes())
	c.writeBuf = *bytes.NewBuffer(newData)
}

func (c *meekVirtualConn) putReadBuf(data []byte) {
	if len(data) == 0 { return }
	c.readCond.L.Lock()
	c.readBuf.Write(data)
	c.readCond.Broadcast()
	c.readCond.L.Unlock()
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
// 2. 动态 Padding 与 0xFFFF 信令装甲
// ==========================================

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
		frameBuf: make([]byte, 32768), hdrBuf: make([]byte, 4), payloadBuf: make([]byte, 16384),
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
		if padLenInt < 0 { padLenInt = mrand.Intn(256) }
	} else {
		padLenInt = 16 + mrand.Intn(112)
	}

	frameLen := 4 + padLenInt + chunkSize
	if frameLen > len(c.frameBuf) { c.frameBuf = make([]byte, frameLen) }
	frame := c.frameBuf[:frameLen]

	binary.BigEndian.PutUint16(frame[0:2], uint16(chunkSize))
	binary.BigEndian.PutUint16(frame[2:4], uint16(padLenInt))
	if padLenInt > 0 { io.ReadFull(rand.Reader, frame[4:4+padLenInt]) }
	if chunkSize > 0 { copy(frame[4+padLenInt:], chunk) }

	_, err := c.w.Write(frame)
	return err
}

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 { return 0, c.writeSingleFrame(nil) }

	written := 0
	maxPayload := 16384
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPayload { chunkSize = maxPayload }
		chunk := p[:chunkSize]
		p = p[chunkSize:]
		if err := c.writeSingleFrame(chunk); err != nil { return written, err }
		written += chunkSize
	}
	return written, nil
}

func (c *xhttpFramedConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		if _, err := io.ReadFull(c.r, c.hdrBuf); err != nil { return 0, err }
		payloadLen := int(binary.BigEndian.Uint16(c.hdrBuf[0:2]))
		padLen := int(binary.BigEndian.Uint16(c.hdrBuf[2:4]))
		
		if padLen > 0 { if _, err := io.CopyN(io.Discard, c.r, int64(padLen)); err != nil { return 0, err } }
		
		if payloadLen == 0xFFFF {
			return 0, io.EOF // 截获远端 0xFFFF 信令，立即切断上传通道
		}
		if payloadLen == 0 { continue }

		if payloadLen > len(c.payloadBuf) { c.payloadBuf = make([]byte, payloadLen) }
		payload := c.payloadBuf[:payloadLen]
		if _, err := io.ReadFull(c.r, payload); err != nil { return 0, err }

		n := copy(p, payload)
		if n < payloadLen { c.readBuf = payload[n:] }
		return n, nil
	}
}

// 主动释放连接时，下发 0xFFFF 魔术帧
func (c *xhttpFramedConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closedFlag, 0, 1) {
		c.mu.Lock()
		frame := make([]byte, 4)
		binary.BigEndian.PutUint16(frame[0:2], 0xFFFF)
		binary.BigEndian.PutUint16(frame[2:4], 0)
		c.w.Write(frame) // 尽力发送，不论成功与否
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
	return fmt.Sprintf("%x", b)
}

// ==========================================
// 3. Android 核心握手逻辑与注册
// ==========================================

func init() {
	xhttpHandler := func(cfg ProxyConfig, baseConn net.Conn, isTLS bool) (net.Conn, error) {
		scheme := "http"
		protoName := "XHTTPC"
		if isTLS {
			scheme = "https"
			protoName = "XHTTP"
		}

		zlog.Infof("%s [Tunnel] 2. 准备进行 %s 隧道握手, 伪装 Host: %s", TAG, protoName, cfg.CustomHost)

		// 1. 初始化物理层
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

		// 2. 组装 Transport 与 URL
		path := cfg.CustomPath
		if path == "" { path = "/stream" }
		reqURL := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)
		sessionID := generateRandomHex(16)

		// 核心保护机制：确保 baseConn 只能被使用一次。
		// 如果 HTTP Client 尝试再次拨号（比如物理连接断开重试），拒绝之，并交给 Android VPN 框架重连。
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
			t1 := &http.Transport{ ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 1, DisableKeepAlives: false }
			if isTLS {
				t1.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialerFunc() }
			} else {
				t1.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialerFunc() }
			}
			rt = t1
		}
		
		// Timeout 设置为稍长，具体依靠自定义的数据泵进行控制
		client := &http.Client{Transport: rt, Timeout: 30 * time.Second}
		virtualConn := newMeekVirtualConn(sessionID, activeConn.LocalAddr(), activeConn.RemoteAddr())

		// =====================================
		// 3. 数据泵：极速稳态轮询 + Android 熔断器
		// =====================================
		go func() {
			defer virtualConn.Close()
			defer activeConn.Close() // 当发生错误退出时，强杀物理连接，向上传递 EOF 让 tun2socks 重连

			consecutiveErrors := 0 

			for !virtualConn.closed {
				upData := virtualConn.takeWriteBuf(32768)

				req, _ := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(upData))
				req.ContentLength = int64(len(upData))

				req.Host = cfg.CustomHost
				req.Header.Set("Host", cfg.CustomHost)
				req.Header.Set("X-Target", cfg.SshAddr) // 核心路由信息
				req.Header.Set("X-Network", "tcp")
				req.Header.Set("X-Session-ID", sessionID)
				req.Header.Set("Content-Type", "application/octet-stream")
				if cfg.ProxyAuthRequired {
					req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
				}

				resp, err := client.Do(req)

				if err != nil {
					// 【核心：数据抢救】
					if len(upData) > 0 { virtualConn.putWriteBufFront(upData) }

					// 【核心：熔断保护 Fail-Fast】
					consecutiveErrors++
					if consecutiveErrors > 5 {
						zlog.Errorf("%s [Tunnel] 连续 5 次网络通信失败，触发熔断，销毁隧道: %s", TAG, cfg.SshAddr)
						break // 直接退出循环
					}
					
					time.Sleep(500 * time.Millisecond)
					continue
				}

				consecutiveErrors = 0

				downData, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if len(downData) > 0 { virtualConn.putReadBuf(downData) }

				// 极速稳态轮询：如果隧道双向空闲，短暂休眠
				if len(upData) == 0 && len(downData) == 0 && !virtualConn.HasWriteData() {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()

		// 返回被包装保护好的连接给框架层
		return newXhttpFramedConn(virtualConn, virtualConn, func() error {
			virtualConn.Close()
			return activeConn.Close()
		}, activeConn.LocalAddr(), activeConn.RemoteAddr()), nil
	}

	// 统一注册：提供明文版(xhttpc)和TLS版(xhttp)
	RegisterTunnel("xhttpc", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return xhttpHandler(cfg, baseConn, false)
	})
	RegisterTunnel("xhttp", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return xhttpHandler(cfg, baseConn, true)
	})
}