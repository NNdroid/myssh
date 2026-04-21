package myssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	maxsendBufSize = 900 * 1000 // 降低单次发送包的大小，避开 Nginx 1MB 拦截
	maxframeSize   = 990 * 1000
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
func (rb *reliableBuffer) GetSlice(remoteAck uint64, dispatchSeq uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// 1. 清理对端已经确认收到的数据
	if remoteAck > rb.baseOffset {
		skip := remoteAck - rb.baseOffset
		if skip <= uint64(len(rb.data)) {
			rb.data = rb.data[skip:]
			rb.baseOffset = remoteAck

			// 【惰性緊縮】：如果底層陣列膨脹超過 4MB 且空間浪費過半，才真正釋放記憶體
			if cap(rb.data) > 4*1024*1024 && len(rb.data) < cap(rb.data)/2 {
				newData := make([]byte, len(rb.data))
				copy(newData, rb.data)
				rb.data = newData
			}
		} else {
			rb.data = nil
			rb.baseOffset = remoteAck
		}
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

func newMeekVirtualConn(sessionID string, local, remote net.Addr) *meekVirtualConn {
	return &meekVirtualConn{
		sessionID: sessionID,
		local:     local,
		remote:    remote,
		readCond:  sync.NewCond(&sync.Mutex{}),
		writeBuf:  &reliableBuffer{},
		oooBuf:    make(map[uint64][]byte),
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
	// TCP 背壓限制 (Flow Control)
	// 防止本地端上傳過快導致記憶體暴漲 100MB+，限制積壓上限為 4MB
	for {
		if c.closed {
			return 0, io.ErrClosedPipe
		}
		if c.writeBuf.Len() < 4*1024*1024 {
			break
		}
		time.Sleep(5 * time.Millisecond) // 阻塞，強迫本地 VPN/代理 客戶端減速
	}
	return c.writeBuf.Write(p)
}

// PutReadData 乱序重组
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	if len(data) > 0 {
		if seq == c.nextReadSeq {
			// 1. 序號正好匹配，寫入緩衝區
			c.readBuf.Write(data)
			c.nextReadSeq += uint64(len(data))

			// 2. 檢查暫存區有沒有「未來的包」現在可以接上了
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
			// 3. 序號太新了，先存進 map
			if len(c.oooBuf) < 1024 { // 防止惡意內存撐爆
				// 因为外层使用了 bytesBufPool，这里必须分配独立内存拷贝！
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

type xhttpFramedConn struct {
	r             io.Reader
	w             io.Writer
	closer        func() error
	local         net.Addr
	remote        net.Addr
	mu            sync.Mutex
	readBuf       []byte
	frameBuf      []byte
	hdrBuf        []byte
	payloadBuf    []byte
	closeCh       chan struct{}
	closedFlag    int32
	lastWriteTime int64
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	conn := &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		frameBuf: make([]byte, maxframeSize), hdrBuf: make([]byte, 6), payloadBuf: make([]byte, maxsendBufSize),
		closeCh:       make(chan struct{}),
		lastWriteTime: time.Now().Unix(),
	}
	go conn.heartbeatLoop()
	return conn
}

func (c *xhttpFramedConn) heartbeatLoop() {
	// 巡逻周期设为 5 秒（不用频繁唤醒），但判断阈值依然是 20 秒
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// 获取上次真实发送数据的时间
			last := atomic.LoadInt64(&c.lastWriteTime)

			// 如果距离上次发包已经过去了 20 秒，说明连接处于绝对空闲状态
			if time.Now().Unix()-last >= 20 {
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
	atomic.StoreInt64(&c.lastWriteTime, time.Now().Unix())
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

				_, err := quic.DialAddr(h3Ctx, cfg.ProxyAddr, h3TlsConf, qconf)
				h3Cancel()

				if err == nil {
					zlog.Infof("%s [Tunnel] ⚡ 探测成功: HTTP/3 (QUIC)", TAG)
					negotiatedProtocol = "h3"
					client = &http.Client{
						// 🌟 必须注入 TLSClientConfig，否则会报 IP SANs 校验错误
						Transport: &http3.Transport{
							TLSClientConfig: h3TlsConf,
						},
						Timeout: 90 * time.Second,
					}
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

				uConn := utls.UClient(tcpConn, utlsConfig, utls.HelloChrome_Auto)
				if err := uConn.HandshakeContext(parentCtx); err != nil {
					tcpConn.Close()
					return nil, fmt.Errorf("utls handshake failed: %w", err)
				}

				negotiatedProtocol = uConn.ConnectionState().NegotiatedProtocol
				zlog.Infof("%s [Tunnel] 探测到 TCP ALPN: %s", TAG, negotiatedProtocol)

				// 缓存探路连接 (Zero-Waste)
				cachedConn := net.Conn(uConn)
				var connOnce sync.Once
				dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
					var c net.Conn
					var isReused bool
					connOnce.Do(func() { c = cachedConn; isReused = true })
					if isReused {
						return c, nil
					}
					tc, err := d.DialContext(ctx, "tcp", cfg.ProxyAddr)
					if err != nil {
						return nil, err
					}
					uc := utls.UClient(tc, utlsConfig, utls.HelloChrome_Auto)
					return uc, uc.HandshakeContext(ctx)
				}

				if negotiatedProtocol == "h2" {
					client = &http.Client{
						Transport: &http2.Transport{
							DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
								return dialTLS(ctx, network, addr)
							},
						},
						Timeout: 90 * time.Second,
					}
				} else {
					client = &http.Client{
						Transport: &http.Transport{
							DialTLSContext:  dialTLS,
							TLSClientConfig: baseTlsConf,
						},
						Timeout: 90 * time.Second,
					}
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
			if probeH2C(parentCtx, cfg.ProxyAddr) {
				zlog.Infof("%s [Tunnel] ⚡ 探测成功，启用 H2C (明文 HTTP/2) 引擎", TAG)
				t2 := &http2.Transport{
					AllowHTTP: true,
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
						return dialTCP(ctx, network, addr)
					},
				}
				client = &http.Client{Transport: t2, Timeout: 90 * time.Second}
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
		virtualConn := newMeekVirtualConn(sessionID, localNetAddr, proxyNetAddr)
		ctx, cancel := context.WithCancel(parentCtx)

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
					for !virtualConn.closed && ctx.Err() == nil {
						// 抢占任务：从写缓冲中划走一段数据
						windowMu.Lock()
						currAck := atomic.LoadUint64(&ackedByServer)
						// 如果派发游标落后（重传重置），强制对齐
						if dispatchSeq < currAck {
							dispatchSeq = currAck
						}

						// GetSlice 实现了核心的滑动窗口
						upData, currentSeq, upBufPtr := virtualConn.writeBuf.GetSlice(currAck, dispatchSeq, maxsendBufSize)

						// 空载限流策略：最多 2 个 Worker 保持长轮询
						if len(upData) == 0 {
							// 如果没有上行数据，只允许最多 2 个 Worker 去服务端进行长轮询
							if atomic.LoadInt32(&emptyPollers) >= 2 {
								windowMu.Unlock()
								time.Sleep(100 * time.Millisecond) // 其他 Worker 本地待命，不发 HTTP 请求
								continue
							}
							atomic.AddInt32(&emptyPollers, 1) // 登记为一个空载探子
							dispatchSeq = currentSeq          // 对齐游标
						} else {
							dispatchSeq = currentSeq + uint64(len(upData))
						}
						windowMu.Unlock()

						// 构造请求
						req, _ := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(upData))
						req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
						req.ContentLength = int64(len(upData))
						req.Host = cfg.CustomHost

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

							time.Sleep(300 * time.Millisecond)
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

							time.Sleep(1 * time.Second)
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
							time.Sleep(300 * time.Millisecond)
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
							time.Sleep(50 * time.Millisecond) // 可以稍微设短一点
						}
					}
				}()
			}
			wg.Wait()
		}()

		return newXhttpFramedConn(virtualConn, virtualConn, func() error {
			cancel()
			return virtualConn.Close()
		}, localNetAddr, proxyNetAddr), nil
	}

	// 注册 Tunnel
	RegisterTunnel("xhttpc", "none", func(ctx context.Context, cfg ProxyConfig, base net.Conn) (net.Conn, error) {
		return xhttpHandler(ctx, cfg, base, false, nil)
	})
	RegisterTunnel("xhttp", "none", func(ctx context.Context, cfg ProxyConfig, base net.Conn) (net.Conn, error) {
		return xhttpHandler(ctx, cfg, base, true, nil)
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
