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

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	xhttpHeaderSize     = 6     //  info  6 bytes (4bytes info  + 2bytesPadding info )
	xhttpMaxPaddingSize = 65535 //  info  padding
)

var (
	xhttpMaxsendBufSize = 512 * 1000 //  info send info ， info  Nginx 1MB  info
	xhttpMaxframeSize   = xhttpMaxsendBufSize + xhttpMaxPaddingSize + xhttpHeaderSize
)

// ==========================================
//  info  BufPool  info （ info ）
// ==========================================

// boundedBufPool  info  sync.Pool  info ， info  channel  info
//
//	info  *[]byte  info ， info 。
//
//	info ：
//	 - channel  info " info "：Put  info  channel  info ， info discarded（ info  GC  info ）。
//	 - Get  info  channel  info ； info  channel  info ， info  newFn  info 。
//	 -  info  sync.Pool  info  GC  info ， info 。
//
// maxIdle： info  *[]byte（ info discarded info  GC）。
// maxCapBytes： info  *[]byte  info ； info " info " info ， info discarded。
type boundedBufPool struct {
	pool       sync.Pool
	tokens     chan struct{} //  info ， info  = maxIdle
	maxCapByte int           //  info  buf  info  cap（bytes）
}

func newBoundedBufPool(maxIdle int, maxCapBytes int, newBufSize int) *boundedBufPool {
	p := &boundedBufPool{
		tokens:     make(chan struct{}, maxIdle),
		maxCapByte: maxCapBytes,
	}
	p.pool.New = func() any {
		b := make([]byte, 0, newBufSize)
		return &b
	}
	return p
}

// Get  info  *[]byte（ info  0）。
func (p *boundedBufPool) Get() *[]byte {
	select {
	case <-p.tokens:
		//  info ： info  sync.Pool  info （ info  Put  info ）
		bp := p.pool.Get().(*[]byte)
		*bp = (*bp)[:0]
		return bp
	default:
		//  info ， info ， info
		bp := p.pool.New().(*[]byte)
		*bp = (*bp)[:0]
		return bp
	}
}

// Put  info  *[]byte  info 。 info ， info discarded。
func (p *boundedBufPool) Put(bp *[]byte) {
	if bp == nil || *bp == nil || cap(*bp) == 0 {
		return
	}
	if cap(*bp) > p.maxCapByte {
		return //  info ，discarded info  GC  info
	}
	*bp = (*bp)[:0]
	select {
	case p.tokens <- struct{}{}:
		p.pool.Put(bp)
	default:
		//  info ，discarded
	}
}

// ==========================================
//  info  Pool  info
// ==========================================

// xhttpFrameBufPool  info （frame buf） info uplink info （up buf）。
//
//	info  init()  info completed info （ info  xhttpMaxframeSize  info ）。
//
// maxIdle=64： info  64  info  buf（ info  64 × ~577 KB ≈ 36 MB  info ）。
// maxCapBytes = xhttpMaxframeSize × 2： info  GC， info 。
var xhttpFrameBufPool *boundedBufPool

func init() {
	xhttpFrameBufPool = newBoundedBufPool(64, xhttpMaxframeSize*2, xhttpMaxframeSize)
}

// getBufFromPool  info  boundedBufPool  info  *[]byte
func getBufFromPool(pool *boundedBufPool) *[]byte {
	return pool.Get()
}

// safelyPutBuf  info  *[]byte  info  boundedBufPool（ info ）
func safelyPutBuf(pool *boundedBufPool, bp *[]byte) {
	if bp == nil {
		return
	}
	pool.Put(bp)
}

// getDownBuf  info  *bytes.Buffer
func getDownBuf() *bytes.Buffer {
	// downBufPool  info  *bytes.Buffer（ info  []byte）
	//  info  sync.Pool  info ，boundedBufPool  info  *[]byte
	//  info  downBuf  info  bytesBufPool  info ， info
	buf := bytesBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func putDownBuf(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	if buf.Cap() <= 2*1024*1024 {
		bytesBufPool.Put(buf)
	}
	//  info discarded
}

// ==========================================
//  info  (Seq/Ack  info )
// ==========================================

type reliableBuffer struct {
	mu         sync.RWMutex
	cond       *sync.Cond
	data       []byte
	baseOffset uint64
	maxSize    int
	closed     bool
}

func newReliableBuffer(maxSize int) *reliableBuffer {
	if maxSize == 0 {
		maxSize = 4 * 1024 * 1024 // default 4MB
	}
	rb := &reliableBuffer{maxSize: maxSize}
	rb.cond = sync.NewCond(&rb.mu)
	return rb
}

func (rb *reliableBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	//  info ， info
	const hardMax = 8 * 1024 * 1024
	if len(rb.data) >= hardMax && !rb.closed {
		zlog.Warnf("[reliableBuffer] Buffer reaching hard limit (%d bytes), waiting...", len(rb.data))
	}

	for len(rb.data) >= rb.maxSize && !rb.closed {
		rb.cond.Wait()
	}

	if rb.closed {
		return 0, io.ErrClosedPipe
	}

	// grow  info ： info  append  info  realloc
	needed := len(rb.data) + len(p)
	if cap(rb.data) < needed {
		newCap := needed
		if newCap < 64*1024 {
			newCap = 64 * 1024
		} else if newCap > 2*1024*1024 {
			newCap = (needed + 1024*1024) & ^(1024*1024 - 1) //  info  1MB
		}
		newData := make([]byte, len(rb.data), newCap)
		copy(newData, rb.data)
		rb.data = newData
	}

	rb.data = append(rb.data, p...)
	return len(p), nil
}

// GetSlice  info ， info cleanup info  (Ack)  info 。
//
//	info  []byte  info  xhttpFrameBufPool  info ， info  safelyPutBuf  info 。
func (rb *reliableBuffer) GetSlice(remoteAck uint64, dispatchSeq uint64, maxLen int) ([]byte, uint64, *[]byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// cleanup info
	if remoteAck > rb.baseOffset {
		skip := remoteAck - rb.baseOffset
		if skip <= uint64(len(rb.data)) {
			rb.data = rb.data[skip:]
			rb.baseOffset = remoteAck
			//  info ： info  2MB  info
			if cap(rb.data) > 2*1024*1024 && len(rb.data) < cap(rb.data)/2 {
				newData := make([]byte, len(rb.data))
				copy(newData, rb.data)
				rb.data = newData
			}
		} else {
			rb.data = nil
			rb.baseOffset = remoteAck
		}
		rb.cond.Broadcast()
	}

	if dispatchSeq < rb.baseOffset {
		dispatchSeq = rb.baseOffset
	}

	offsetInBuf := dispatchSeq - rb.baseOffset
	if offsetInBuf >= uint64(len(rb.data)) {
		return nil, dispatchSeq, nil
	}

	availLen := uint64(len(rb.data)) - offsetInBuf
	length := int(availLen)
	if length > maxLen {
		length = maxLen
	}

	//  info  Pool  info
	bufPtr := xhttpFrameBufPool.Get()
	if cap(*bufPtr) < length {
		newCap := length
		if newCap < xhttpMaxframeSize {
			newCap = xhttpMaxframeSize
		}
		*bufPtr = make([]byte, length, newCap)
	} else {
		*bufPtr = (*bufPtr)[:length]
	}

	copy(*bufPtr, rb.data[offsetInBuf:offsetInBuf+uint64(length)])
	return *bufPtr, dispatchSeq, bufPtr
}

func (rb *reliableBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.data)
}

func (rb *reliableBuffer) Close() {
	rb.cond.L.Lock()
	rb.closed = true
	rb.cond.Broadcast()
	rb.cond.L.Unlock()
}

// ==========================================
// Meek  info  ( info )
// ==========================================
type retryChunk struct {
	seq    uint64
	data   []byte
	bufPtr *[]byte
}

type meekVirtualConn struct {
	ctx       context.Context
	sessionID string
	local     net.Addr
	remote    net.Addr

	readCond     *sync.Cond
	readBuf      bytes.Buffer
	nextReadSeq  atomic.Uint64
	oooBuf       map[uint64][]byte
	oooBytesSize int

	writeBuf *reliableBuffer

	retryMu sync.Mutex
	retryQ  []retryChunk

	closed bool

	onWriteSignal func()
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
		c.readCond.Wait()
	}

	if c.ctx.Err() != nil || c.closed {
		c.closed = true
		return 0, io.EOF
	}

	n, err := c.readBuf.Read(p)

	//  info ： info ， info  Buffer
	if c.readBuf.Len() == 0 && c.readBuf.Cap() > 512*1024 {
		c.readBuf = bytes.Buffer{}
	}

	return n, err
}

func (c *meekVirtualConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := c.writeBuf.Write(p)
	if c.onWriteSignal != nil {
		c.onWriteSignal()
	}
	return n, err
}

// PutReadData  info
func (c *meekVirtualConn) PutReadData(seq uint64, data []byte) uint64 {
	c.readCond.L.Lock()
	defer c.readCond.L.Unlock()

	curNext := c.nextReadSeq.Load()
	if c.closed || len(data) == 0 {
		return curNext
	}

	if seq == curNext {
		c.readBuf.Write(data)
		curNext += uint64(len(data))
		c.nextReadSeq.Store(curNext)

		for {
			if nextData, ok := c.oooBuf[curNext]; ok {
				c.readBuf.Write(nextData)
				c.oooBytesSize -= len(nextData)
				delete(c.oooBuf, curNext)
				curNext += uint64(len(nextData))
				c.nextReadSeq.Store(curNext)
			} else {
				break
			}
		}
		c.readCond.Broadcast()

	} else if seq > curNext {
		if seq-curNext > 4*1024*1024 {
			zlog.Warnf("[meekVirtualConn] Drop far-future packet seq=%d (gap=%d)", seq, seq-curNext)
			return curNext
		}

		const maxOOOMem = 6 * 1024 * 1024
		const maxOOOPkts = 96

		if c.oooBytesSize+len(data) > maxOOOMem || len(c.oooBuf) >= maxOOOPkts {
			zlog.Warnf("[meekVirtualConn] OOO buffer full (mem=%d, pkts=%d), drop seq=%d",
				c.oooBytesSize, len(c.oooBuf), seq)
			return curNext
		}

		if _, exists := c.oooBuf[seq]; !exists {
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)
			c.oooBuf[seq] = dataCopy
			c.oooBytesSize += len(data)
		}
	}

	return curNext
}

func (c *meekVirtualConn) Close() error {
	c.readCond.L.Lock()
	c.closed = true

	if c.oooBuf != nil {
		c.oooBuf = nil
	}
	c.oooBytesSize = 0

	c.readCond.Broadcast()
	c.readCond.L.Unlock()

	c.retryMu.Lock()
	for i := range c.retryQ {
		if c.retryQ[i].bufPtr != nil {
			safelyPutBuf(xhttpFrameBufPool, c.retryQ[i].bufPtr)
		}
		c.retryQ[i] = retryChunk{}
	}
	c.retryQ = nil
	c.retryMu.Unlock()

	if c.writeBuf != nil {
		c.writeBuf.Close()
	}
	return nil
}

func (c *meekVirtualConn) LocalAddr() net.Addr                { return c.local }
func (c *meekVirtualConn) RemoteAddr() net.Addr               { return c.remote }
func (c *meekVirtualConn) SetDeadline(t time.Time) error      { return nil }
func (c *meekVirtualConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *meekVirtualConn) SetWriteDeadline(t time.Time) error { return nil }

// ==========================================
//  info  Padding  info  0xFFFF  info
// ==========================================

type xhttpFramedConn struct {
	lastWriteTime atomic.Int64
	closedFlag    atomic.Int32

	r             io.Reader
	w             io.Writer
	closer        func() error
	local         net.Addr
	remote        net.Addr
	mu            sync.Mutex
	readBuf       []byte
	frameBufPtr   *[]byte
	hdrBuf        []byte
	payloadBufPtr *[]byte
	closeCh       chan struct{}
}

func newXhttpFramedConn(r io.Reader, w io.Writer, closer func() error, local, remote net.Addr) *xhttpFramedConn {
	fBufPtr := xhttpFrameBufPool.Get()
	pBufPtr := xhttpFrameBufPool.Get()

	conn := &xhttpFramedConn{
		r: r, w: w, closer: closer, local: local, remote: remote,
		frameBufPtr:   fBufPtr,
		hdrBuf:        make([]byte, 6),
		payloadBufPtr: pBufPtr,
		closeCh:       make(chan struct{}),
	}
	conn.lastWriteTime.Store(time.Now().Unix())
	go conn.heartbeatLoop()
	return conn
}

func (c *xhttpFramedConn) heartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			last := c.lastWriteTime.Load()
			if time.Now().Unix()-last >= 60 {
				c.Write(nil)
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
	} else if chunkSize > 1024*100 {
		padLenInt = 0
	} else {
		padLenInt = 16 + mrand.IntN(112)
	}

	frameLen := 6 + padLenInt + chunkSize
	fBuf := *c.frameBufPtr

	if frameLen > cap(fBuf) {
		newCap := frameLen
		if newCap > xhttpMaxframeSize*2 {
			newCap = xhttpMaxframeSize * 2
		}
		fBuf = make([]byte, frameLen, newCap)
		*c.frameBufPtr = fBuf
	} else {
		fBuf = fBuf[:frameLen]
	}

	binary.BigEndian.PutUint32(fBuf[0:4], uint32(chunkSize))
	binary.BigEndian.PutUint16(fBuf[4:6], uint16(padLenInt))

	if padLenInt > 0 {
		offset := mrand.IntN(padPoolLen - padLenInt)
		copy(fBuf[6:6+padLenInt], padPool[offset:offset+padLenInt])
	}

	if chunkSize > 0 {
		copy(fBuf[6+padLenInt:], chunk)
	}

	_, err := c.w.Write(fBuf)
	return err
}

func (c *xhttpFramedConn) Write(p []byte) (int, error) {
	if c.closedFlag.Load() == 1 {
		return 0, io.ErrClosedPipe
	}
	c.lastWriteTime.Store(time.Now().Unix())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedFlag.Load() == 1 || c.frameBufPtr == nil {
		return 0, io.ErrClosedPipe
	}
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
	if len(c.readBuf) > 0 {
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

		if padLen > xhttpMaxPaddingSize {
			return 0, fmt.Errorf("xhttp: invalid padding length %d exceeds max %d", padLen, xhttpMaxPaddingSize)
		}

		if rawPayloadLen != uint32(0xFFFFFFFF) && rawPayloadLen > uint32(xhttpMaxframeSize*4) {
			return 0, fmt.Errorf("xhttp: frame payload length %d exceeds safety limit", rawPayloadLen)
		}

		pBuf := *c.payloadBufPtr

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

		if rawPayloadLen == uint32(0xFFFFFFFF) {
			return 0, io.EOF
		}
		if rawPayloadLen == 0 {
			continue
		}

		payloadLen := int(rawPayloadLen)

		readIntoP := payloadLen
		if readIntoP > len(p) {
			readIntoP = len(p)
		}

		if _, err := io.ReadFull(c.r, p[:readIntoP]); err != nil {
			return readIntoP, err
		}

		leftover := payloadLen - readIntoP
		if leftover > 0 {
			pBuf = *c.payloadBufPtr
			if leftover > cap(pBuf) {
				pBuf = make([]byte, leftover)
				*c.payloadBufPtr = pBuf
			}
			leftoverBuf := pBuf[:leftover]

			if _, err := io.ReadFull(c.r, leftoverBuf); err != nil {
				return readIntoP, err
			}
			c.readBuf = leftoverBuf
		}

		return readIntoP, nil
	}
}

func (c *xhttpFramedConn) Close() error {
	if c.closedFlag.CompareAndSwap(0, 1) {
		c.mu.Lock()
		frame := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
		c.w.Write(frame)
		c.readBuf = nil
		c.mu.Unlock()

		close(c.closeCh)

		//  info  xhttpFrameBufPool
		if c.frameBufPtr != nil {
			xhttpFrameBufPool.Put(c.frameBufPtr)
			c.frameBufPtr = nil
		}
		if c.payloadBufPtr != nil {
			xhttpFrameBufPool.Put(c.payloadBufPtr)
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

func drainAndCloseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(body, 1024*1024))
	body.Close()
}

// retryEnqueue  info （ info  seq  info ），O(n)  info  n  info 。
//
//	info  slices.SortFunc， info 。
func retryEnqueue(q []retryChunk, chunk retryChunk) []retryChunk {
	i := len(q)
	for i > 0 && q[i-1].seq > chunk.seq {
		i--
	}
	q = append(q, retryChunk{})
	copy(q[i+1:], q[i:])
	q[i] = chunk
	return q
}

// ==========================================
//
//	info
//
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

		zlog.Infof("%s [Tunnel] Preparing %s handshake, Spoofed Host: %s, Allowed ALPNs: %v", TAG, protoName, cfg.CustomHost, alpnList)

		path := cfg.CustomPath
		if path == "" {
			path = "/stream"
		}
		reqURL := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)
		sessionID := generateRandomHex(16)

		var client *http.Client
		var negotiatedProtocol string
		var cleanupFuncs []func()

		baseTlsConf := &tls.Config{
			ServerName:            cfg.ServerName,
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
		}

		if isTLS {
			// ==========================================
			//  info  HTTP/3 (QUIC)
			// ==========================================
			if slices.Contains(alpnList, "h3") {
				tr3, h3Err := getH3Transport(cfg)

				if h3Err == nil && tr3 != nil {
					zlog.Infof("%s [Tunnel] ⚡ Probe successful: HTTP/3 (QUIC), reusing underlying physical UDP link", TAG)
					negotiatedProtocol = "h3"

					client = &http.Client{
						Transport: tr3,
						Timeout:   90 * time.Second,
					}

				} else {
					zlog.Warnf("%s [Tunnel] ⚠️ HTTP/3 (QUIC) probe/fetch failed, downgrading to TCP probe: %v", TAG, h3Err)
				}
			}

			// ==========================================
			// TCP ALPN  info  (h2 / http/1.1)
			// ==========================================
			if client == nil {
				var tcpConn net.Conn
				var err error
				tcpConn, err = dialTCP(parentCtx, cfg, cfg.ProxyAddr)
				if err != nil {
					return nil, fmt.Errorf("probe tcp failed: %w", err)
				}

				tcpAlpns := slices.DeleteFunc(slices.Clone(alpnList), func(s string) bool { return s == "h3" })
				utlsConfig := &utls.Config{
					ServerName:            baseTlsConf.ServerName,
					InsecureSkipVerify:    baseTlsConf.InsecureSkipVerify,
					VerifyPeerCertificate: baseTlsConf.VerifyPeerCertificate,
					NextProtos:            tcpAlpns,
				}

				handshakeUTLS := func(ctx context.Context, conn net.Conn) (*utls.UConn, string, error) {
					uConn := utls.UClient(conn, utlsConfig, utls.HelloChrome_Auto)
					if err := uConn.BuildHandshakeState(); err != nil {
						return nil, "", fmt.Errorf("utls build handshake state failed: %w", err)
					}
					for _, ext := range uConn.Extensions {
						if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
							alpnExt.AlpnProtocols = tcpAlpns
							break
						}
					}
					if err := uConn.HandshakeContext(ctx); err != nil {
						return nil, "", fmt.Errorf("utls handshake failed: %w", err)
					}
					return uConn, uConn.ConnectionState().NegotiatedProtocol, nil
				}

				var uConn *utls.UConn
				uConn, negotiatedProtocol, err = handshakeUTLS(parentCtx, tcpConn)
				zlog.Infof("%s [Tunnel] Detected TCP ALPN: %s", TAG, negotiatedProtocol)

				if err != nil {
					tcpConn.Close()
					return nil, fmt.Errorf("utls verify&handshake failed: %w", err)
				}

				cachedConn := net.Conn(uConn)
				var connConsumed atomic.Bool

				cleanupFuncs = append(cleanupFuncs, func() {
					if !connConsumed.Load() && cachedConn != nil {
						cachedConn.Close()
					}
				})

				dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
					if connConsumed.CompareAndSwap(false, true) {
						return cachedConn, nil
					}

					tc, err := dialTCP(ctx, cfg, cfg.ProxyAddr)
					if err != nil {
						return nil, fmt.Errorf("dial proxy tcp failed: %w", err)
					}

					uc, np, err := handshakeUTLS(ctx, tc)
					zlog.Infof("%s [Tunnel] Detected TCP ALPN: %s", TAG, np)

					if err != nil {
						tc.Close()
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
			//  info  TCP mode (h2c  info )
			// ==========================================
			dialTCPWithBind := func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialProtected(ctx, cfg, network, addr, 10*time.Second)
			}

			if probeH2C(parentCtx, cfg) && slices.Contains(alpnList, "h2") {
				zlog.Infof("%s [Tunnel] ⚡ Probe successful, enabling H2C (Cleartext HTTP/2) engine", TAG)
				t2 := &http2.Transport{
					AllowHTTP: true,
					DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
						return dialTCPWithBind(ctx, network, addr)
					},
				}
				client = &http.Client{Transport: t2, Timeout: 90 * time.Second}
				cleanupFuncs = append(cleanupFuncs, func() {
					t2.CloseIdleConnections()
				})
			} else {
				zlog.Infof("%s [Tunnel] 🐢 H2C probe failed, smoothly falling back to pure TCP HTTP/1.1 engine", TAG)
				t1 := &http.Transport{
					DialContext:           dialTCPWithBind,
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

		//  info
		proxyNetAddr, _ := net.ResolveTCPAddr("tcp", cfg.ProxyAddr)
		var localNetAddr net.Addr
		if proxyNetAddr.IP.To4() != nil {
			localNetAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
		} else {
			localNetAddr = &net.TCPAddr{IP: net.IPv6zero, Port: 0}
		}
		ctx, cancel := context.WithCancel(parentCtx)
		virtualConn := newMeekVirtualConn(ctx, sessionID, localNetAddr, proxyNetAddr)

		sessionHeaders := generateBrowserHeaders()

		//  info uplink info
		safelyPutUpBuf := func(bufPtr *[]byte) {
			safelyPutBuf(xhttpFrameBufPool, bufPtr)
		}

		//  info
		go func() {
			defer virtualConn.Close()
			defer cancel()

			var ackedByServer atomic.Uint64
			var dispatchSeq uint64
			var windowMu sync.Mutex
			var consecutiveErrors, triggerRetry atomic.Int32

			const minWorkers = 1
			const maxWorkers = 16
			var activeWorkers atomic.Int32
			var lastRxTime atomic.Int64
			var wg sync.WaitGroup

			var workerLoop func()
			trySpawnWorker := func() {
				for {
					curr := activeWorkers.Load()
					if curr >= maxWorkers {
						return
					}
					if activeWorkers.CompareAndSwap(curr, curr+1) {
						wg.Add(1)
						go workerLoop()
						return
					}
				}
			}

			workerLoop = func() {
				defer wg.Done()
				defer activeWorkers.Add(-1)

				idleTimer := time.NewTimer(50 * time.Millisecond)
				if !idleTimer.Stop() {
					<-idleTimer.C
				}
				defer idleTimer.Stop()

				// handleRetryEnqueue  info  Sort
				handleRetryEnqueue := func(seq uint64, data []byte, bufPtr *[]byte) {
					enqueued := false
					if len(data) > 0 {
						currAck := ackedByServer.Load()
						if seq >= currAck {
							virtualConn.retryMu.Lock()
							virtualConn.retryQ = retryEnqueue(virtualConn.retryQ, retryChunk{seq: seq, data: data, bufPtr: bufPtr})
							virtualConn.retryMu.Unlock()
							enqueued = true
						}
					}
					if !enqueued && bufPtr != nil {
						safelyPutUpBuf(bufPtr)
					}
					triggerRetry.Store(1)
				}

				for !virtualConn.closed && ctx.Err() == nil {
					var upData []byte
					var currentSeq uint64
					var upBufPtr *[]byte
					var isRetry bool

					virtualConn.retryMu.Lock()
					currAck := ackedByServer.Load()
					for len(virtualConn.retryQ) > 0 && virtualConn.retryQ[0].seq < currAck {
						if virtualConn.retryQ[0].bufPtr != nil {
							safelyPutUpBuf(virtualConn.retryQ[0].bufPtr)
						}
						virtualConn.retryQ[0] = retryChunk{}
						virtualConn.retryQ = virtualConn.retryQ[1:]
					}
					if len(virtualConn.retryQ) > 0 {
						chunk := virtualConn.retryQ[0]
						virtualConn.retryQ[0] = retryChunk{}
						virtualConn.retryQ = virtualConn.retryQ[1:]
						upData = chunk.data
						currentSeq = chunk.seq
						upBufPtr = chunk.bufPtr
						isRetry = true
					}
					virtualConn.retryMu.Unlock()

					if !isRetry {
						windowMu.Lock()
						currAck := ackedByServer.Load()
						if dispatchSeq < currAck {
							dispatchSeq = currAck
						}

						upData, currentSeq, upBufPtr = virtualConn.writeBuf.GetSlice(currAck, dispatchSeq, xhttpMaxsendBufSize)

						if len(upData) == 0 {
							allowedPollers := int32(minWorkers)
							if time.Now().UnixMilli()-lastRxTime.Load() < 2000 {
								allowedPollers = 16
							}

							if activeWorkers.Load() > allowedPollers {
								windowMu.Unlock()
								return
							}

							dispatchSeq = currentSeq
							windowMu.Unlock()
						} else {
							dispatchSeq = currentSeq + uint64(len(upData))
							windowMu.Unlock()
						}
					}

					var method string
					var bodyReader io.Reader
					var reqTimeout time.Duration
					if len(upData) > 0 {
						method = http.MethodPost
						bodyReader = bytes.NewReader(upData)
						reqTimeout = 15 * time.Second
					} else {
						method = http.MethodGet
						bodyReader = http.NoBody
						reqTimeout = 30 * time.Second
					}

					reqCtx, reqCancel := context.WithTimeout(ctx, reqTimeout)
					req, err := http.NewRequestWithContext(reqCtx, method, reqURL, bodyReader)
					if err != nil {
						reqCancel()
						zlog.Errorf("%s [Tunnel] Failed to create HTTP request (Seq: %d): %v", TAG, currentSeq, err)
						safelyPutUpBuf(upBufPtr)
						return
					}
					req.Host = cfg.CustomHost

					for k, v := range sessionHeaders {
						req.Header.Set(k, v)
					}

					if len(upData) == 0 {
						q := req.URL.Query()
						q.Set("t", strconv.FormatInt(time.Now().UnixNano(), 36))
						req.URL.RawQuery = q.Encode()
						req.Header.Set("Accept", "*/*")
						req.Header.Set("Cache-Control", "no-cache")
					} else {
						req.ContentLength = int64(len(upData))
						req.Header.Set("Content-Type", "application/octet-stream")
						req.Header.Set("Accept", "*/*")
					}

					req.Header.Set("Host", cfg.CustomHost)
					req.Header.Set("X-Target", cfg.SshAddr)
					req.Header.Set("X-Network", "tcp")
					req.Header.Set("X-Session-ID", sessionID)
					req.Header.Set("X-Seq", strconv.FormatUint(currentSeq, 10))
					req.Header.Set("X-Ack", strconv.FormatUint(virtualConn.nextReadSeq.Load(), 10))

					if cfg.ProxyAuthRequired {
						req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
					}

					if triggerRetry.CompareAndSwap(1, 0) {
						req.Header.Set("X-Retry", "1")
					}

					resp, err := client.Do(req)

					//  info  1
					if err != nil {
						reqCancel()
						if ctx.Err() != nil {
							safelyPutUpBuf(upBufPtr)
							break
						}
						zlog.Errorf("%s [Tunnel] HTTP failed (Seq: %d): %v", TAG, currentSeq, err)
						if errors.Is(err, context.Canceled) {
							safelyPutUpBuf(upBufPtr)
							break
						}
						handleRetryEnqueue(currentSeq, upData, upBufPtr)
						upBufPtr = nil
						upData = nil

						if consecutiveErrors.Add(1) > 20 {
							break
						}
						idleTimer.Reset(300 * time.Millisecond)
						select {
						case <-idleTimer.C:
						case <-ctx.Done():
							idleTimer.Stop()
							return
						}
						continue
					}

					if sAckStr := resp.Header.Get("X-Ack"); sAckStr != "" {
						sAck, _ := strconv.ParseUint(sAckStr, 10, 64)
						for {
							old := ackedByServer.Load()
							if sAck <= old || ackedByServer.CompareAndSwap(old, sAck) {
								break
							}
						}
					}

					//  info  2
					if resp.StatusCode != http.StatusOK {
						downBuf := getDownBuf()
						downBuf.ReadFrom(resp.Body)
						drainAndCloseBody(resp.Body)
						putDownBuf(downBuf)

						reqCancel()

						handleRetryEnqueue(currentSeq, upData, upBufPtr)
						upBufPtr = nil
						upData = nil
						if consecutiveErrors.Add(1) > 20 {
							break
						}
						idleTimer.Reset(1 * time.Second)
						select {
						case <-idleTimer.C:
						case <-ctx.Done():
							idleTimer.Stop()
							return
						}
						continue
					}

					consecutiveErrors.Store(0)

					sSeqStr := resp.Header.Get("X-Seq")
					sSeq, _ := strconv.ParseUint(sSeqStr, 10, 64)

					downBuf := getDownBuf()
					_, errBody := downBuf.ReadFrom(resp.Body)
					downData := downBuf.Bytes()
					drainAndCloseBody(resp.Body)

					reqCancel()

					//  info  3
					if errBody != nil {
						putDownBuf(downBuf)
						handleRetryEnqueue(currentSeq, upData, upBufPtr)
						upBufPtr = nil
						upData = nil
						idleTimer.Reset(300 * time.Millisecond)
						select {
						case <-idleTimer.C:
						case <-ctx.Done():
							idleTimer.Stop()
							return
						}
						continue
					}

					if len(downData) > 0 || sSeqStr != "" {
						if len(downData) > 0 {
							lastRxTime.Store(time.Now().UnixMilli())
						}
						virtualConn.PutReadData(sSeq, downData)
					}

					putDownBuf(downBuf)
					safelyPutUpBuf(upBufPtr)

					//  info  Worker
					if len(downData) > 0 {
						if activeWorkers.Load() < 4 {
							trySpawnWorker()
						}
					} else if virtualConn.writeBuf.Len() > xhttpMaxsendBufSize {
						if activeWorkers.Load() < 8 {
							trySpawnWorker()
						}
					}

					if len(upData) == 0 && len(downData) == 0 && virtualConn.writeBuf.Len() == 0 {
						if activeWorkers.Load() > 2 {
							return
						}
						idleTimer.Reset(50 * time.Millisecond)
						select {
						case <-idleTimer.C:
						case <-ctx.Done():
							idleTimer.Stop()
							return
						}
					}
				}
			}

			virtualConn.onWriteSignal = func() {
				trySpawnWorker()
			}

			for i := 0; i < minWorkers; i++ {
				trySpawnWorker()
			}

			wg.Wait()
		}()

		return newXhttpFramedConn(virtualConn, virtualConn, func() error {
			cancel()
			for _, cleanup := range cleanupFuncs {
				cleanup()
			}
			return virtualConn.Close()
		}, localNetAddr, proxyNetAddr), nil
	}

	//  info  Tunnel
	RegisterTunnel("xhttpc", "custom", func(ctx context.Context, cfg ProxyConfig, base net.Conn) (net.Conn, error) {
		alpnList := strings.Split(cfg.Alpn, ",")
		return xhttpHandler(ctx, cfg, base, false, alpnList)
	})
	RegisterTunnel("xhttp", "custom", func(ctx context.Context, cfg ProxyConfig, base net.Conn) (net.Conn, error) {
		alpnList := strings.Split(cfg.Alpn, ",")
		return xhttpHandler(ctx, cfg, base, true, alpnList)
	})
}

// info ： info
func updateUint64IfGreater(addr *atomic.Uint64, newVal uint64) {
	for {
		old := addr.Load()
		if newVal <= old || addr.CompareAndSwap(old, newVal) {
			break
		}
	}
}

// info ： info  H2C  info
func probeH2C(ctx context.Context, cfg ProxyConfig) bool {
	conn, err := dialProtected(ctx, cfg, "tcp", cfg.ProxyAddr, 2*time.Second)
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

// ==========================================
//
//	info  ( info  CDN / WAF  info )
//
// ==========================================
func generateBrowserHeaders() map[string]string {
	profiles := []map[string]string{
		{
			"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Sec-Ch-Ua":          `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": `"Windows"`,
			"Accept-Language":    "zh-CN,zh;q=0.9,en;q=0.8",
			"Sec-Fetch-Dest":     "empty",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Site":     "same-origin",
		},
		{
			"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
			"Sec-Ch-Ua":          `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`,
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": `"macOS"`,
			"Accept-Language":    "en-US,en;q=0.9",
			"Sec-Fetch-Dest":     "empty",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Site":     "same-origin",
		},
		{
			"User-Agent":         "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
			"Sec-Ch-Ua":          `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
			"Sec-Ch-Ua-Mobile":   "?1",
			"Sec-Ch-Ua-Platform": `"Android"`,
			"Accept-Language":    "zh-CN,zh;q=0.9",
			"Sec-Fetch-Dest":     "empty",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Site":     "same-origin",
		},
	}
	return profiles[mrand.IntN(len(profiles))]
}
