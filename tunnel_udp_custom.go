package myssh

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	UDPC_MAGIC_DEFAULT = uint32(0x55445043) // "UDPC"
	UDPC_VERSION       = uint8(0x01)

	// Command Types
	CMD_HANDSHAKE_SYN = uint8(0x01)
	CMD_HANDSHAKE_ACK = uint8(0x02)
	CMD_DATA          = uint8(0x03)
	CMD_ACK           = uint8(0x04)
	CMD_PING          = uint8(0x05)
	CMD_PONG          = uint8(0x06)
	CMD_FIN           = uint8(0x07)

	// Header Sizes
	UDPC_HDR_SIZE = 24 // Magic(4)+Ver(1)+Cmd(1)+Flags(2)+SessionID(4)+Seq(4)+Ack(4)+Win(2)+Len(2)
	UDPC_MAX_PKT  = 1450
	UDPC_MAX_DATA = 1350
)

// UDPCFrame represents a single protocol packet frame
type UDPCFrame struct {
	Magic      uint32
	Version    uint8
	Cmd        uint8
	Flags      uint16
	SessionID  uint32
	Seq        uint32
	Ack        uint32
	WindowSize uint16
	Data       []byte
}

func (f *UDPCFrame) Encode() []byte {
	dataLen := len(f.Data)
	buf := make([]byte, UDPC_HDR_SIZE+dataLen+4) // +4 for CRC32
	binary.BigEndian.PutUint32(buf[0:4], f.Magic)
	buf[4] = f.Version
	buf[5] = f.Cmd
	binary.BigEndian.PutUint16(buf[6:8], f.Flags)
	binary.BigEndian.PutUint32(buf[8:12], f.SessionID)
	binary.BigEndian.PutUint32(buf[12:16], f.Seq)
	binary.BigEndian.PutUint32(buf[16:20], f.Ack)
	binary.BigEndian.PutUint16(buf[20:22], f.WindowSize)
	binary.BigEndian.PutUint16(buf[22:24], uint16(dataLen))
	if dataLen > 0 {
		copy(buf[UDPC_HDR_SIZE:], f.Data)
	}
	checksum := crc32.ChecksumIEEE(buf[:UDPC_HDR_SIZE+dataLen])
	binary.BigEndian.PutUint32(buf[UDPC_HDR_SIZE+dataLen:], checksum)
	return buf
}

func DecodeUDPCFrame(buf []byte, expectedMagic uint32) (*UDPCFrame, error) {
	if len(buf) < UDPC_HDR_SIZE+4 {
		return nil, errors.New("frame too short")
	}
	dataLen := int(binary.BigEndian.Uint16(buf[22:24]))
	if len(buf) < UDPC_HDR_SIZE+dataLen+4 {
		return nil, errors.New("invalid payload length")
	}

	checksum := binary.BigEndian.Uint32(buf[UDPC_HDR_SIZE+dataLen : UDPC_HDR_SIZE+dataLen+4])
	calculated := crc32.ChecksumIEEE(buf[:UDPC_HDR_SIZE+dataLen])
	if checksum != calculated {
		return nil, errors.New("checksum mismatch")
	}

	magic := binary.BigEndian.Uint32(buf[0:4])
	if expectedMagic != 0 && magic != expectedMagic {
		return nil, errors.New("magic mismatch")
	}

	frame := &UDPCFrame{
		Magic:      magic,
		Version:    buf[4],
		Cmd:        buf[5],
		Flags:      binary.BigEndian.Uint16(buf[6:8]),
		SessionID:  binary.BigEndian.Uint32(buf[8:12]),
		Seq:        binary.BigEndian.Uint32(buf[12:16]),
		Ack:        binary.BigEndian.Uint32(buf[16:20]),
		WindowSize: binary.BigEndian.Uint16(buf[20:22]),
	}
	if dataLen > 0 {
		frame.Data = make([]byte, dataLen)
		copy(frame.Data, buf[UDPC_HDR_SIZE:UDPC_HDR_SIZE+dataLen])
	}
	return frame, nil
}

// UDPCConn provides a reliable, ordered net.Conn over UDP with ARQ sliding window
type UDPCConn struct {
	baseConn   net.Conn
	raddr      net.Addr
	sessionID  uint32
	magic      uint32
	password   string
	isServer   bool

	// Sequence & ARQ State
	sendSeq     uint32
	recvSeq     uint32
	lastAckSent uint32

	readBuf    bytes.Buffer
	readMu     sync.Mutex
	readCond   *sync.Cond
	writeMu    sync.Mutex

	recvQueue  map[uint32][]byte // Out of order packets buffer
	recvMu     sync.Mutex

	unacked    map[uint32]*unackedPacket
	unackedMu  sync.Mutex

	closed     int32
	closeChan  chan struct{}
	closeOnce  sync.Once
	readDead   time.Time
	writeDead  time.Time
}

type unackedPacket struct {
	frame    *UDPCFrame
	sentTime time.Time
	retries  int
}

func newUDPCConn(base net.Conn, raddr net.Addr, sessionID uint32, magic uint32, password string, isServer bool) *UDPCConn {
	c := &UDPCConn{
		baseConn:   base,
		raddr:      raddr,
		sessionID:  sessionID,
		magic:      magic,
		password:   password,
		isServer:   isServer,
		sendSeq:    1,
		recvSeq:    1,
		recvQueue:  make(map[uint32][]byte),
		unacked:    make(map[uint32]*unackedPacket),
		closeChan:  make(chan struct{}),
	}
	c.readCond = sync.NewCond(&c.readMu)

	// Start packet receiver and retransmission loops
	go c.readLoop()
	go c.retransmitLoop()
	return c
}

func (c *UDPCConn) readLoop() {
	buf := make([]byte, 2048)
	for {
		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}
		n, err := c.baseConn.Read(buf)
		if err != nil {
			c.Close()
			return
		}

		frame, err := DecodeUDPCFrame(buf[:n], c.magic)
		if err != nil || frame.SessionID != c.sessionID {
			continue
		}

		// Process ACK
		if frame.Ack > 0 {
			c.handleAck(frame.Ack)
		}

		switch frame.Cmd {
		case CMD_DATA:
			c.handleData(frame)
		case CMD_ACK:
			// Already handled Ack above
		case CMD_PING:
			c.sendFrame(CMD_PONG, 0, frame.Seq, nil)
		case CMD_PONG:
			// Ping acknowledged
		case CMD_FIN:
			c.Close()
			return
		}
	}
}

func (c *UDPCConn) handleAck(ack uint32) {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()
	for seq := range c.unacked {
		if seq < ack {
			delete(c.unacked, seq)
		}
	}
}

func (c *UDPCConn) handleData(frame *UDPCFrame) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	seq := frame.Seq
	if seq == c.recvSeq {
		// In-order packet
		c.readMu.Lock()
		c.readBuf.Write(frame.Data)
		c.recvSeq += uint32(len(frame.Data))
		
		// Drain consecutive queued packets if present
		for {
			nextData, exists := c.recvQueue[c.recvSeq]
			if !exists {
				break
			}
			delete(c.recvQueue, c.recvSeq)
			c.readBuf.Write(nextData)
			c.recvSeq += uint32(len(nextData))
		}
		c.readCond.Signal()
		c.readMu.Unlock()

		// Send ACK
		c.sendAck(c.recvSeq)
	} else if seq > c.recvSeq {
		// Out-of-order packet: buffer it and send duplicate ACK
		if len(c.recvQueue) < 512 {
			c.recvQueue[seq] = frame.Data
		}
		c.sendAck(c.recvSeq)
	} else {
		// Old packet, ACK current state
		c.sendAck(c.recvSeq)
	}
}

func (c *UDPCConn) sendAck(ack uint32) {
	c.sendFrame(CMD_ACK, 0, ack, nil)
}

func (c *UDPCConn) sendFrame(cmd uint8, seq uint32, ack uint32, data []byte) error {
	frame := &UDPCFrame{
		Magic:      c.magic,
		Version:    UDPC_VERSION,
		Cmd:        cmd,
		SessionID:  c.sessionID,
		Seq:        seq,
		Ack:        ack,
		WindowSize: 65535,
		Data:       data,
	}
	pkt := frame.Encode()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.baseConn.Write(pkt)
	return err
}

func (c *UDPCConn) retransmitLoop() {
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.closeChan:
			return
		case now := <-ticker.C:
			c.unackedMu.Lock()
			for _, pkt := range c.unacked {
				if now.Sub(pkt.sentTime) > 150*time.Millisecond {
					// Retransmit
					pkt.sentTime = now
					pkt.retries++
					if pkt.retries > 10 {
						c.unackedMu.Unlock()
						c.Close()
						return
					}
					c.writeMu.Lock()
					c.baseConn.Write(pkt.frame.Encode())
					c.writeMu.Unlock()
				}
			}
			c.unackedMu.Unlock()
		}
	}
}

func (c *UDPCConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readBuf.Len() == 0 {
		if atomic.LoadInt32(&c.closed) == 1 {
			return 0, io.EOF
		}
		if !c.readDead.IsZero() && time.Now().After(c.readDead) {
			return 0, errors.New("i/o timeout")
		}
		c.readCond.Wait()
	}
	return c.readBuf.Read(b)
}

func (c *UDPCConn) Write(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, io.ErrClosedPipe
	}

	total := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > UDPC_MAX_DATA {
			chunkSize = UDPC_MAX_DATA
		}
		chunk := b[:chunkSize]

		seq := atomic.AddUint32(&c.sendSeq, uint32(chunkSize)) - uint32(chunkSize)
		frame := &UDPCFrame{
			Magic:      c.magic,
			Version:    UDPC_VERSION,
			Cmd:        CMD_DATA,
			SessionID:  c.sessionID,
			Seq:        seq,
			Ack:        atomic.LoadUint32(&c.recvSeq),
			WindowSize: 65535,
			Data:       chunk,
		}

		c.unackedMu.Lock()
		c.unacked[seq] = &unackedPacket{
			frame:    frame,
			sentTime: time.Now(),
		}
		c.unackedMu.Unlock()

		c.writeMu.Lock()
		if !c.writeDead.IsZero() {
			c.baseConn.SetWriteDeadline(c.writeDead)
		}
		_, err := c.baseConn.Write(frame.Encode())
		c.writeMu.Unlock()

		if err != nil {
			return total, err
		}

		total += chunkSize
		b = b[chunkSize:]
	}
	return total, nil
}

func (c *UDPCConn) Close() error {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)
		close(c.closeChan)
		c.readMu.Lock()
		c.readCond.Broadcast()
		c.readMu.Unlock()

		// Send FIN packet
		c.sendFrame(CMD_FIN, 0, 0, nil)
		c.baseConn.Close()
	})
	return nil
}

func (c *UDPCConn) LocalAddr() net.Addr                { return c.baseConn.LocalAddr() }
func (c *UDPCConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *UDPCConn) SetDeadline(t time.Time) error      { c.readDead = t; c.writeDead = t; return nil }
func (c *UDPCConn) SetReadDeadline(t time.Time) error  { c.readDead = t; return nil }
func (c *UDPCConn) SetWriteDeadline(t time.Time) error { c.writeDead = t; return nil }

// ComputeAuthHMAC generates an HMAC-SHA256 signature for handshake authentication
func ComputeAuthHMAC(nonce []byte, password string, timestamp int64) []byte {
	h := hmac.New(sha256.New, []byte(password))
	h.Write(nonce)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	h.Write(tsBuf[:])
	return h.Sum(nil)
}

func init() {
	RegisterTunnel("udp_custom", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		target := cfg.ProxyAddr
		if target == "" {
			target = cfg.SshAddr
		}
		zlog.Infof("%s [Tunnel] 2. Preparing UDPCustom v1.0 Handshake with %s", TAG, target)

		password := cfg.Pass
		if cfg.UdpCustomPayload != "" && password == "" {
			password = cfg.UdpCustomPayload
		}
		magic := UDPC_MAGIC_DEFAULT

		// 1. Generate Nonce & Handshake SYN
		nonce := make([]byte, 16)
		rand.Read(nonce)
		now := time.Now().Unix()
		sig := ComputeAuthHMAC(nonce, password, now)

		var payload bytes.Buffer
		payload.Write(nonce)
		binary.Write(&payload, binary.BigEndian, now)
		payload.Write(sig)

		synFrame := &UDPCFrame{
			Magic:      magic,
			Version:    UDPC_VERSION,
			Cmd:        CMD_HANDSHAKE_SYN,
			SessionID:  0,
			Seq:        0,
			Ack:        0,
			WindowSize: 65535,
			Data:       payload.Bytes(),
		}

		baseConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := baseConn.Write(synFrame.Encode()); err != nil {
			zlog.Errorf("%s [Tunnel] ❌ Failed to send UDPCustom SYN: %v", TAG, err)
			return nil, err
		}

		// 2. Receive Handshake ACK
		baseConn.SetReadDeadline(time.Now().Add(6 * time.Second))
		respBuf := make([]byte, 1024)
		n, err := baseConn.Read(respBuf)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ UDPCustom server handshake response failed: %v", TAG, err)
			return nil, fmt.Errorf("udpc-custom handshake response failed: %w", err)
		}

		ackFrame, err := DecodeUDPCFrame(respBuf[:n], magic)
		if err != nil || ackFrame.Cmd != CMD_HANDSHAKE_ACK {
			zlog.Errorf("%s [Tunnel] ❌ Invalid UDPCustom handshake ACK frame: %v", TAG, err)
			return nil, fmt.Errorf("invalid udpc-custom ACK frame")
		}

		sessionID := ackFrame.SessionID
		zlog.Infof("%s [Tunnel] ✅ UDPCustom v1.0 Handshake successful! SessionID: 0x%08X", TAG, sessionID)

		udpcConn := newUDPCConn(baseConn, baseConn.RemoteAddr(), sessionID, magic, password, false)
		return udpcConn, nil
	})
}
