package myssh

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strings"
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

	// UDPC_MAX_CHUNK is the largest application payload put into one frame.
	// It leaves room for the 16-byte Noise AEAD tag so that an encrypted frame
	// still fits within UDPC_MAX_PKT, and it matches the chunk size the server
	// uses when it reads from the target.
	UDPC_MAX_CHUNK = UDPC_MAX_DATA - 16
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
	baseConn  net.Conn
	raddr     net.Addr
	sessionID uint32
	magic     uint32
	password  string
	isServer  bool

	// Sequence & ARQ State
	sendSeq     uint32
	recvSeq     uint32
	lastAckSent uint32

	readBuf  bytes.Buffer
	readMu   sync.Mutex
	readCond *sync.Cond
	writeMu  sync.Mutex

	recvQueue map[uint32][]byte // Out of order packets buffer
	recvMu    sync.Mutex

	unacked   map[uint32]*unackedPacket
	unackedMu sync.Mutex

	rttEst *rttEstimator // adaptive RTO estimator (RFC 6298 + Karn's rule)

	noiseSession *NoiseSession
	closed       int32
	closeChan    chan struct{}
	closeOnce    sync.Once
	readDead     time.Time
	writeDead    time.Time
	lastRecv     int64 // Unix timestamp of the most recent inbound packet; keepalive uses
	// it to detect an idle peer

	// Diagnostics. Always cheap; only surfaced through the debug log.
	txPkts     uint64 // frames handed to baseConn.Write
	rxPkts     uint64 // frames decoded and accepted
	rxDropped  uint64 // frames dropped (bad magic / CRC / wrong session)
	retrans    uint64 // retransmissions performed
	rxOutOfOrd uint64 // DATA frames buffered out of order
}

type unackedPacket struct {
	frame         *UDPCFrame
	firstSent     time.Time // when the frame was first sent; used to sample RTT
	sentTime      time.Time
	rto           time.Duration
	retries       int
	retransmitted bool // Karn's rule: never sample RTT from a retransmitted frame
}

func newUDPCConn(base net.Conn, raddr net.Addr, sessionID uint32, magic uint32, password string, isServer bool, noiseSess *NoiseSession) *UDPCConn {
	c := &UDPCConn{
		baseConn:     base,
		raddr:        raddr,
		sessionID:    sessionID,
		magic:        magic,
		password:     password,
		isServer:     isServer,
		noiseSession: noiseSess,
		sendSeq:      1,
		recvSeq:      1,
		recvQueue:    make(map[uint32][]byte),
		unacked:      make(map[uint32]*unackedPacket),
		closeChan:    make(chan struct{}),
		rttEst:       newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	c.readCond = sync.NewCond(&c.readMu)
	atomic.StoreInt64(&c.lastRecv, time.Now().Unix())

	// Start packet receiver, retransmission, and keepalive loops
	go c.readLoop()
	go c.retransmitLoop()
	go c.keepaliveLoop()
	return c
}

func (c *UDPCConn) keepaliveLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	idleTimeout := int64(45) // 45s = three consecutive missed 15s PINGs
	for {
		select {
		case <-c.closeChan:
			return
		case <-ticker.C:
			// Periodic health snapshot. When port-range spreading is in use the
			// retransmission ratio is the key number: a range that "connects but
			// does not carry traffic" shows up as tx climbing while rx stays flat
			// and retrans grows.
			zlog.Debugf("%s [UDPCConn 0x%08X] 📊 tx=%d rx=%d retrans=%d outOfOrder=%d dropped=%d rto=%v unacked=%d",
				TAG, c.sessionID,
				atomic.LoadUint64(&c.txPkts), atomic.LoadUint64(&c.rxPkts),
				atomic.LoadUint64(&c.retrans), atomic.LoadUint64(&c.rxOutOfOrd),
				atomic.LoadUint64(&c.rxDropped), c.rttEst.RTO(), c.unackedLen())
			if atomic.LoadInt32(&c.closed) == 0 {
				// lastRecv stays 0 until the first packet arrives, so only judge
				// idleness once we have actually heard from the peer
				if last := atomic.LoadInt64(&c.lastRecv); last != 0 && time.Now().Unix()-last > idleTimeout {
					zlog.Warnf("%s [UDPCConn] ⚠️ Idle timeout (%ds) detected, closing connection", TAG, idleTimeout)
					c.Close()
					return
				}
				// Broadcast the PING to every path so all N NAT
				// mappings stay alive (a single-path PING would let
				// the other N-1 mappings expire and drop their
				// replies). Falls back to a single write on legacy
				// (non-multipath) transports.
				pingBytes := (&UDPCFrame{
					Magic:      c.magic,
					Version:    UDPC_VERSION,
					Cmd:        CMD_PING,
					SessionID:  c.sessionID,
					Seq:        0,
					Ack:        0,
					WindowSize: 65535,
				}).Encode()
				if bc, ok := c.baseConn.(broadcaster); ok {
					bc.WriteAll(pingBytes)
				} else {
					c.baseConn.Write(pingBytes)
				}
				atomic.AddUint64(&c.txPkts, 1)
			}
		}
	}
}

func (c *UDPCConn) readLoop() {
	buf := make([]byte, 2048)
	for {
		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}
		n, err := c.baseConn.Read(buf)
		if err != nil {
			zlog.Debugf("%s [UDPCConn 0x%08X] 🛑 base read error after %d rx packet(s): %v",
				TAG, c.sessionID, atomic.LoadUint64(&c.rxPkts), err)
			c.Close()
			return
		}

		frame, err := DecodeUDPCFrame(buf[:n], c.magic)
		if err != nil || frame.SessionID != c.sessionID {
			// With port-range spreading the socket is unconnected, so it also
			// sees stray traffic; count it rather than spam.
			if d := atomic.AddUint64(&c.rxDropped, 1); d <= 3 || d%500 == 0 {
				zlog.Debugf("%s [UDPCConn 0x%08X] 🗑️ dropped packet #%d len=%d wantSid=0x%08X err=%v",
					TAG, c.sessionID, d, n, c.sessionID, err)
			}
			continue
		}

		atomic.AddUint64(&c.rxPkts, 1)
		if rx := atomic.LoadUint64(&c.rxPkts); rx <= 32 || rx%200 == 0 {
			zlog.Debugf("%s [UDPCConn 0x%08X] 📥 #%d cmd=0x%02X seq=%d ack=%d len=%d",
				TAG, c.sessionID, rx, frame.Cmd, frame.Seq, frame.Ack, n)
		}

		//  info  info  info  info  info  info  keepalive  info  info
		atomic.StoreInt64(&c.lastRecv, time.Now().Unix())

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
			// Echo the ping's sequence and piggyback our ack, matching what the
			// server does when it answers a PING. Use ackFor(), not recvSeq:
			// recvSeq is the next EXPECTED sequence, which we have not received.
			c.sendFrame(CMD_PONG, frame.Seq, c.ackFor(), nil)
		case CMD_PONG:
			// Ping acknowledged
		case CMD_FIN:
			c.Close()
			return
		}
	}
}

// unackedLen reports how many frames are awaiting acknowledgement.
func (c *UDPCConn) unackedLen() int {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()
	return len(c.unacked)
}

// handleAck retires every packet the peer has confirmed.
//
// The server sets the ack number to the highest CONTIGUOUS sequence it has
// delivered, so that number is cumulative: everything at or below it is
// confirmed. Retiring only the single matching entry (the old behaviour) is a
// bug that strands the in-between packets: they stay in the retransmit queue,
// get resent, arrive as duplicates, and starve the connection until its retry
// window expires. Reordering is routine once the port range spreads packets
// across many paths, so this fires constantly in that mode.
//
// Note the deliberate asymmetry: the server's ack number is cumulative, while
// the ACKs this client emits are per-sequence (see handleData). Both are valid
// as long as each receiver interprets them the way the sender meant them,
// which is what both sides do today.
func (c *UDPCConn) handleAck(ackSeq uint32) {
	if ackSeq == 0 {
		return
	}
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()

	var sampled *unackedPacket
	for seq, pkt := range c.unacked {
		if int32(seq-ackSeq) > 0 {
			continue // beyond the cumulative ack, still outstanding
		}
		// Karn's rule: only sample RTT from a frame that was never
		// retransmitted; the RTT of a retransmitted one is not trustworthy.
		// Sample at most once per ack, from the newest packet it covers.
		if sampled == nil || int32(seq-sampled.frame.Seq) > 0 {
			sampled = pkt
		}
		delete(c.unacked, seq)
	}
	if sampled != nil && sampled.retries == 0 {
		c.rttEst.Sample(time.Since(sampled.firstSent))
	}
}

// ackFor returns the acknowledgement number this side should advertise: the
// highest contiguous sequence actually delivered, i.e. recvSeq-1.
//
// It is never the next EXPECTED sequence: that one has not been received, and
// advertising it would make the peer drop a genuinely outstanding packet from
// its retransmit queue.
func (c *UDPCConn) ackFor() uint32 {
	return atomic.LoadUint32(&c.recvSeq) - 1
}

func (c *UDPCConn) handleData(frame *UDPCFrame) {
	c.recvMu.Lock()
	seq := frame.Seq
	expected := atomic.LoadUint32(&c.recvSeq)

	switch {
	case seq < expected:
		// Duplicate of something already delivered. Re-ack the highest
		// contiguous sequence we hold so the peer can retire its queue; the
		// original ACK may simply have been lost, and without a fresh ACK the
		// peer keeps retransmitting until its retry window expires.
		c.recvMu.Unlock()
		c.sendAck(c.ackFor())

	case seq > expected:
		// Out of order: buffer the raw frame and wait for the missing one to
		// be (re)transmitted. We deliberately do NOT Ack here — the server
		// interprets ACKs cumulatively, so acknowledging a gap would make it
		// retire the still-missing head frame. This matches the udp_custom
		// server's own receive path.
		if len(c.recvQueue) < 512 {
			c.recvQueue[seq] = frame.Data
		}
		if oo := atomic.AddUint64(&c.rxOutOfOrd, 1); oo <= 10 || oo%100 == 0 {
			zlog.Debugf("%s [UDPCConn 0x%08X] 🔀 #%d out-of-order DATA seq=%d (expecting %d, queued=%d)",
				TAG, c.sessionID, oo, seq, expected, len(c.recvQueue))
		}
		c.recvMu.Unlock()

	default:
		// In order. Hold the lock across decrypt + deliver + drain so the
		// receive window advances atomically.
		payload := frame.Data
		if c.noiseSession != nil && c.noiseSession.RecvCipher != nil {
			decrypted, err := c.noiseSession.RecvCipher.DecryptWithSeq(frame.Seq, frame.Data)
			if err != nil {
				c.recvMu.Unlock()
				return
			}
			payload = decrypted
		}

		c.readMu.Lock()
		c.readBuf.Write(payload)
		atomic.AddUint32(&c.recvSeq, 1)

		for {
			nextSeq := atomic.LoadUint32(&c.recvSeq)
			nextRaw, exists := c.recvQueue[nextSeq]
			if !exists {
				break
			}
			delete(c.recvQueue, nextSeq)
			nextPayload := nextRaw
			if c.noiseSession != nil && c.noiseSession.RecvCipher != nil {
				decrypted, err := c.noiseSession.RecvCipher.DecryptWithSeq(nextSeq, nextRaw)
				if err != nil {
					break
				}
				nextPayload = decrypted
			}
			c.readBuf.Write(nextPayload)
			atomic.AddUint32(&c.recvSeq, 1)
		}
		c.readCond.Signal()
		c.readMu.Unlock()

		c.recvMu.Unlock()
		// Sequence that filled the head of the window. We may have just drained
		// one or more out-of-order frames from recvQueue; those were NOT
		// acknowledged when they arrived (ACKs are deferred until the window
		// head advances). Acknowledge the highest contiguous sequence actually
		// delivered so the peer can retire everything in one shot.
		c.sendAck(c.ackFor())
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
	n, err := c.baseConn.Write(pkt)
	if err != nil {
		zlog.Warnf("%s [UDPCConn 0x%08X] ❌ send cmd=0x%02X seq=%d ack=%d len=%d failed: %v",
			TAG, c.sessionID, cmd, seq, ack, len(pkt), err)
		return err
	}
	atomic.AddUint64(&c.txPkts, 1)
	if tx := atomic.LoadUint64(&c.txPkts); tx <= 32 || tx%200 == 0 {
		zlog.Debugf("%s [UDPCConn 0x%08X] 📤 #%d cmd=0x%02X seq=%d ack=%d len=%d",
			TAG, c.sessionID, tx, cmd, seq, ack, n)
	}
	return nil
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
				if now.Sub(pkt.sentTime) >= pkt.rto {
					// A frame still unacknowledged after 60s means the path is dead:/n/t/t/t/t/t// the peer's SSH layer gives up on an open at 60s, so there is
					// nothing left to deliver. Close instead of retrying forever.
					if now.Sub(pkt.firstSent) > 60*time.Second {
						c.unackedMu.Unlock()
						zlog.Warnf("%s [UDPCConn] ⚠️ Packet seq=%d max retransmit window exceeded (60s), closing connection", TAG, pkt.frame.Seq)
						c.Close()
						return
					}
					pkt.sentTime = now
					pkt.retries++
					if pkt.retries == 1 {
						pkt.retransmitted = true // flagged on the first retry; later retries are not sampled
					}
					pkt.rto = time.Duration(float64(pkt.rto) * 1.5) // back off 1.5x from the adaptive RTO
					if pkt.rto > c.rttEst.maxRTT {
						pkt.rto = c.rttEst.maxRTT
					}
					// Piggyback our ack so the peer learns our progress even when
					// the pure ACKs are being lost. Must be ackFor(), not
					// recvSeq: recvSeq is the next EXPECTED sequence, which we
					// have not actually received, and advertising it would make
					// the peer retire a genuinely outstanding packet.
					pkt.frame.Ack = c.ackFor()
					c.writeMu.Lock()
					_, werr := c.baseConn.Write(pkt.frame.Encode())
					c.writeMu.Unlock()

					// Retransmissions are the primary symptom of a broken port
					// range: the client keeps spreading but nothing comes back.
					// Head-sample the first ones, then 1-in-50.
					if rt := atomic.AddUint64(&c.retrans, 1); rt <= 10 || rt%50 == 0 {
						zlog.Debugf("%s [UDPCConn 0x%08X] 🔁 #%d retransmit seq=%d attempt=%d rto=%v err=%v",
							TAG, c.sessionID, rt, pkt.frame.Seq, pkt.retries, pkt.rto, werr)
					}
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
		if chunkSize > UDPC_MAX_CHUNK {
			chunkSize = UDPC_MAX_CHUNK
		}
		chunk := b[:chunkSize]

		seq := atomic.AddUint32(&c.sendSeq, 1) - 1
		now := time.Now()

		dataToSend := chunk
		if c.noiseSession != nil && c.noiseSession.SendCipher != nil {
			// Nonce = Seq: retransmissions reuse the same ciphertext AND
			// nonce, which is exactly what the server expects.
			dataToSend = c.noiseSession.SendCipher.EncryptWithSeq(seq, chunk)
		}

		frame := &UDPCFrame{
			Magic:      c.magic,
			Version:    UDPC_VERSION,
			Cmd:        CMD_DATA,
			SessionID:  c.sessionID,
			Seq:        seq,
			Ack:        c.ackFor(), // highest contiguous received, never the next expected
			WindowSize: 65535,
			Data:       dataToSend,
		}

		c.unackedMu.Lock()
		c.unacked[seq] = &unackedPacket{
			frame:     frame,
			firstSent: now,
			sentTime:  now,
			rto:       c.rttEst.RTO(), // adaptive RTO replaces the old fixed 500ms
			retries:   0,
		}
		c.unackedMu.Unlock()

		if !c.writeDead.IsZero() && time.Now().After(c.writeDead) {
			return total, errors.New("i/o timeout")
		}

		c.writeMu.Lock()
		n, err := c.baseConn.Write(frame.Encode())
		c.writeMu.Unlock()

		if err != nil {
			zlog.Warnf("%s [UDPCConn 0x%08X] ❌ write seq=%d len=%d failed: %v",
				TAG, c.sessionID, seq, len(dataToSend), err)
			return total, err
		}
		atomic.AddUint64(&c.txPkts, 1)
		if tx := atomic.LoadUint64(&c.txPkts); tx <= 32 || tx%200 == 0 {
			zlog.Debugf("%s [UDPCConn 0x%08X] 📤 #%d DATA seq=%d ack=%d payload=%d wire=%d",
				TAG, c.sessionID, tx, seq, frame.Ack, len(dataToSend), n)
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

func parseUDPCMagic(s string) uint32 {
	if len(s) == 0 {
		return UDPC_MAGIC_DEFAULT
	}
	if len(s) == 4 {
		return binary.BigEndian.Uint32([]byte(s))
	}
	return UDPC_MAGIC_DEFAULT
}

func init() {
	RegisterTunnel("udp_custom", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		target := cfg.ProxyAddr
		if target == "" {
			target = cfg.SshAddr
		}
		zlog.Infof("%s [Tunnel] 2. Preparing UDPCustom v1.0 Handshake with %s", TAG, target)

		password := strings.TrimSpace(cfg.UdpCustomPsk)
		if password == "" {
			password = strings.TrimSpace(cfg.Pass)
		}
		magic := parseUDPCMagic(cfg.UdpCustomMagic)
		zlog.Infof("%s [Tunnel] 2. Handshake auth: PSK configured=%v (len=%d), Magic=0x%08X", TAG, password != "", len(password), magic)

		// Noise_NK setup. The SYN/ACK exchange itself runs in performHandshake
		// over a bootstrap socket. The server does NOT advertise ports: path
		// selection is entirely client-driven — the client picks its own random
		// ports from the configured range and the server mirrors each one back via
		// IP_RECVORIGDSTADDR.
		pubKeyStr := cfg.UdpCustomPublicKey
		if pubKeyStr == "" {
			pubKeyStr = cfg.NoisePublicKey
		}
		var nk *ClientNK
		if pubKeyStr != "" {
			if pk, err := ParseNoiseKey(pubKeyStr); err == nil {
				if clientNK, err := NewClientNK(pk); err == nil {
					nk = clientNK
					zlog.Infof("%s [Tunnel] 🔐 UDPCustom Noise_NK AEAD encryption enabled", TAG)
				} else {
					zlog.Warnf("%s [Tunnel] ⚠️ Noise_NK init failed: %v", TAG, err)
				}
			} else {
				zlog.Warnf("%s [Tunnel] ⚠️ invalid UDPCustom public key %q", TAG, pubKeyStr)
			}
		}

		// Resolve the target into host, the bootstrap (primary) port, and the full
		// candidate port set. The target is the client-facing address the server's
		// gen-uri emits, of the form "host:port_range" (e.g. "1.2.3.4:25000-26000");
		// the port range is the single source of truth the firewall DNATs onto the
		// server's listen port. When a port range is present the client selects its
		// own N ports from it; otherwise it falls back to the framework-provided
		// single socket. (A "host:primary,range" form with an explicit bootstrap
		// port is also accepted.)
		host, primaryPort, portCandidates, perr := ParseServerAddrWithRange(target)
		if perr != nil {
			host, primaryPort = hostAndPrimary(target)
			portCandidates = []int{primaryPort}
		}

		var (
			sessionID uint32
			noiseSess *NoiseSession
		)

		var transport net.Conn
		if len(portCandidates) <= 1 {
			// Single-path target (no port range, or a legacy single-port server):
			// the handshake AND the data share ONE socket (baseConn), so the server
			// echoes back to the exact socket we read from. This is what a
			// single-port deployment does, and it is required for the in-process
			// interop server, which records the handshake source as its reply
			// address. Burning a separate bootstrap port here would make the reply
			// land on a closed socket and the connection would stall.
			sid, ns, herr := performHandshake(parentCtx, baseConn, cfg, magic, nk)
			if herr != nil {
				zlog.Errorf("%s [Tunnel] ❌ UDPCustom handshake failed: %v", TAG, herr)
				return nil, herr
			}
			sessionID, noiseSess = sid, ns
			transport = baseConn
			zlog.Infof("%s [Tunnel] ℹ️ No port range in target %q; using single-path transport", TAG, target)
		} else {
			// Port range configured: a dedicated bootstrap socket carries the
			// handshake, then N client-selected paths carry the data. The client is
			// the source of truth for path selection — it picks N random ports from
			// the range and opens one connected socket per port. The firewall DNATs
			// the whole range onto the server's single listening port; the server
			// recovers each packet's original destination port (IP_RECVORIGDSTADDR)
			// and replies FROM that port, so every path's reply is accepted by the
			// client's CGNAT.
			bootstrap, berr := dialUDP(parentCtx, cfg, fmt.Sprintf("%s:%d", host, primaryPort))
			if berr != nil {
				zlog.Errorf("%s [Tunnel] ❌ Failed to dial bootstrap %s:%d: %v", TAG, host, primaryPort, berr)
				return nil, berr
			}
			defer bootstrap.Close()

			sid, ns, herr := performHandshake(parentCtx, bootstrap, cfg, magic, nk)
			if herr != nil {
				zlog.Errorf("%s [Tunnel] ❌ UDPCustom handshake failed: %v", TAG, herr)
				return nil, herr
			}
			sessionID, noiseSess = sid, ns

			n := cfg.UdpCustomPaths
			if n <= 0 {
				n = udpCustomDefaultPaths
			}
			chosen := pickRandomPorts(portCandidates, n)
			paths, perr2 := openMultipath(parentCtx, cfg, host, chosen)
			if perr2 != nil {
				zlog.Errorf("%s [Tunnel] ❌ Failed to open %d multi-path ports: %v", TAG, len(chosen), perr2)
				return nil, perr2
			}
			// We use our own N-path transport; close the unused framework socket.
			baseConn.Close()
			transport = newMultipathConn(paths)
			zlog.Infof("%s [Tunnel] 🛣️ Multi-path transport ready: %d client-selected paths from range %s to %s",
				TAG, len(paths), FormatPortList(portCandidates), host)
		}

		zlog.Infof("%s [Tunnel] ✅ UDPCustom v1.0 Handshake successful! SessionID: 0x%08X", TAG, sessionID)
		return newUDPCConn(transport, transport.RemoteAddr(), sessionID, magic, password, false, noiseSess), nil
	})
}
