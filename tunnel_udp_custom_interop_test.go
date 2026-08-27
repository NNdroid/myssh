package myssh

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// testServer is a minimal in-process udp_custom server that implements the
// exact handshake + transport the real udp_custom server uses. It exists to
// prove the myssh client (tunnel_udp_custom.go) interoperates with a
// conformant server: standard Noise_NK (msg1 in the SYN, msg2 in the ACK) and
// Seq-derived AEAD nonces. It echoes every client payload back so the test can
// verify a full encrypted round trip.
type testServer struct {
	conn     *net.UDPConn
	addrStr  string
	priv     [32]byte
	psk      string
	magic    uint32
	useNoise bool

	mu         sync.Mutex
	sess       *NoiseSession
	msg2       []byte // server message 2 to return in the handshake ACK
	sid        uint32
	cliRecvSeq uint32
	srvSendSeq uint32
	raddr      *net.UDPAddr
	unacked    map[uint32][]byte // server->client echo frames awaiting client ACK

	closeOnce sync.Once
	closeCh   chan struct{}
}

func newTestServer(priv [32]byte, psk string, magic uint32, useNoise bool) *testServer {
	return &testServer{
		priv:     priv,
		psk:      psk,
		magic:    magic,
		useNoise: useNoise,
		unacked:  make(map[uint32][]byte),
		closeCh:  make(chan struct{}),
	}
}

func (s *testServer) start(t *testing.T) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	s.conn = pc
	s.addrStr = pc.LocalAddr().String()
	go s.run()
	go s.retransmitLoop()
}

func (s *testServer) stop() {
	s.closeOnce.Do(func() { close(s.closeCh); _ = s.conn.Close() })
}

func (s *testServer) run() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closeCh:
				return
			default:
				continue
			}
		}
		frame, err := DecodeUDPCFrame(buf[:n], s.magic)
		if err != nil {
			continue
		}
		switch frame.Cmd {
		case CMD_HANDSHAKE_SYN:
			s.handleSyn(frame, addr)
		case CMD_FIN:
			s.stop()
			return
		}
		if frame.SessionID != s.sid {
			continue
		}
		switch frame.Cmd {
		case CMD_DATA:
			s.handleData(frame)
		case CMD_ACK:
			s.handleAck(frame.Ack)
		case CMD_PING:
			ack := (&UDPCFrame{Magic: s.magic, Version: UDPC_VERSION, Cmd: CMD_PONG,
				SessionID: s.sid, Seq: frame.Seq, Ack: s.cliRecvSeq - 1})
			s.write(ack.Encode())
		}
	}
}

func (s *testServer) handleSyn(frame *UDPCFrame, addr *net.UDPAddr) {
	if len(frame.Data) < 56 {
		return
	}
	nonce := frame.Data[0:16]
	ts := int64(binary.BigEndian.Uint64(frame.Data[16:24]))
	sig := frame.Data[24:56]
	if !verifyHMAC(nonce, s.psk, ts, sig) {
		return
	}
	now := time.Now().Unix()
	if ts < now-300 || ts > now+300 {
		return
	}
	if s.useNoise {
		if len(frame.Data) < 56+noiseMsg1Size {
			return
		}
		sess, msg2, err := NewServerNoiseSession(s.priv, frame.Data[56:56+noiseMsg1Size])
		if err != nil {
			return
		}
		s.sess = sess
		s.msg2 = msg2
	} else {
		if len(frame.Data) != 56 {
			return
		}
	}
	s.raddr = addr
	s.cliRecvSeq = 1
	s.srvSendSeq = 1
	s.unacked = make(map[uint32][]byte)

	var b [4]byte
	_, _ = rand.Read(b[:])
	s.sid = binary.BigEndian.Uint32(b[:])
	if s.sid == 0 {
		s.sid = 1
	}

	ack := &UDPCFrame{Magic: s.magic, Version: UDPC_VERSION, Cmd: CMD_HANDSHAKE_ACK, SessionID: s.sid}
	if s.useNoise {
		// In the real server msg2 is derived from the client's msg1; here we
		// already produced it inside NewServerNoiseSession and stashed it on
		// the session for the test. We recompute it by re-running the
		// handshake is overkill, so store it on the server struct instead.
		ack.Data = s.msg2
	}
	s.write(ack.Encode())
}

func (s *testServer) handleData(frame *UDPCFrame) {
	if frame.Seq != s.cliRecvSeq {
		// Only the in-order head is processed in this echo test; out-of-order
		// frames are simply ignored (the client keeps them outstanding and
		// retransmits the head).
		return
	}
	var plain []byte
	if s.useNoise {
		p, err := s.sess.RecvCipher.DecryptWithSeq(frame.Seq, frame.Data)
		if err != nil {
			return
		}
		plain = p
	} else {
		plain = frame.Data
	}
	s.cliRecvSeq++

	// Cumulative ACK for the client frame we just delivered.
	s.write((&UDPCFrame{Magic: s.magic, Version: UDPC_VERSION, Cmd: CMD_ACK,
		SessionID: s.sid, Ack: frame.Seq, WindowSize: 65535}).Encode())

	// Echo the payload back to the client as a server DATA frame.
	seq := s.srvSendSeq
	s.srvSendSeq++
	var ct []byte
	if s.useNoise {
		ct = s.sess.SendCipher.EncryptWithSeq(seq, plain)
	} else {
		ct = plain
	}
	enc := (&UDPCFrame{Magic: s.magic, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: s.sid, Seq: seq, Ack: s.cliRecvSeq - 1, Data: ct}).Encode()
	s.mu.Lock()
	s.unacked[seq] = enc
	s.mu.Unlock()
	s.write(enc)
}

func (s *testServer) handleAck(ackSeq uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for seq := range s.unacked {
		if int32(seq-ackSeq) <= 0 {
			delete(s.unacked, seq)
		}
	}
}

func (s *testServer) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			for _, enc := range s.unacked {
				s.write(enc)
			}
			s.mu.Unlock()
		}
	}
}

func (s *testServer) write(b []byte) {
	if s.raddr == nil {
		return
	}
	_, _ = s.conn.WriteToUDP(b, s.raddr)
}

func verifyHMAC(nonce []byte, password string, timestamp int64, clientSig []byte) bool {
	expected := ComputeAuthHMAC(nonce, password, timestamp)
	return hmac.Equal(expected, clientSig)
}

// runScenario drives one full client<->server round trip.
func runUDPCustomScenario(t *testing.T, useNoise bool) {
	t.Helper()
	initLoggerIfNeed()

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubHex, _ := FormatNoiseKey(kp.PublicKey)
	psk := "test-shared-secret"

	srv := newTestServer(kp.PrivateKey, psk, UDPC_MAGIC_DEFAULT, useNoise)
	srv.start(t)
	defer srv.stop()

	raddr, err := net.ResolveUDPAddr("udp", srv.addrStr)
	if err != nil {
		t.Fatal(err)
	}
	baseConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}

	cfg := ProxyConfig{
		ProxyAddr:          srv.addrStr,
		SshAddr:            srv.addrStr,
		UdpCustomPsk:       psk,
		UdpCustomMagic:     "UDPC",
		UdpCustomPublicKey: pubHex,
	}
	if !useNoise {
		cfg.UdpCustomPublicKey = "" // open mode, no encryption
	}

	proto, err := GetTunnel("udp_custom")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := proto.Handler(context.Background(), cfg, baseConn)
	if err != nil {
		t.Fatalf("udp_custom tunnel handshake failed: %v", err)
	}
	defer conn.Close()

	// Multiple writes of varying sizes to exercise chunking + ordering.
	messages := [][]byte{
		[]byte("hello udp_custom over noise!"),
		bytes.Repeat([]byte("A"), 2000), // crosses the chunk boundary
		[]byte("final-frame"),
	}
	for _, msg := range messages {
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("client write failed: %v", err)
		}
		buf := make([]byte, 4096)
		got := buf[:0]
		deadline := time.Now().Add(5 * time.Second)
		for len(got) < len(msg) {
			conn.SetReadDeadline(deadline)
			n, rerr := conn.Read(buf[len(got):])
			if rerr != nil {
				t.Fatalf("client read failed (want %d bytes, got %d): %v", len(msg), len(got), rerr)
			}
			got = append(got, buf[len(got):len(got)+n]...)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("echo mismatch: got %q want %q", got, msg)
		}
	}
}

func TestUDPCustomInterop_NoiseHandshake(t *testing.T) {
	runUDPCustomScenario(t, true)
}

func TestUDPCustomInterop_OpenHandshake(t *testing.T) {
	runUDPCustomScenario(t, false)
}
