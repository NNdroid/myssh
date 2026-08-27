package myssh

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Real-server interop: drive the myssh udp_custom *client* primitives against a
// genuine udp_custom server binary (built from E:\GolandProjects\udp_custom) in
// front of a local TCP echo. This is the only test that proves cross-implementation
// wire compatibility — the other interop test uses myssh's own server port.

var (
	udpcBin     string
	udpcBinOnce sync.Once
)

// getUDPCBin resolves a usable udp_custom server binary once, skipping the test
// if none can be located or built.
func getUDPCBin(t *testing.T) string {
	t.Helper()
	udpcBinOnce.Do(func() {
		b, err := ensureUDPCBin()
		if err != nil {
			t.Logf("udp_custom server binary unavailable: %v", err)
			udpcBin = ""
			return
		}
		udpcBin = b
	})
	if udpcBin == "" {
		t.Skip("udp_custom server binary unavailable (set UDPC_BIN or build from E:\\GolandProjects\\udp_custom)")
	}
	return udpcBin
}

// ensureUDPCBin returns a usable udp_custom server binary, preferring an env
// override or the prebuilt binary, and building from source as a last resort.
func ensureUDPCBin() (string, error) {
	if p := os.Getenv("UDPC_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	def := `E:\GolandProjects\udp_custom\bin\udpc.exe`
	if _, err := os.Stat(def); err == nil {
		return def, nil
	}
	src := os.Getenv("UDPC_SRC")
	if src == "" {
		src = `E:\GolandProjects\udp_custom`
	}
	tmp, err := os.CreateTemp("", "udpc-*.exe")
	if err != nil {
		return "", err
	}
	tmp.Close()
	out := tmp.Name()
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = src
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build udp_custom: %v: %s", err, b)
	}
	return out, nil
}

// startTCPEcho returns the listener port and a stop func.
func startTCPEcho(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

type realServerCfg struct {
	Mode        string   `json:"mode"`
	Listen      string   `json:"listen"`
	PortRange   string   `json:"port_range"`
	Target      string   `json:"target"`
	Passwords   []string `json:"passwords"`
	Magic       string   `json:"magic"`
	PrivKey     string   `json:"privkey"`
	LogLevel    string   `json:"log_level"`
	OrigDst     bool     `json:"origdst"`
	SendsockMax int      `json:"sendsock_max"`
}

// startRealServer boots a genuine udp_custom server in front of the TCP echo.
func startRealServer(t *testing.T, privHex string, echoPort int) (udpPort int, stop func()) {
	t.Helper()
	udpPort = 38123
	cfg := realServerCfg{
		Mode:        "server",
		Listen:      fmt.Sprintf("127.0.0.1:%d", udpPort),
		PortRange:   fmt.Sprintf("%d", udpPort),
		Target:      fmt.Sprintf("tcp://127.0.0.1:%d", echoPort),
		Passwords:   []string{"test_psk_123"},
		Magic:       "UDPC",
		PrivKey:     privHex,
		LogLevel:    "warn",
		OrigDst:     false,
		SendsockMax: 512,
	}
	f, err := os.CreateTemp("", "udpc-server-*.json")
	if err != nil {
		t.Fatalf("temp cfg: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		t.Fatalf("encode cfg: %v", err)
	}
	cfgPath := f.Name()

	cmd := exec.Command(udpcBin, "-c", cfgPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	// Give the server time to bind.
	time.Sleep(800 * time.Millisecond)
	return udpPort, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(cfgPath)
	}
}

// runRoundTrip performs a full handshake + encrypted DATA echo against the live
// server using myssh's client primitives, and verifies the echoed bytes match.
func runRoundTrip(t *testing.T, udpPort int, pubHex, psk string, useNoise bool, payload []byte) {
	t.Helper()
	magic := UDPC_MAGIC_DEFAULT

	ua, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var nk *ClientNK
	var noiseSess *NoiseSession
	var msg1 []byte
	if useNoise {
		pk, perr := ParseNoiseKey(pubHex)
		if perr != nil {
			t.Fatalf("parse pubkey: %v", perr)
		}
		clientNK, merr := NewClientNK(pk)
		if merr != nil {
			t.Fatalf("NewClientNK: %v", merr)
		}
		m1, merr := clientNK.Message1()
		if merr != nil {
			t.Fatalf("Message1: %v", merr)
		}
		nk = clientNK
		msg1 = m1
	}

	// SYN with retries (server may still be binding).
	var ackFrame *UDPCFrame
	for attempt := 0; attempt < 6; attempt++ {
		nonce := make([]byte, 16)
		_, _ = io.ReadFull(rand.Reader, nonce)
		now := time.Now().Unix()
		sig := ComputeAuthHMAC(nonce, psk, now)

		payloadBuf := make([]byte, 56+len(msg1))
		copy(payloadBuf[0:16], nonce)
		binary.BigEndian.PutUint64(payloadBuf[16:24], uint64(now))
		copy(payloadBuf[24:56], sig)
		copy(payloadBuf[56:], msg1)

		syn := &UDPCFrame{Magic: magic, Version: UDPC_VERSION, Cmd: CMD_HANDSHAKE_SYN, SessionID: 0, Data: payloadBuf}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(syn.Encode()); err != nil {
			t.Fatalf("syn write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			time.Sleep(400 * time.Millisecond)
			continue
		}
		f, derr := DecodeUDPCFrame(buf[:n], magic)
		if derr != nil || f.Cmd != CMD_HANDSHAKE_ACK {
			t.Fatalf("bad ACK: decode=%v cmd=%d", derr, func() uint8 {
				if f != nil {
					return f.Cmd
				}
				return 0
			}())
		}
		ackFrame = f
		break
	}
	if ackFrame == nil {
		t.Fatalf("no ACK received from real server")
	}

	if useNoise {
		fin, ferr := nk.Finish(ackFrame.Data)
		if ferr != nil {
			t.Fatalf("Finish: %v", ferr)
		}
		noiseSess = fin
	}
	sessionID := ackFrame.SessionID

	// Send DATA (possibly chunked by the client's own framing).
	seq := uint32(1)
	for off := 0; off < len(payload); {
		chunk := payload[off:]
		if len(chunk) > UDPC_MAX_CHUNK {
			chunk = chunk[:UDPC_MAX_CHUNK]
		}
		dataToSend := chunk
		if useNoise && noiseSess != nil && noiseSess.SendCipher != nil {
			dataToSend = noiseSess.SendCipher.EncryptWithSeq(seq, chunk)
		}
		frame := &UDPCFrame{Magic: magic, Version: UDPC_VERSION, Cmd: CMD_DATA, SessionID: sessionID, Seq: seq, Ack: 0, Data: dataToSend}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(frame.Encode()); err != nil {
			t.Fatalf("data write: %v", err)
		}
		off += len(chunk)
		seq++
	}

	// Read the echoed DATA back, decrypt, and verify.
	var got []byte
	seen := map[uint32]bool{}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	for len(got) < len(payload) {
		buf := make([]byte, 2048)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			t.Fatalf("read echo (got %d/%d): %v", len(got), len(payload), rerr)
		}
		f, derr := DecodeUDPCFrame(buf[:n], magic)
		if derr != nil {
			t.Fatalf("decode echo: %v", derr)
		}
		if f.Cmd != CMD_DATA {
			conn.SetReadDeadline(time.Now().Add(8 * time.Second))
			continue
		}
		if seen[f.Seq] {
			conn.SetReadDeadline(time.Now().Add(8 * time.Second))
			continue
		}
		seen[f.Seq] = true
		p := f.Data
		if useNoise && noiseSess != nil && noiseSess.RecvCipher != nil {
			dec, derr := noiseSess.RecvCipher.DecryptWithSeq(f.Seq, f.Data)
			if derr != nil {
				t.Fatalf("decrypt seq %d: %v", f.Seq, derr)
			}
			p = dec
		}
		got = append(got, p...)
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}
}

func TestRealServerInterop_Noise(t *testing.T) {
	getUDPCBin(t)
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	echoPort, stopEcho := startTCPEcho(t)
	defer stopEcho()
	_, stopSrv := startRealServer(t, privHex, echoPort)
	defer stopSrv()

	payload := bytes.Repeat([]byte("udp_custom<->myssh cross-impl "), 120) // ~3.6KB, multi-frame
	runRoundTrip(t, 38123, pubHex, "test_psk_123", true, payload)
}

func TestRealServerInterop_Open(t *testing.T) {
	getUDPCBin(t)
	echoPort, stopEcho := startTCPEcho(t)
	defer stopEcho()
	_, stopSrv := startRealServer(t, "", echoPort)
	defer stopSrv()

	payload := []byte("open-mode echo round trip works")
	runRoundTrip(t, 38123, "", "test_psk_123", false, payload)
}
