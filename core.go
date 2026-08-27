package myssh

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

var (
	Version  = "dev"
	DebugStr = "false"
	Debug    = false
	//  info  TCP io.CopyBuffer  info  64KB  info
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64*1024+1024)
			return &buf
		},
	}
	//  info  UDP  info  64KB  info  ( info / info )
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64*1024+1024)
			return &buf
		},
	}
	//  info  MTU UDP  info  (<=1500bytes)  info  2KB  info ， info  GC  info
	udpSmallBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 2048)
			return &buf
		},
	}
	//  info  bytes.Buffer  info ， info
	bytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	//  info
	padPool    []byte
	padPoolLen = 64 * 1024
	// tcp:  info 。
	//  info  4MB  info / info ， info  1MB  info  BDP  info 。
	tcpOptimizeBufferSize   = 1 * 1024 * 1024
	tcpKeepaliveIntervalSec = 15
)

func init() {
	if DebugStr == "true" {
		Debug = true
	}
	//  info
	padPool = make([]byte, padPoolLen)
	io.ReadFull(rand.Reader, padPool)
}

func tcpRelay(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr

	defer tcpBufPool.Put(bufPtr)

	//  info  CopyBuffer， info
	//  info  src  info  EOF  info
	return io.CopyBuffer(dst, src, buf)
}

// relayStream  info ：
//
//	info  Linux/Android  info  splice(2)  info ；
//	info support info  Socket  info ， info  tcpRelay  info 。
func relayStream(dst, src net.Conn) (int64, error) {
	if n, err := trySplice(dst, src); err == nil {
		return n, nil
	}
	return tcpRelay(dst, src)
}

// formatSHA256Fingerprint  info  SHA-256  info  (XX:XX:XX:...)
func formatSHA256Fingerprint(raw []byte) string {
	sha256Sum := sha256.Sum256(raw)
	var fpBuilder strings.Builder
	for i, b := range sha256Sum {
		if i > 0 {
			fpBuilder.WriteString(":")
		}
		fmt.Fprintf(&fpBuilder, "%02X", b)
	}
	return fpBuilder.String()
}

// ensureHostPort  info address info port， info defaultport
func ensureHostPort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// MakePeerCertVerifier  info
func MakePeerCertVerifier(verifyFingerprint bool, expectedFingerprint string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificates presented by peer")
		}

		//  info ， info ， info
		actualFingerprint := formatSHA256Fingerprint(rawCerts[0])

		//  info ， info  TLS/QUIC  info  INFO  info
		zlog.Debugf("%s [Tunnel] Actual certificate fingerprint: %s", TAG, actualFingerprint)

		if !verifyFingerprint {
			return nil //  info ， info
		}

		zlog.Infof("%s [Tunnel] Expected certificate fingerprint: %s", TAG, expectedFingerprint)

		//  info ： info
		cleanExpected := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(expectedFingerprint, ":", ""), " ", ""))
		cleanActual := strings.ReplaceAll(actualFingerprint, ":", "")

		if cleanExpected != cleanActual {
			return fmt.Errorf("certificate fingerprint mismatch! expected: %s, got: %s", expectedFingerprint, actualFingerprint)
		}

		zlog.Infof("%s [Tunnel] ✅ Peer certificate fingerprint matched successfully", TAG)
		return nil
	}
}

type DumpConn struct {
	net.Conn
	Prefix string
}

func (c *DumpConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		zlog.Debugf("\n--- [%s] ⬇️ Read %d bytes ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

func (c *DumpConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		zlog.Debugf("\n--- [%s] ⬆️ Sent %d bytes ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}
