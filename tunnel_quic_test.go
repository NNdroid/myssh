package myssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// newTestQUICTLSConfig  info ， info  QUIC  info 。
// clienttunneldefault InsecureSkipVerify=true， info ， info 。
func newTestQUICTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa gen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 key pair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"}, //  info client ALPN  info
	}
}

// TestQUICEchoRoundTrip  info  quic tunnel： info  QUIC  info ， info 、
// bidirectionalbytes info  Padding  info 。
func TestQUICEchoRoundTrip(t *testing.T) {
	//  info ， info 。
	quicConnCache = sync.Map{}
	defer func() { quicConnCache = sync.Map{} }()

	ln, err := quic.ListenAddr("127.0.0.1:0", newTestQUICTLSConfig(t), &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	serverAddr := ln.Addr().String()
	defer ln.Close()

	//  info ： info ， info （ info  Padding  info ）。
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = io.Copy(stream, stream)
	}()

	// client：baseConn  info  *net.UDPConn，handler  info  QUIC  info 。
	baseConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	cfg := ProxyConfig{ProxyAddr: serverAddr, ServerName: "localhost"}
	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		t.Fatalf("quic handler: %v", err)
	}
	defer conn.Close()

	// bidirectional info ：uplink info  ->  info  -> downlink info 。
	up := []byte("SSH-2.0-myssh-quic-roundtrip-11223344556677889900AABBCCDDEEFF")
	writeDone := make(chan error, 1)
	go func() {
		_, werr := conn.Write(up)
		writeDone <- werr
	}()

	got := make([]byte, 0, len(up))
	buf := make([]byte, 512)
	for len(got) < len(up) {
		n, rerr := conn.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	if werr := <-writeDone; werr != nil {
		t.Fatalf("write: %v", werr)
	}
	if string(got) != string(up) {
		t.Fatalf("echo mismatch: got %q want %q", got, up)
	}

	// cleanup info  QUIC  info （handler  info ， info  conn.Close closed）， info  goleak  info 。
	defer func() {
		if v, ok := quicConnCache.Load(serverAddr); ok {
			_ = v.(*quic.Conn).CloseWithError(0, "test end")
			quicConnCache.Delete(serverAddr)
		}
		_ = baseConn.Close()
	}()
}

// TestQUICNonUDPConn  info  baseConn  info  *net.UDPConn  info ，handler  info ，
//
//	info  QUIC  info （ info  socket  info ）。
func TestQUICNonUDPConn(t *testing.T) {
	quicConnCache = sync.Map{}
	defer func() { quicConnCache = sync.Map{} }()

	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}
	// fakeConn  info  net.Conn  info  *net.UDPConn。
	if _, err := proto.Handler(context.Background(), ProxyConfig{ProxyAddr: "127.0.0.1:443"}, &fakeConn{}); err == nil {
		t.Fatal("expected error for non-UDPConn baseConn, got nil")
	}
}

// TestQUICRegistration  info  quic  info  udp。
func TestQUICRegistration(t *testing.T) {
	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}
	if proto.Network != "udp" {
		t.Fatalf("quic network = %q, want \"udp\"", proto.Network)
	}
}
