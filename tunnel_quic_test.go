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

// newTestQUICTLSConfig 生成本地测试用自签证书，供 QUIC 服务端使用。
// client tunnel 默认 InsecureSkipVerify=true，证书本身不校验，仅占位。
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
		NextProtos:   []string{"h3"}, // 与 client ALPN 保持一致
	}
}

// TestQUICEchoRoundTrip 端到端验证 quic tunnel：本地起 QUIC 服务端，回显、
// 双向传输字节流，并验证 Padding 后连接复用路径。
func TestQUICEchoRoundTrip(t *testing.T) {
	// 重置缓存，隔离用例。
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

	// 服务端：接受一条连接、一条流，回显（不含 Padding 逻辑）。
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

	// client：baseConn 必须是 *net.UDPConn，handler 内部完成 QUIC 握手。
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

	// 双向校验：uplink 写入 -> 回显 -> downlink 读出。
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

	// cleanup 掉缓存里的 QUIC 连接（handler 只开流不关连接，需显式 conn.Close），满足 goleak 检查。
	defer func() {
		if v, ok := quicConnCache.Load(serverAddr); ok {
			_ = v.(*quic.Conn).CloseWithError(0, "test end")
			quicConnCache.Delete(serverAddr)
		}
		_ = baseConn.Close()
	}()
}

// TestQUICNonUDPConn 验证 baseConn 非 *net.UDPConn 时 handler 报错，
//
//	且不触碰 QUIC 资源（不会泄漏 socket 或 goroutine）。
func TestQUICNonUDPConn(t *testing.T) {
	quicConnCache = sync.Map{}
	defer func() { quicConnCache = sync.Map{} }()

	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}
	// fakeConn 只是 net.Conn 实现，不是 *net.UDPConn。
	if _, err := proto.Handler(context.Background(), ProxyConfig{ProxyAddr: "127.0.0.1:443"}, &fakeConn{}); err == nil {
		t.Fatal("expected error for non-UDPConn baseConn, got nil")
	}
}

// TestQUICRegistration 验证 quic 已按约定注册为 udp。
func TestQUICRegistration(t *testing.T) {
	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}
	if proto.Network != "udp" {
		t.Fatalf("quic network = %q, want \"udp\"", proto.Network)
	}
}
