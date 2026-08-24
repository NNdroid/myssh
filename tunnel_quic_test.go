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

// newTestQUICTLSConfig 生成自签名证书，供 QUIC 回声服务端使用。
// 客户端隧道默认 InsecureSkipVerify=true，因此自签名即可，无需可信链。
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
		NextProtos:   []string{"h3"}, // 与客户端 ALPN 伪裝保持一致
	}
}

// TestQUICEchoRoundTrip 验证 quic 隧道：通过真实 QUIC 服务端回声，确认握手、
// 双向字节流透传以及 Padding 封装均正常。
func TestQUICEchoRoundTrip(t *testing.T) {
	// 重置全局连接缓存，避免复用上一用例的物理连接。
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

	// 服务端：接受连接与流，原样回声（含 Padding 帧）。
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

	// 客户端：baseConn 必须是 *net.UDPConn，handler 在其上做 QUIC 拨号。
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

	// 双向并发回声：上行写 -> 服务端回声 -> 下行读。
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

	// 清理底层 QUIC 连接（handler 刻意保留供多工复用，不会随 conn.Close 关闭），避免 goleak 报泄漏。
	defer func() {
		if v, ok := quicConnCache.Load(serverAddr); ok {
			_ = v.(*quic.Conn).CloseWithError(0, "test end")
			quicConnCache.Delete(serverAddr)
		}
		_ = baseConn.Close()
	}()
}

// TestQUICNonUDPConn 验证当底层 baseConn 不是 *net.UDPConn 时，handler 立即返回错误，
// 而非尝试在错误类型上做 QUIC 拨号（保护 socket 类型前置检查分支）。
func TestQUICNonUDPConn(t *testing.T) {
	quicConnCache = sync.Map{}
	defer func() { quicConnCache = sync.Map{} }()

	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}
	// fakeConn 实现 net.Conn 但不是 *net.UDPConn。
	if _, err := proto.Handler(context.Background(), ProxyConfig{ProxyAddr: "127.0.0.1:443"}, &fakeConn{}); err == nil {
		t.Fatal("expected error for non-UDPConn baseConn, got nil")
	}
}

// TestQUICRegistration 验证 quic 协议已注册且底层网络类型为 udp。
func TestQUICRegistration(t *testing.T) {
	proto, err := GetTunnel("quic")
	if err != nil {
		t.Fatalf("GetTunnel(quic): %v", err)
	}
	if proto.Network != "udp" {
		t.Fatalf("quic network = %q, want \"udp\"", proto.Network)
	}
}
