package myssh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// startTLSCertProbeServer 起一个绑定 127.0.0.1 的临时 crypto/tls 服务器，
// 供证书探测路径测试使用。alpn 为空时不宣告 ALPN（模拟不协商 ALPN 的前置代理）。
// 返回监听地址。
func startTLSCertProbeServer(t *testing.T, alpn []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "probe.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              []string{"probe.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	if len(alpn) > 0 {
		srvCfg.NextProtos = alpn
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
				}
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// ip4POf 把 (IPv4, port) 编码成 2001:: 前缀的 IP4P 字面量地址。
//
// 写成 :0 是刻意的：IP4P 形态下真实端口由地址本身携带，host:port 里的端口字段
// 只是占位，运行时由 resolveIP4PDialAddress 换成解出来的端口。
func ip4POf(t *testing.T, ipv4 net.IP, port int) string {
	t.Helper()
	v4 := ipv4.To4()
	if v4 == nil {
		t.Fatalf("%v is not IPv4", ipv4)
	}
	literal := net.IP(make([]byte, 16))
	literal[0], literal[1] = 0x20, 0x01
	literal[10], literal[11] = byte(port>>8), byte(port)
	copy(literal[12:], v4)
	return net.JoinHostPort(literal.String(), "0")
}

// TestProbeTLSCertResolvesIP4P 是「raw + TLS 无法获取证书」的回归测试。
//
// 运行时隧道的拨号走 dialTunnel → dialTCP → dialSocket → resolveIP4PDialAddress，
// 会解开 IP4P 形态的 proxy_addr；而证书探测此前用裸 net.Dialer 直接拨，拿到的还是
// 那个端口为 0 的 IPv6 字面量——connect 在握手之前就失败，证书根本拿不到。
// 于是表现是：隧道能连、SSH 能通，唯独「获取指纹/详情」永远报错。
//
// 这里用 IP4P 字面量指向 127.0.0.1 上的测试服务器：修复前必败，修复后必须解出
// 真实端口并握手成功。
func TestProbeTLSCertResolvesIP4P(t *testing.T) {
	addr := startTLSCertProbeServer(t, []string{"h2", "http/1.1"})
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	target := ip4POf(t, net.ParseIP(host), port)

	details, err := probeTLSCert(target, "probe.local", "")
	if err != nil {
		t.Fatalf("probeTLSCert(%s) via IP4P failed: %v", target, err)
	}
	if details.FingerprintSHA256 == "" {
		t.Fatalf("probeTLSCert(%s) returned an empty fingerprint", target)
	}
	if details.NegotiatedProtocol != "h2" {
		t.Errorf("negotiated ALPN = %q, want %q", details.NegotiatedProtocol, "h2")
	}
}

// TestProbeTLSCertServerWithoutALPN 服务端不宣告 ALPN 时探测仍然要成功：
// uTLS 的 checkALPN 只在「客户端宣告了 ALPN 而服务端一个都没选」时放行，
// 所以这类服务器（很多简易 TLS 前置代理）本来就能过，不能被 ALPN 改动打破。
func TestProbeTLSCertServerWithoutALPN(t *testing.T) {
	addr := startTLSCertProbeServer(t, nil)
	details, err := probeTLSCert(addr, "probe.local", "")
	if err != nil {
		t.Fatalf("probeTLSCert(%s) against a server without ALPN failed: %v", addr, err)
	}
	if details.FingerprintSHA256 == "" {
		t.Fatalf("empty fingerprint")
	}
	if details.NegotiatedProtocol != "" {
		t.Errorf("negotiated ALPN = %q, want empty", details.NegotiatedProtocol)
	}
}
