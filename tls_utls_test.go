package myssh

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// startChromeTestTLSServer 启动一个绑定 127.0.0.1 的临时 crypto/tls 服务端，
// 使用与 QUIC 测试相同的自签 "localhost" 证书，协商 alpn。返回监听地址，
// 每次接受连接时主动完成握手后关闭，供 newChromeUConn 客户端测试使用。
func startChromeTestTLSServer(t *testing.T, alpn []string) string {
	t.Helper()
	base := newTestQUICTLSConfig(t)
	srvCfg := &tls.Config{Certificates: base.Certificates, NextProtos: alpn}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(tc *tls.Conn) {
				defer tc.Close()
				if err := tc.Handshake(); err != nil {
					return
				}
				// 读取至 EOF 或超时，让客户端能正常取到连接状态后结束。
				_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.Copy(io.Discard, tc)
			}(c.(*tls.Conn))
		}
	}()
	return ln.Addr().String()
}

func TestNewChromeUConnNegotiatesAndReadsPeerCert(t *testing.T) {
	addr := startChromeTestTLSServer(t, []string{"dot"})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	uConn, err := newChromeUConn(ctx, conn, "localhost", []string{"dot"}, nil, false)
	if err != nil {
		t.Fatalf("chrome handshake: %v", err)
	}
	defer uConn.Close()

	st := uConn.ConnectionState()
	if st.NegotiatedProtocol != "dot" {
		t.Errorf("negotiated ALPN = %q, want %q", st.NegotiatedProtocol, "dot")
	}
	if st.Version != tls.VersionTLS13 {
		t.Errorf("TLS version = %d, want TLS1.3", st.Version)
	}
	if len(st.PeerCertificates) == 0 {
		t.Fatalf("no peer certificates returned by uTLS handshake")
	}
	if st.PeerCertificates[0].Subject.CommonName != "localhost" {
		t.Errorf("peer cert CN = %q, want %q", st.PeerCertificates[0].Subject.CommonName, "localhost")
	}
}

// strictVerify=false 探测场景可信任自签；strictVerify=true 则必须被系统根拒绝，
// 证明 helper 的校验开关语义与 crypto/tls 一致，DoT 不会退化成明文信任。
func TestNewChromeUConnStrictVerifyRejectsSelfSigned(t *testing.T) {
	addr := startChromeTestTLSServer(t, []string{"dot"})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	uConn, err := newChromeUConn(ctx, conn, "localhost", []string{"dot"}, nil, true)
	if err == nil {
		uConn.Close()
		t.Fatalf("expected verification failure against self-signed cert with strictVerify=true")
	}
	// 必须是证书校验失败，而非 ALPN 协商失败——后者说明 helper 的 ALPN 覆盖没生效。
	if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate verification error, got: %v", err)
	}
}

func TestNewChromeUConnWithSessionCache(t *testing.T) {
	addr := startChromeTestTLSServer(t, []string{"dot"})
	cache := utls.NewLRUClientSessionCache(8)

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	uConn1, err := newChromeUConn(c1, first, "localhost", []string{"dot"}, cache, false)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	uConn1.Close()

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	uConn2, err := newChromeUConn(c2, second, "localhost", []string{"dot"}, cache, false)
	if err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	defer uConn2.Close()
	if uConn2.ConnectionState().NegotiatedProtocol != "dot" {
		t.Errorf("session-cache handshake ALPN = %q, want %q", uConn2.ConnectionState().NegotiatedProtocol, "dot")
	}
}

// TestChromeSpecWithALPN 钉住改写函数的两个契约：未指定 alpn 时保持 Chrome
// 模板默认（["h2","http/1.1"]——这正是 wss 走 handshakeUTLS 时 h2 会上线路的
// 根源），指定时只替换 ALPNExtension、其余扩展原样保留。
func TestChromeSpecWithALPN(t *testing.T) {
	defaultSpec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("build default spec: %v", err)
	}
	var defaultAlpn *utls.ALPNExtension
	for _, ext := range defaultSpec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			defaultAlpn = a
		}
	}
	if defaultAlpn == nil {
		t.Fatal("Chrome template carries no ALPNExtension")
	}
	if strings.Join(defaultAlpn.AlpnProtocols, ",") != "h2,http/1.1" {
		t.Errorf("Chrome template ALPN = %v, want [h2 http/1.1]", defaultAlpn.AlpnProtocols)
	}

	spec, err := chromeSpecWithALPN([]string{"http/1.1"})
	if err != nil {
		t.Fatalf("chromeSpecWithALPN: %v", err)
	}
	alpnCount := 0
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			alpnCount++
			if strings.Join(a.AlpnProtocols, ",") != "http/1.1" {
				t.Errorf("rewritten spec ALPN = %v, want [http/1.1]", a.AlpnProtocols)
			}
		}
	}
	if alpnCount != 1 {
		t.Errorf("rewritten spec ALPNExtension count = %d, want 1", alpnCount)
	}
	if len(spec.Extensions) != len(defaultSpec.Extensions) {
		t.Errorf("rewritten spec must keep Chrome extension set: got %d exts, want %d", len(spec.Extensions), len(defaultSpec.Extensions))
	}
}

// TestHandshakeUTLSWithSpecRewritesALPNOnWire 走完整握手验证改写真的上了线路：
// 服务端按自身偏好顺序宣告 ["h2","http/1.1"]（Go 服务端按服务端顺序选择），
// 客户端只有宣告 ["http/1.1"] 才会协商出 http/1.1；若改写未生效、客户端仍按
// 模板宣告 h2+http/1.1，这里会协商出 h2——正是 wss 在 h2 优先 CDN 上握不上手
// 的故障形态。
func TestHandshakeUTLSWithSpecRewritesALPNOnWire(t *testing.T) {
	addr := startChromeTestTLSServer(t, []string{"h2", "http/1.1"})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conf := &utls.Config{ServerName: "localhost", InsecureSkipVerify: true}
	spec, err := chromeSpecWithALPN([]string{"http/1.1"})
	if err != nil {
		t.Fatalf("chromeSpecWithALPN: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uConn, err := handshakeUTLSWithSpec(ctx, conn, conf, spec)
	if err != nil {
		t.Fatalf("handshake with rewritten spec: %v", err)
	}
	defer uConn.Close()
	if uConn.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Errorf("negotiated ALPN = %q, want %q (spec rewrite did not reach the wire)", uConn.ConnectionState().NegotiatedProtocol, "http/1.1")
	}
}
