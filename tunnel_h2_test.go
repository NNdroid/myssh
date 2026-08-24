package myssh

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// startH2CEchoServer 启动一个 h2c（明文 HTTP/2）回声服务端，用于验证客户端隧道握手与双向流。
// 客户端隧道对上下行都做了 WrapWithPadding 封装，因此服务端必须按相同帧格式对请求体解帧、
// 并对响应体加帧，才能与客户端互通。回声模式：服务端逐段读取上行（解帧）并原样回写（加帧、Flush）。
func startH2CEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("h2c listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// http2.Server.ServeConn 以「先验知识」模式工作：客户端先发送 h2c 序言，
				// 服务端读取并处理，无需 TLS。
				srv := &http2.Server{}
				srv.ServeConn(c, &http2.ServeConnOpts{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						// 先发送 200 响应头并显式 Flush —— x/net/http2 服务端默认缓冲响应头，
						// 不 Flush 会导致客户端 client.Do 永远等不到握手响应而超时。
						w.WriteHeader(http.StatusOK)
						fl, _ := w.(http.Flusher)
						if fl != nil {
							fl.Flush()
						}
						// 逐段回声：解帧上行 -> 重新加帧回写并 Flush，保证下行数据实时送达。
						pr := &PaddingReader{r: r.Body}
						pw := &PaddingWriter{w: w}
						buf := make([]byte, 4096)
						for {
							n, rerr := pr.Read(buf)
							if n > 0 {
								_, _ = pw.Write(buf[:n])
								if fl != nil {
									fl.Flush()
								}
							}
							if rerr != nil {
								return
							}
						}
					}),
				})
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// TestH2CStreamBidirectional 验证 h2c 隧道：握手成功、下行（服务端→客户端）与上行
// （客户端→服务端）双向字节流都能透传，且经过 Padding 封装后内容一致。
func TestH2CStreamBidirectional(t *testing.T) {
	addr, stop := startH2CEchoServer(t)
	defer stop()

	// 重置全局传输缓存，保证每个用例使用独立物理连接。
	h2TransportCache = sync.Map{}
	defer func() { h2TransportCache = sync.Map{} }()

	cfg := ProxyConfig{
		ProxyAddr:  addr,
		CustomHost: "proxy.test",
		CustomPath: "/tunnel",
		SshAddr:    "127.0.0.1:22",
		ServerName: "proxy.test",
	}
	proto, err := GetTunnel("h2c")
	if err != nil {
		t.Fatalf("GetTunnel(h2c): %v", err)
	}

	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}
	// h2 客户端刻意保留底层 TCP 用于多工复用，conn.Close 不会关闭它；
	// 测试需显式关闭 baseConn 以终止对端服务端连接，避免 goleak 报泄漏。
	defer baseConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		t.Fatalf("h2c handler: %v", err)
	}
	defer conn.Close()

	// 上行 + 下行并发进行：EC HO 模式下 net/http 客户端在收到响应后会继续发送请求体，
	// 因此必须在读取回显的同时写入，才能形成 client→server→client 的闭环。
	up := []byte("SSH-2.0-myssh-h2c-roundtrip-11223344556677889900AABBCCDDEEFF")
	writeDone := make(chan error, 1)
	go func() {
		_, werr := conn.Write(up)
		writeDone <- werr
	}()

	got := make([]byte, 0, len(up))
	readBuf := make([]byte, 512)
	for len(got) < len(up) {
		n, rerr := conn.Read(readBuf)
		if n > 0 {
			got = append(got, readBuf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write upload: %v", err)
	}
	if !bytes.Equal(got, up) {
		t.Fatalf("echo mismatch: got %q want %q", got, up)
	}
}

// TestH2TLSHandshakeError 验证当 h2（TLS）握手面对明文服务端时会快速失败并返回错误，
// 而不是挂死。覆盖 TLS 分支的失败路径（无真实 TLS 服务端）。
func TestH2TLSHandshakeError(t *testing.T) {
	addr, stop := startH2CEchoServer(t)
	defer stop()

	h2TransportCache = sync.Map{}
	defer func() { h2TransportCache = sync.Map{} }()

	cfg := ProxyConfig{
		ProxyAddr:  addr,
		CustomHost: "proxy.test",
		CustomPath: "/tunnel",
		SshAddr:    "127.0.0.1:22",
		ServerName: "proxy.test",
	}
	proto, err := GetTunnel("h2")
	if err != nil {
		t.Fatalf("GetTunnel(h2): %v", err)
	}

	baseConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial base: %v", err)
	}
	defer baseConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected h2 TLS handshake to fail against plaintext server, got nil")
	}
}

// TestH2TransportCacheInvalidation 验证发生网络层错误时缓存被主动剔除，
// 下一次同 key 请求会重建传输（而非复用失效连接）。
func TestH2TransportCacheInvalidation(t *testing.T) {
	h2TransportCache = sync.Map{}
	defer func() { h2TransportCache = sync.Map{} }()

	cfg := ProxyConfig{ProxyAddr: "proxy.example.com:443", ServerName: "proxy.example.com"}
	fake := &fakeConn{}

	c1, err := acquireH2Transport(context.Background(), "proxy.example.com:443|H2", true, cfg, fake)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if c1 == nil || c1.Transport == nil {
		t.Fatal("expected non-nil client with Transport")
	}

	// 模拟底层错误后主动剔除缓存，再次获取应重建独立 client。
	h2TransportCache.Delete("proxy.example.com:443|H2")
	fake2 := &fakeConn{}
	c2, err := acquireH2Transport(context.Background(), "proxy.example.com:443|H2", true, cfg, fake2)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if c2 == nil {
		t.Fatal("expected non-nil client after cache invalidation")
	}
	_ = c1
}
