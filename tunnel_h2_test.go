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

// startH2CEchoServer  info  h2c（ info  HTTP/2） info ， info clienttunnel info bidirectional info 。
// clienttunnel info downlink info  WrapWithPadding  info ， info 、
//
//	info ， info client info 。 info mode： info uplink（ info ） info （ info 、Flush）。
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
				// http2.Server.ServeConn  info 「 info 」mode info ：client info send h2c  info ，
				//  info ， info  TLS。
				srv := &http2.Server{}
				srv.ServeConn(c, &http2.ServeConnOpts{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						//  info send 200  info  Flush —— x/net/http2  info default info ，
						//  info  Flush  info client client.Do  info timeout。
						w.WriteHeader(http.StatusOK)
						fl, _ := w.(http.Flusher)
						if fl != nil {
							fl.Flush()
						}
						//  info ： info uplink ->  info  Flush， info downlink info 。
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

// TestH2CStreamBidirectional  info  h2c tunnel：Handshake successful、downlink（ info →client） info uplink
// （client→ info ）bidirectionalbytes info ， info  Padding  info 。
func TestH2CStreamBidirectional(t *testing.T) {
	addr, stop := startH2CEchoServer(t)
	defer stop()

	//  info ， info 。
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
	// h2 client info  TCP  info ，conn.Close  info closed info ；
	//  info closed baseConn  info ， info  goleak  info 。
	defer baseConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil {
		t.Fatalf("h2c handler: %v", err)
	}
	defer conn.Close()

	// uplink + downlink info ：EC HO mode info  net/http client info send info ，
	//  info ， info  client→server→client  info 。
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

// TestH2TLSHandshakeError  info  h2（TLS） info failed info ，
//
//	info 。 info  TLS  info failed info （ info  TLS  info ）。
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

// TestH2TransportCacheInvalidation  info ，
//
//	info  key  info （ info ）。
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

	//  info ， info  client。
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
