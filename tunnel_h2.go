package myssh

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// info  HTTP/2  info ， info  (Multiplexing)
var h2TransportCache sync.Map

// ==========================================
// HTTP/2  info  net.Conn  info
// ==========================================
type streamConn struct {
	pw       *io.PipeWriter
	respBody io.ReadCloser
	cancel   context.CancelFunc
	remote   string //  info address， info  net.Conn
}

func (s *streamConn) Read(b []byte) (n int, err error)  { return s.respBody.Read(b) }
func (s *streamConn) Write(b []byte) (n int, err error) { return s.pw.Write(b) }
func (s *streamConn) Close() error {
	s.cancel()
	s.pw.Close()
	return s.respBody.Close()
	// 🚨  info  TCP  info ， info ！
}
func (s *streamConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (s *streamConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", s.remote)
	if addr == nil {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 443}
	}
	return addr
}
func (s *streamConn) SetDeadline(t time.Time) error      { return nil }
func (s *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *streamConn) SetWriteDeadline(t time.Time) error { return nil }

// ==========================================
// gRPC  info
// ==========================================

// gRPC  info ， info  GC  info
var grpcBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024+5) //  info  32KB + 5 bytes Header
		return &b
	},
}

type grpcWriter struct {
	w io.Writer
}

func (g *grpcWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	bufPtr := grpcBufPool.Get().(*[]byte)
	buf := *bufPtr

	//  info  Header  info  Payload  info ， info  H2 Framer  info  DATA  info
	totalLen := len(p) + 5
	if totalLen > cap(buf) {
		buf = make([]byte, totalLen) //  info
	} else {
		buf = buf[:totalLen]
	}

	binary.BigEndian.PutUint32(buf[1:5], uint32(len(p)))
	copy(buf[5:], p)

	_, err = g.w.Write(buf)

	if cap(buf) <= 64*1024 { //  info ： info
		grpcBufPool.Put(bufPtr)
	}

	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type grpcReader struct {
	r    io.Reader
	left uint32
}

func (g *grpcReader) Read(p []byte) (n int, err error) {
	for g.left == 0 {
		var header [5]byte
		if _, err := io.ReadFull(g.r, header[:]); err != nil {
			return 0, err
		}
		g.left = binary.BigEndian.Uint32(header[1:5])
	}

	toRead := uint32(len(p))
	if toRead > g.left {
		toRead = g.left
	}

	n, err = g.r.Read(p[:toRead])
	g.left -= uint32(n)
	return n, err
}

type grpcConn struct {
	net.Conn
	gw *grpcWriter
	gr *grpcReader
}

func (g *grpcConn) Read(b []byte) (n int, err error)  { return g.gr.Read(b) }
func (g *grpcConn) Write(b []byte) (n int, err error) { return g.gw.Write(b) }

// ==========================================
//  info
// ==========================================

// acquireH2Transport  info  HTTP/2（ info  gRPC） info channel。
//
//	info closed info  baseConn  info  Transport； info  baseConn
//	info  Transport  info 。 info  *http.Client  info tunnel info 。
func acquireH2Transport(ctx context.Context, cacheKey string, isTLS bool, cfg ProxyConfig, baseConn net.Conn) (*http.Client, error) {
	if cached, ok := h2TransportCache.Load(cacheKey); ok {
		//  info ： info  TCP  info ， info channel
		baseConn.Close()
		zlog.Debugf("%s [Tunnel] ⚡ Reused cached multiplexing transport", TAG)
		return cached.(*http.Client), nil
	}

	//  info ： info  Transport
	var firstConnUsed int32
	transport := &http2.Transport{}

	//  info ： info  baseConn， info
	smartDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var c net.Conn
		var dialErr error
		if atomic.CompareAndSwapInt32(&firstConnUsed, 0, 1) {
			c = baseConn //  info  Socket
		} else {
			c, dialErr = dialTCP(ctx, cfg, cfg.ProxyAddr)
			if dialErr != nil {
				return nil, dialErr
			}
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		return c, nil
	}

	if isTLS {
		transport.DialTLSContext = func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
			c, err := smartDialer(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			utlsConfig := buildUTLSConfig(cfg, []string{"h2", "http/1.1"})
			uConn, err := handshakeUTLS(ctx, c, utlsConfig)
			if err != nil {
				c.Close()
				return nil, err
			}
			c.SetDeadline(time.Time{})
			return uConn, nil
		}
	} else {
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
			c, err := smartDialer(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			c.SetDeadline(time.Time{}) //  info timeout
			return c, nil
		}
	}

	client := &http.Client{Transport: transport}
	h2TransportCache.Store(cacheKey, client)
	return client, nil
}

func init() {
	h2Handler := func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn, isTLS bool, isGRPC bool) (net.Conn, error) {
		scheme := "http"
		protoName := "H2C"
		if isTLS {
			scheme = "https"
			protoName = "H2"
		}
		if isGRPC {
			protoName = "gRPC"
			if !isTLS {
				protoName = "gRPC-Cleartext"
			}
		}

		zlog.Infof("%s [Tunnel] 2. Preparing %s tunnel handshake, spoofed Host: %s", TAG, protoName, cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}
		reqUrl := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)

		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(parentCtx)
		req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
		if err != nil {
			baseConn.Close()
			cancel()
			return nil, err
		}

		req.Header.Set("Host", cfg.CustomHost)
		if cfg.CustomHost != "" {
			req.Host = cfg.CustomHost
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
		req.Header.Set("X-Target", cfg.SshAddr)
		req.Header.Set("X-Network", "tcp")
		if cfg.ProxyAuthRequired {
			req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
		}

		if isGRPC {
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("TE", "trailers")
		}

		// ==========================================
		//  info  Zero-Waste  info
		// ==========================================
		cacheKey := cfg.ProxyAddr + "|" + protoName
		client, err := acquireH2Transport(ctx, cacheKey, isTLS, cfg, baseConn)
		if err != nil {
			baseConn.Close()
			cancel()
			return nil, err
		}

		respChan := make(chan *http.Response, 1)
		errChan := make(chan error, 1)

		go func() {
			resp, err := client.Do(req)
			if err != nil {
				errChan <- err
				return
			}
			respChan <- resp
		}()

		select {
		case err := <-errChan:
			cancel()
			pw.CloseWithError(err)
			pr.CloseWithError(err)
			h2TransportCache.Delete(cacheKey) //  info ， info
			zlog.Errorf("%s [Tunnel] ❌ %s handshake request failed: %v", TAG, protoName, err)
			return nil, err

		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				cancel()
				resp.Body.Close()
				pw.CloseWithError(fmt.Errorf("status %d", resp.StatusCode))
				pr.CloseWithError(fmt.Errorf("status %d", resp.StatusCode))
				h2TransportCache.Delete(cacheKey) //  info
				zlog.Errorf("%s [Tunnel] ❌ %s server rejected, status code: %d", TAG, protoName, resp.StatusCode)
				return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ %s tunnel handshake successful", TAG, protoName)

			sConn := &streamConn{
				remote:   cfg.ProxyAddr, //  info address
				pw:       pw,
				respBody: resp.Body,
				cancel:   cancel,
			}

			var rConn net.Conn = sConn

			if isGRPC {
				rConn = &grpcConn{
					Conn: sConn,
					gw:   &grpcWriter{w: sConn},
					gr:   &grpcReader{r: sConn},
				}
			}

			return WrapWithPadding(rConn), nil

		case <-time.After(15 * time.Second):
			cancel()
			timeoutErr := fmt.Errorf("%s handshake timeout", protoName)
			pw.CloseWithError(timeoutErr)
			pr.CloseWithError(timeoutErr)
			h2TransportCache.Delete(cacheKey) //  info
			zlog.Errorf("%s [Tunnel] ❌ %s handshake timeout", TAG, protoName)
			return nil, timeoutErr
		}
	}

	RegisterTunnel("h2c", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, false, false)
	})
	RegisterTunnel("h2", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, true, false)
	})
	RegisterTunnel("grpcc", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, false, true)
	})
	RegisterTunnel("grpc", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, true, true)
	})
}
