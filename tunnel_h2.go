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

// 全域 HTTP/2 連線快取，實現真正的多工複用 (Multiplexing)
var h2TransportCache sync.Map

// ==========================================
// HTTP/2 雙向流轉 net.Conn 适配器
// ==========================================
type streamConn struct {
	pw       *io.PipeWriter
	respBody io.ReadCloser
	cancel   context.CancelFunc
	remote   string // 儲存遠端地址，取代實體的 net.Conn
}

func (s *streamConn) Read(b []byte) (n int, err error)  { return s.respBody.Read(b) }
func (s *streamConn) Write(b []byte) (n int, err error) { return s.pw.Write(b) }
func (s *streamConn) Close() error {
	s.cancel()
	s.pw.Close()
	return s.respBody.Close()
	// 🚨 絕對不可在此關閉實體 TCP 連線，因為它是多工複用共享的！
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
// gRPC 数据帧封装器
// ==========================================

// gRPC 專用的零分配記憶體池，完美解決高頻率發送時的 GC 壓力
var grpcBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024+5) // 預設 32KB + 5 bytes Header
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

	// 將 Header 與 Payload 合併寫入，確保底層 H2 Framer 只發送一個 DATA 幀
	totalLen := len(p) + 5
	if totalLen > cap(buf) {
		buf = make([]byte, totalLen) // 若超載則臨時分配
	} else {
		buf = buf[:totalLen]
	}

	binary.BigEndian.PutUint32(buf[1:5], uint32(len(p)))
	copy(buf[5:], p)

	_, err = g.w.Write(buf)

	if cap(buf) <= 64*1024 { // 保護機制：不回收異常巨大的記憶體塊
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
// 核心握手逻辑与注册
// ==========================================
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
		// 多工複用快取機制與 Zero-Waste 撥號
		// ==========================================
		cacheKey := cfg.ProxyAddr + "|" + protoName
		var client *http.Client

		if cached, ok := h2TransportCache.Load(cacheKey); ok {
			// 命中快取：釋放外層多餘撥號的 TCP 連線，直接複用現有高速通道
			baseConn.Close()
			client = cached.(*http.Client)
			zlog.Debugf("%s [Tunnel] ⚡ Reused cached %s multiplexing transport", TAG, protoName)
		} else {
			// 快取未命中：建立新的 Transport
			var firstConnUsed int32
			transport := &http2.Transport{}

			// 智慧撥號器：第一次握手消耗 baseConn，若未來斷線重連則自動撥號新連線
			smartDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
				var c net.Conn
				var dialErr error
				if atomic.CompareAndSwapInt32(&firstConnUsed, 0, 1) {
					c = baseConn // 充分利用外層已建立的 Socket
				} else {
					c, dialErr = dialTCP(ctx, cfg, cfg.ProxyAddr) // 假設你的 myssh 包裡有 dialTCP 函數
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
					c.SetDeadline(time.Time{}) // 清除超時
					return c, err
				}
			}

			client = &http.Client{Transport: transport}
			h2TransportCache.Store(cacheKey, client)
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
			h2TransportCache.Delete(cacheKey) // 發生網路底層錯誤時，主動剔除失效快取
			zlog.Errorf("%s [Tunnel] ❌ %s handshake request failed: %v", TAG, protoName, err)
			return nil, err

		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				cancel()
				resp.Body.Close()
				pw.CloseWithError(fmt.Errorf("status %d", resp.StatusCode))
				pr.CloseWithError(fmt.Errorf("status %d", resp.StatusCode))
				h2TransportCache.Delete(cacheKey) // 剔除失效快取
				zlog.Errorf("%s [Tunnel] ❌ %s server rejected, status code: %d", TAG, protoName, resp.StatusCode)
				return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ %s tunnel handshake successful", TAG, protoName)

			sConn := &streamConn{
				remote:   cfg.ProxyAddr, // 傳入遠端地址
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
			h2TransportCache.Delete(cacheKey) // 剔除失效快取
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
