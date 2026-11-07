package myssh

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/maphash"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/txthinking/socks5"
)

// Bound work before allocating packet buffers or starting packet handlers.
const udpWorkers = 16
const udpQueueDepth = 32

// udpDownlinkBufSize 是 UDP 会话下行 goroutine 的读缓冲。9KB 覆盖巨型帧以内
// 的全部现实数据报：QUIC 已被 UDP 443 拦截、DNS EDNS0 常见 ≤4KB、SOCKS5 的
// 65507 上限在公网路径上实际不可达。该缓冲在会话存续期间被下行 goroutine
// 长期占住（阻塞在 Read 上不回池），用 64KB 池时默认 1024 会话上限最坏常驻
// ~67MB，降到 9KB 后为 ~9MB。
const udpDownlinkBufSize = 9 * 1024

// udpDownlinkBufPool 是下行读缓冲的复用池：会话高频建立/销毁时避免反复分配。
var udpDownlinkBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, udpDownlinkBufSize)
		return &buf
	},
}

var udpQueueDrops atomic.Uint64
var preparedSocks sync.Map // *socks5.Server -> *socksRuntime

type socksRuntime struct {
	listener    *net.TCPListener
	connections sync.Map
	closed      atomic.Bool
	mu          sync.Mutex
}

func prepareSocksServer(ctx context.Context, s *socks5.Server) error {
	addr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", ln.Addr().String())
	if err != nil {
		ln.Close()
		return err
	}
	uc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		ln.Close()
		return err
	}
	s.UDPConn = uc
	// Absorb short bursts in the kernel; userspace queues remain bounded.
	_ = uc.SetReadBuffer(1024 * 1024)
	r := &socksRuntime{listener: ln}
	preparedSocks.Store(s, r)
	return nil
}

func stopSocksServer(s *socks5.Server) {
	if value, ok := preparedSocks.Load(s); ok {
		r := value.(*socksRuntime)
		r.mu.Lock()
		r.closed.Store(true)
		r.listener.Close()
		s.UDPConn.Close()
		r.connections.Range(func(k, v any) bool { v.(net.Conn).Close(); return true })
		r.mu.Unlock()
	}
}

// udpJob 携带一个已解析好的数据报。datagram 的各切片（Data/DstAddr/DstPort）
// 全部指向 buffer，因此 buffer 必须在 UDPHandle 返回后才能归还池——worker 里
// 的 putPacketBuffer 就排在调用之后。
//
// 只解析一次：reader 先把报文拷进池化缓冲，再从**该拷贝**解析，解析结果就能
// 安全地跨 goroutine 交给 worker 复用。旧实现在 reader 里解析一次（只为算分片
// 哈希）、在 worker 里又解析一次，等于每个 UDP 包付两次解析和两次分配。
type udpJob struct {
	addr     *net.UDPAddr
	buffer   *[]byte
	datagram *socks5.Datagram
}

// socksRequestHandler is intentionally small so the production handler can be
// decorated with cross-cutting policy (for example IPv6 egress capability)
// without duplicating the mature forwarding implementation.
type socksRequestHandler interface {
	TCPHandle(*socks5.Server, *net.TCPConn, *socks5.Request) error
	UDPHandle(*socks5.Server, *net.UDPAddr, *socks5.Datagram) error
	reapUDPSessions(context.Context)
}

func serveSocks(ctx context.Context, s *socks5.Server, h socksRequestHandler) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	value, _ := preparedSocks.Load(s)
	r := value.(*socksRuntime)
	defer preparedSocks.Delete(s)
	defer stopSocksServer(s)
	var wg sync.WaitGroup
	queues := make([]chan udpJob, udpWorkers)
	for i := range queues {
		queues[i] = make(chan udpJob, udpQueueDepth)
		wg.Add(1)
		go func(q <-chan udpJob) {
			defer wg.Done()
			for job := range q {
				// Frag != 0 已在 reader 侧过滤，这里只需看引擎是否已停。
				if ctx.Err() == nil {
					_ = h.UDPHandle(s, job.addr, job.datagram)
				}
				putPacketBuffer(job.buffer)
			}
		}(queues[i])
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			for _, q := range queues {
				close(q)
			}
		}()
		buf := make([]byte, 65536)
		seed := maphash.MakeSeed()
		for {
			n, addr, err := s.UDPConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// 先拷进池化缓冲，再从**拷贝**解析：解析结果的所有切片都指向该
			// 缓冲，worker 因此可以零成本复用，不必再解析一遍。
			p := getPacketBuffer(n)
			data := (*p)[:n]
			copy(data, buf[:n])

			d, err := socks5.NewDatagramFromBytes(data)
			if err != nil || d.Frag != 0 {
				putPacketBuffer(p)
				continue
			}
			// Same source/destination always uses one FIFO worker.
			var hash maphash.Hash
			hash.SetSeed(seed)
			// 直接哈希 IP 原始字节与端口，不走 addr.String()——后者每个包
			// 都要分配一个字符串出来。
			hash.Write(addr.IP)
			var portBuf [2]byte
			binary.BigEndian.PutUint16(portBuf[:], uint16(addr.Port))
			hash.Write(portBuf[:])
			hash.WriteByte(d.Atyp)
			hash.Write(d.DstAddr)
			hash.Write(d.DstPort)
			q := queues[hash.Sum64()%uint64(len(queues))]
			if len(q) == cap(q) {
				putPacketBuffer(p)
				udpQueueDrops.Add(1)
				continue
			}
			select {
			case q <- udpJob{addr: addr, buffer: p, datagram: d}:
			default:
				putPacketBuffer(p)
				udpQueueDrops.Add(1)
			}
		}
	}()
	wg.Add(1)
	go func() { defer wg.Done(); h.reapUDPSessions(ctx) }()
	var tcpWG sync.WaitGroup
	for {
		c, err := r.listener.AcceptTCP()
		if err != nil {
			// 只有 listener 被主动关闭才算正常退出。fd 临时耗尽（EMFILE，
			// UDP 会话风暴下现实存在）等瞬态错误如果直接 return，会杀掉
			// 整个 SOCKS 服务——SSH 隧道还活着、UI 显示已连接，但所有
			// 代理请求失败且永不恢复。退避后继续 accept。
			if errors.Is(err, net.ErrClosed) {
				cancel()
				stopSocksServer(s)
				wg.Wait()
				tcpWG.Wait()
				return err
			}
			zlog.Warnf("%s [SOCKS5] ⚠️ Accept failed (%v), retrying in 500ms", TAG, err)
			select {
			case <-ctx.Done():
				cancel()
				stopSocksServer(s)
				wg.Wait()
				tcpWG.Wait()
				return err
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		r.mu.Lock()
		if r.closed.Load() {
			r.mu.Unlock()
			c.Close()
			continue
		}
		r.connections.Store(c, c)
		r.mu.Unlock()
		tcpWG.Add(1)
		go func() {
			defer tcpWG.Done()
			defer c.Close()
			defer r.connections.Delete(c)
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if s.Negotiate(c) != nil {
				return
			}
			req, err := s.GetRequest(c)
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Time{})
			_ = h.TCPHandle(s, c, req)
		}()
	}
}

func getPacketBuffer(n int) *[]byte {
	if n <= 2048 {
		return udpSmallBufPool.Get().(*[]byte)
	}
	return relayBufPool.Get().(*[]byte)
}

func putPacketBuffer(p *[]byte) {
	if cap(*p) == 2048 {
		udpSmallBufPool.Put(p)
	} else {
		relayBufPool.Put(p)
	}
}
