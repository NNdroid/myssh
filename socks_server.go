package myssh

import (
	"context"
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

type udpJob struct {
	addr   *net.UDPAddr
	buffer *[]byte
	data   []byte
}

func serveSocks(ctx context.Context, s *socks5.Server, h *SshProxyHandler) error {
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
				if ctx.Err() == nil {
					if d, err := socks5.NewDatagramFromBytes(job.data); err == nil && d.Frag == 0 {
						_ = h.UDPHandle(s, job.addr, d)
					}
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
			d, err := socks5.NewDatagramFromBytes(buf[:n])
			if err != nil || d.Frag != 0 {
				continue
			}
			// Same source/destination always uses one FIFO worker.
			var hash maphash.Hash
			hash.SetSeed(seed)
			hash.WriteString(addr.String())
			hash.WriteByte(d.Atyp)
			hash.Write(d.DstAddr)
			hash.Write(d.DstPort)
			q := queues[hash.Sum64()%uint64(len(queues))]
			if len(q) == cap(q) {
				udpQueueDrops.Add(1)
				continue
			}
			p := getPacketBuffer(n)
			data := (*p)[:n]
			copy(data, buf[:n])
			select {
			case q <- udpJob{addr: addr, buffer: p, data: data}:
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
			cancel()
			stopSocksServer(s)
			wg.Wait()
			tcpWG.Wait()
			return err
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
	return udpBufPool.Get().(*[]byte)
}

func putPacketBuffer(p *[]byte) {
	if cap(*p) == 2048 {
		udpSmallBufPool.Put(p)
	} else {
		udpBufPool.Put(p)
	}
}
