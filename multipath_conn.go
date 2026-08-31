package myssh

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// broadcaster lets the reliable layer broadcast a single frame to every path.
// multipathConn implements it; the keepalive loop uses it so that all N NAT
// mappings stay alive even when the tunnel is idle.
type broadcaster interface {
	WriteAll([]byte) (int, error)
}

// multipathConn implements net.Conn over N independent UDP sockets, one per
// server-side port. Each socket carries its own local (client) source port, so
// the N (client-port, server-port) tuples are distinct NAT mappings — i.e. N
// independent pathways between the client and the server.
//
// Writes are spread across the paths (round-robin) so application data is
// load-balanced over all N pathways; reads are fanned in from every path.
// Because each path's socket is connected to exactly one server port, a reply
// arriving on path i necessarily comes from server port i — and the server
// replies from the same port the client contacted, which is what a CGNAT
// requires in order to accept the packet.
type multipathConn struct {
	paths     []*pathConn
	n         int
	rr        atomic.Uint64
	readCh    chan readPkt
	closeCh   chan struct{}
	closed    atomic.Int32
	readDead  time.Time
	writeDead time.Time
	primary   *pathConn
}

type pathConn struct {
	sent       atomic.Uint64
	recv       atomic.Uint64
	conn       *net.UDPConn
	serverPort int
	raddr      *net.UDPAddr
	mu         sync.Mutex
}

type readPkt struct {
	buf []byte
	n   int
	err error
}

func newMultipathConn(paths []*pathConn) *multipathConn {
	m := &multipathConn{
		paths:   paths,
		n:       len(paths),
		readCh:  make(chan readPkt, 64),
		closeCh: make(chan struct{}),
	}
	if m.n > 0 {
		m.primary = paths[0]
	}
	for _, p := range paths {
		go m.readLoop(p)
	}
	return m
}

func (m *multipathConn) readLoop(p *pathConn) {
	buf := make([]byte, 2048)
	for {
		n, err := p.conn.Read(buf)
		if m.closed.Load() == 1 {
			return
		}
		if err != nil {
			select {
			case m.readCh <- readPkt{nil, 0, err}:
			case <-m.closeCh:
			}
			return
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		p.recv.Add(1)
		select {
		case m.readCh <- readPkt{cp, n, nil}:
		case <-m.closeCh:
			return
		}
	}
}

func (m *multipathConn) Read(b []byte) (int, error) {
	if !m.readDead.IsZero() {
		remaining := time.Until(m.readDead)
		if remaining <= 0 {
			return 0, errors.New("i/o timeout")
		}
		t := time.NewTimer(remaining)
		defer t.Stop()
		select {
		case pkt := <-m.readCh:
			return m.deliver(pkt, b)
		case <-t.C:
			return 0, errors.New("i/o timeout")
		case <-m.closeCh:
			return 0, errors.New("use of closed network connection")
		}
	}
	select {
	case pkt := <-m.readCh:
		return m.deliver(pkt, b)
	case <-m.closeCh:
		return 0, errors.New("use of closed network connection")
	}
}

func (m *multipathConn) deliver(pkt readPkt, b []byte) (int, error) {
	if pkt.err != nil {
		return 0, pkt.err
	}
	return copy(b, pkt.buf), nil
}

func (m *multipathConn) Write(b []byte) (int, error) {
	idx := m.rr.Add(1)
	p := m.paths[idx%uint64(m.n)]
	p.sent.Add(1)
	if !m.writeDead.IsZero() && time.Now().After(m.writeDead) {
		return 0, errors.New("i/o timeout")
	}
	return p.conn.Write(b)
}

// WriteAll broadcasts b to every path. Used by the keepalive so all N NAT
// mappings are refreshed, not just one.
func (m *multipathConn) WriteAll(b []byte) (int, error) {
	var lastErr error
	total := 0
	for _, p := range m.paths {
		n, err := p.conn.Write(b)
		if err != nil {
			lastErr = err
			continue
		}
		total += n
		p.sent.Add(1)
	}
	if lastErr != nil && total == 0 {
		return 0, lastErr
	}
	return total, nil
}

func (m *multipathConn) Close() error {
	if !m.closed.CompareAndSwap(0, 1) {
		return nil
	}
	close(m.closeCh)
	for _, p := range m.paths {
		p.conn.Close()
	}
	return nil
}

func (m *multipathConn) LocalAddr() net.Addr  { return m.primary.conn.LocalAddr() }
func (m *multipathConn) RemoteAddr() net.Addr { return m.primary.raddr }
func (m *multipathConn) SetDeadline(t time.Time) error {
	m.readDead = t
	m.writeDead = t
	return nil
}
func (m *multipathConn) SetReadDeadline(t time.Time) error  { m.readDead = t; return nil }
func (m *multipathConn) SetWriteDeadline(t time.Time) error { m.writeDead = t; return nil }

// openMultipath dials one connected UDP socket per server port. Each call lets
// the kernel pick a distinct local (client) source port, so the resulting N
// (client-port, server-port) tuples are distinct pathways.
func openMultipath(ctx context.Context, cfg ProxyConfig, host string, ports []int) ([]*pathConn, error) {
	paths := make([]*pathConn, 0, len(ports))
	ip := net.ParseIP(host)
	for _, sp := range ports {
		pc, err := dialUDP(ctx, cfg, fmt.Sprintf("%s:%d", host, sp))
		if err != nil {
			for _, p := range paths {
				p.conn.Close()
			}
			return nil, fmt.Errorf("failed to open path to %s:%d: %w", host, sp, err)
		}
		uc, ok := pc.(*net.UDPConn)
		if !ok {
			pc.Close()
			for _, p := range paths {
				p.conn.Close()
			}
			return nil, fmt.Errorf("expected *net.UDPConn for path %s:%d, got %T", host, sp, pc)
		}
		paths = append(paths, &pathConn{
			conn:       uc,
			serverPort: sp,
			raddr:      &net.UDPAddr{IP: ip, Port: sp},
		})
	}
	return paths, nil
}

// hostAndPrimary splits "host:port" (or "host") into a host and the primary
// (handshake/bootstrap) port, defaulting to 36712 when no port is given.
func hostAndPrimary(target string) (string, int) {
	host := target
	port := 36712
	if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		if pp, e := parsePort(p); e == nil {
			port = pp
		}
	}
	return host, port
}

func parsePort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	return p, err
}

// udpCustomDefaultPaths is the number of independent UDP paths the client
// opens when a port range is configured. Each path dials a randomly chosen
// port from the range — NOT a server-advertised list. The server never
// advertises ports; it recovers the original destination port via
// IP_RECVORIGDSTADDR and replies FROM that exact port so a CGNAT accepts the
// packet. 32 is the recommended default: enough distinct NAT mappings to
// defeat per-(dst-port) rate limits and survive path churn, small enough to
// keep the keepalive broadcast cheap.
const udpCustomDefaultPaths = 32

// pickRandomPorts returns n distinct ports drawn uniformly at random from the
// supplied candidate list. The client is the single source of truth for path
// selection: it chooses which ports to use, and the server merely mirrors
// them on the way back (replies from the same port the client contacted). If
// n exceeds len(candidates) the whole list is returned.
func pickRandomPorts(candidates []int, n int) []int {
	if n <= 0 || len(candidates) == 0 {
		return nil
	}
	if n > len(candidates) {
		n = len(candidates)
	}
	// Partial Fisher-Yates over an index slice keeps it O(n) and avoids
	// mutating the caller's slice. The RNG is seeded from crypto/rand so the
	// spread is not predictable from run to run.
	idx := make([]int, len(candidates))
	for i := range idx {
		idx[i] = i
	}
	var seed [8]byte
	_, _ = rand.Read(seed[:])
	rng := mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(seed[:]))))
	for i := 0; i < n; i++ {
		j := i + rng.Intn(len(candidates)-i)
		idx[i], idx[j] = idx[j], idx[i]
	}
	out := make([]int, n)
	for i := 0; i < n; i++ {
		out[i] = candidates[idx[i]]
	}
	return out
}

// performHandshake runs the UDPCustom v1.0 SYN/ACK exchange over conn and
// returns the negotiated session id and the Noise session (when a public key
// was configured). The ACK carries ONLY the Noise msg2 (when encryption is on);
// legacy/Open servers send no Data at all. The server never advertises a port
// list — the client is the source of truth for path selection and picks its own
// ports from the configured range, so path setup is entirely client-driven.
func performHandshake(ctx context.Context, conn net.Conn, cfg ProxyConfig, magic uint32, nk *ClientNK) (sessionID uint32, noiseSess *NoiseSession, err error) {
	password := strings.TrimSpace(cfg.UdpCustomPsk)
	if password == "" {
		password = strings.TrimSpace(cfg.Pass)
	}

	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		err = e
		return
	}
	now := time.Now().Unix()
	sig := ComputeAuthHMAC(nonce, password, now)

	var msg1 []byte
	if nk != nil {
		if m1, e := nk.Message1(); e == nil {
			msg1 = m1
		}
	}
	payload := make([]byte, 56+len(msg1))
	copy(payload[0:16], nonce)
	binary.BigEndian.PutUint64(payload[16:24], uint64(now))
	copy(payload[24:56], sig)
	if len(msg1) > 0 {
		copy(payload[56:], msg1)
	}

	syn := &UDPCFrame{
		Magic:      magic,
		Version:    UDPC_VERSION,
		Cmd:        CMD_HANDSHAKE_SYN,
		SessionID:  0,
		Seq:        0,
		Ack:        0,
		WindowSize: 65535,
		Data:       payload,
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write(syn.Encode()); err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	resp := make([]byte, 1024)
	n, rerr := conn.Read(resp)
	if rerr != nil {
		err = rerr
		return
	}
	ackFrame, derr := DecodeUDPCFrame(resp[:n], magic)
	if derr != nil {
		err = derr
		return
	}
	if ackFrame.Cmd != CMD_HANDSHAKE_ACK {
		err = fmt.Errorf("invalid handshake ACK frame (cmd=0x%02X)", ackFrame.Cmd)
		return
	}

	// The ACK Data is the Noise msg2 verbatim (legacy/Open servers send no
	// Data at all). The server NEVER sends a port list — path selection is the
	// client's job, so we simply feed the whole payload to Noise.
	if nk != nil {
		ns, ferr := nk.Finish(ackFrame.Data)
		if ferr != nil {
			err = ferr
			return
		}
		noiseSess = ns
	}

	sessionID = ackFrame.SessionID
	return
}
