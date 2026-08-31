package myssh

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// rangeUDPConn wraps an *unconnected* UDP socket together with a per-packet
// port selector. It implements net.Conn; every Write spreads the datagram
// across the configured port range by calling WriteToUDP with a freshly
// selected destination port.
//
// Why unconnected? A connected UDP socket pins a single (dst-IP, dst-port)
// tuple, which is exactly what per-destination-port UDP rate limiters key on.
// By leaving the socket unconnected we can vary the destination port on every
// single datagram, defeating that limit.
//
// Server side: a firewall DNAT (nftables/iptables) redirects the whole range
// onto one internal UDP port, and the server routes purely by SessionID, so it
// still binds a single port. It does need one accommodation though — since DNAT
// erases the original destination, the server enables IP_RECVORIGDSTADDR and
// replies from a socket bound to the port this datagram was addressed to. An
// older server without that support answers from its listening port instead,
// and any NAT stricter than full-cone drops those replies; noteRecv detects
// exactly that case and warns.
//
// Troubleshooting: the connection keeps per-port counters and logs a warning
// whenever a reply arrives from a source port that is neither inside the
// configured range nor the server's own listening port. A reply from the
// listening port is expected (handshake ACK, or a "via=main" fallback) and is
// NOT flagged. Any other unexpected source port is the definitive signal that
// the server is NOT mirroring the original destination port (its
// IP_RECVORIGDSTADDR support is off) — which is precisely the "handshake works
// but the port range does not carry traffic" symptom.
type rangeUDPConn struct {
	// --- diagnostics -------------------------------------------------------
	sendCount atomic.Uint64 // datagrams handed to WriteToUDP
	recvCount atomic.Uint64 // datagrams returned to the caller

	conn    *net.UDPConn
	host    string
	ip      net.IP // resolved once; falls back to host string per-write if nil
	primary int    // The first port in the config (guaranteed to be listened on by server)
	sel     *PortSelector

	portsMu   sync.Mutex
	sentPorts map[int]uint64 // destination port -> packets sent to it
	recvPorts map[int]uint64 // reply source port  -> packets received from it

	warnMu   sync.Mutex
	lastWarn time.Time
}

// NewRangeConn wraps an already-created unconnected *net.UDPConn. host is the
// server hostname/IP; primary is the handshake port; sel drives port spread.
func NewRangeConn(conn *net.UDPConn, host string, primary int, sel *PortSelector) *rangeUDPConn {
	ip := net.ParseIP(host)
	if ip == nil {
		if addrs, err := net.LookupIP(host); err == nil && len(addrs) > 0 {
			ip = addrs[0]
		}
	}
	return &rangeUDPConn{
		conn:      conn,
		host:      host,
		ip:        ip,
		primary:   primary,
		sel:       sel,
		sentPorts: make(map[int]uint64),
		recvPorts: make(map[int]uint64),
	}
}

// Write sends b to the next selected port in the range.
func (r *rangeUDPConn) Write(b []byte) (int, error) {
	return r.writeToPort(b, r.sel.Next(), false)
}

// WriteToPrimary sends b specifically to the primary port. This should be used
// for handshakes to ensure connectivity before enabling full range spreading.
func (r *rangeUDPConn) WriteToPrimary(b []byte) (int, error) {
	return r.writeToPort(b, r.primary, true)
}

func (r *rangeUDPConn) writeToPort(b []byte, port int, isPrimary bool) (int, error) {
	dst := r.resolveAddr(port)
	n, err := r.conn.WriteToUDP(b, dst)

	seq := r.sendCount.Add(1)
	r.notePort(&r.portsMu, r.sentPorts, port)

	if err != nil {
		// A failed write is always worth a warning: with an unconnected socket
		// the usual cause is the Android VPN protect() hook missing this fd, or
		// the resolved family not matching the socket family.
		zlog.Warnf("%s [Range-Send] ❌ #%d dst=%s cmd=0x%02X sid=0x%08X len=%d err=%v",
			TAG, seq, dst, cmdOfPacket(b), sidOfPacket(b), len(b), err)
		return n, err
	}

	// Head-sampling for the first packets (handshake + early data, where a
	// mismatch is most informative), then 1-in-200 so a busy tunnel does not
	// drown the log.
	if seq <= 32 || seq%200 == 0 {
		zlog.Debugf("%s [Range-Send] #%d 📤 dst=%s primary=%v cmd=0x%02X sid=0x%08X seq=%d len=%d (distinct dst ports so far: %d)",
			TAG, seq, dst, isPrimary, cmdOfPacket(b), sidOfPacket(b), seqOfPacket(b), n, r.distinctSent())
	}
	return n, nil
}

// resolveAddr builds the destination address for port, resolving the host on
// demand if it was not a literal IP at construction time.
func (r *rangeUDPConn) resolveAddr(port int) *net.UDPAddr {
	if r.ip != nil {
		return &net.UDPAddr{IP: r.ip, Port: port}
	}
	if addrs, err := net.LookupIP(r.host); err == nil && len(addrs) > 0 {
		r.ip = addrs[0]
		return &net.UDPAddr{IP: r.ip, Port: port}
	}
	return &net.UDPAddr{IP: net.ParseIP(r.host), Port: port}
}

// Read receives one datagram. It uses ReadFromUDP (rather than Read) purely so
// the reply's SOURCE address can be logged and checked: a correctly mirroring
// server always answers from a port inside the configured range.
func (r *rangeUDPConn) Read(b []byte) (int, error) {
	n, from, err := r.conn.ReadFromUDP(b)
	if err != nil {
		if seq := r.recvCount.Load(); seq == 0 {
			// Nothing has ever arrived: usually means the server's reply never
			// made it back through the NAT (source-port mismatch).
			zlog.Debugf("%s [Range-Recv] ⏳ read error before any reply arrived: %v", TAG, err)
		}
		if n < 0 {
			n = 0
		}
		return n, err
	}
	r.noteRecv(from, b[:n])
	return n, nil
}

func (r *rangeUDPConn) noteRecv(from *net.UDPAddr, pkt []byte) {
	seq := r.recvCount.Add(1)

	srcPort := 0
	if from != nil {
		srcPort = from.Port
		r.notePort(&r.portsMu, r.recvPorts, srcPort)
	}

	// A reply is acceptable when its source port is inside the spread range
	// (the server mirrored the original destination port) OR equal to the
	// server's own listening port. The latter is expected and benign: the
	// handshake ACK is answered from the server's main socket, and any reply
	// that falls back to "via=main" also originates from the listening port.
	// This mirrors the server-side guard that skips mirroring its own listen
	// port, so the client must not flag these as a mirroring failure.
	inRange := srcPort > 0 && r.srcPortAccepted(srcPort)
	if !inRange {
		// Throttled: one warning per 5s instead of one per packet.
		r.warnMu.Lock()
		due := time.Since(r.lastWarn) > 5*time.Second
		if due {
			r.lastWarn = time.Now()
		}
		r.warnMu.Unlock()
		if due {
			zlog.Warnf("%s [Range-Recv] ⚠️ reply srcPort=%d (from %s) is OUTSIDE the configured range %s — the server is not mirroring destination ports. "+
				"Check: (1) server has origdst enabled (IP_RECVORIGDSTADDR, Linux only), (2) server logs show '[Send] via=port:N' not 'via=main', (3) the DNAT rule covers the whole range.",
				TAG, srcPort, from, r.rangeSpec())
		}
	}

	if seq <= 32 || seq%200 == 0 {
		zlog.Debugf("%s [Range-Recv] #%d 📥 from=%s srcPortInRange=%v cmd=0x%02X sid=0x%08X ack=%d len=%d (distinct src ports so far: %d)",
			TAG, seq, from, inRange, cmdOfPacket(pkt), sidOfPacket(pkt), ackOfPacket(pkt), len(pkt), r.distinctRecv())
	}
}

// srcPortAccepted reports whether a reply arriving from srcPort is consistent
// with a correctly mirroring server. It is true when srcPort lies inside the
// configured spread range (the normal n:n case) or equals the server's own
// listening port (handshake ACK and "via=main" fallbacks legitimately
// originate there). Anything else is genuine evidence that the server is not
// mirroring destination ports.
func (r *rangeUDPConn) srcPortAccepted(srcPort int) bool {
	if srcPort == r.primary {
		return true
	}
	return r.sel != nil && r.sel.pr != nil && r.sel.pr.Contains(srcPort)
}

// notePort bumps the per-port packet counter. The map is bounded by the port
// range itself, so it can never grow without limit.
func (r *rangeUDPConn) notePort(mu *sync.Mutex, m map[int]uint64, port int) {
	mu.Lock()
	m[port]++
	mu.Unlock()
}

func (r *rangeUDPConn) distinctSent() int {
	r.portsMu.Lock()
	defer r.portsMu.Unlock()
	return len(r.sentPorts)
}

func (r *rangeUDPConn) distinctRecv() int {
	r.portsMu.Lock()
	defer r.portsMu.Unlock()
	return len(r.recvPorts)
}

func (r *rangeUDPConn) rangeSpec() string {
	if r.sel == nil || r.sel.pr == nil {
		return "?"
	}
	return r.sel.pr.String()
}

func (r *rangeUDPConn) Close() error {
	// Closing summary: the spread ratio is the single most useful number when
	// debugging a range that "does not work". distinctDst >> 1 means the client
	// is spreading; distinctSrc ~= distinctDst means the server is mirroring.
	zlog.Infof("%s [Range] 🔚 closed: sent=%d recv=%d distinctDstPorts=%d distinctSrcPorts=%d range=%s",
		TAG, r.sendCount.Load(), r.recvCount.Load(),
		r.distinctSent(), r.distinctRecv(), r.rangeSpec())
	return r.conn.Close()
}

func (r *rangeUDPConn) LocalAddr() net.Addr { return r.conn.LocalAddr() }

// RemoteAddr for an unconnected socket returns a string representation of the
// target host and the configured port range. This avoids nil pointer panics
// in logging and connection tracking.
func (r *rangeUDPConn) RemoteAddr() net.Addr {
	return &rangeAddr{host: r.host, rangeSpec: r.rangeSpec()}
}

type rangeAddr struct {
	host      string
	rangeSpec string
}

func (a *rangeAddr) Network() string { return "udp-range" }
func (a *rangeAddr) String() string  { return a.host + ":" + a.rangeSpec }

func (r *rangeUDPConn) SetDeadline(t time.Time) error      { return r.conn.SetDeadline(t) }
func (r *rangeUDPConn) SetReadDeadline(t time.Time) error  { return r.conn.SetReadDeadline(t) }
func (r *rangeUDPConn) SetWriteDeadline(t time.Time) error { return r.conn.SetWriteDeadline(t) }

// --- frame field peekers -----------------------------------------------------
// Layout (big endian): [0:4] Magic, [4] Version, [5] Cmd, [6:8] Flags,
// [8:12] SessionID, [12:16] Seq, [16:20] Ack, [20:22] Window, [22:24] DataLen.
// They exist so the hot send/recv path can log without decoding + allocating.

func cmdOfPacket(pkt []byte) byte {
	if len(pkt) > 5 {
		return pkt[5]
	}
	return 0
}

func sidOfPacket(pkt []byte) uint32 {
	if len(pkt) >= 12 {
		return binary.BigEndian.Uint32(pkt[8:12])
	}
	return 0
}

func seqOfPacket(pkt []byte) uint32 {
	if len(pkt) >= 16 {
		return binary.BigEndian.Uint32(pkt[12:16])
	}
	return 0
}

func ackOfPacket(pkt []byte) uint32 {
	if len(pkt) >= 20 {
		return binary.BigEndian.Uint32(pkt[16:20])
	}
	return 0
}

// dialUDPRange establishes the underlying socket for the udp_custom tunnel.
// If the target carries a UDP destination-port range it returns an
// *unconnected* UDP socket wrapped by a rangeUDPConn (per-packet port spread).
// If the target is a plain single port, or the range cannot be parsed, it
// falls back to a normal connected UDP socket (identical to dialUDP) so
// behaviour is unchanged for existing deployments.
func dialUDPRange(ctx context.Context, cfg ProxyConfig, target string) (net.Conn, error) {
	if target == "" {
		target = cfg.SshAddr
	}
	host, primary, ports, err := ParseServerAddrWithRange(target)
	if err != nil || len(ports) <= 1 {
		// No usable range: behave exactly like a normal connected UDP socket.
		zlog.Debugf("%s [Dialer] ℹ️ single-port target %q (err=%v, ports=%d) — using a connected UDP socket, no spread",
			TAG, target, err, len(ports))
		return dialUDP(ctx, cfg, target)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		zlog.Warnf("%s [Dialer] ⚠️ port range %q parsed but could not be built (%v) — falling back to connected UDP", TAG, target, err)
		return dialUDP(ctx, cfg, target)
	}

	// Pick the address family from the parsed host (fallback: IPv4).
	network := "udp4"
	bind := "0.0.0.0:0"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "udp6"
		bind = "[::]:0"
	}

	lc := rangeListenConfig(cfg)
	pc, err := lc.ListenPacket(ctx, network, bind)
	if err != nil {
		return nil, fmt.Errorf("failed to open unconnected UDP socket for port-range spread: %w", err)
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("expected *net.UDPConn from ListenPacket, got %T", pc)
	}

	sel := NewPortSelector(pr, SelectorRandom)
	zlog.Infof("%s [Dialer] 🎲 UDP port-range spreading enabled: host=%s primary=%d ports=%s (total %d) local=%s network=%s",
		TAG, host, primary, pr.String(), pr.Total(), uc.LocalAddr(), network)
	return NewRangeConn(uc, host, primary, sel), nil
}
