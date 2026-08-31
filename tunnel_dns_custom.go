package myssh

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// =============================================================
// SSH-over-DNS tunnel (tunnel_dns)
// =============================================================
//
// This carries a byte stream (an SSH client) inside DNS queries: every upstream
// chunk rides in a DNS question and the answer carries data back. All sockets go
// through the protected dialer (dialProtected) so traffic stays outside the
// Android VPN; the only thing that must be reachable is an upstream DNS resolver
// for the authoritative tunnel domain. No direct socket to the SSH server is
// needed, so the SSH handshake itself rides inside DNS queries.
//
// Upstream query name layout (shared with dns_custom - keep both in sync):
//
//	{querySeq}.{ack}.{flag}.{dataSeq}.{b32data}.{session}.tunnel.<DOMAIN>
//
//	- querySeq : unique per query, monotonic; defeats DNS caching
//	- ack      : highest contiguous downstream serverSeq the client has received
//	- flag     : 'D' data / 'P' poll (pull downstream) / 'C' close
//	- dataSeq  : per-chunk upstream ordering sequence; drives server-side dedup
//	             and in-order reassembly (a retry reuses the same dataSeq)
//	- b32data  : base32 chunk, "-" when empty; must stay inside one 63-char DNS
//	             label, i.e. <= 39 raw bytes
//	- session  : per-tunnel session id chosen by the client
//	- tunnel   : fixed marker separating the payload labels from the domain
//	- DOMAIN   : authoritative tunnel domain
//
// Downstream ("server -> client") rides in the DNS answer, using whichever record
// type is configured (TXT/NULL/CNAME/A/AAAA/MX/SRV/NS). TXT additionally uses an
// 8-byte frame header (see encodeDownstreamFrame) that makes the downstream
// direction reliable and ordered: the client reassembles by serverSeq, ACKs what
// it has, and the server retransmits what is still unacked. Other record types
// stay best-effort - they have no room for a header, so they get no dedup, no
// reordering and no retransmission.
//
// Note: <DOMAIN> must be served by a dns_custom server, or by the in-process
// DNSTunnelServer below. Anything else answers NXDOMAIN and the tunnel never
// comes up.

const (
	dnsTunnelDefaultChunk   = 32 // Upstream chunk: base32 must fit one 63-char label (63*5/8 = 39 bytes).
	dnsTunnelQueryTimeout   = 5 * time.Second
	dnsTunnelPollInterval   = 150 * time.Millisecond
	dnsTunnelMaxServerChunk = 200 // Downstream chunk: nominal size; the reply is always shrunk to the 512-byte UDP budget by maxDownstreamPayload.
	dnsTunnelCloseTimeout   = 2 * time.Second
	dnsTunnelMarker         = "tunnel"
	// A downstream chunk still unacked after this long is abandoned and a gap is
	// accepted. Without it, one response a resolver keeps dropping would stall the
	// stream forever, because the server would retransmit the oldest chunk and
	// never serve anything else.
	dnsTunnelDownstreamGiveUp = 30 * time.Second

	// dnsTunnelDownstreamWindow bounds how many downstream chunks may be
	// outstanding (unacked) at once. Concurrent polls each fetch one chunk, so the
	// window is what lets several upstream servers add up to more throughput
	// instead of every poll getting a retransmit of the same oldest chunk. It also
	// caps how many answers one session can have in flight, which is what keeps the
	// query rate and the per-session retransmit buffer bounded.
	dnsTunnelDownstreamWindow = 16
	// Upstream window knobs bound the adaptive in-flight window for upstream chunks.
	// Chunks carry their own dataSeq, so the server dedups and reorder-assembles them
	// no matter which path delivers them - but how many may be in flight at once has no
	// universally correct value. Measured on a loopback link 8 is already the peak
	// (more in flight makes every query slower and throughput falls), while on a 20 ms
	// path 16 nearly doubles throughput. The window therefore adapts from the RTT of
	// the queries themselves instead of being hardcoded.
	dnsTunnelUpstreamWindow    = 8 // per path, initial
	dnsTunnelMinUpstreamWindow = 4 // per path
	dnsTunnelMaxUpstreamWindow = 16
	// dnsTunnelMaxTotalWindow caps the window across every path, so a long server list
	// cannot turn into an unbounded query flood.
	dnsTunnelMaxTotalWindow = 64
	// dnsTunnelWindowWarmup is how many leading upstream samples the adaptive window
	// ignores, so cold-start latency is never mistaken for the path's best RTT.
	dnsTunnelWindowWarmup = 16
	// dnsTunnelPollBusyInterval paces a poller that just received data. On a real
	// network the round trip dominates anyway; this only stops a zero-RTT peer from
	// turning into a busy loop.
	dnsTunnelPollBusyInterval = time.Millisecond
	// dnsTunnelDownstreamBacklog is how much undelivered data the pollers buffer
	// before they stop asking for more, so a slow reader cannot make the tunnel hoard
	// answers in memory.
	dnsTunnelDownstreamBacklog = 64 * 1024
	// dnsTunnelMaxSendAttempts is how many times one upstream chunk is re-sent before
	// the tunnel gives up on it. Retries reuse the same dataSeq (and therefore the
	// same ciphertext), so duplicates are harmless on the server side.
	dnsTunnelMaxSendAttempts = 5
	// dnsTunnelConnPool is how many sockets each upstream path keeps warm.
	// dns.Client.Exchange dials a fresh socket per query, and on most platforms that
	// dial costs more than the query itself - it was the real ceiling on how much
	// concurrency could buy.
	dnsTunnelConnPool = 16
	// dnsTunnelPathCooldown is how long a failing upstream path is skipped before it
	// gets another chance. Without it a dead path still takes its round-robin turn on
	// every chunk, and every other chunk pays the timeout.
	dnsTunnelPathCooldown = 2 * time.Second
	// dnsTunnelMaxUDPResponse is the largest UDP response a client can actually
	// receive without EDNS0: resolvers and DNS client libraries buffer exactly 512
	// bytes, and a larger datagram is dropped or fails the read outright (the query
	// name is echoed in the answer, so a data query plus a full-size chunk easily
	// overruns this).
	dnsTunnelMaxUDPResponse = 512
	// nonTxtNoiseHeaderSize is the 4-byte sequence header a Noise-encrypted, non-TXT
	// downstream frame carries in front of the ciphertext: the client needs the
	// sequence number before it can derive the nonce and decrypt.
	nonTxtNoiseHeaderSize = 4
)

const (
	flagData  = 'D'
	flagPoll  = 'P'
	flagClose = 'C'
)

// seqLess compares two sequence numbers safely across uint32 wraparound. A plain
// `<` would misread a fresh chunk as a stale duplicate once the counter wraps,
// which would silently kill the stream.
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

// dnsTunnelB32 is lowercase, unpadded base32: DNS is case-insensitive, and the
// padding would only waste precious label space.
var dnsTunnelB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Downstream framing for the reliable-ordered TXT transport:
//
//	[serverSeq:4 BE][skipTo:4 BE][payload...]
//
// serverSeq lets the client reassemble out-of-order / lost downstream chunks.
// skipTo (0 = none) tells the client the server abandoned every chunk below it,
// so the client jumps forward instead of blocking forever on an unrecoverable
// gap. A gap corrupts the byte stream for the current session, but the app (SSH)
// reconnects with a clean session, which beats a permanently stuck tunnel.
const downstreamHeaderSize = 8

func encodeDownstreamFrame(serverSeq, skipTo uint32, payload []byte) []byte {
	buf := make([]byte, downstreamHeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], serverSeq)
	binary.BigEndian.PutUint32(buf[4:8], skipTo)
	copy(buf[downstreamHeaderSize:], payload)
	return buf
}

func decodeDownstreamFrame(buf []byte) (serverSeq, skipTo uint32, payload []byte, ok bool) {
	if len(buf) < downstreamHeaderSize {
		return 0, 0, nil, false
	}
	serverSeq = binary.BigEndian.Uint32(buf[0:4])
	skipTo = binary.BigEndian.Uint32(buf[4:8])
	payload = buf[downstreamHeaderSize:]
	return serverSeq, skipTo, payload, true
}

func dnsTypeToQType(t string) (uint16, error) {
	switch strings.ToLower(t) {
	case "", "txt":
		return dns.TypeTXT, nil
	case "null":
		return dns.TypeNULL, nil
	case "cname":
		return dns.TypeCNAME, nil
	case "a":
		return dns.TypeA, nil
	case "aaaa":
		return dns.TypeAAAA, nil
	case "mx":
		return dns.TypeMX, nil
	case "srv":
		return dns.TypeSRV, nil
	case "ns":
		return dns.TypeNS, nil
	default:
		return 0, fmt.Errorf("unsupported dns tunnel type: %q (want txt/null/cname/a/aaaa/mx/srv/ns)", t)
	}
}

// buildQueryName encodes a tunnel query. The name layout is:
//
//	{querySeq}.{ack}.{flag}.{dataSeq}.{b32data}.{session}.tunnel.<DOMAIN>
//
// querySeq : unique per query, defeats DNS caching (monotonic)
// ack      : highest contiguous downstream serverSeq the client has received
// flag     : D/P/C (data/poll/close)
// dataSeq  : per-data-chunk upstream ordering sequence (server dedup + reassembly)
func buildQueryName(domain, session string, querySeq, ack, dataSeq uint32, flag byte, data []byte) string {
	seqStr := strconv.FormatUint(uint64(querySeq), 10)
	ackStr := strconv.FormatUint(uint64(ack), 10)
	dataSeqStr := strconv.FormatUint(uint64(dataSeq), 10)
	// An empty payload must not produce an empty label: ".." is invalid in a DNS
	// name and the resolver rejects it as "bad rdata". "-" stands in for "no data".
	b32Str := "-"
	if len(data) > 0 {
		b32Str = dnsTunnelB32.EncodeToString(data)
	}
	name := strings.Join([]string{
		seqStr,
		ackStr,
		string(flag),
		dataSeqStr,
		b32Str,
		session,
		dnsTunnelMarker,
		dns.Fqdn(domain),
	}, ".")
	return name
}

// parseQueryName decodes a tunnel query name back into its parts.
func parseQueryName(domain, name string) (session string, querySeq, ack, dataSeq uint32, flag byte, data []byte, err error) {
	labels := dns.SplitDomainName(name)
	domainLabels := dns.SplitDomainName(domain)
	// Layout: querySeq.ack.flag.dataSeq.b32.session.marker + domain
	if len(labels) < 6+len(domainLabels)+1 {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("dns tunnel: malformed query name %q", name)
	}
	markerIndex := len(labels) - len(domainLabels) - 1
	if markerIndex < 6 || !strings.EqualFold(labels[markerIndex], dnsTunnelMarker) {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("dns tunnel: marker not found in %q", name)
	}
	session = labels[markerIndex-1]
	b32Str := labels[markerIndex-2]
	if flagStr := labels[markerIndex-4]; len(flagStr) > 0 {
		flag = flagStr[0]
	} else {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("dns tunnel: empty flag in %q", name)
	}
	if ds, e := strconv.ParseUint(labels[markerIndex-3], 10, 32); e == nil {
		dataSeq = uint32(ds)
	}
	if ak, e := strconv.ParseUint(labels[markerIndex-5], 10, 32); e == nil {
		ack = uint32(ak)
	}
	seqU, perr := strconv.ParseUint(labels[markerIndex-6], 10, 32)
	if perr != nil {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("dns tunnel: bad seq in %q: %w", name, perr)
	}
	querySeq = uint32(seqU)
	data, derr := dnsTunnelB32.DecodeString(strings.ToLower(b32Str))
	if derr != nil {
		// "-" (the empty-payload placeholder) never decodes; treat it as no data
		// rather than as an error.
		data = nil
	}
	return session, querySeq, ack, dataSeq, flag, data, nil
}

// splitTxt splits a base32 string into pieces that fit a TXT record, where DNS
// caps a single character-string at 255 bytes.
//
// Base32 packs 8 characters into 5 bytes, so a split must land on a group
// boundary or the fragments will not decode independently. 248 is the largest
// multiple of 8 that still fits inside 255, which keeps every fragment both
// byte-aligned and separately decodable.
func splitTxt(s string) []string {
	const max = 255
	const step = 248 // multiple of 8: aligns the split with base32 group boundaries
	if len(s) <= max {
		return []string{s}
	}
	var out []string
	for i := 0; i < len(s); i += step {
		end := i + step
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

// makeAnswer wraps downstream bytes into whatever record type is configured.
func makeAnswer(qname string, qtype uint16, data []byte, domain string) dns.RR {
	hdr := dns.RR_Header{Name: qname, Rrtype: qtype, Class: dns.ClassINET, Ttl: 0}
	switch qtype {
	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: splitTxt(dnsTunnelB32.EncodeToString(data))}
	case dns.TypeNULL:
		return &dns.NULL{Hdr: hdr, Data: string(data)}
	case dns.TypeCNAME:
		// A CNAME label is capped at 63 chars, so at most 39 raw bytes fit.
		// Truncating silently corrupts the stream, so warn loudly instead.
		b32s := dnsTunnelB32.EncodeToString(data)
		if len(b32s) > 63 {
			b32s = b32s[:63]
			zlog.Warnf("%s [Tunnel-DNS-Server] ⚠️ CNAME label truncated to 63 chars; payload too large for this record type", TAG)
		}
		target := b32s + "." + dnsTunnelMarker + "." + dns.Fqdn(domain)
		return &dns.CNAME{Hdr: hdr, Target: target}
	case dns.TypeA:
		ip := net.IPv4zero.To4()
		if len(data) >= 4 {
			ip = net.IP(append([]byte(nil), data[:4]...)).To4()
		}
		return &dns.A{Hdr: hdr, A: ip}
	case dns.TypeAAAA:
		ip := net.IPv6zero.To16()
		if len(data) >= 16 {
			ip = net.IP(append([]byte(nil), data[:16]...)).To16()
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip}
	case dns.TypeMX:
		return &dns.MX{Hdr: hdr, Preference: 0, Mx: encodeTunnelLabel(data, domain)}
	case dns.TypeSRV:
		return &dns.SRV{Hdr: hdr, Priority: 0, Weight: 0, Port: 0, Target: encodeTunnelLabel(data, domain)}
	case dns.TypeNS:
		return &dns.NS{Hdr: hdr, Ns: encodeTunnelLabel(data, domain)}
	default:
		return &dns.TXT{Hdr: hdr, Txt: splitTxt(dnsTunnelB32.EncodeToString(data))}
	}
}

// extractAnswer pulls the downstream bytes back out of a DNS answer record.
func extractAnswer(rr dns.RR) []byte {
	switch v := rr.(type) {
	case *dns.TXT:
		var sb strings.Builder
		for _, s := range v.Txt {
			sb.WriteString(s)
		}
		fullStr := strings.ToLower(sb.String())
		if d, e := dnsTunnelB32.DecodeString(fullStr); e == nil {
			return d
		}
		return nil
	case *dns.NULL:
		return []byte(v.Data)
	case *dns.CNAME:
		return decodeTunnelLabel(v.Target)
	case *dns.A:
		// The all-zero address is the "no data" sentinel, not a payload.
		if v.A.Equal(net.IPv4zero) {
			return nil
		}
		return v.A.To4()
	case *dns.AAAA:
		// Same sentinel as the A case.
		if bytes.Equal(v.AAAA, net.IPv6zero) {
			return nil
		}
		return v.AAAA.To16()
	case *dns.MX:
		return decodeTunnelLabel(v.Mx)
	case *dns.SRV:
		return decodeTunnelLabel(v.Target)
	case *dns.NS:
		return decodeTunnelLabel(v.Ns)
	}
	return nil
}

// encodeTunnelLabel packs downstream bytes into the "target" field used by the
// MX / SRV / NS / CNAME answer types.
//
// A DNS label is capped at 63 chars (39 raw bytes), so anything larger has to be
// truncated - which silently corrupts the stream, hence the warning. TXT is the
// only type meant for real payloads; these are fallback channels.
func encodeTunnelLabel(data []byte, domain string) string {
	b32s := dnsTunnelB32.EncodeToString(data)
	if len(b32s) > 63 {
		b32s = b32s[:63]
		zlog.Warnf("%s [Tunnel-DNS-Server] ⚠️ DNS tunnel label truncated to 63 chars; payload too large for this record type", TAG)
	}
	return b32s + "." + dnsTunnelMarker + "." + dns.Fqdn(domain)
}

// decodeTunnelLabel reverses encodeTunnelLabel, taking the base32 payload back
// out of a target field.
//
// A missing or malformed payload decodes to nil, which callers treat as "this
// answer carried no data" rather than as an error - the tunnel just polls again.
func decodeTunnelLabel(name string) []byte {
	labels := dns.SplitDomainName(name)
	if len(labels) == 0 {
		return nil
	}
	if d, e := dnsTunnelB32.DecodeString(strings.ToLower(labels[0])); e == nil {
		return d
	}
	return nil
}

// encodedRdataSize is the wire size of an answer's rdata for n payload bytes.
func encodedRdataSize(n int, qtype uint16) int {
	switch qtype {
	case dns.TypeNULL:
		return n // raw rdata bytes
	case dns.TypeA, dns.TypeAAAA:
		return 0 // fixed-size rdata; the payload length never inflates the answer
	case dns.TypeTXT:
		b32 := (n*8 + 4) / 5
		// One length byte per TXT string, strings capped at 248 chars by splitTxt.
		return b32 + (b32+247)/248
	default:
		// CNAME / MX / SRV / NS: a single base32 label -> one length byte + chars.
		return 1 + (n*8+4)/5
	}
}

// fitDownstreamPayload shrinks n until the complete answer fits inside a plain
// 512-byte UDP response. The query name is echoed in the answer, so a data query -
// which carries the upstream chunk inside its name - leaves much less room for the
// downstream payload than a short poll does.
func fitDownstreamPayload(qname string, n int, qtype uint16) int {
	if n <= 0 {
		return 0
	}
	// Header (12) + question (name + 4) + answer header (name echoed + 10).
	fixed := 12 + (len(qname) + 2) + 4 + (len(qname) + 2) + 10
	budget := dnsTunnelMaxUDPResponse - fixed
	for n > 0 && encodedRdataSize(n, qtype) > budget {
		n--
	}
	return n
}

// maxDownstreamPayload is the largest plaintext payload one answer may carry: the
// record type capacity, minus the framing overhead the receiver has to see, shrunk
// until the whole response fits on the wire.
func maxDownstreamPayload(qtype uint16, noise bool, qname string) int {
	capacity := downstreamCap(qtype, noise)
	overhead := 0
	switch {
	case qtype == dns.TypeTXT:
		overhead = downstreamHeaderSize
		if noise {
			overhead += noiseTagSize
		}
	default:
		if noise {
			overhead = nonTxtNoiseHeaderSize + noiseTagSize
		}
	}
	avail := fitDownstreamPayload(qname, capacity+overhead, qtype) - overhead
	if avail > capacity {
		avail = capacity
	}
	if avail < 0 {
		avail = 0
	}
	return avail
}

// downstreamCap is the largest plaintext payload one answer of the given record
// type can carry. Serving more than this silently truncates the chunk (A/AAAA only
// hold one address, and label-based records are bounded by the 63-byte DNS label
// limit), so the sender must chunk to the record type, not to a fixed 32 bytes.
func downstreamCap(qtype uint16, noise bool) int {
	switch qtype {
	case dns.TypeNULL:
		// NULL RDATA is raw bytes, bounded only by the 512-byte UDP response.
		return dnsTunnelMaxServerChunk
	case dns.TypeA:
		return 4
	case dns.TypeAAAA:
		return 16
	default:
		// CNAME / MX / SRV / NS: the whole payload is base32'd into a single
		// label, so 63 label chars == 39 bytes of frame.
		if noise {
			// [seq:4] + ciphertext(payload + 16 byte AEAD tag).
			return 19
		}
		return 39
	}
}

// =============================================================
// Client: DNSTunnel (implements net.Conn, so SSH can run over it)
// =============================================================

type dnsTunnelAddr struct{ domain string }

func (a *dnsTunnelAddr) Network() string { return "dns_custom" }
func (a *dnsTunnelAddr) String() string  { return "dns_custom:" + a.domain }

// DNSTunnel turns a DNS resolver pair into a byte stream: writes are chunked into
// DNS queries, reads pull data back out of the DNS answers. It implements
// net.Conn, so an SSH client can be handed straight to it.
type DNSTunnel struct {
	ctx     context.Context
	cancel  context.CancelFunc
	cfg     ProxyConfig
	servers []string // Upstream DNS server addresses (udp/tcp/tls/doh forms)
	domain  string   // FQDN, e.g. "tunnel.example.com."
	qtype   uint16
	session string

	chunkSize    int
	pollInterval time.Duration

	// Multi-path concurrency: one dnsPath per configured upstream server. Each
	// path keeps a warm socket pool and runs its own poll loop, so every server
	// contributes throughput instead of only being a failover spare.
	paths        []*dnsPath
	serverCursor atomic.Uint32  // atomic; round-robin cursor over upstream servers
	failUntil    []atomic.Int64 // atomic per element; deadline until a path is skipped
	seq          atomic.Uint32  // atomic; per-query anti-cache sequence

	inMu   sync.Mutex
	inCond *sync.Cond
	inBuf  *bytes.Buffer

	noiseSession *NoiseSession

	// Adaptive in-flight window for upstream chunks (see onWindowSample).
	window     atomic.Int32 // atomic; current total in-flight window
	winCredit  atomic.Int64 // atomic; successful samples since the last growth step
	winSamples atomic.Int64 // atomic; samples seen so far, used to skip the cold-start ones
	bestRTT    atomic.Int64 // atomic; best upstream round trip seen so far, in nanoseconds

	// Reliable-ordered transport: dedup plus in-order reassembly in both directions.
	dataSeq  atomic.Uint32     // atomic; per-chunk upstream ordering sequence
	ack      atomic.Uint32     // atomic; highest contiguous downstream serverSeq received (== recvNext-1)
	recvNext uint32            // next expected downstream serverSeq
	recvOOO  map[uint32][]byte // out-of-order downstream chunks buffered for in-order delivery
	recvMu   sync.Mutex

	closed  atomic.Bool
	closeCh chan struct{}

	dlMu          sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// NewDNSTunnel builds a DNS tunnel from the config's dns_tunnel_* fields.
func NewDNSTunnel(ctx context.Context, cfg ProxyConfig) (net.Conn, error) {
	domain := cfg.DnsTunnelDomain
	servers := cfg.DnsTunnelServers
	if domain == "" || len(servers) == 0 {
		return nil, fmt.Errorf("dns tunnel requires dns_tunnel_domain and dns_tunnel_servers in config")
	}
	qtype, err := dnsTypeToQType(cfg.DnsTunnelType)
	if err != nil {
		return nil, err
	}
	t := newDNSTunnel(ctx, cfg, servers, domain, qtype, "")
	zlog.Infof("%s [Tunnel-DNS] 🚀 DNS tunnel initialized | Domain=%s | Servers=%v | Type=%s",
		TAG, domain, servers, cfg.DnsTunnelType)
	return t, nil
}

// newDNSTunnel builds the tunnel; the session id is only injected by tests that
// need a stable, pre-known session.
func newDNSTunnel(ctx context.Context, cfg ProxyConfig, servers []string, domain string, qtype uint16, session string) *DNSTunnel {
	if session == "" {
		session = fmt.Sprintf("%x", mrand.Uint64())
	}
	cctx, cancel := context.WithCancel(ctx)
	paths := make([]*dnsPath, 0, len(servers))
	for _, srv := range servers {
		paths = append(paths, newDNSPath(cfg, srv))
	}
	t := &DNSTunnel{
		ctx:          cctx,
		cancel:       cancel,
		cfg:          cfg,
		servers:      servers,
		domain:       dns.Fqdn(domain),
		qtype:        qtype,
		session:      session,
		chunkSize:    dnsTunnelDefaultChunk,
		pollInterval: dnsTunnelPollInterval,
		paths:        paths,
		failUntil:    make([]atomic.Int64, len(servers)),
		inBuf:        new(bytes.Buffer),
		closeCh:      make(chan struct{}),
		recvNext:     1,
		recvOOO:      make(map[uint32][]byte),
	}
	t.window.Store(dnsTunnelUpstreamWindow)

	pubKeyStr := cfg.DnsTunnelPublicKey
	if pubKeyStr == "" {
		pubKeyStr = cfg.NoisePublicKey
	}
	if pubKeyStr != "" {
		if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			cancel()
			zlog.Errorf("%s [Tunnel-DNS] ⚠️ record type cannot carry authenticated Noise frames (A/AAAA hold 4/16 bytes); use txt/null/cname/mx/srv/ns", TAG)
			return nil
		}
		if pk, err := ParseNoiseKey(pubKeyStr); err == nil {
			if ns, ePub, err := NewClientNoiseSession(pk); err == nil {
				t.noiseSession = ns
				// 22 plain bytes + 16 AEAD tag = 38 -> 61 base32 chars, which is
				// still within the 63-char DNS label limit.
				t.chunkSize = 22
				// The handshake is retried across servers under the SAME dataSeq.
				// The server anchors its in-order state on the handshake seq, so a
				// retry must not advance it - otherwise a slow-but-delivered first
				// attempt leaves a hole the peer would wait on forever. The ePub is
				// sent in the clear (Noise_NK sends the ephemeral pubkey openly).
				hsSeq := t.dataSeq.Add(1)
				var hsErr error
				for i := range t.paths {
					if _, err := t.sendQuery(i, flagData, ePub, hsSeq); err != nil {
						hsErr = err
						continue
					}
					hsErr = nil
					break
				}
				if hsErr != nil {
					cancel()
					zlog.Errorf("%s [Tunnel-DNS] ❌ Noise_NK handshake exchange failed: %v", TAG, hsErr)
					return nil
				}
				zlog.Infof("%s [Tunnel-DNS] 🔐 Noise_NK AEAD encryption enabled", TAG)
			}
		}
	}

	// One poller per upstream server. Polls are independent, each answer carries one
	// downstream frame, and reassembly is order-independent, so every configured path
	// contributes throughput instead of only serving as a failover spare.
	for i := range t.servers {
		go t.pollLoop(i)
	}

	return t
}

func (t *DNSTunnel) isClosed() bool { return t.closed.Load() }

func (t *DNSTunnel) appendIn(b []byte) {
	t.inMu.Lock()
	t.inBuf.Write(b)
	t.inMu.Unlock()
}

// dnsPath is one upstream resolver plus its warm socket pool. A pooled socket is
// owned exclusively by the query that is in flight on it: a shared socket would
// let one caller's read steal another caller's response.
type dnsPath struct {
	server  string
	dohURL  string
	network string
	addr    string
	dnsCli  *dns.Client
	httpCli *http.Client
	pool    chan *dns.Conn
	closed  atomic.Bool
}

// newDNSPath builds a path for one upstream server, wiring every socket through the
// protected dialer so tunnel traffic stays outside the host VPN.
func newDNSPath(cfg ProxyConfig, server string) *dnsPath {
	p := &dnsPath{server: server, pool: make(chan *dns.Conn, dnsTunnelConnPool)}
	switch {
	case strings.HasPrefix(server, "https://"), strings.HasPrefix(server, "http://"):
		p.dohURL = server
	case strings.HasPrefix(server, "doh://"):
		p.dohURL = "https://" + strings.TrimPrefix(server, "doh://")
	case strings.HasPrefix(server, "tcp://"):
		p.network, p.addr = "tcp", strings.TrimPrefix(server, "tcp://")
	case strings.HasPrefix(server, "tls://"), strings.HasPrefix(server, "dot://"):
		p.network, p.addr = "tcp-tls", strings.TrimPrefix(strings.TrimPrefix(server, "tls://"), "dot://")
	default:
		p.network, p.addr = "udp", server
	}
	if p.network != "" && !strings.Contains(p.addr, ":") {
		p.addr += ":53"
	}
	if p.dohURL != "" {
		p.httpCli = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return newProtectedDialer(cfg, dnsTunnelQueryTimeout).DialContext(ctx, network, addr)
			},
		}}
	} else {
		p.dnsCli = &dns.Client{
			Net:     p.network,
			Dialer:  newProtectedDialer(cfg, dnsTunnelQueryTimeout),
			Timeout: dnsTunnelQueryTimeout,
		}
	}
	return p
}

func (p *dnsPath) acquire() (*dns.Conn, error) {
	select {
	case co := <-p.pool:
		return co, nil
	default:
	}
	return p.dnsCli.Dial(p.addr)
}

func (p *dnsPath) release(co *dns.Conn) {
	if co == nil {
		return
	}
	if p.closed.Load() {
		_ = co.Close()
		return
	}
	select {
	case p.pool <- co:
	default:
		_ = co.Close() // pool is full; do not grow it without bound
	}
}

func (p *dnsPath) close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	for {
		select {
		case co := <-p.pool:
			_ = co.Close()
		default:
			return
		}
	}
}

func (p *dnsPath) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if p.dohURL != "" {
		return p.exchangeDoH(ctx, m)
	}
	co, err := p.acquire()
	if err != nil {
		return nil, err
	}
	resp, _, err := p.dnsCli.ExchangeWithConnContext(ctx, m, co)
	if err != nil {
		// Drop the socket: a pooled one may have gone stale (peer closed it, NAT
		// expired), and the next acquire dials a fresh one.
		_ = co.Close()
		return nil, err
	}
	p.release(co)
	return resp, nil
}

func (p *dnsPath) exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	raw, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.dohURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := p.httpCli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	return reply, nil
}

// sendQuery sends one tunnel query to a single upstream server and feeds any answer
// payload into the downstream reassembly. It returns the number of downstream bytes
// that became available to Read.
//
// Queries are no longer serialized globally: the only ordering requirement used to be
// the AEAD nonce, and that is now derived from the sequence number carried by the
// query/frame itself.
func (t *DNSTunnel) sendQuery(pathIdx int, flag byte, wirePayload []byte, dataSeq uint32) (int, error) {
	if t.closed.Load() {
		return 0, net.ErrClosed
	}

	seq := t.seq.Add(1)
	name := buildQueryName(t.domain, t.session, seq, t.ack.Load(), dataSeq, flag, wirePayload)

	m := new(dns.Msg)
	m.SetQuestion(name, t.qtype)
	m.RecursionDesired = false
	m.Id = uint16(seq)

	resp, err := t.paths[pathIdx].exchange(t.ctx, m)
	if err != nil {
		return 0, err
	}
	delivered := 0
	if resp != nil {
		for _, ans := range resp.Answer {
			if raw := extractAnswer(ans); len(raw) > 0 {
				delivered += t.deliverDownstream(raw)
			}
		}
	}
	return delivered, nil
}

// nextServer returns the next upstream path in round-robin order, skipping paths that
// are still cooling down after a failure. If every path is cooling down - or the
// process is offline entirely - it falls back to plain round-robin so a chunk is never
// left without a path to try.
func (t *DNSTunnel) nextServer() int {
	n := uint32(len(t.paths))
	now := time.Now().UnixNano()
	var fallback uint32
	for i := uint32(0); i < n; i++ {
		idx := t.serverCursor.Add(1) % n
		if i == 0 {
			fallback = idx
		}
		if t.failUntil[idx].Load() <= now {
			return int(idx)
		}
	}
	return int(fallback)
}

// upstreamWindow is how many upstream chunks may be in flight at once. It starts
// conservatively and is grown by onWindowSample, and its ceiling scales with the
// number of paths: every configured path carries its own share of the load, so more
// paths justify more in-flight queries - but only the measurements can say how many.
func (t *DNSTunnel) upstreamWindow() int {
	w := int(t.window.Load())
	max := dnsTunnelMaxUpstreamWindow * len(t.paths)
	if max > dnsTunnelMaxTotalWindow {
		max = dnsTunnelMaxTotalWindow
	}
	if w > max {
		w = max
	}
	if w < dnsTunnelMinUpstreamWindow {
		w = dnsTunnelMinUpstreamWindow
	}
	return w
}

// onWindowSample adapts the in-flight window from a completed upstream query, the same
// way congestion control does: grow while the path still answers at its best RTT, back
// off as soon as it slows down or drops. The right window is a property of the path,
// not of the code - on a loopback link 8 in-flight queries already saturate it and 32
// roughly halves the throughput, while on a 20 ms path 16 nearly doubles it - so it is
// measured rather than configured, and it is what lets several paths add up.
func (t *DNSTunnel) onWindowSample(ok bool, rtt time.Duration) {
	if !ok {
		t.halveWindow()
		return
	}
	// A zero round trip is a shutdown or clock artifact, not a measurement. Taking it
	// as the best RTT ever seen would make every later sample look slow and pin the
	// window at its minimum.
	if rtt <= 0 {
		return
	}
	// The first queries include socket setup, DNS server warm-up and GC noise, so
	// their latency says nothing about the path. Adopting one of those as the
	// "best" RTT would make every later sample look fast and pin the window at its
	// maximum, which is the exact opposite of what adaptation is for.
	if t.winSamples.Add(1) <= dnsTunnelWindowWarmup {
		return
	}
	best := t.bestRTT.Load()
	switch {
	case best > 0 && rtt > time.Duration(best)*2:
		// The path is clearly slower than it can be: we are past the useful window.
		// 2x is deliberately tight - on a low-latency link the queueing shows up well
		// before any query actually fails, and sitting at a too-wide window costs more
		// throughput than backing off does.
		t.resizeWindow(func(cur int32) int32 {
			if cur-1 < dnsTunnelMinUpstreamWindow {
				return dnsTunnelMinUpstreamWindow
			}
			return cur - 1
		})
		t.winCredit.Store(0)
		return
	case best > 0 && rtt > time.Duration(best)+time.Duration(best)/2:
		// Congested but not failing. Holding steady is not enough on its own: on a
		// low-latency path the queueing that a too-wide window causes never grows past
		// the shrink threshold, so the window would sit at the wrong size forever.
		// Decay slowly instead - one step per window's worth of queued samples.
		if t.winCredit.Add(1) >= int64(t.window.Load()) {
			t.winCredit.Store(0)
			t.resizeWindow(func(cur int32) int32 {
				if cur-1 < dnsTunnelMinUpstreamWindow {
					return dnsTunnelMinUpstreamWindow
				}
				return cur - 1
			})
		}
		return
	}

	if best == 0 || int64(rtt) < best {
		t.bestRTT.Store(int64(rtt))
	}

	// Additive increase, paced to roughly one step per round trip: a window's worth of
	// successful queries is about one RTT at the current concurrency.
	if t.winCredit.Add(1) >= int64(t.window.Load()) {
		t.winCredit.Store(0)
		t.resizeWindow(func(cur int32) int32 {
			ceil := dnsTunnelMaxUpstreamWindow * len(t.paths)
			if ceil > dnsTunnelMaxTotalWindow {
				ceil = dnsTunnelMaxTotalWindow
			}
			if cur+1 > int32(ceil) {
				return int32(ceil)
			}
			return cur + 1
		})
	}
}

// halveWindow backs the window off after a failed query: a path that is dropping
// queries must not keep a wide window, or every retry floods it further.
func (t *DNSTunnel) halveWindow() {
	t.resizeWindow(func(cur int32) int32 {
		next := cur / 2
		if next < dnsTunnelMinUpstreamWindow {
			return dnsTunnelMinUpstreamWindow
		}
		return next
	})
	t.winCredit.Store(0)
}

// resizeWindow applies a clamp-and-grow step atomically.
func (t *DNSTunnel) resizeWindow(step func(int32) int32) {
	for {
		cur := t.window.Load()
		next := step(cur)
		if next == cur || t.window.CompareAndSwap(cur, next) {
			return
		}
	}
}

func (t *DNSTunnel) markPathHealthy(idx int) {
	if idx >= 0 && idx < len(t.failUntil) {
		t.failUntil[idx].Store(0)
	}
}

func (t *DNSTunnel) markPathFailed(idx int) {
	if idx >= 0 && idx < len(t.failUntil) {
		t.failUntil[idx].Store(time.Now().Add(dnsTunnelPathCooldown).UnixNano())
	}
}

// deliverDownstream reassembles downstream chunks in serverSeq order and updates the
// ACK the client advertises to the server. For TXT it reads the reliable-transport
// frame header, decrypts the payload with the nonce derived from serverSeq, and then
// runs the in-order reassembly. Other record types are best-effort: with Noise they
// carry a 4-byte sequence header in front of the ciphertext for the same reason.
//
// Reassembly bookkeeping happens under recvMu, but inBuf is only ever touched under
// inMu. Any number of pollers can deliver downstream data while the Read goroutine
// drains inBuf, so one lock per buffer is what keeps this race-free.
func (t *DNSTunnel) deliverDownstream(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	noise := t.noiseSession != nil && t.noiseSession.RecvCipher != nil

	if t.qtype == dns.TypeTXT {
		serverSeq, skipTo, tail, ok := decodeDownstreamFrame(raw)
		if !ok {
			// Not a framed chunk (legacy or truncated answer). Without a sequence
			// number there is no nonce, so an authenticated chunk cannot be opened.
			if noise {
				zlog.Warnf("%s [Tunnel-DNS] short TXT frame (%d bytes) cannot be authenticated, dropped", TAG, len(raw))
				return 0
			}
			return t.writeInBuf(raw)
		}

		payload := tail
		if noise {
			dec, err := t.noiseSession.RecvCipher.DecryptWithSeq(serverSeq, tail)
			if err != nil {
				zlog.Warnf("%s [Tunnel-DNS] downstream frame serverSeq=%d failed to decrypt: %v", TAG, serverSeq, err)
				return 0
			}
			payload = dec
		}

		t.recvMu.Lock()
		// The server abandoned everything below skipTo: accept the gap rather than
		// block forever on chunks that will never arrive.
		if seqLess(t.recvNext, skipTo) {
			for k := range t.recvOOO {
				if seqLess(k, skipTo) {
					delete(t.recvOOO, k)
				}
			}
			t.recvNext = skipTo
		}
		var out []byte
		if seqLess(serverSeq, t.recvNext) {
			// duplicate, already delivered in order
		} else if serverSeq == t.recvNext {
			out = append(out, payload...)
			t.recvNext++
		} else if _, exists := t.recvOOO[serverSeq]; !exists {
			t.recvOOO[serverSeq] = append([]byte(nil), payload...)
		}
		out = append(out, t.drainRecvOOO()...)
		t.ack.Store(t.recvNext - 1)
		t.recvMu.Unlock()

		return t.writeInBuf(out)
	}

	// Non-TXT: best-effort delivery.
	if noise {
		if len(raw) < nonTxtNoiseHeaderSize {
			return 0
		}
		seq := binary.BigEndian.Uint32(raw[:nonTxtNoiseHeaderSize])
		dec, err := t.noiseSession.RecvCipher.DecryptWithSeq(seq, raw[nonTxtNoiseHeaderSize:])
		if err != nil {
			zlog.Warnf("%s [Tunnel-DNS] downstream chunk seq=%d failed to decrypt: %v", TAG, seq, err)
			return 0
		}
		return t.writeInBuf(dec)
	}
	return t.writeInBuf(raw)
}

func (t *DNSTunnel) writeInBuf(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	t.inMu.Lock()
	n, _ := t.inBuf.Write(b)
	if t.inCond != nil {
		t.inCond.Broadcast()
	}
	t.inMu.Unlock()
	return n
}

func (t *DNSTunnel) pendingDownstream() int {
	t.inMu.Lock()
	defer t.inMu.Unlock()
	return t.inBuf.Len()
}

// drainRecvOOO returns the contiguous run of buffered chunks starting at recvNext.
// Caller must hold t.recvMu.
func (t *DNSTunnel) drainRecvOOO() []byte {
	var out []byte
	for {
		c, ok := t.recvOOO[t.recvNext]
		if !ok {
			return out
		}
		out = append(out, c...)
		delete(t.recvOOO, t.recvNext)
		t.recvNext++
	}
}

// pollLoop keeps one upstream path busy: it polls, hands any answer to the reassembly,
// and paces itself. Data-bearing polls pipeline; empty polls back off. It also pauses
// while the reader has not drained what was already fetched, so a slow consumer cannot
// make the tunnel hoard answers.
func (t *DNSTunnel) pollLoop(idx int) {
	for {
		if t.closed.Load() {
			return
		}
		select {
		case <-t.ctx.Done():
			return
		case <-t.closeCh:
			return
		default:
		}

		// Back off only once a real backlog has piled up. Throttling on ">0" would
		// stall a poller for a whole poll interval every time the reader happens to
		// be a few microseconds behind.
		if t.pendingDownstream() >= dnsTunnelDownstreamBacklog {
			t.sleep(t.pollInterval)
			continue
		}

		n, err := t.sendQuery(idx, flagPoll, nil, 0)
		switch {
		case err != nil:
			t.markPathFailed(idx)
			t.sleep(t.pollInterval)
		case n > 0:
			t.markPathHealthy(idx)
			t.sleep(dnsTunnelPollBusyInterval)
		default:
			t.markPathHealthy(idx)
			t.sleep(t.pollInterval)
		}
	}
}

func (t *DNSTunnel) sleep(d time.Duration) {
	select {
	case <-t.ctx.Done():
	case <-t.closeCh:
	case <-time.After(d):
	}
}

func (t *DNSTunnel) Read(p []byte) (int, error) {
	t.inMu.Lock()
	defer t.inMu.Unlock()

	for t.inBuf.Len() == 0 {
		if t.closed.Load() {
			return 0, net.ErrClosed
		}
		if t.readDeadlineExceeded() {
			return 0, fmt.Errorf("dns tunnel: %w", os.ErrDeadlineExceeded)
		}
		select {
		case <-t.ctx.Done():
			return 0, t.ctx.Err()
		case <-t.closeCh:
			return 0, net.ErrClosed
		default:
		}

		if t.inCond != nil {
			t.inCond.Wait()
		} else {
			t.inMu.Unlock()
			time.Sleep(10 * time.Millisecond)
			t.inMu.Lock()
		}
	}

	return t.inBuf.Read(p)
}

func (t *DNSTunnel) Write(p []byte) (int, error) {
	if t.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	total := len(p)

	type chunkJob struct {
		seq  uint32
		data []byte
	}
	var jobs []chunkJob
	for len(p) > 0 {
		n := len(p)
		if n > t.chunkSize {
			n = t.chunkSize
		}
		jobs = append(jobs, chunkJob{seq: t.dataSeq.Add(1), data: p[:n]})
		p = p[n:]
	}

	// Upstream chunks fly concurrently. The window scales with the number of paths so
	// each path can keep several queries in flight - that, not the path count alone, is
	// what turns latency into throughput.
	win := t.upstreamWindow()
	if win > len(jobs) {
		win = len(jobs)
	}
	if win <= 0 {
		win = 1
	}

	jobsCh := make(chan chunkJob, len(jobs))
	for _, j := range jobs {
		jobsCh <- j
	}
	close(jobsCh)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var sentBytes int

	for i := 0; i < win; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsCh {
				if t.closed.Load() {
					mu.Lock()
					if firstErr == nil {
						firstErr = net.ErrClosed
					}
					mu.Unlock()
					return
				}
				if err := t.sendDataChunkWithRetry(job.data, job.seq); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				sentBytes += len(job.data)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return sentBytes, firstErr
	}
	return total, nil
}

// sendDataChunkWithRetry sends a data chunk and retransmits it (same dataSeq, hence the
// same ciphertext) on failure. The server dedups by dataSeq, so a retransmit is safe and
// just re-delivers the in-order chunk - this makes the upstream direction loss-tolerant.
func (t *DNSTunnel) sendDataChunkWithRetry(chunk []byte, dataSeq uint32) error {
	wire := chunk
	if t.noiseSession != nil && t.noiseSession.SendCipher != nil {
		// Sealed once, outside the retry loop: the nonce is derived from dataSeq, so
		// every attempt is byte-identical and the server can dedup it.
		wire = t.noiseSession.SendCipher.EncryptWithSeq(dataSeq, chunk)
	}
	var lastErr error
	for attempt := 0; attempt < dnsTunnelMaxSendAttempts; attempt++ {
		if t.closed.Load() {
			return net.ErrClosed
		}
		idx := t.nextServer()
		start := time.Now()
		_, err := t.sendQuery(idx, flagData, wire, dataSeq)
		t.onWindowSample(err == nil, time.Since(start))
		if err != nil {
			lastErr = err
			t.markPathFailed(idx)
		} else {
			t.markPathHealthy(idx)
			return nil
		}
		t.sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return fmt.Errorf("dns tunnel: data chunk dataSeq=%d failed after %d attempts: %w", dataSeq, dnsTunnelMaxSendAttempts, lastErr)
}

func (t *DNSTunnel) Close() error {
	if t.closed.CompareAndSwap(false, true) {
		close(t.closeCh)
		t.inMu.Lock()
		if t.inCond != nil {
			t.inCond.Broadcast()
		}
		t.inMu.Unlock()
		t.sendCloseSignal()
		t.cancel()
		for _, p := range t.paths {
			p.close()
		}
	}
	return nil
}

// sendCloseSignal tells the server to tear down the session. It runs on a detached
// deadline: cancelling the tunnel context would otherwise also prevent the close
// query from ever leaving the host.
func (t *DNSTunnel) sendCloseSignal() {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTunnelCloseTimeout)
	defer cancel()

	seq := t.seq.Add(1)
	name := buildQueryName(t.domain, t.session, seq, t.ack.Load(), 0, flagClose, nil)
	m := new(dns.Msg)
	m.SetQuestion(name, t.qtype)
	m.RecursionDesired = false
	m.Id = uint16(seq)

	// Send on the detached context through a throwaway path so it still goes out
	// after the tunnel's own context is cancelled.
	_, _ = newDNSPath(t.cfg, t.servers[t.nextServer()]).exchange(ctx, m)
}

func (t *DNSTunnel) LocalAddr() net.Addr  { return &dnsTunnelAddr{t.domain} }
func (t *DNSTunnel) RemoteAddr() net.Addr { return &dnsTunnelAddr{t.domain} }
func (t *DNSTunnel) SetDeadline(deadline time.Time) error {
	t.SetReadDeadline(deadline)
	t.SetWriteDeadline(deadline)
	return nil
}
func (t *DNSTunnel) SetReadDeadline(deadline time.Time) error {
	t.dlMu.Lock()
	t.readDeadline = deadline
	t.dlMu.Unlock()
	return nil
}
func (t *DNSTunnel) SetWriteDeadline(deadline time.Time) error {
	t.dlMu.Lock()
	t.writeDeadline = deadline
	t.dlMu.Unlock()
	return nil
}
func (t *DNSTunnel) readDeadlineExceeded() bool {
	t.dlMu.Lock()
	d := t.readDeadline
	t.dlMu.Unlock()
	return !d.IsZero() && time.Now().After(d)
}
func (t *DNSTunnel) writeDeadlineExceeded() bool {
	t.dlMu.Lock()
	d := t.writeDeadline
	t.dlMu.Unlock()
	return !d.IsZero() && time.Now().After(d)
}

// =============================================================
// Server side: DNSTunnelServer (terminates the tunnel in-process)
// =============================================================

// downstreamChunk is one un-acked downstream chunk. ct is the payload as it goes on
// the wire: plaintext when Noise is off, ciphertext otherwise. It is sealed once when
// the chunk is created, because the AEAD nonce is derived from serverSeq - re-sealing
// on every retransmission would reuse a nonce with a fresh (wrong) counter, and the
// client could never decrypt a retransmitted chunk.
type downstreamChunk struct {
	ct        []byte
	firstSent time.Time
}

type dnsTunnelSession struct {
	mu        sync.Mutex
	clientBuf bytes.Buffer // client -> server, delivered strictly in dataSeq order
	serverBuf bytes.Buffer // server -> client, framed for TXT, raw otherwise
	readCond  *sync.Cond
	closed    bool

	// pumpWaiting is true while the backend pump (ReadSession) is blocked in
	// readCond.Wait. Broadcasting on every chunk would make each concurrent
	// upstream query pay for a futex wakeup plus the mutex handoff that follows,
	// which is what capped throughput once several paths were in flight at once.
	pumpWaiting bool

	// noiseSession is the Noise_NK transport state, set when the server is
	// configured with a static private key. It stays nil for the in-process
	// terminator used by tests, which is a cleartext (non-Noise) server.
	noiseSession *NoiseSession

	// Reliable-ordered transport: dedup plus in-order reassembly in both directions.
	clientNext   uint32                      // next in-order upstream dataSeq expected from client
	clientOOO    map[uint32][]byte           // out-of-order upstream chunks buffered for later delivery
	serverNext   uint32                      // next downstream serverSeq to assign
	serverOut    map[uint32]*downstreamChunk // un-acked downstream chunks kept for retransmission
	serverSkipTo uint32                      // >0 once chunks were abandoned: client must expect this seq
}

func newDnsTunnelSession() *dnsTunnelSession {
	s := &dnsTunnelSession{
		clientNext: 1, // first upstream data chunk is always dataSeq=1
		clientOOO:  make(map[uint32][]byte),
		serverNext: 1,
		serverOut:  make(map[uint32]*downstreamChunk),
	}
	s.readCond = sync.NewCond(&s.mu)
	return s
}

// ReadSession blocks until the client has sent something, then returns up to max
// bytes of it.
func (s *dnsTunnelSession) ReadSession(max int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.clientBuf.Len() == 0 && !s.closed {
		s.pumpWaiting = true
		s.readCond.Wait()
		s.pumpWaiting = false
	}
	if s.clientBuf.Len() == 0 && s.closed {
		return nil, io.EOF
	}
	n := s.clientBuf.Len()
	if n > max {
		n = max
	}
	out := make([]byte, n)
	_, _ = s.clientBuf.Read(out)
	return out, nil
}

// WriteSession queues bytes for the "server -> client" direction.
func (s *dnsTunnelSession) WriteSession(b []byte) {
	s.mu.Lock()
	s.serverBuf.Write(b)
	s.mu.Unlock()
}

// pushClient delivers one upstream chunk: it drops duplicates, buffers
// out-of-order chunks, and hands the backend a strictly dataSeq-ordered stream.
func (s *dnsTunnelSession) pushClient(seq uint32, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(b) == 0 {
		return
	}
	payload := b
	if s.noiseSession != nil && s.noiseSession.RecvCipher != nil {
		// Nonce is derived from the upstream sequence number, not from arrival
		// order: duplicates decrypt to the same plaintext and out-of-order chunks
		// decrypt independently, which is what makes concurrent paths safe.
		dec, err := s.noiseSession.RecvCipher.DecryptWithSeq(seq, b)
		if err != nil {
			zlog.Warnf("%s [Tunnel-DNS-Server] Noise decryption failed for dataSeq=%d: %v", TAG, seq, err)
			return
		}
		payload = dec
	}
	if seqLess(seq, s.clientNext) {
		return // duplicate, already delivered in order
	}
	if seq == s.clientNext {
		s.clientBuf.Write(payload)
		s.clientNext++
		for {
			c, ok := s.clientOOO[s.clientNext]
			if !ok {
				break
			}
			s.clientBuf.Write(c)
			delete(s.clientOOO, s.clientNext)
			s.clientNext++
		}
	} else if _, exists := s.clientOOO[seq]; !exists {
		s.clientOOO[seq] = append([]byte(nil), payload...)
	}
	// Wake the backend pump only when it is actually parked. Broadcasting on every
	// chunk makes each concurrent upstream query pay for a futex wakeup plus the
	// mutex handoff that follows, which is what capped throughput once several
	// paths were in flight at once.
	if s.pumpWaiting {
		s.readCond.Broadcast()
	}
}

// popServerNow serves one best-effort chunk for non-TXT record types, chunked to the
// capacity of the record type. With Noise the payload is sealed under the sequence
// number and the 4-byte header in front of it lets the client rebuild the nonce.
func (s *dnsTunnelSession) popServerNow(max int, noise bool) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverBuf.Len() == 0 {
		return nil
	}
	n := s.serverBuf.Len()
	if n > max {
		n = max
	}
	out := make([]byte, n)
	_, _ = s.serverBuf.Read(out)

	if !noise {
		return out
	}
	seq := s.serverNext
	s.serverNext++
	ct := s.sealDownstream(seq, out)
	frame := make([]byte, nonTxtNoiseHeaderSize+len(ct))
	binary.BigEndian.PutUint32(frame[:nonTxtNoiseHeaderSize], seq)
	copy(frame[nonTxtNoiseHeaderSize:], ct)
	return frame
}

// freeDownstream drops downstream chunks the client has confirmed (ack = highest
// contiguous serverSeq it received). Keeps the retransmit buffer bounded.
func (s *dnsTunnelSession) freeDownstream(ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.serverOut {
		if !seqLess(ack, k) { // k <= ack (wraparound-safe)
			delete(s.serverOut, k)
		}
	}
}

// oldestDownstreamSeq returns the lowest (wraparound-aware) seq in serverOut.
// Caller must hold s.mu.
func oldestDownstreamSeq(m map[uint32]*downstreamChunk) uint32 {
	var minK uint32
	first := true
	for k := range m {
		if first || seqLess(k, minK) {
			minK = k
			first = false
		}
	}
	return minK
}

// sealDownstream encrypts a payload under the nonce derived from seq.
// Caller must hold s.mu.
func (s *dnsTunnelSession) sealDownstream(seq uint32, payload []byte) []byte {
	if s.noiseSession != nil && s.noiseSession.SendCipher != nil {
		return s.noiseSession.SendCipher.EncryptWithSeq(seq, payload)
	}
	return payload
}

// serveDownstream returns the next downstream chunk for the client.
//
// For TXT it implements the reliable-ordered transport as a sliding window: while
// fewer than dnsTunnelDownstreamWindow chunks are outstanding it serves fresh data,
// so concurrent polls across multiple upstream servers each fetch a different chunk
// and their throughput adds up. Once the window is full it falls back to
// retransmitting the oldest un-acked chunk.
//
// The chunk is sized against the response budget: a data query echoes the upstream
// chunk label in the answer, so it can carry less downstream data than a poll can,
// and overshooting 512 bytes of UDP loses the whole datagram.
//
// A chunk that stays unacked past dnsTunnelDownstreamGiveUp is abandoned: it is
// dropped from serverOut and serverSkipTo tells the client to expect the next
// seq. Accepting a gap is what stops one repeatedly-dropped response from
// stalling the entire stream forever.
//
// Other record types use the legacy best-effort path (popServerNow), which has no
// retransmission and therefore no window, but is now chunked to the capacity of the
// record type instead of a fixed 32 bytes.
func (s *dnsTunnelSession) serveDownstream(qtype uint16, qname string) []byte {
	noise := s.noiseSession != nil && s.noiseSession.SendCipher != nil
	if qtype != dns.TypeTXT {
		// A/AAAA answers hold exactly one address, which cannot carry a framed,
		// authenticated payload. Serve nothing rather than ship a truncated
		// ciphertext the client can only reject.
		if noise && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
			return nil
		}
		return s.popServerNow(maxDownstreamPayload(qtype, noise, qname), noise)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Abandon chunks the client never acked within the give-up window.
	for len(s.serverOut) > 0 {
		oldest := oldestDownstreamSeq(s.serverOut)
		if time.Since(s.serverOut[oldest].firstSent) <= dnsTunnelDownstreamGiveUp {
			break
		}
		delete(s.serverOut, oldest)
		s.serverSkipTo = oldest + 1
	}

	// Window has room and there is fresh data: hand the poll a new chunk. Each
	// concurrent poll takes a distinct chunk because serverOut grows under s.mu.
	//
	// The chunk is sized against the response budget: a data query echoes the
	// upstream chunk label in the answer, so it can carry less downstream data than
	// a poll can, and overshooting 512 bytes of UDP loses the whole datagram.
	maxPayload := maxDownstreamPayload(dns.TypeTXT, noise, qname)
	if maxPayload > 0 && len(s.serverOut) < dnsTunnelDownstreamWindow && s.serverBuf.Len() > 0 {
		avail := maxPayload
		if s.serverBuf.Len() < avail {
			avail = s.serverBuf.Len()
		}
		out := make([]byte, avail)
		_, _ = s.serverBuf.Read(out)
		seq := s.serverNext
		s.serverNext++
		s.serverOut[seq] = &downstreamChunk{
			ct:        s.sealDownstream(seq, out),
			firstSent: time.Now(),
		}
		return encodeDownstreamFrame(seq, s.serverSkipTo, s.serverOut[seq].ct)
	}

	if len(s.serverOut) > 0 {
		// Window full (or nothing fresh to send): refill the oldest gap. The frame
		// is rebuilt each time so retransmissions carry the current skipTo.
		oldest := oldestDownstreamSeq(s.serverOut)
		return encodeDownstreamFrame(oldest, s.serverSkipTo, s.serverOut[oldest].ct)
	}
	return nil
}

func (s *dnsTunnelSession) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.readCond.Broadcast()
	s.mu.Unlock()
}

// DNSTunnelServer terminates DNS tunnels in-process instead of dialing a target:
// it is the counterpart of DNSTunnel, for when the app wants to receive a tunnel
// (for example to feed an SSH server) rather than connect out through one.
//
// Usage: WaitForSession learns about a new client, ReadSession pulls the client's
// bytes, WriteSession pushes bytes back to it. Sessions are keyed by the session
// id the client chose.
type DNSTunnelServer struct {
	domain      string
	mu          sync.Mutex
	sessions    map[string]*dnsTunnelSession
	newSessions chan string
}

// NewDNSTunnelServer starts a tunnel terminator for the given authoritative domain.
func NewDNSTunnelServer(domain string) *DNSTunnelServer {
	return &DNSTunnelServer{
		domain:      dns.Fqdn(domain),
		sessions:    make(map[string]*dnsTunnelSession),
		newSessions: make(chan string, 16),
	}
}

func (s *DNSTunnelServer) getOrCreate(session string) *dnsTunnelSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[session]; ok {
		return sess
	}
	sess := newDnsTunnelSession()
	s.sessions[session] = sess
	select {
	case s.newSessions <- session:
	default:
	}
	return sess
}

// WaitForSession blocks until a new client session appears (or the timeout fires).
func (s *DNSTunnelServer) WaitForSession(timeout time.Duration) (string, error) {
	select {
	case sess := <-s.newSessions:
		return sess, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("dns tunnel server: wait for session timeout")
	}
}

// ReadSession pulls up to max bytes that the client sent on this session.
func (s *DNSTunnelServer) ReadSession(session string, max int) ([]byte, error) {
	s.mu.Lock()
	sess, ok := s.sessions[session]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("dns tunnel server: unknown session %q", session)
	}
	return sess.ReadSession(max)
}

// WriteSession queues bytes for the "server -> client" direction of this session.
func (s *DNSTunnelServer) WriteSession(session string, b []byte) {
	s.mu.Lock()
	sess, ok := s.sessions[session]
	s.mu.Unlock()
	if !ok {
		return
	}
	sess.WriteSession(b)
}

// ServeDNS is the miekg/dns Handler that terminates tunnel queries.
func (s *DNSTunnelServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	reply := new(dns.Msg)
	if len(req.Question) == 0 {
		reply.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}
	q := req.Question[0]
	session, _, ack, dataSeq, flag, data, err := parseQueryName(s.domain, q.Name)
	if err != nil {
		zlog.Debugf("%s [Tunnel-DNS-Server] ⚠️ Parse failed: %v", TAG, err)
		reply.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	sess := s.getOrCreate(session)
	if flag == flagData && len(data) > 0 {
		// A client retry reuses the same dataSeq, so pushClient's dedup makes
		// this a no-op for anything already delivered in order.
		sess.pushClient(dataSeq, data)
	}
	if flag == flagClose {
		sess.markClosed()
	}

	// Release downstream chunks the client has confirmed receiving; this is what
	// keeps the retransmit buffer from growing without bound.
	sess.freeDownstream(ack)

	reply.SetReply(req)
	if out := sess.serveDownstream(q.Qtype, q.Name); len(out) > 0 {
		reply.Answer = append(reply.Answer, makeAnswer(q.Name, q.Qtype, out, s.domain))
	}
	_ = w.WriteMsg(reply)
}

// =============================================================
// Tunnel registration: exposes this transport as the "dns_custom" tunnel
// =============================================================

func init() {
	// Network="none": the DNS tunnel opens no socket of its own - it reaches the
	// network purely through DNS queries, so dialTunnel has nothing to set up.
	RegisterTunnel("dns_custom", "none", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return NewDNSTunnel(ctx, cfg)
	})
}
