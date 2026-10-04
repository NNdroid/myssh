package myssh

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

// Unified outbound design
//
// SOCKS DOMAIN requests already carry the strongest possible target identity and
// go directly into the domain-aware dial path. Transparent/TUN frontends may
// instead hand us an IP literal; in that case recoverDomainFromDNSCache() uses
// only DNS answers that this process actually observed. Ambiguous shared-IP
// mappings are deliberately rejected rather than guessed.
//
// Once a domain is known, DIRECT and PROXY share exactly the same candidate
// scheduler. Only the final dial primitive differs:
//   DIRECT -> dialProtected()
//   PROXY  -> ssh.Client.DialContext() (SSH direct-tcpip)
//
// UDP intentionally does not use this TCP race. A UDP connect/write cannot prove
// end-to-end reachability, and duplicating arbitrary UDP application payloads
// across address families is unsafe.

const (
	happyEyeballsDelay         = 250 * time.Millisecond
	happyEyeballsMaxCandidates = 4
	outboundDialTimeout        = 10 * time.Second
	reverseDNSMemoTTL          = 30 * time.Second
	reverseDNSNegativeTTL      = 5 * time.Second
)

type reverseDNSMemoEntry struct {
	domain  string
	expires time.Time
	found   bool
}

var reverseDNSMemo = struct {
	sync.Mutex
	entries map[string]reverseDNSMemoEntry
}{entries: make(map[string]reverseDNSMemoEntry)}

func resetReverseDNSMemo() {
	reverseDNSMemo.Lock()
	clear(reverseDNSMemo.entries)
	reverseDNSMemo.Unlock()
}

func parseIPLiteral(host string) (net.IP, bool) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	return ip, ip != nil
}

// recoverDomainFromDNSCache is the TPROXY/TUN fallback for flows whose frontend
// only retained an IP literal. It scans the authoritative in-process DNS cache
// on the first lookup for an IP and memoizes the result briefly. Only one unique
// domain may own the IP during its still-valid DNS TTL window; CDN/shared-IP
// ambiguity intentionally falls back to literal dialing.
func recoverDomainFromDNSCache(host string) (string, bool) {
	ip, ok := parseIPLiteral(host)
	if !ok {
		return "", false
	}
	key := ip.String()
	now := time.Now()

	reverseDNSMemo.Lock()
	if memo, exists := reverseDNSMemo.entries[key]; exists && now.Before(memo.expires) {
		reverseDNSMemo.Unlock()
		return memo.domain, memo.found
	}
	delete(reverseDNSMemo.entries, key)
	reverseDNSMemo.Unlock()

	lds := localDnsServer.Load()
	if lds == nil {
		return "", false
	}

	domains := make(map[string]time.Time)
	lds.cacheMu.RLock()
	for cacheKey, entry := range lds.cache {
		if !now.Before(entry.expiresAt) {
			continue
		}
		matched := false
		for _, cachedIP := range entry.ips {
			if cachedIP != nil && cachedIP.Equal(ip) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Cache keys are FQDN + "-" + numeric qtype. Splitting from the end is
		// safe for ordinary DNS names, including labels containing '-'.
		sep := strings.LastIndexByte(cacheKey, '-')
		if sep <= 0 {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(cacheKey[:sep]), ".")
		if domain == "" {
			continue
		}
		if old, exists := domains[domain]; !exists || entry.expiresAt.Before(old) {
			domains[domain] = entry.expiresAt
		}
	}
	lds.cacheMu.RUnlock()

	memo := reverseDNSMemoEntry{expires: now.Add(reverseDNSNegativeTTL)}
	if len(domains) == 1 {
		for domain, dnsExpiry := range domains {
			memo.domain = domain
			memo.found = true
			memo.expires = now.Add(reverseDNSMemoTTL)
			if dnsExpiry.Before(memo.expires) {
				memo.expires = dnsExpiry
			}
		}
	}

	reverseDNSMemo.Lock()
	reverseDNSMemo.entries[key] = memo
	reverseDNSMemo.Unlock()
	return memo.domain, memo.found
}

func proxyFamilyMode() string {
	remoteIPv6Egress.mu.Lock()
	defer remoteIPv6Egress.mu.Unlock()
	return remoteIPv6Egress.mode
}

func outboundAllowedFamilies(isDirect bool) (allow4, allow6 bool) {
	// DIRECT is intentionally auto. Public probe results are diagnostics only;
	// they cannot prove that an internal/private address family is unavailable.
	if isDirect {
		return true, true
	}

	switch proxyFamilyMode() {
	case IPv6EgressModeIPv4Only:
		return true, false
	case IPv6EgressModeIPv6Only:
		return false, true
	default: // auto and dual-stack
		return true, true
	}
}

func ipFamilyAllowed(ip net.IP, isDirect bool) bool {
	allow4, allow6 := outboundAllowedFamilies(isDirect)
	if ip == nil {
		return true
	}
	if ip.To4() != nil {
		return allow4
	}
	return allow6
}

// resolveAllOutboundIPs asks the existing routed DNS engine for both families
// concurrently. That preserves the app's local-vs-remote DNS policy and its DNS
// cache while giving the outbound scheduler all candidates rather than only one.
func resolveAllOutboundIPs(host string, isDirect bool) []net.IP {
	lds := localDnsServer.Load()
	if lds == nil || host == "" {
		return nil
	}

	allow4, allow6 := outboundAllowedFamilies(isDirect)
	types := make([]uint16, 0, 2)
	if allow4 {
		types = append(types, dns.TypeA)
	}
	if allow6 {
		types = append(types, dns.TypeAAAA)
	}
	if len(types) == 0 {
		return nil
	}

	type familyResult struct {
		ips []net.IP
	}
	results := make(chan familyResult, len(types))
	for _, qtype := range types {
		qtype := qtype
		taskTrack()
		go func() {
			defer taskRelease()
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(host), qtype)
			reply, err := lds.HandleDnsRequest(msg)
			if err != nil || reply == nil {
				results <- familyResult{}
				return
			}
			ips := extractAnswerIPs(reply)
			filtered := ips[:0]
			for _, ip := range ips {
				if ip == nil {
					continue
				}
				if qtype == dns.TypeA && ip.To4() == nil {
					continue
				}
				if qtype == dns.TypeAAAA && ip.To4() != nil {
					continue
				}
				filtered = append(filtered, ip)
			}
			results <- familyResult{ips: filtered}
		}()
	}

	seen := make(map[string]struct{})
	var out []net.IP
	for range types {
		for _, ip := range (<-results).ips {
			key := ip.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

func appendUniqueHost(dst []string, seen map[string]struct{}, host string) []string {
	if host == "" {
		return dst
	}
	if _, exists := seen[host]; exists {
		return dst
	}
	seen[host] = struct{}{}
	return append(dst, host)
}

// orderTCPHosts preserves an original literal chosen by the application as the
// first candidate (when policy allows it), then interleaves the opposite family.
// SOCKS DOMAIN requests have no original literal, so IPv6 gets the first slot
// and IPv4 starts after the Happy-Eyeballs delay.
func orderTCPHosts(ips []net.IP, originalHost string, isDirect bool) []string {
	var v4, v6 []string
	seenIP := make(map[string]struct{})
	for _, ip := range ips {
		if ip == nil || !ipFamilyAllowed(ip, isDirect) {
			continue
		}
		host := ip.String()
		if _, exists := seenIP[host]; exists {
			continue
		}
		seenIP[host] = struct{}{}
		if ip.To4() != nil {
			v4 = append(v4, host)
		} else {
			v6 = append(v6, host)
		}
	}

	var ordered []string
	seen := make(map[string]struct{})
	originalIP, originalIsIP := parseIPLiteral(originalHost)
	originalFamily6 := false
	if originalIsIP && ipFamilyAllowed(originalIP, isDirect) {
		originalFamily6 = originalIP.To4() == nil
		ordered = appendUniqueHost(ordered, seen, originalIP.String())
	}

	// Strip the already-preferred original from family queues.
	filter := func(in []string) []string {
		out := in[:0]
		for _, host := range in {
			if _, exists := seen[host]; !exists {
				out = append(out, host)
			}
		return out
	}
	v4 = filter(v4)
	v6 = filter(v6)

	// Alternate families. After an original literal, start with the opposite
	// family. Without an original target, prefer IPv6 but race IPv4 shortly after.
	preferV6 := !originalIsIP || !originalFamily6
	for (len(v4) > 0 || len(v6) > 0) && len(ordered) < happyEyeballsMaxCandidates {
		if preferV6 {
			if len(v6) > 0 {
				ordered = appendUniqueHost(ordered, seen, v6[0])
				v6 = v6[1:]
			} else if len(v4) > 0 {
				ordered = appendUniqueHost(ordered, seen, v4[0])
				v4 = v4[1:]
			}
		} else {
			if len(v4) > 0 {
				ordered = appendUniqueHost(ordered, seen, v4[0])
				v4 = v4[1:]
			} else if len(v6) > 0 {
				ordered = appendUniqueHost(ordered, seen, v6[0])
				v6 = v6[1:]
			}
		}
		preferV6 = !preferV6
	}
	if len(ordered) > happyEyeballsMaxCandidates {
		ordered = ordered[:happyEyeballsMaxCandidates]
	}
	return ordered
}

type tcpRaceResult struct {
	conn   net.Conn
	target string
	err    error
}

type tcpDialFunc func(context.Context, string) (net.Conn, error)

// raceTCPDial is a bounded Happy-Eyeballs scheduler. The first candidate starts
// immediately, later candidates are staggered by 250 ms, and a hard failure
// accelerates the next candidate when no other attempt is still running.
func raceTCPDial(ctx context.Context, targets []string, dial tcpDialFunc) (net.Conn, string, error) {
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("no outbound candidates")
	}
	if len(targets) == 1 {
		conn, err := dial(ctx, targets[0])
		return conn, targets[0], err
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan tcpRaceResult, len(targets))

	next := 0
	active := 0
	launch := func(target string) {
		active++
		taskTrack()
		go func() {
			defer taskRelease()
			conn, err := dial(raceCtx, target)
			if err == nil && raceCtx.Err() != nil {
				_ = conn.Close()
				conn = nil
				err = raceCtx.Err()
			}
			results <- tcpRaceResult{conn: conn, target: target, err: err}
		}()
	}

	launch(targets[next])
	next++

	var timer *time.Timer
	var timerC <-chan time.Time
	resetTimer := func() {
		if next >= len(targets) {
			if timer != nil {
				timer.Stop()
			}
			timerC = nil
			return
		}
		if timer == nil {
			timer = time.NewTimer(happyEyeballsDelay)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(happyEyeballsDelay)
		}
		timerC = timer.C
	}
	resetTimer()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	var lastErr error
	for active > 0 || next < len(targets) {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case result := <-results:
			active--
			if result.err == nil && result.conn != nil {
				cancel()
				return result.conn, result.target, nil
			}
			lastErr = result.err
			// Nothing else is currently testing reachability: don't pay the full
			// delay after an immediate ENETUNREACH/SSH channel-open failure.
			if active == 0 && next < len(targets) {
				launch(targets[next])
				next++
				resetTimer()
			}
		case <-timerC:
			// Keep at most two connection attempts live at once. This captures the
			// useful v4/v6 race without opening a burst of SSH channels.
			if next < len(targets) && active < 2 {
				launch(targets[next])
				next++
			}
			resetTimer()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all outbound candidates failed")
	}
	return nil, "", lastErr
}

func unifiedTCPDial(
	ctx context.Context,
	cfg ProxyConfig,
	client *ssh.Client,
	host, port string,
	isDirect bool,
	originalHost string,
) (net.Conn, string, error) {
	if port == "" {
		return nil, "", fmt.Errorf("missing destination port")
	}

	ip, isLiteral := parseIPLiteral(host)
	if isLiteral && !ipFamilyAllowed(ip, isDirect) {
		return nil, "", fmt.Errorf("destination family disabled by outbound policy: %s", host)
	}

	var targets []string
	if !isLiteral {
		ips := resolveAllOutboundIPs(host, isDirect)
		for _, candidateHost := range orderTCPHosts(ips, originalHost, isDirect) {
			targets = append(targets, net.JoinHostPort(candidateHost, port))
		}
		// DNS can be intentionally split or temporarily unavailable. Falling back
		// to the domain preserves the old behavior (local resolver for DIRECT,
		// remote SSH resolver for PROXY) instead of turning a DNS-side failure into
		// an artificial connection failure.
		if len(targets) == 0 {
			targets = append(targets, net.JoinHostPort(host, port))
		}
	} else {
		targets = append(targets, net.JoinHostPort(ip.String(), port))
	}

	overallCtx, cancel := context.WithTimeout(ctx, outboundDialTimeout)
	defer cancel()

	var dial tcpDialFunc
	if isDirect {
		dial = func(dialCtx context.Context, target string) (net.Conn, error) {
			return dialProtected(dialCtx, cfg, "tcp", target, 5*time.Second)
		}
	} else {
		if client == nil {
			return nil, "", fmt.Errorf("ssh client is currently reconnecting")
		}
		dial = func(dialCtx context.Context, target string) (net.Conn, error) {
			return client.DialContext(dialCtx, "tcp", target)
		}
	}

	conn, winner, err := raceTCPDial(overallCtx, targets, dial)
	if err != nil {
		return nil, "", err
	}
	if isDirect {
		applyTCPConfig(conn, cfg)
	}
	return conn, winner, nil
}

// handleUnifiedTCPConnect owns CONNECT from route decision through candidate
// selection and relay. Keeping this in the handler decorator lets UDP retain its
// mature single-path implementation while both VPN/TUN and root TPROXY feed the
// same TCP outbound architecture.
func (h *egressAwareSocksHandler) handleUnifiedTCPConnect(c *net.TCPConn, r *socks5.Request) error {
	if h.context().Err() != nil {
		return context.Canceled
	}
	if c == nil || r == nil {
		return fmt.Errorf("invalid SOCKS5 TCP request")
	}

	taskTrack()
	defer taskRelease()

	target := r.Address()
	connKey := c.RemoteAddr().String() + "->" + target
	tcpConnMap.Store(connKey, c)
	defer tcpConnMap.CompareAndDelete(connKey, c)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid destination %q: %w", target, err)
	}
	originalHost := host
	effectiveHost := host

	if _, literal := parseIPLiteral(host); literal {
		if domain, ok := recoverDomainFromDNSCache(host); ok {
			effectiveHost = domain
			if Debug {
				zlog.Debugf("%s [Outbound] recovered domain from DNS cache: %s -> %s", TAG, host, domain)
			}
		}
	}

	isDirect := false
	if gr := globalRouter.Load(); gr != nil {
		isDirect = gr.ShouldDirect(effectiveHost).IsDirect
	}

	mu.Lock()
	client := sshClient
	mu.Unlock()
	if !isDirect && client == nil {
		rep := socks5.NewReply(socks5.RepServerFailure, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		_, _ = rep.WriteTo(c)
		return fmt.Errorf("ssh client is currently reconnecting")
	}

	remote, winner, dialErr := unifiedTCPDial(h.context(), h.cfg, client, effectiveHost, port, isDirect, originalHost)
	if dialErr != nil {
		rep := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		_, _ = rep.WriteTo(c)
		return dialErr
	}

	if Debug {
		route := "PROXY"
		if isDirect {
			route = "DIRECT"
		}
		zlog.Debugf("%s [Outbound] %s target=%s effective=%s winner=%s", TAG, route, target, effectiveHost, winner)
	}

	remote = WrapConn(remote, target)
	defer remote.Close()

	rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	if _, err := rep.WriteTo(c); err != nil {
		return err
	}
	relayBidirectional(h.context(), c, remote, isDirect)
	return nil
}

// Keep strconv referenced here intentionally: several downstream forks build
// this file with additional UDP-domain helpers behind tags. A compile-time use
// also documents that ports are treated as numeric SOCKS values before joining.
var _ = strconv.Itoa
