package myssh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

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

// recoverDomainFromDNSCache is the transparent-proxy fallback for frontends
// that only retain an IP literal. Only one unique, still-valid DNS owner is
// accepted. Shared CDN IPs remain literals instead of being guessed.
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
	if isDirect {
		return true, true
	}
	switch proxyFamilyMode() {
	case IPv6EgressModeIPv4Only:
		return true, false
	case IPv6EgressModeIPv6Only:
		return false, true
	default:
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

func resolveAllOutboundIPs(host string, isDirect bool) []net.IP {
	lds := localDnsServer.Load()
	if lds == nil || host == "" {
		return nil
	}

	allow4, allow6 := outboundAllowedFamilies(isDirect)
	qtypes := make([]uint16, 0, 2)
	if allow4 {
		qtypes = append(qtypes, dns.TypeA)
	}
	if allow6 {
		qtypes = append(qtypes, dns.TypeAAAA)
	}

	type familyResult struct{ ips []net.IP }
	results := make(chan familyResult, len(qtypes))
	for _, qtype := range qtypes {
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
			var ips []net.IP
			for _, ip := range extractAnswerIPs(reply) {
				if ip == nil {
					continue
				}
				if qtype == dns.TypeA && ip.To4() == nil {
					continue
				}
				if qtype == dns.TypeAAAA && ip.To4() != nil {
					continue
				}
				ips = append(ips, ip)
			}
			results <- familyResult{ips: ips}
		}()
	}

	seen := make(map[string]struct{})
	var out []net.IP
	for range qtypes {
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
	originalIsV6 := false
	if originalIsIP && ipFamilyAllowed(originalIP, isDirect) {
		originalIsV6 = originalIP.To4() == nil
		ordered = appendUniqueHost(ordered, seen, originalIP.String())
	}

	filterSeen := func(in []string) []string {
		out := in[:0]
		for _, host := range in {
			if _, exists := seen[host]; !exists {
				out = append(out, host)
			}
		}
		return out
	}
	v4 = filterSeen(v4)
	v6 = filterSeen(v6)

	preferV6 := !originalIsIP || !originalIsV6
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
	return ordered
}

type tcpRaceResult struct {
	conn   net.Conn
	target string
	err    error
}

type tcpDialFunc func(context.Context, string) (net.Conn, error)

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
	armTimer := func() {
		if next >= len(targets) {
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
	armTimer()
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
			if active == 0 && next < len(targets) {
				launch(targets[next])
				next++
				armTimer()
			}
		case <-timerC:
			if next < len(targets) && active < 2 {
				launch(targets[next])
				next++
			}
			armTimer()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all outbound candidates failed")
	}
	return nil, "", lastErr
}

type outboundRoute struct {
	isDirect          bool
	domainDirect      bool
	geoIPDirectTarget string
}

func classifyOutboundRoute(host string) outboundRoute {
	gr := globalRouter.Load()
	if gr == nil {
		return outboundRoute{}
	}
	if _, literal := parseIPLiteral(host); !literal && gr.MatchDomain(host) {
		return outboundRoute{isDirect: true, domainDirect: true}
	}
	result := gr.ShouldDirect(host)
	return outboundRoute{
		isDirect:          result.IsDirect,
		geoIPDirectTarget: result.DialHost,
	}
}

func filterDirectCandidates(ips []net.IP, route outboundRoute) []net.IP {
	if !route.isDirect || route.domainDirect {
		return ips
	}
	gr := globalRouter.Load()
	if gr == nil {
		return nil
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip != nil && gr.MatchIP(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func unifiedTCPDial(
	ctx context.Context,
	cfg ProxyConfig,
	client *ssh.Client,
	host, port string,
	route outboundRoute,
	originalHost string,
) (net.Conn, string, error) {
	if port == "" {
		return nil, "", fmt.Errorf("missing destination port")
	}

	ip, isLiteral := parseIPLiteral(host)
	if isLiteral && !ipFamilyAllowed(ip, route.isDirect) {
		return nil, "", fmt.Errorf("destination family disabled by outbound policy: %s", host)
	}

	var targets []string
	if isLiteral {
		targets = []string{net.JoinHostPort(ip.String(), port)}
	} else {
		ips := resolveAllOutboundIPs(host, route.isDirect)
		ips = filterDirectCandidates(ips, route)
		for _, candidateHost := range orderTCPHosts(ips, originalHost, route.isDirect) {
			targets = append(targets, net.JoinHostPort(candidateHost, port))
		}

		if len(targets) == 0 && route.isDirect && route.geoIPDirectTarget != "" && route.geoIPDirectTarget != host {
			if candidateIP, ok := parseIPLiteral(route.geoIPDirectTarget); ok && ipFamilyAllowed(candidateIP, true) {
				targets = append(targets, net.JoinHostPort(candidateIP.String(), port))
			}
		}
		if len(targets) == 0 && (!route.isDirect || route.domainDirect) {
			targets = append(targets, net.JoinHostPort(host, port))
		}
	}

	if len(targets) == 0 {
		return nil, "", fmt.Errorf("no eligible outbound candidates for %s", host)
	}

	overallCtx, cancel := context.WithTimeout(ctx, outboundDialTimeout)
	defer cancel()

	var dial tcpDialFunc
	if route.isDirect {
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
	if route.isDirect {
		applyTCPConfig(conn, cfg)
	}
	return conn, winner, nil
}

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

	route := classifyOutboundRoute(effectiveHost)
	mu.Lock()
	client := sshClient
	mu.Unlock()
	if !route.isDirect && client == nil {
		rep := socks5.NewReply(socks5.RepServerFailure, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		_, _ = rep.WriteTo(c)
		return fmt.Errorf("ssh client is currently reconnecting")
	}

	remote, winner, dialErr := unifiedTCPDial(h.context(), h.cfg, client, effectiveHost, port, route, originalHost)
	if dialErr != nil {
		rep := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		_, _ = rep.WriteTo(c)
		return dialErr
	}
	if Debug {
		routeName := "PROXY"
		if route.isDirect {
			routeName = "DIRECT"
		}
		zlog.Debugf("%s [Outbound] %s target=%s effective=%s winner=%s", TAG, routeName, target, effectiveHost, winner)
	}

	remote = WrapConn(remote, target)
	defer remote.Close()

	rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	if _, err := rep.WriteTo(c); err != nil {
		return err
	}
	relayBidirectional(h.context(), c, remote, route.isDirect)
	return nil
}
