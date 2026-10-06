package myssh

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

const (
	IPv6EgressModeAuto      = "auto"
	IPv6EgressModeIPv4Only  = "ipv4-only"
	IPv6EgressModeIPv6Only  = "ipv6-only"
	IPv6EgressModeDualStack = "dual-stack"

	ipv6EgressUnknown     = -1
	ipv6EgressUnavailable = 0
	ipv6EgressAvailable   = 1

	ipv6EgressProbeTimeout = 1500 * time.Millisecond
)

// ipv6EgressPolicy is the lock-free mirror of the configured mode.
//
// Why a separate atomic instead of reading remoteIPv6Egress.mode under its
// mutex: the mode is written once per config load but read on the hot path —
// every intercepted DNS packet (shouldSuppressDNSFamily) and every outbound
// TCP dial (outboundAllowedFamilies). remoteIPv6Egress.mu used to be held
// across zlog writes by the probe goroutine, so a lock-based read could park
// packet handling behind logger I/O.
type ipv6EgressPolicy int32

const (
	policyAuto ipv6EgressPolicy = iota
	policyIPv4Only
	policyIPv6Only
	policyDualStack
)

func ipv6EgressPolicyOf(mode string) ipv6EgressPolicy {
	switch mode {
	case IPv6EgressModeIPv4Only:
		return policyIPv4Only
	case IPv6EgressModeIPv6Only:
		return policyIPv6Only
	case IPv6EgressModeDualStack:
		return policyDualStack
	default:
		return policyAuto
	}
}

// proxyFamilyPolicy is the hot-path reader: lock-free, never blocks on the
// tracker mutex that guards the probe state machine.
func proxyFamilyPolicy() ipv6EgressPolicy {
	return ipv6EgressPolicy(remoteIPv6Egress.policy.Load())
}

// ipv6EgressTracker now represents a *diagnostic* public-IPv6 observation when
// mode=auto. A failed probe cannot prove that private/ULA/enterprise IPv6 is
// unreachable, so auto-mode forwarding never uses this state to reject traffic.
// Explicit ipv4-only remains a hard user policy and is enforced by the unified
// outbound layer.
type ipv6EgressTracker struct {
	mu sync.Mutex
	// policy mirrors mode for lock-free hot-path reads. Written under mu.
	policy     atomic.Int32
	mode       string
	state      int
	client     *ssh.Client
	done       chan struct{}
	doneClosed bool
}

var remoteIPv6Egress = ipv6EgressTracker{
	mode:  IPv6EgressModeAuto,
	state: ipv6EgressUnknown,
	done:  make(chan struct{}),
}

// Public diagnostic targets. Success positively proves public IPv6 egress;
// failure is only "not confirmed" and must not be treated as a routing policy.
var ipv6EgressProbeTargets = []string{
	"[2606:4700:4700::1111]:443", // Cloudflare DNS
	"[2001:4860:4860::8888]:443", // Google Public DNS
	"[2400:3200::1]:443",         // AliDNS DoH
}

var ipv6EgressProbeDial = func(ctx context.Context, client *ssh.Client, target string) error {
	conn, err := client.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

type ipv6EgressJSONConfig struct {
	Mode string `json:"ipv6_egress_mode"`
}

func normalizeIPv6EgressMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return IPv6EgressModeAuto, nil
	case "ipv4", "ipv4-only", "ipv4_only", "v4":
		return IPv6EgressModeIPv4Only, nil
	case "ipv6-only", "ipv6_only", "v6-only", "v6_only":
		return IPv6EgressModeIPv6Only, nil
	// Preserve the old ipv6/v6 aliases as "IPv6 enabled" (= dual-stack) for
	// compatibility. Use the explicit ipv6-only spelling to disable IPv4.
	case "dual", "dual-stack", "dual_stack", "dualstack", "ipv6", "v6":
		return IPv6EgressModeDualStack, nil
	default:
		return "", fmt.Errorf("invalid ipv6_egress_mode %q: expected auto, ipv4-only, ipv6-only, or dual-stack", mode)
	}
}

func configureIPv6EgressFromJSON(configJSON string) error {
	var cfg ipv6EgressJSONConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return err
	}
	mode, err := normalizeIPv6EgressMode(cfg.Mode)
	if err != nil {
		return err
	}

	remoteIPv6Egress.mu.Lock()
	defer remoteIPv6Egress.mu.Unlock()
	remoteIPv6Egress.mode = mode
	remoteIPv6Egress.policy.Store(int32(ipv6EgressPolicyOf(mode)))
	remoteIPv6Egress.client = nil
	remoteIPv6Egress.done = make(chan struct{})
	remoteIPv6Egress.doneClosed = false

	switch mode {
	case IPv6EgressModeIPv4Only:
		remoteIPv6Egress.state = ipv6EgressUnavailable
		close(remoteIPv6Egress.done)
		remoteIPv6Egress.doneClosed = true
	case IPv6EgressModeIPv6Only, IPv6EgressModeDualStack:
		remoteIPv6Egress.state = ipv6EgressAvailable
		close(remoteIPv6Egress.done)
		remoteIPv6Egress.doneClosed = true
	default:
		remoteIPv6Egress.state = ipv6EgressUnknown
	}

	zlog.Infof("%s [IPv6-Egress] policy=%s", TAG, mode)
	return nil
}

func startIPv6EgressProbe(client *ssh.Client) {
	if client == nil {
		return
	}

	// Local probing is retained for diagnostics/UI only. It does not gate DIRECT
	// traffic; a target-specific dial is the source of truth in auto mode.
	startLocalDirectIPv6Probe()

	if proxyFamilyPolicy() != policyAuto {
		return
	}

	remoteIPv6Egress.mu.Lock()
	if remoteIPv6Egress.state != ipv6EgressUnknown || remoteIPv6Egress.doneClosed {
		remoteIPv6Egress.done = make(chan struct{})
		remoteIPv6Egress.doneClosed = false
	}
	remoteIPv6Egress.state = ipv6EgressUnknown
	remoteIPv6Egress.client = client
	remoteIPv6Egress.mu.Unlock()

	taskTrack()
	go func() {
		defer taskRelease()
		available := probeIPv6Egress(client)

		remoteIPv6Egress.mu.Lock()
		if proxyFamilyPolicy() != policyAuto || remoteIPv6Egress.client != client {
			remoteIPv6Egress.mu.Unlock()
			return
		}
		if available {
			remoteIPv6Egress.state = ipv6EgressAvailable
		} else {
			remoteIPv6Egress.state = ipv6EgressUnavailable
		}
		if !remoteIPv6Egress.doneClosed {
			close(remoteIPv6Egress.done)
			remoteIPv6Egress.doneClosed = true
		}
		remoteIPv6Egress.mu.Unlock()

		// Log only after releasing the mutex: a zlog write can block once its
		// buffer is full, and hot-path readers must never queue behind that.
		if available {
			zlog.Infof("%s [IPv6-Egress] ✅ diagnostic: remote public IPv6 reachable", TAG)
		} else {
			zlog.Warnf("%s [IPv6-Egress] ⚠️ diagnostic: remote public IPv6 not confirmed; target-specific IPv6 remains allowed", TAG)
		}
	}()
}

type ipv6EgressProbeResult struct {
	target string
	err    error
}

func probeIPv6Egress(client *ssh.Client) bool {
	if client == nil || len(ipv6EgressProbeTargets) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(currentEngineCtx(), ipv6EgressProbeTimeout)
	defer cancel()
	probeDial := ipv6EgressProbeDial
	results := make(chan ipv6EgressProbeResult, len(ipv6EgressProbeTargets))
	for _, target := range ipv6EgressProbeTargets {
		target := target
		taskTrack()
		go func() {
			defer taskRelease()
			err := probeDial(ctx, client, target)
			select {
			case results <- ipv6EgressProbeResult{target: target, err: err}:
			case <-ctx.Done():
			}
		}()
	}

	remaining := len(ipv6EgressProbeTargets)
	for remaining > 0 {
		select {
		case result := <-results:
			remaining--
			if result.err == nil {
				cancel()
				return true
			}
			if Debug {
				zlog.Debugf("%s [IPv6-Egress] diagnostic probe failed target=%s err=%v", TAG, result.target, result.err)
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}

func waitIPv6EgressMs(timeoutMs int) int {
	remoteIPv6Egress.mu.Lock()
	state := remoteIPv6Egress.state
	done := remoteIPv6Egress.done
	remoteIPv6Egress.mu.Unlock()

	if state != ipv6EgressUnknown {
		return state
	}
	if timeoutMs <= 0 {
		return ipv6EgressUnknown
	}

	timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		remoteIPv6Egress.mu.Lock()
		state = remoteIPv6Egress.state
		remoteIPv6Egress.mu.Unlock()
		return state
	case <-timer.C:
		return ipv6EgressUnknown
	}
}

func ipv6EgressStateName() string {
	remoteIPv6Egress.mu.Lock()
	defer remoteIPv6Egress.mu.Unlock()
	switch remoteIPv6Egress.state {
	case ipv6EgressAvailable:
		return "available"
	case ipv6EgressUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

func proxyIPv6ExplicitlyDisabled() bool {
	return proxyFamilyPolicy() == policyIPv4Only
}

func proxyIPv4ExplicitlyDisabled() bool {
	return proxyFamilyPolicy() == policyIPv6Only
}

func isIPv6Literal(host string) bool {
	ip, ok := parseIPLiteral(host)
	return ok && ip.To4() == nil
}

// Compatibility helper retained for tests/callers. Auto probe failures no longer
// cause rejection; only an explicit proxy ipv4-only policy does. DIRECT always
// relies on the concrete target dial in the unified outbound path.
func shouldRejectProxyIPv6Literal(host string, isDirect bool) bool {
	return !isDirect && isIPv6Literal(host) && proxyIPv6ExplicitlyDisabled()
}

func shouldSuppressDNSFamily(req *dns.Msg) bool {
	if req == nil || len(req.Question) == 0 {
		return false
	}
	domain := strings.TrimSuffix(req.Question[0].Name, ".")
	if gr := globalRouter.Load(); gr != nil && gr.MatchDomain(domain) {
		return false
	}
	switch req.Question[0].Qtype {
	case dns.TypeAAAA:
		return proxyIPv6ExplicitlyDisabled()
	case dns.TypeA:
		return proxyIPv4ExplicitlyDisabled()
	default:
		return false
	}
}

func shouldSuppressProxyAAAA(req *dns.Msg) bool {
	return req != nil && len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAAAA && shouldSuppressDNSFamily(req)
}

func makeAAAANoDataReply(req *dns.Msg) ([]byte, error) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Rcode = dns.RcodeSuccess
	reply.RecursionAvailable = true
	return reply.Pack()
}

// interceptedDNSReply handles client-originated SOCKS/TUN/TPROXY UDP DNS before
// the legacy UDP forwarding path. All inbound port-53 queries must pass through
// LocalDnsServer so the unified outbound has one authoritative A/AAAA cache for
// later IP->domain recovery. LocalDnsServer's own upstream dials do not re-enter
// this SOCKS handler, so configured DNS endpoints cannot recurse here.
func interceptedDNSReply(payload []byte) (reply []byte, handled bool, err error) {
	req := new(dns.Msg)
	if err := req.Unpack(payload); err != nil {
		// It is still a port-53 client packet. Do not leak malformed DNS into the
		// generic UDP path merely because parsing failed.
		return nil, true, err
	}
	if shouldSuppressDNSFamily(req) {
		reply, err := makeAAAANoDataReply(req)
		return reply, true, err
	}
	if lds := localDnsServer.Load(); lds != nil {
		reply, err := lds.HandleDNSRequestPacked(req)
		return reply, true, err
	}
	// During the tiny startup/teardown window where the DNS engine is absent,
	// preserve the old UDP behavior instead of blackholing otherwise valid DNS.
	return nil, false, nil
}

// egressAwareSocksHandler is now the unified TCP outbound entry point. UDP keeps
// the existing mature single-path implementation; DNS is intercepted first so
// all client A/AAAA answers populate the same cache used by TCP domain recovery.
type egressAwareSocksHandler struct {
	*SshProxyHandler
}

func (h *egressAwareSocksHandler) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r != nil && r.Cmd == socks5.CmdConnect {
		return h.handleUnifiedTCPConnect(c, r)
	}
	return h.SshProxyHandler.TCPHandle(s, c, r)
}

func (h *egressAwareSocksHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	if d != nil && len(d.DstPort) == 2 && binary.BigEndian.Uint16(d.DstPort) == 53 {
		replyData, handled, err := interceptedDNSReply(d.Data)
		if handled {
			if err != nil {
				return err
			}
			if Debug {
				req := new(dns.Msg)
				if req.Unpack(d.Data) == nil && len(req.Question) > 0 {
					zlog.Debugf("%s [Outbound-DNS] intercepted %s for %s", TAG, dns.TypeToString[req.Question[0].Qtype], req.Question[0].Name)
				}
			}
			h.sendSocks5UDPResponse(s, addr, d.Atyp, d.DstAddr, d.DstPort, replyData)
			return nil
		}
	}
	return h.SshProxyHandler.UDPHandle(s, addr, d)
}
