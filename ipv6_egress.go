package myssh

import (
	"context"
	"encoding/binary"
	"encoding/json"
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
	IPv6EgressModeAuto      = "auto"
	IPv6EgressModeIPv4Only  = "ipv4-only"
	IPv6EgressModeDualStack = "dual-stack"

	ipv6EgressUnknown     = -1
	ipv6EgressUnavailable = 0
	ipv6EgressAvailable   = 1

	ipv6EgressProbeTimeout = 1500 * time.Millisecond
)

// ipv6EgressTracker describes the forwarding capability of the *remote SSH
// exit*, not the address family used to reach the SSH server itself. An SSH
// server may be reached over IPv4 and still have perfectly good IPv6 egress.
type ipv6EgressTracker struct {
	mu         sync.Mutex
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

// These are literal IPv6 addresses on purpose: the capability probe must not
// depend on DNS, which is one of the consumers of this result. TCP/443 is used
// because it is far less likely to be filtered than arbitrary ports. The list
// spans three independent operators/regions to reduce false IPv4-only verdicts.
var ipv6EgressProbeTargets = []string{
	"[2606:4700:4700::1111]:443", // Cloudflare DNS
	"[2001:4860:4860::8888]:443", // Google Public DNS
	"[2400:3200::1]:443",         // AliDNS DoH (dns.alidns.com)
}

// Indirection keeps the state machine unit-testable without external network
// access. Tests may replace this function temporarily; production always uses
// SSH direct-tcpip through the currently connected server.
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
	case "dual", "dual-stack", "dual_stack", "dualstack", "ipv6", "v6":
		return IPv6EgressModeDualStack, nil
	default:
		return "", fmt.Errorf("invalid ipv6_egress_mode %q: expected auto, ipv4-only, or dual-stack", mode)
	}
}

// configureIPv6EgressFromJSON intentionally parses the mode separately from
// ProxyConfig. This keeps the existing public ProxyConfig ABI stable while the
// JSON configuration remains forward-compatible for gomobile callers.
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
	remoteIPv6Egress.client = nil
	remoteIPv6Egress.done = make(chan struct{})
	remoteIPv6Egress.doneClosed = false

	switch mode {
	case IPv6EgressModeIPv4Only:
		remoteIPv6Egress.state = ipv6EgressUnavailable
		close(remoteIPv6Egress.done)
		remoteIPv6Egress.doneClosed = true
	case IPv6EgressModeDualStack:
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

	// Local DIRECT capability is independent from the remote SSH exit. Refresh
	// it on initial connect and every reconnect so network changes eventually
	// get a fresh protected-socket probe as well.
	startLocalDirectIPv6Probe()

	remoteIPv6Egress.mu.Lock()
	if remoteIPv6Egress.mode != IPv6EgressModeAuto {
		remoteIPv6Egress.mu.Unlock()
		return
	}

	// The initial auto configuration already created an open done channel so a
	// WaitIPv6Egress call made immediately after Start can wait across the SSH
	// handshake. On later reconnects the previous result is complete, therefore
	// start a fresh generation.
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
		defer remoteIPv6Egress.mu.Unlock()
		// Ignore a late result from an SSH client that has already been replaced.
		if remoteIPv6Egress.mode != IPv6EgressModeAuto || remoteIPv6Egress.client != client {
			return
		}
		if available {
			remoteIPv6Egress.state = ipv6EgressAvailable
			zlog.Infof("%s [IPv6-Egress] ✅ remote SSH exit has IPv6 connectivity", TAG)
		} else {
			remoteIPv6Egress.state = ipv6EgressUnavailable
			zlog.Warnf("%s [IPv6-Egress] ⚠️ remote SSH exit is IPv4-only; proxied AAAA answers and IPv6 literal CONNECTs will be suppressed", TAG)
		}
		if !remoteIPv6Egress.doneClosed {
			close(remoteIPv6Egress.done)
			remoteIPv6Egress.doneClosed = true
		}
	}()
}

type ipv6EgressProbeResult struct {
	target string
	err    error
}

// probeIPv6Egress races all independent probe targets in parallel. A single
// successful SSH direct-tcpip connection proves IPv6 egress immediately. The
// shared deadline bounds the whole probe generation, so three unreachable
// targets still cost about one timeout instead of three sequential timeouts.
func probeIPv6Egress(client *ssh.Client) bool {
	if client == nil || len(ipv6EgressProbeTargets) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(currentEngineCtx(), ipv6EgressProbeTimeout)
	defer cancel()

	// Snapshot the injectable dialer before workers start. Besides keeping each
	// probe generation internally consistent, this avoids racing test-time
	// replacement of ipv6EgressProbeDial against worker goroutines.
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
				cancel() // abort slower probes as soon as one target succeeds
				return true
			}
			if Debug {
				zlog.Debugf("%s [IPv6-Egress] probe failed target=%s err=%v", TAG, result.target, result.err)
			}
		case <-ctx.Done():
			return false
		}
	}

	return false
}

// waitIPv6EgressMs returns 1 for available, 0 for unavailable, and -1 when no
// result became available before the timeout. Forced modes return immediately.
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

func proxyIPv6EgressAvailable() bool {
	remoteIPv6Egress.mu.Lock()
	defer remoteIPv6Egress.mu.Unlock()
	return remoteIPv6Egress.state == ipv6EgressAvailable
}

func proxyIPv6EgressUnavailable() bool {
	remoteIPv6Egress.mu.Lock()
	defer remoteIPv6Egress.mu.Unlock()
	return remoteIPv6Egress.state == ipv6EgressUnavailable
}

func isIPv6Literal(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// shouldRejectProxyIPv6Literal now applies the appropriate capability source:
// PROXY literals depend on the remote SSH exit, while DIRECT literals depend
// on the device's protected local path. Unknown local state is intentionally
// allowed to avoid false-negative startup caching.
func shouldRejectProxyIPv6Literal(host string, isDirect bool) bool {
	if !isIPv6Literal(host) {
		return false
	}
	if isDirect {
		return localDirectIPv6Unavailable()
	}
	return proxyIPv6EgressUnavailable()
}

func shouldSuppressProxyAAAA(req *dns.Msg) bool {
	if req == nil || len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAAAA {
		return false
	}

	domain := strings.TrimSuffix(req.Question[0].Name, ".")
	// DIRECT domains use the Android/device network, so their AAAA eligibility
	// follows local protected-socket IPv6 reachability rather than the SSH exit.
	if gr := globalRouter.Load(); gr != nil && gr.MatchDomain(domain) {
		return localDirectIPv6Unavailable()
	}
	return !proxyIPv6EgressAvailable()
}

func makeAAAANoDataReply(req *dns.Msg) ([]byte, error) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Rcode = dns.RcodeSuccess // NOERROR + empty Answer = NODATA, not NXDOMAIN.
	reply.RecursionAvailable = true
	return reply.Pack()
}

// egressAwareSocksHandler decorates the existing handler without changing its
// mature TCP/UDP forwarding implementation. It chooses local-vs-remote IPv6
// capability according to the routing decision before suppressing AAAA or
// fail-fast rejecting an IPv6 literal CONNECT.
type egressAwareSocksHandler struct {
	*SshProxyHandler
}

func (h *egressAwareSocksHandler) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r != nil && r.Cmd == socks5.CmdConnect {
		target := r.Address()
		host := target
		if splitHost, _, err := net.SplitHostPort(target); err == nil {
			host = splitHost
		}

		isDirect := false
		if gr := globalRouter.Load(); gr != nil {
			isDirect = gr.ShouldDirect(host).IsDirect
		}

		if shouldRejectProxyIPv6Literal(host, isDirect) {
			scope := "remote SSH exit"
			logTag := "IPv6-Egress"
			if isDirect {
				scope = "local DIRECT path"
				logTag = "IPv6-Direct"
			}
			if Debug {
				zlog.Debugf("%s [%s] rejecting IPv6 literal because %s has no IPv6 connectivity: %s", TAG, logTag, scope, target)
			}
			rep := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
			if c != nil {
				_, _ = rep.WriteTo(c)
			}
			return fmt.Errorf("%s has no IPv6 connectivity for literal target %s", scope, target)
		}
	}
	return h.SshProxyHandler.TCPHandle(s, c, r)
}

func (h *egressAwareSocksHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	if d != nil && len(d.DstPort) == 2 && binary.BigEndian.Uint16(d.DstPort) == 53 {
		req := new(dns.Msg)
		if err := req.Unpack(d.Data); err == nil && shouldSuppressProxyAAAA(req) {
			replyData, err := makeAAAANoDataReply(req)
			if err != nil {
				return err
			}
			if Debug && len(req.Question) > 0 {
				zlog.Debugf("%s [IPv6] suppressing unusable AAAA for %s", TAG, req.Question[0].Name)
			}
			h.sendSocks5UDPResponse(s, addr, d.Atyp, d.DstAddr, d.DstPort, replyData)
			return nil
		}
	}
	return h.SshProxyHandler.UDPHandle(s, addr, d)
}
