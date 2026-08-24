package myssh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base32"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// =============================================================
// SSH-over-DNS 隧道 (tunnel_dns)
// =============================================================
//
// 设计目标：把 SSH 客户端的字节流完整封装进「标准 DNS 报文」里，
// 通过被 protect 的 socket（dialProtected，自动绕过 Android VPN）发往
// 用户自有的「权威 DNS 服务器」（即隧道服务端）。服务端解码出字节流后，
// 再转发给真正的 SSH 服务；回程数据同样塞进 DNS 应答里送回。
//
// 报文布局（每个查询的 Name）：
//
//	<seq>.<flag>.<b32data>.<session>.tunnel.<DOMAIN>
//
//	- seq     : 单调递增序号（十进制），用于去重/调试
//	- flag    : 'D' 携带客户端数据 / 'P' 纯轮询(拉取服务端数据) / 'C' 关闭
//	- b32data : 本片客户端数据的 base32（小写、无填充），长度受 DNS 标签 63 字节限制
//	- session : 本次隧道的会话标识（客户端随机生成）
//	- tunnel  : 固定标记标签，解析时用于定位 DOMAIN 边界
//	- DOMAIN  : 用户委托给隧道服务端的权威域名
//
// 服务端在应答里用相同的记录类型（TXT/NULL/CNAME/A）把「服务端->客户端」数据
// 回传（TXT 用 base32，NULL 用裸字节，CNAME 用首标签，A 仅 4 字节）。
//
// ⚠️ 部署前提：用户必须在自己的权威 DNS 上把 <DOMAIN> 委托给本文件实现的
// DNSTunnelServer（或等价实现）。仅客户端无法构成完整隧道。
// 受 DNS 单包容量限制，本隧道吞吐天然偏低，定位是「能通就行」的兜底通道。

const (
	dnsTunnelDefaultChunk   = 32 // 单个查询数据标签可承载的字节数（< 63*5/8=39）
	dnsTunnelQueryTimeout   = 5 * time.Second
	dnsTunnelPollInterval   = 150 * time.Millisecond
	dnsTunnelMaxServerChunk = 150             // 单个应答可回传的最大原始字节数：base32 后 ≤240 字符，恰好塞进单条 TXT 字符串（≤255），既保证解码精确，又使整体应答 < 512 字节 UDP 上限，兼容真实网络
	dnsTunnelCloseTimeout   = 2 * time.Second // 关闭通知的短超时：尽力通知服务端即可，避免对不可达上游长时间阻塞
	dnsTunnelMarker         = "tunnel"
)

// 标志位
const (
	flagData  = 'D'
	flagPoll  = 'P'
	flagClose = 'C'
)

// dnsTunnelB32 使用小写字母表且无填充，保证生成的标签符合 DNS 大小写不敏感规则。
var dnsTunnelB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

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
	default:
		return 0, fmt.Errorf("unsupported dns tunnel type: %q (want txt/null/cname/a)", t)
	}
}

// buildQueryName 构造隧道查询域名。
func buildQueryName(domain, session string, seq uint32, flag byte, data []byte) string {
	seqStr := strconv.FormatUint(uint64(seq), 10)
	// 空数据时 base32 会得到空串，导致 DNS 名字出现空标签（".."），
	// 解析会报 "bad rdata"。用占位符 "-" 表示空负载。
	b32Str := "-"
	if len(data) > 0 {
		b32Str = dnsTunnelB32.EncodeToString(data)
	}
	name := strings.Join([]string{
		seqStr,
		string(flag),
		b32Str,
		session,
		dnsTunnelMarker,
		dns.Fqdn(domain),
	}, ".")
	return name
}

// parseQueryName 解析隧道查询域名，返回会话、序号、标志与解码后的客户端数据。
func parseQueryName(domain, name string) (session string, seq uint32, flag byte, data []byte, err error) {
	labels := dns.SplitDomainName(name)
	domainLabels := dns.SplitDomainName(domain)
	// 至少需要: seq.flag.b32.session.marker + domain
	if len(labels) < 4+len(domainLabels)+1 {
		return "", 0, 0, nil, fmt.Errorf("dns tunnel: malformed query name %q", name)
	}
	markerIndex := len(labels) - len(domainLabels) - 1
	if markerIndex < 4 || labels[markerIndex] != dnsTunnelMarker {
		return "", 0, 0, nil, fmt.Errorf("dns tunnel: marker not found in %q", name)
	}
	session = labels[markerIndex-1]
	b32Str := labels[markerIndex-2]
	if flagStr := labels[markerIndex-3]; len(flagStr) > 0 {
		flag = flagStr[0]
	} else {
		return "", 0, 0, nil, fmt.Errorf("dns tunnel: empty flag in %q", name)
	}
	seqU, perr := strconv.ParseUint(labels[markerIndex-4], 10, 32)
	if perr != nil {
		return "", 0, 0, nil, fmt.Errorf("dns tunnel: bad seq in %q: %w", name, perr)
	}
	data, derr := dnsTunnelB32.DecodeString(b32Str)
	if derr != nil {
		// 占位符 "-"（空负载）解码失败属正常，按空数据处理
		data = nil
	}
	return session, uint32(seqU), flag, data, nil
}

// splitTxt 将长 base32 字符串切分为多个 <=255 字符的 TXT 字符申（DNS 单字符申上限）。
// 关键：base32 以 8 个字符为一组（=5 字节），必须沿「整组」边界切分，否则跨段会
// 丢失尾部无法凑整的字节。因此每段取 248（<=255 且为 8 的整数倍）字符，末段为剩余长度
// （其内部结构与原串后缀一致，独立解码结果与整体解码一致）。
func splitTxt(s string) []string {
	const max = 255
	const step = 248 // 8 的整数倍，保证切分点落在 base32 整组边界，避免跨段丢字节
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

// makeAnswer 根据查询类型构造「服务端->客户端」应答记录。
func makeAnswer(qname string, qtype uint16, data []byte, domain string) dns.RR {
	hdr := dns.RR_Header{Name: qname, Rrtype: qtype, Class: dns.ClassINET, Ttl: 0}
	switch qtype {
	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: splitTxt(dnsTunnelB32.EncodeToString(data))}
	case dns.TypeNULL:
		return &dns.NULL{Hdr: hdr, Data: string(data)}
	case dns.TypeCNAME:
		// CNAME 单标签上限 63 字符，故仅适合极小负载（约 39 字节）；其余类型更推荐
		b32s := dnsTunnelB32.EncodeToString(data)
		if len(b32s) > 63 {
			b32s = b32s[:63]
			zlog.Warnf("%s [Tunnel-DNS-Server] ⚠️ CNAME 容量受限，数据被截断", TAG)
		}
		target := b32s + "." + dnsTunnelMarker + "." + dns.Fqdn(domain)
		return &dns.CNAME{Hdr: hdr, Target: target}
	case dns.TypeA:
		ip := net.IPv4zero.To4()
		if len(data) >= 4 {
			ip = net.IP(append([]byte(nil), data[:4]...)).To4()
		}
		return &dns.A{Hdr: hdr, A: ip}
	default:
		return &dns.TXT{Hdr: hdr, Txt: splitTxt(dnsTunnelB32.EncodeToString(data))}
	}
}

// extractAnswer 从应答记录中取出「服务端->客户端」数据。
func extractAnswer(rr dns.RR) []byte {
	switch v := rr.(type) {
	case *dns.TXT:
		var buf []byte
		for _, s := range v.Txt {
			if d, e := dnsTunnelB32.DecodeString(s); e == nil {
				buf = append(buf, d...)
			}
		}
		return buf
	case *dns.NULL:
		return []byte(v.Data)
	case *dns.CNAME:
		labels := dns.SplitDomainName(v.Target)
		if len(labels) > 0 {
			if d, e := dnsTunnelB32.DecodeString(labels[0]); e == nil {
				return d
			}
		}
	case *dns.A:
		return v.A.To4()
	}
	return nil
}

// =============================================================
// 客户端：DNSTunnel（实现 net.Conn，可直接作为 SSH 传输）
// =============================================================

type dnsTunnelAddr struct{ domain string }

func (a *dnsTunnelAddr) Network() string { return "dns" }
func (a *dnsTunnelAddr) String() string  { return "dns:" + a.domain }

// DNSTunnel 把任意字节流封装进 DNS 查询/应答，透传给受保护的权威 DNS 服务端。
// 它实现了 net.Conn，因此能直接被 SSH 客户端当作底层传输使用。
type DNSTunnel struct {
	ctx     context.Context
	cfg     ProxyConfig
	servers []string // 多个权威 DNS 服务端地址（故障转移）
	domain  string   // FQDN，如 "tunnel.example.com."
	qtype   uint16
	session string

	chunkSize    int
	pollInterval time.Duration

	exchangeMu sync.Mutex
	lastGood   int
	seq        uint32

	inMu  sync.Mutex
	inBuf *bytes.Buffer

	closed  atomic.Bool
	closeCh chan struct{}

	dlMu          sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

// NewDNSTunnel 从 ProxyConfig 构造 DNS 隧道（供 tunnel 注册表调用）。
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

// newDNSTunnel 是底层构造函数，允许测试直接注入参数（含固定 session）。
func newDNSTunnel(ctx context.Context, cfg ProxyConfig, servers []string, domain string, qtype uint16, session string) *DNSTunnel {
	if session == "" {
		session = fmt.Sprintf("%x", mrand.Uint64())
	}
	return &DNSTunnel{
		ctx:          ctx,
		cfg:          cfg,
		servers:      servers,
		domain:       dns.Fqdn(domain),
		qtype:        qtype,
		session:      session,
		chunkSize:    dnsTunnelDefaultChunk,
		pollInterval: dnsTunnelPollInterval,
		inBuf:        new(bytes.Buffer),
		closeCh:      make(chan struct{}),
	}
}

func (t *DNSTunnel) isClosed() bool { return t.closed.Load() }

func (t *DNSTunnel) appendIn(b []byte) {
	t.inMu.Lock()
	t.inBuf.Write(b)
	t.inMu.Unlock()
}

// doExchange 发送一次 DNS 查询（携带客户端数据或纯轮询），并把应答中的
// 「服务端->客户端」数据写进 inBuf。多个服务端按顺序故障转移。
func (t *DNSTunnel) doExchange(flag byte, data []byte) error {
	return t.doExchangeWithTimeout(flag, data, dnsTunnelQueryTimeout)
}

// doExchangeWithTimeout 发送一次 DNS 查询（携带客户端数据或纯轮询），并把应答中的
// 「服务端->客户端」数据写进 inBuf。多个服务端按顺序故障转移。timeout 控制单次上行超时。
func (t *DNSTunnel) doExchangeWithTimeout(flag byte, data []byte, timeout time.Duration) error {
	if t.isClosed() {
		return net.ErrClosed
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}

	t.exchangeMu.Lock()
	defer t.exchangeMu.Unlock()

	seq := atomic.AddUint32(&t.seq, 1)
	name := buildQueryName(t.domain, t.session, seq, flag, data)

	m := new(dns.Msg)
	m.SetQuestion(name, t.qtype)
	m.RecursionDesired = false
	m.Id = uint16(seq)

	n := len(t.servers)
	var lastErr error
	for i := 0; i < n; i++ {
		idx := (t.lastGood + i) % n
		resp, err := t.sendOneWithTimeout(t.servers[idx], m, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		t.lastGood = idx
		if resp != nil {
			for _, ans := range resp.Answer {
				if payload := extractAnswer(ans); len(payload) > 0 {
					t.appendIn(payload)
				}
			}
		}
		return nil
	}
	return fmt.Errorf("dns tunnel: all upstream servers failed: %w", lastErr)
}

// sendOne 通过受保护 socket 向单个上游发送 DNS 报文并读取应答，
// 支持 udp（默认）/ tcp:// / tls://(dot://) 三种传输。
//
// 直接复用 miekg/dns.Client，仅把底层拨号器替换为本项目的受保护拨号器
// （dialProtected），从而既保证「protect socket」语义，又由库正确处理
// RFC 1035 线速格式的打包/解包（含 UDP 分片、TCP 长度前缀、DoT）。
func (t *DNSTunnel) sendOneWithTimeout(server string, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	netw, addr := "udp", server
	switch {
	case strings.HasPrefix(server, "tcp://"):
		netw, addr = "tcp", server[len("tcp://"):]
	case strings.HasPrefix(server, "tls://"), strings.HasPrefix(server, "dot://"):
		netw = "tcp-tls"
		addr = strings.TrimPrefix(strings.TrimPrefix(server, "tls://"), "dot://")
	}
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	client := &dns.Client{
		Net:     netw,
		Dialer:  newProtectedDialer(t.cfg, timeout),
		Timeout: timeout,
	}
	if netw == "tcp-tls" {
		host, _, _ := net.SplitHostPort(addr)
		client.TLSConfig = &tls.Config{ServerName: host, InsecureSkipVerify: true}
	}
	resp, _, err := client.Exchange(m, addr)
	return resp, err
}

// ---------- net.Conn 接口实现 ----------

func (t *DNSTunnel) Write(p []byte) (int, error) {
	if t.isClosed() {
		return 0, net.ErrClosed
	}
	if t.writeDeadlineExceeded() {
		return 0, fmt.Errorf("dns tunnel: %w", os.ErrDeadlineExceeded)
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > t.chunkSize {
			chunk = chunk[:t.chunkSize]
		}
		if err := t.doExchange(flagData, chunk); err != nil {
			return total, err
		}
		p = p[len(chunk):]
		total += len(chunk)
	}
	return total, nil
}

func (t *DNSTunnel) Read(p []byte) (int, error) {
	for {
		if t.isClosed() {
			return 0, net.ErrClosed
		}
		if err := t.ctx.Err(); err != nil {
			return 0, err
		}

		t.inMu.Lock()
		if t.inBuf.Len() > 0 {
			n, _ := t.inBuf.Read(p)
			t.inMu.Unlock()
			return n, nil
		}
		t.inMu.Unlock()

		if t.readDeadlineExceeded() {
			return 0, fmt.Errorf("dns tunnel: %w", os.ErrDeadlineExceeded)
		}

		// 休眠避免空轮询打满 CPU；休眠后再看一眼缓冲（Write 的应答可能已填充）
		time.Sleep(t.pollInterval)
		t.inMu.Lock()
		if t.inBuf.Len() > 0 {
			t.inMu.Unlock()
			continue
		}
		t.inMu.Unlock()

		if err := t.doExchange(flagPoll, nil); err != nil {
			if t.isClosed() {
				return 0, net.ErrClosed
			}
			return 0, err
		}
	}
}

func (t *DNSTunnel) Close() error {
	if t.isClosed() {
		return nil
	}
	// 先发送关闭通知（此时尚未置位 closed，doExchange 才会真正发包）；
	// 否则 doExchange 开头的 isClosed 检查会直接返回，导致服务端收不到关闭信号、
	// 服务端 ReadSession 永久阻塞。使用较短的 dnsTunnelCloseTimeout 避免对不可达上游长时间阻塞。
	_ = t.doExchangeWithTimeout(flagClose, nil, dnsTunnelCloseTimeout)
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(t.closeCh)
	return nil
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
// 服务端：DNSTunnelServer（权威 DNS 处理，供部署/测试）
// =============================================================

type dnsTunnelSession struct {
	mu        sync.Mutex
	clientBuf bytes.Buffer // 客户端 -> 服务端
	serverBuf bytes.Buffer // 服务端 -> 客户端
	readCond  *sync.Cond
	closed    bool
}

func newDnsTunnelSession() *dnsTunnelSession {
	s := &dnsTunnelSession{}
	s.readCond = sync.NewCond(&s.mu)
	return s
}

// ReadSession 后端阻塞读取客户端发来的数据（最多 max 字节）。
func (s *dnsTunnelSession) ReadSession(max int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.clientBuf.Len() == 0 && !s.closed {
		s.readCond.Wait()
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

// WriteSession 后端向客户端推送数据。
func (s *dnsTunnelSession) WriteSession(b []byte) {
	s.mu.Lock()
	s.serverBuf.Write(b)
	s.mu.Unlock()
}

func (s *dnsTunnelSession) pushClient(b []byte) {
	s.mu.Lock()
	s.clientBuf.Write(b)
	s.readCond.Broadcast()
	s.mu.Unlock()
}

func (s *dnsTunnelSession) popServerNow(max int) []byte {
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
	return out
}

func (s *dnsTunnelSession) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.readCond.Broadcast()
	s.mu.Unlock()
}

// DNSTunnelServer 是隧道服务端的权威 DNS 处理器。把它挂到用户自有域名的
// 权威解析上，即可让客户端 DNS 隧道落地（再转发给真正的 SSH 服务）。
//
// 后端对接：用 WaitForSession 拿到会话后，ReadSession 读取客户端字节流，
// WriteSession 把要回给客户端的数据写入；典型做法是把两端分别接到真实 SSH 服务。
type DNSTunnelServer struct {
	domain      string
	mu          sync.Mutex
	sessions    map[string]*dnsTunnelSession
	newSessions chan string
}

// NewDNSTunnelServer 构造隧道服务端，domain 为委托给本服务的权威域名。
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

// WaitForSession 阻塞直到出现一个新会话（用于后端接入）。
func (s *DNSTunnelServer) WaitForSession(timeout time.Duration) (string, error) {
	select {
	case sess := <-s.newSessions:
		return sess, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("dns tunnel server: wait for session timeout")
	}
}

// ReadSession 从指定会话读取客户端发来的字节流（后端视角）。
func (s *DNSTunnelServer) ReadSession(session string, max int) ([]byte, error) {
	s.mu.Lock()
	sess, ok := s.sessions[session]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("dns tunnel server: unknown session %q", session)
	}
	return sess.ReadSession(max)
}

// WriteSession 向指定会话推送「服务端->客户端」数据（后端视角）。
func (s *DNSTunnelServer) WriteSession(session string, b []byte) {
	s.mu.Lock()
	sess, ok := s.sessions[session]
	s.mu.Unlock()
	if !ok {
		return
	}
	sess.WriteSession(b)
}

// ServeDNS 实现 miekg/dns 的 Handler 接口，处理隧道查询。
func (s *DNSTunnelServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	reply := new(dns.Msg)
	if len(req.Question) == 0 {
		reply.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}
	q := req.Question[0]
	session, _, flag, data, err := parseQueryName(s.domain, q.Name)
	if err != nil {
		zlog.Debugf("%s [Tunnel-DNS-Server] ⚠️ Parse failed: %v", TAG, err)
		reply.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	sess := s.getOrCreate(session)
	if flag == flagData && len(data) > 0 {
		sess.pushClient(data)
	}
	if flag == flagClose {
		sess.markClosed()
	}

	reply.SetReply(req)
	if out := sess.popServerNow(dnsTunnelMaxServerChunk); len(out) > 0 {
		reply.Answer = append(reply.Answer, makeAnswer(q.Name, q.Qtype, out, s.domain))
	}
	_ = w.WriteMsg(reply)
}

// =============================================================
// 隧道注册：把 "dns" 接入全局隧道注册表
// =============================================================

func init() {
	// Network="none"：dialTunnel 不会预先拨号，由本处理器自行用受保护 socket 建立 DNS 通道
	RegisterTunnel("dns", "none", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return NewDNSTunnel(ctx, cfg)
	})
}
