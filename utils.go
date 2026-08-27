package myssh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// PrintAndroidUserInfo  info  Go  info  Android  info
func PrintAndroidUserInfo() {
	//  info  Linux UID  info  GID
	realUid := os.Getuid()
	realGid := os.Getgid()

	//  info  Android  info
	// Android UID  info : UID = (UserID * 100000) + AppBaseID
	androidUserId := realUid / 100000
	appBaseId := realUid % 100000

	//  info
	var username, homeDir string
	u, err := user.Current()
	if err != nil {
		zlog.Warn("user.Current() failed (Normal on highly customized Android)", zap.Error(err))
		username = "unknown"
		homeDir = "unknown"
	} else {
		username = u.Username
		homeDir = u.HomeDir
	}

	//  info  zap  info
	zlog.Info("========== GO PROCESS USER INFO ==========",
		zap.Int("real_linux_uid", realUid),
		zap.Int("real_linux_gid", realGid),
		zap.Int("android_user_id", androidUserId),
		zap.Int("app_base_id", appBaseId),
		zap.String("username", username),
		zap.String("home_dir", homeDir),
	)
}

// CheckIfKeyEncrypted  info  Android  info
//
//	info :
//
// 0 -  info
// 1 -  info
// 2 -  info
func CheckIfKeyEncrypted(key string) int {
	keyBytes := []byte(key)
	_, err := ssh.ParsePrivateKey(keyBytes)

	if err == nil {
		return 0
	}

	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return 1
	}

	return 2
}

func buildUTLSConfig(cfg ProxyConfig, alpn []string) *utls.Config {
	c := &utls.Config{
		ServerName:            cfg.ServerName,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
	}
	if len(alpn) > 0 {
		c.NextProtos = alpn
	}
	return c
}

func handshakeUTLS(ctx context.Context, conn net.Conn, utlsConfig *utls.Config) (*utls.UConn, error) {
	uConn := utls.UClient(conn, utlsConfig, utls.HelloChrome_Auto)
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uConn, nil
}

// ValidatePassphrase  info ： info
func ValidatePassphrase(key string, pass string) bool {
	_, err := ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
	return err == nil
}

// parsePrivateKeySshSigner  info  SSH  info
func parsePrivateKeySshSigner(privateKey []byte, passphrase []byte) (ssh.Signer, error) {
	//  info
	signer, err := ssh.ParsePrivateKey(privateKey)
	//  info  (Passphrase)
	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return ssh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
	}
	return signer, err
}

type CertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	SANs       string `json:"sans"`
	Raw        []byte `json:"raw_der"`
	Protocol   string `json:"protocol"`
	IsVerified bool   `json:"is_verified"`
}

// FetchCertInfo  info  TLS  info  QUIC  info server info
func FetchCertInfo(target string, useQUIC bool) (*CertInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := ensureHostPort(target, "443")
	host, _, _ := net.SplitHostPort(addr)

	var peerCerts []*x509.Certificate
	var protocol string
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "http/1.1"},
	}

	if useQUIC {
		protocol = "QUIC"
		baseConn, err := dialProtected(ctx, ProxyConfig{}, "udp", addr, 8*time.Second)
		if err != nil {
			return nil, err
		}
		udpConn, ok := baseConn.(*net.UDPConn)
		if !ok {
			baseConn.Close()
			return nil, fmt.Errorf("expected *net.UDPConn, got %T", baseConn)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsConfig, nil)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		defer conn.CloseWithError(0, "")
		peerCerts = conn.ConnectionState().TLS.PeerCertificates
	} else {
		protocol = "TLS"
		dialer := newProtectedDialer(ProxyConfig{}, 8*time.Second)
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		peerCerts = conn.ConnectionState().PeerCertificates
	}

	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no cert")
	}

	cert := peerCerts[0]
	_, verifyErr := cert.Verify(x509.VerifyOptions{DNSName: host})

	return &CertInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore.Unix(),
		NotAfter:   cert.NotAfter.Unix(),
		SANs:       strings.Join(cert.DNSNames, ","),
		Raw:        cert.Raw,
		Protocol:   protocol,
		IsVerified: verifyErr == nil,
	}, nil
}

// SSHServerDetails  info  SSH  info
type SSHServerDetails struct {
	Address           string `json:"address"`
	Banner            string `json:"banner"`
	KeyType           string `json:"key_type"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	FingerprintMD5    string `json:"fingerprint_md5"`
	LatencyMs         int64  `json:"latency_ms"`
}

// probeSSHServer  info ： info  SSH  info
func probeSSHServer(sshAddr string) (*SSHServerDetails, error) {
	if strings.TrimSpace(sshAddr) == "" {
		return nil, fmt.Errorf("empty sshAddr")
	}
	addr := ensureHostPort(sshAddr, "22")

	startTime := time.Now()
	var capturedKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "probe",
		Auth: []ssh.AuthMethod{
			ssh.Password("probe"),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			capturedKey = key
			return nil
		},
		Timeout: 6 * time.Second,
	}

	dialer := wrapAndroidProtect(&net.Dialer{Timeout: 6 * time.Second})
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	latencyMs := time.Since(startTime).Milliseconds()

	var serverVersion string
	if sshConn != nil {
		serverVersion = string(sshConn.ServerVersion())
		sshConn.Close()
	}
	_ = chans
	_ = reqs

	if capturedKey == nil {
		return nil, fmt.Errorf("failed to retrieve ssh host key")
	}

	return &SSHServerDetails{
		Address:           addr,
		Banner:            serverVersion,
		KeyType:           capturedKey.Type(),
		FingerprintSHA256: ssh.FingerprintSHA256(capturedKey),
		FingerprintMD5:    ssh.FingerprintLegacyMD5(capturedKey),
		LatencyMs:         latencyMs,
	}, nil
}

// GetSSHFingerprint  info  SSH  info  SHA256  info
func GetSSHFingerprint(sshAddr string) (string, error) {
	details, err := probeSSHServer(sshAddr)
	if err != nil {
		return "", err
	}
	return details.FingerprintSHA256, nil
}

// GetSSHServerDetailsJSON  info  SSH  info  JSON  info
func GetSSHServerDetailsJSON(sshAddr string) (string, error) {
	details, err := probeSSHServer(sshAddr)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TLSCertDetails  info  TLS  info
type TLSCertDetails struct {
	Target             string   `json:"target"`
	SNI                string   `json:"sni"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBefore          int64    `json:"not_before"`
	NotAfter           int64    `json:"not_after"`
	DaysRemaining      int      `json:"days_remaining"`
	IsExpired          bool     `json:"is_expired"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	TLSVersion         string   `json:"tls_version"`
	NegotiatedProtocol string   `json:"negotiated_protocol"`
	LatencyMs          int64    `json:"latency_ms"`
}

// probeTLSCert  info ： info target TLS/HTTPS  info
func probeTLSCert(target string, serverName string) (*TLSCertDetails, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := ensureHostPort(target, "443")
	host, _, _ := net.SplitHostPort(addr)

	sni := strings.TrimSpace(serverName)
	if sni == "" {
		sni = host
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	startTime := time.Now()
	dialer := wrapAndroidProtect(&net.Dialer{Timeout: 6 * time.Second})
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	latencyMs := time.Since(startTime).Milliseconds()
	connState := conn.ConnectionState()
	peerCerts := connState.PeerCertificates
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no certificate presented by server")
	}

	cert := peerCerts[0]
	var tlsVerStr string
	switch connState.Version {
	case tls.VersionTLS13:
		tlsVerStr = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVerStr = "TLS 1.2"
	case tls.VersionTLS11:
		tlsVerStr = "TLS 1.1"
	case tls.VersionTLS10:
		tlsVerStr = "TLS 1.0"
	default:
		tlsVerStr = fmt.Sprintf("0x%04X", connState.Version)
	}

	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	isExpired := time.Now().After(cert.NotAfter)

	return &TLSCertDetails{
		Target:             addr,
		SNI:                sni,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.Unix(),
		NotAfter:           cert.NotAfter.Unix(),
		DaysRemaining:      daysRemaining,
		IsExpired:          isExpired,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ips,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		FingerprintSHA256:  formatSHA256Fingerprint(cert.Raw),
		TLSVersion:         tlsVerStr,
		NegotiatedProtocol: connState.NegotiatedProtocol,
		LatencyMs:          latencyMs,
	}, nil
}

// GetTLSCertFingerprint  info target TLS/HTTPS/WSS  info  SHA256  info  ( info : XX:XX:XX:...)
func GetTLSCertFingerprint(target string, serverName string) (string, error) {
	details, err := probeTLSCert(target, serverName)
	if err != nil {
		return "", err
	}
	return details.FingerprintSHA256, nil
}

// GetTLSCertDetailsJSON  info  TLS  info  JSON  info
func GetTLSCertDetailsJSON(target string, serverName string) (string, error) {
	details, err := probeTLSCert(target, serverName)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ==========================================
//  info  (support Android GoMobile  info )
// ==========================================

// ConnInfo  info  ( info  json  info  Android  info )
type ConnInfo struct {
	ID         int64     `json:"id"`
	TargetAddr string    `json:"target_addr"`
	TargetHost string    `json:"target_host"`
	ProxyAddr  string    `json:"proxy_addr"`
	StartTime  time.Time `json:"start_time"`
	ReadBytes  uint64    `json:"read_bytes"`
	WriteBytes uint64    `json:"write_bytes"`
}

// info
func (c *ConnInfo) String() string {
	duration := time.Since(c.StartTime).Round(time.Second)
	return fmt.Sprintf("[ID:%d] Target:%s | Uptime:%s | ↑%d B | ↓%d B",
		c.ID, c.TargetAddr, duration, atomic.LoadUint64(&c.WriteBytes), atomic.LoadUint64(&c.ReadBytes))
}

// ==========================================
//  info
// ==========================================

// domainStat is the internal struct for calculation
type domainStat struct {
	currentTxBytes uint64
	currentRxBytes uint64
}

// DomainActivity represents the real-time activity of a single domain for JSON export.
type DomainActivity struct {
	Domain string `json:"domain"`
	TxRate int64  `json:"tx_rate"`
	RxRate int64  `json:"rx_rate"`
}

type domainStatsManager struct {
	stats      sync.Map // key: string (domain), value: *domainStat
	rankMu     sync.RWMutex
	rankedList []DomainActivity
}

var globalDomainStatsManager = &domainStatsManager{}

// calculateAndRank is called periodically to update the ranked list of active domains.
func (dsm *domainStatsManager) calculateAndRank(elapsed time.Duration) {
	var currentActivities []DomainActivity
	dsm.stats.Range(func(key, value interface{}) bool {
		domain := key.(string)
		stat := value.(*domainStat)
		tx := atomic.SwapUint64(&stat.currentTxBytes, 0)
		rx := atomic.SwapUint64(&stat.currentRxBytes, 0)
		txRate := bytesPerSecond(tx, elapsed)
		rxRate := bytesPerSecond(rx, elapsed)
		if txRate > 0 || rxRate > 0 {
			currentActivities = append(currentActivities, DomainActivity{Domain: domain, TxRate: int64(txRate), RxRate: int64(rxRate)})
		}
		return true
	})
	sort.Slice(currentActivities, func(i, j int) bool {
		return (currentActivities[i].TxRate + currentActivities[i].RxRate) > (currentActivities[j].TxRate + currentActivities[j].RxRate)
	})
	const topN = 20
	if len(currentActivities) > topN {
		currentActivities = currentActivities[:topN]
	}
	dsm.rankMu.Lock()
	dsm.rankedList = currentActivities
	dsm.rankMu.Unlock()
}

// reset clears all domain statistics and the ranked list.
func (dsm *domainStatsManager) reset() {
	dsm.stats.Range(func(key, value interface{}) bool {
		dsm.stats.Delete(key)
		return true
	})
	dsm.rankMu.Lock()
	dsm.rankedList = nil
	dsm.rankMu.Unlock()
}

// ==========================================
//  info ：TrafficManager
// ==========================================

// info
type trafficManager struct {
	TxTotal uint64 //  info uplink info  (Bytes)
	RxTotal uint64 //  info downlink info  (Bytes)

	ActiveConns   int64    //  info
	TotalConns    int64    //  info
	activeMap     sync.Map // key: int64 ( info ID), value: *ConnInfo
	connIDCounter int64    //  info  ID
}

// info  init()  info
var globalTrafficManager = &trafficManager{}

// info
var (
	lastTxTotal   uint64
	lastRxTotal   uint64
	currentTxRate uint64
	currentRxRate uint64
)

const maxInt64AsUint64 = uint64(1<<63 - 1)

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func uint64ToInt64(v uint64) int64 {
	if v > maxInt64AsUint64 {
		return int64(maxInt64AsUint64)
	}
	return int64(v)
}

func trafficDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func bytesPerSecond(delta uint64, elapsed time.Duration) uint64 {
	if delta == 0 {
		return 0
	}
	elapsedNs := elapsed.Nanoseconds()
	if elapsedNs <= 0 {
		return delta
	}

	divisor := uint64(elapsedNs)
	hi, lo := bits.Mul64(delta, uint64(time.Second))
	if hi >= divisor {
		return ^uint64(0)
	}

	quotient, remainder := bits.Div64(hi, lo, divisor)
	if remainder >= (divisor+1)/2 && quotient < ^uint64(0) {
		quotient++
	}
	return quotient
}

// ==========================================
//  info  (TrackedConn / TrackedPacketConn)
// ==========================================

type TrackedConn struct {
	net.Conn
	manager    *trafficManager
	info       *ConnInfo
	domainStat *domainStat //  info ， info  sync.Map
	closeOnce  sync.Once
	closeErr   error
}

func (tc *TrackedConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&tc.manager.RxTotal, uint64(n)) //  info downlink
		atomic.AddUint64(&tc.info.ReadBytes, uint64(n))  //  info downlink
		if tc.domainStat != nil {
			atomic.AddUint64(&tc.domainStat.currentRxBytes, uint64(n))
		}
	}
	return n, err
}

func (tc *TrackedConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&tc.manager.TxTotal, uint64(n)) //  info uplink
		atomic.AddUint64(&tc.info.WriteBytes, uint64(n)) //  info uplink
		if tc.domainStat != nil {
			atomic.AddUint64(&tc.domainStat.currentTxBytes, uint64(n))
		}
	}
	return n, err
}

func (tc *TrackedConn) Close() error {
	tc.closeOnce.Do(func() {
		atomic.AddInt64(&tc.manager.ActiveConns, -1)
		tc.manager.activeMap.Delete(tc.info.ID)
		tc.closeErr = tc.Conn.Close()
	})
	return tc.closeErr
}

type TrackedPacketConn struct {
	net.PacketConn
	manager   *trafficManager
	info      *ConnInfo
	closeOnce sync.Once
	closeErr  error
}

func (tc *TrackedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = tc.PacketConn.ReadFrom(p)
	if n > 0 {
		atomic.AddUint64(&tc.manager.RxTotal, uint64(n))
		atomic.AddUint64(&tc.info.ReadBytes, uint64(n))
	}
	return n, addr, err
}

func (tc *TrackedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = tc.PacketConn.WriteTo(p, addr)
	if n > 0 {
		atomic.AddUint64(&tc.manager.TxTotal, uint64(n))
		atomic.AddUint64(&tc.info.WriteBytes, uint64(n))
	}
	return n, err
}

func (tc *TrackedPacketConn) Close() error {
	tc.closeOnce.Do(func() {
		atomic.AddInt64(&tc.manager.ActiveConns, -1)
		tc.manager.activeMap.Delete(tc.info.ID)
		tc.closeErr = tc.PacketConn.Close()
	})
	return tc.closeErr
}

// ==========================================
//  info  API ( info )
// ==========================================

// DialTracked  info  net.DialTimeout
func DialTracked(network, address string, timeout time.Duration, targetAddr string) (net.Conn, error) {
	conn, err := dialProtected(currentEngineCtx(), ProxyConfig{}, network, address, timeout)
	if err != nil {
		return nil, err
	}
	return WrapConn(conn, targetAddr), nil
}

// ListenPacketTracked  info  UDP Listen
func ListenPacketTracked(network, address string, sessionName string) (net.PacketConn, error) {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return WrapPacketConn(conn, sessionName), nil
}

// WrapConn  info  TCP  info
func WrapConn(conn net.Conn, targetAddr string) net.Conn {
	atomic.AddInt64(&globalTrafficManager.TotalConns, 1)
	atomic.AddInt64(&globalTrafficManager.ActiveConns, 1)
	id := atomic.AddInt64(&globalTrafficManager.connIDCounter, 1)

	var host string
	h, _, err := net.SplitHostPort(targetAddr)
	if err == nil {
		host = h
	} else {
		if net.ParseIP(targetAddr) == nil {
			host = targetAddr
		}
	}
	info := &ConnInfo{
		ID:         id,
		TargetAddr: targetAddr,
		TargetHost: host,
		ProxyAddr:  addrString(conn.RemoteAddr()),
		StartTime:  time.Now(),
	}
	globalTrafficManager.activeMap.Store(id, info)

	//  info target info ， info 。
	//  info  Read/Write  info ， info  sync.Map  info 。
	var stat *domainStat
	if host != "" {
		val, _ := globalDomainStatsManager.stats.LoadOrStore(host, &domainStat{})
		stat = val.(*domainStat)
	}

	return &TrackedConn{
		Conn:       conn,
		manager:    globalTrafficManager,
		info:       info,
		domainStat: stat,
	}
}

// WrapPacketConn  info  UDP  info
func WrapPacketConn(conn net.PacketConn, sessionName string) net.PacketConn {
	atomic.AddInt64(&globalTrafficManager.TotalConns, 1)
	atomic.AddInt64(&globalTrafficManager.ActiveConns, 1)
	id := atomic.AddInt64(&globalTrafficManager.connIDCounter, 1)

	var host string
	h, _, err := net.SplitHostPort(sessionName)
	if err == nil {
		host = h
	} else {
		if net.ParseIP(sessionName) == nil {
			host = sessionName
		}
	}
	info := &ConnInfo{
		ID:         id,
		TargetAddr: sessionName,
		TargetHost: host,
		ProxyAddr:  addrString(conn.LocalAddr()),
		StartTime:  time.Now(),
	}
	globalTrafficManager.activeMap.Store(id, info)

	return &TrackedPacketConn{
		PacketConn: conn,
		manager:    globalTrafficManager,
		info:       info,
	}
}

// ==========================================
// GoMobile  info  Android  info
// ==========================================

var (
	trafficCb  TrafficCallback
	sysInfoCb  SysInfoCallback
	callbackMu sync.RWMutex
	cpuStatsMu sync.Mutex
)

// TrafficStats  info  ( info )
type TrafficStats struct {
	TxRate      int64
	RxRate      int64
	TxTotal     int64
	RxTotal     int64
	ActiveConns int64
	TotalConns  int64
}

// SysStats  info
type SysStats struct {
	CpuPercent float64
	MemAllocMB float64
	MemSysMB   float64
	Goroutines int
}

// TrafficCallback GoMobile  info  ( info  activeConns, totalConns)
type TrafficCallback interface {
	OnTrafficUpdate(txRate int64, rxRate int64, txTotal int64, rxTotal int64, activeConns int64, totalConns int64)
}

// SysInfoCallback GoMobile  info
type SysInfoCallback interface {
	OnSysInfoUpdate(cpuPercent float64, memAllocMB float64, memSysMB float64, goroutines int)
}

func RegisterTrafficCallback(cb TrafficCallback) {
	callbackMu.Lock()
	trafficCb = cb
	callbackMu.Unlock()
}

func RegisterSysInfoCallback(cb SysInfoCallback) {
	callbackMu.Lock()
	sysInfoCb = cb
	callbackMu.Unlock()
}

// GetTrafficStats  info
func GetTrafficStats() *TrafficStats {
	return &TrafficStats{
		TxRate:      uint64ToInt64(atomic.LoadUint64(&currentTxRate)),
		RxRate:      uint64ToInt64(atomic.LoadUint64(&currentRxRate)),
		TxTotal:     uint64ToInt64(atomic.LoadUint64(&globalTrafficManager.TxTotal)),
		RxTotal:     uint64ToInt64(atomic.LoadUint64(&globalTrafficManager.RxTotal)),
		ActiveConns: atomic.LoadInt64(&globalTrafficManager.ActiveConns),
		TotalConns:  atomic.LoadInt64(&globalTrafficManager.TotalConns),
	}
}

// GetSysStats  info
func GetSysStats() *SysStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &SysStats{
		CpuPercent: getCpuPercent(),
		MemAllocMB: float64(m.Alloc) / 1024.0 / 1024.0,
		MemSysMB:   float64(m.Sys) / 1024.0 / 1024.0,
		Goroutines: runtime.NumGoroutine(),
	}
}

// GetActiveConnectionsJSON  info  JSON  info  ( info  GoMobile  info )
func GetActiveConnectionsJSON() string {
	var list []ConnInfo
	globalTrafficManager.activeMap.Range(func(key, value interface{}) bool {
		info, ok := value.(*ConnInfo)
		if !ok || info == nil {
			return true
		}
		list = append(list, ConnInfo{
			ID:         info.ID,
			TargetAddr: info.TargetAddr,
			ProxyAddr:  info.ProxyAddr,
			StartTime:  info.StartTime,
			ReadBytes:  atomic.LoadUint64(&info.ReadBytes),
			WriteBytes: atomic.LoadUint64(&info.WriteBytes),
		})
		return true
	})
	if len(list) == 0 {
		return "[]"
	}
	data, err := json.Marshal(list)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// GetDomainActivityJSON  info  JSON  info 。
func GetDomainActivityJSON() string {
	globalDomainStatsManager.rankMu.RLock()
	defer globalDomainStatsManager.rankMu.RUnlock()
	if len(globalDomainStatsManager.rankedList) == 0 {
		return "[]"
	}
	data, err := json.Marshal(globalDomainStatsManager.rankedList)
	if err != nil {
		zlog.Errorf("%s [Stats] ❌ Failed to serialize domain activity ranking: %v", TAG, err)
		return "[]"
	}
	return string(data)
}

// ResetDomainStatsAndCache  info  (Android)  info ， info
func ResetDomainStatsAndCache() {
	if gr := globalRouter.Load(); gr != nil {
		gr.ResetCacheAndStats()
	}
	globalDomainStatsManager.reset()
	zlog.Infof("%s [Stats] ♻️ Domain stats ranking and route cache have been reset per UI request", TAG)
}

// RouterStats  info
type RouterStats struct {
	QueryCount    int64
	CacheHitCount int64
	HitRate       float64
}

// GetRouterStats  info  (Android)  info ， info
func GetRouterStats() *RouterStats {
	gr := globalRouter.Load()
	if gr == nil {
		return &RouterStats{}
	}

	total, hits := gr.getStats()
	var rate float64
	if total > 0 {
		rate = float64(hits) / float64(total) * 100.0
	}
	return &RouterStats{
		QueryCount:    total,
		CacheHitCount: hits,
		HitRate:       rate,
	}
}

// ==========================================
//  info  CPU  info
// ==========================================

var (
	lastUtime float64
	lastStime float64
	lastTime  time.Time
)

func getCpuPercent() float64 {
	//  info  Linux/Android  info  /proc/self/stat； info （Windows/macOS  info ） info  0，
	//  info 。
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return 0.0
	}
	cpuStatsMu.Lock()
	defer cpuStatsMu.Unlock()

	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0.0
	}
	fields := bytes.Fields(data)
	if len(fields) < 15 {
		return 0.0
	}
	utime, _ := strconv.ParseFloat(string(fields[13]), 64)
	stime, _ := strconv.ParseFloat(string(fields[14]), 64)

	now := time.Now()
	if !lastTime.IsZero() {
		timeDelta := now.Sub(lastTime).Seconds()
		if timeDelta > 0 {
			utimeDelta := (utime - lastUtime) / 100.0
			stimeDelta := (stime - lastStime) / 100.0
			cpuPercent := ((utimeDelta + stimeDelta) / timeDelta) * 100.0
			lastUtime = utime
			lastStime = stime
			lastTime = now
			return cpuPercent
		}
	}
	lastUtime = utime
	lastStime = stime
	lastTime = now
	return 0.0
}

func init() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		lastSampleTime := time.Now()
		for range ticker.C {
			now := time.Now()
			elapsed := now.Sub(lastSampleTime)
			lastSampleTime = now

			//  info
			tTx := atomic.LoadUint64(&globalTrafficManager.TxTotal)
			tRx := atomic.LoadUint64(&globalTrafficManager.RxTotal)
			actConns := atomic.LoadInt64(&globalTrafficManager.ActiveConns)
			totConns := atomic.LoadInt64(&globalTrafficManager.TotalConns)

			//  info ， info
			lTx := atomic.SwapUint64(&lastTxTotal, tTx)
			lRx := atomic.SwapUint64(&lastRxTotal, tRx)

			//  info  1  info
			txRate := bytesPerSecond(trafficDelta(tTx, lTx), elapsed)
			rxRate := bytesPerSecond(trafficDelta(tRx, lRx), elapsed)

			//  info
			atomic.StoreUint64(&currentTxRate, txRate)
			atomic.StoreUint64(&currentRxRate, rxRate)

			globalDomainStatsManager.calculateAndRank(elapsed)

			//  info  Android
			if trafficCb != nil {
				trafficCb.OnTrafficUpdate(int64(txRate), int64(rxRate), int64(tTx), int64(tRx), actConns, totConns)
			}
			if sysInfoCb != nil {
				sys := GetSysStats()
				sysInfoCb.OnSysInfoUpdate(sys.CpuPercent, sys.MemAllocMB, sys.MemSysMB, sys.Goroutines)
			}
		}
	}()
}
