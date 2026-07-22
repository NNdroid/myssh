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

// PrintAndroidUserInfo 打印当前 Go 进程在 Android 上的底层身份信息
func PrintAndroidUserInfo() {
	// 获取最底层的真实 Linux UID 和 GID
	realUid := os.Getuid()
	realGid := os.Getgid()

	// 逆向推算 Android 的用户空间架构
	// Android UID 计算公式: UID = (UserID * 100000) + AppBaseID
	androidUserId := realUid / 100000
	appBaseId := realUid % 100000

	// 尝试获取标准的系统用户信息
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

	// 使用 zap 打印结构化日志
	zlog.Info("========== GO PROCESS USER INFO ==========",
		zap.Int("real_linux_uid", realUid),
		zap.Int("real_linux_gid", realGid),
		zap.Int("android_user_id", androidUserId),
		zap.Int("app_base_id", appBaseId),
		zap.String("username", username),
		zap.String("home_dir", homeDir),
	)
}

// CheckIfKeyEncrypted 供 Android 调用
// 返回值:
// 0 - 不需要密码
// 1 - 需要密码
// 2 - 格式错误
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

// ValidatePassphrase 示例：带密码解析并测试是否通过
func ValidatePassphrase(key string, pass string) bool {
	_, err := ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
	return err == nil
}

// parsePrivateKeySshSigner 解析 SSH 私钥
func parsePrivateKeySshSigner(privateKey []byte, passphrase []byte) (ssh.Signer, error) {
	// 尝试直接解析
	signer, err := ssh.ParsePrivateKey(privateKey)
	// 如果报错提示需要密码 (Passphrase)
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

// FetchCertInfo 尝试通过 TLS 或 QUIC 获取服务器证书信息
func FetchCertInfo(target string, useQUIC bool) (*CertInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := target
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = target + ":443"
	}
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

// ==========================================
// 流量统计与系统监控 (支持 Android GoMobile 回调)
// ==========================================

// ConnInfo 记录单个连接的详细数据 (增加 json 标签供 Android 解析)
type ConnInfo struct {
	ID         int64     `json:"id"`
	TargetAddr string    `json:"target_addr"`
	TargetHost string    `json:"target_host"`
	ProxyAddr  string    `json:"proxy_addr"`
	StartTime  time.Time `json:"start_time"`
	ReadBytes  uint64    `json:"read_bytes"`
	WriteBytes uint64    `json:"write_bytes"`
}

// 格式化输出
func (c *ConnInfo) String() string {
	duration := time.Since(c.StartTime).Round(time.Second)
	return fmt.Sprintf("[ID:%d] Target:%s | Uptime:%s | ↑%d B | ↓%d B",
		c.ID, c.TargetAddr, duration, atomic.LoadUint64(&c.WriteBytes), atomic.LoadUint64(&c.ReadBytes))
}

// ==========================================
// 域名实时流量排行榜
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
// 内部核心统计引擎：TrafficManager
// ==========================================

// 内部使用的全局管理器
type trafficManager struct {
	TxTotal uint64 // 总计上行流量 (Bytes)
	RxTotal uint64 // 总计下行流量 (Bytes)

	ActiveConns   int64    // 当前活跃连接数
	TotalConns    int64    // 累计连接总数
	activeMap     sync.Map // key: int64 (连接ID), value: *ConnInfo
	connIDCounter int64    // 用于生成自增的唯一连接 ID
}

// 实例化一个全局单例供各个连接和 init() 调用
var globalTrafficManager = &trafficManager{}

// 速率计算专用的内部全局变量
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
// 内部网络连接包装器 (TrackedConn / TrackedPacketConn)
// ==========================================

type TrackedConn struct {
	net.Conn
	manager   *trafficManager
	info      *ConnInfo
	closeOnce sync.Once
	closeErr  error
}

func (tc *TrackedConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&tc.manager.RxTotal, uint64(n)) // 增加全局下行
		atomic.AddUint64(&tc.info.ReadBytes, uint64(n))  // 增加本连接下行
		if tc.info.TargetHost != "" {
			val, _ := globalDomainStatsManager.stats.LoadOrStore(tc.info.TargetHost, &domainStat{})
			stat := val.(*domainStat)
			atomic.AddUint64(&stat.currentRxBytes, uint64(n))
		}
	}
	return n, err
}

func (tc *TrackedConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&tc.manager.TxTotal, uint64(n)) // 增加全局上行
		atomic.AddUint64(&tc.info.WriteBytes, uint64(n)) // 增加本连接上行
		if tc.info.TargetHost != "" {
			val, _ := globalDomainStatsManager.stats.LoadOrStore(tc.info.TargetHost, &domainStat{})
			stat := val.(*domainStat)
			atomic.AddUint64(&stat.currentTxBytes, uint64(n))
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
// 包装 API (供你在代码中调用建立连接)
// ==========================================

// DialTracked 替代 net.DialTimeout
func DialTracked(network, address string, timeout time.Duration, targetAddr string) (net.Conn, error) {
	conn, err := dialProtected(context.Background(), ProxyConfig{}, network, address, timeout)
	if err != nil {
		return nil, err
	}
	return WrapConn(conn, targetAddr), nil
}

// ListenPacketTracked 封装 UDP Listen
func ListenPacketTracked(network, address string, sessionName string) (net.PacketConn, error) {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return WrapPacketConn(conn, sessionName), nil
}

// WrapConn 包装现有 TCP 连接
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

	return &TrackedConn{
		Conn:    conn,
		manager: globalTrafficManager,
		info:    info,
	}
}

// WrapPacketConn 包装现有 UDP 连接
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
// GoMobile 导出的供 Android 调用的结构体与接口
// ==========================================

var (
	trafficCb  TrafficCallback
	sysInfoCb  SysInfoCallback
	callbackMu sync.RWMutex
	cpuStatsMu sync.Mutex
)

// TrafficStats 供外部获取流量数据的结构体 (新增了连接数)
type TrafficStats struct {
	TxRate      int64
	RxRate      int64
	TxTotal     int64
	RxTotal     int64
	ActiveConns int64
	TotalConns  int64
}

// SysStats 供外部获取系统资源信息的结构体
type SysStats struct {
	CpuPercent float64
	MemAllocMB float64
	MemSysMB   float64
	Goroutines int
}

// TrafficCallback GoMobile 导出的安卓回调接口 (增加 activeConns, totalConns)
type TrafficCallback interface {
	OnTrafficUpdate(txRate int64, rxRate int64, txTotal int64, rxTotal int64, activeConns int64, totalConns int64)
}

// SysInfoCallback GoMobile 导出的安卓回调接口
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

// GetTrafficStats 供外部主动调用
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

// GetSysStats 供外部主动调用
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

// GetActiveConnectionsJSON 返回当前活跃连接的 JSON 字符串 (完美解决 GoMobile 无法返回结构体切片的问题)
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

// GetDomainActivityJSON 返回按速度排名的顶级活动域的 JSON 字符串。
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

// ResetDomainStatsAndCache 供外部 (Android) 主动调用，清空路由缓存与域名活动排行榜数据
func ResetDomainStatsAndCache() {
	if globalRouter != nil {
		globalRouter.ResetCacheAndStats()
	}
	globalDomainStatsManager.reset()
	zlog.Infof("%s [Stats] ♻️ Domain stats ranking and route cache have been reset per UI request", TAG)
}

// RouterStats 供外部获取路由分流统计数据的结构体
type RouterStats struct {
	QueryCount    int64
	CacheHitCount int64
	HitRate       float64
}

// GetRouterStats 供外部 (Android) 主动调用，获取当前路由引擎的实时统计信息
func GetRouterStats() *RouterStats {
	if globalRouter == nil {
		return &RouterStats{}
	}

	total, hits := globalRouter.getStats()
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
// 后台定时计算器与 CPU 统计
// ==========================================

var (
	lastUtime float64
	lastStime float64
	lastTime  time.Time
)

func getCpuPercent() float64 {
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

			// 当前总流量和连接数
			tTx := atomic.LoadUint64(&globalTrafficManager.TxTotal)
			tRx := atomic.LoadUint64(&globalTrafficManager.RxTotal)
			actConns := atomic.LoadInt64(&globalTrafficManager.ActiveConns)
			totConns := atomic.LoadInt64(&globalTrafficManager.TotalConns)

			// 上一秒总流量，并替换为最新总流量
			lTx := atomic.SwapUint64(&lastTxTotal, tTx)
			lRx := atomic.SwapUint64(&lastRxTotal, tRx)

			// 计算当前 1 秒内产生的流量速率
			txRate := bytesPerSecond(trafficDelta(tTx, lTx), elapsed)
			rxRate := bytesPerSecond(trafficDelta(tRx, lRx), elapsed)

			// 更新供主动查询使用的速率
			atomic.StoreUint64(&currentTxRate, txRate)
			atomic.StoreUint64(&currentRxRate, rxRate)

			globalDomainStatsManager.calculateAndRank(elapsed)

			// 触发回调给 Android
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
