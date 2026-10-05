package myssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 本文件实现流量统计与连接追踪：TrackedConn/TrackedPacketConn 包装层、
// 全局限速采样、域名活跃度排行，以及暴露给 GoMobile 宿主的回调与 JSON API。

// ConnInfo 单条连接的实时统计（以 json 导出给 Android UI）。
//
// Protocol 把「连接数」拆成四摊。没有它就没法回答"tproxy 模式连接数是 VPN 的
// 20 倍"到底是哪一摊撑起来的 —— 四摊的成因与修法毫不相干：
//   - "tcp"：TCP 隧道连接。多 = 短连接风暴（每个 HTTP 请求一条 / 没开 keepalive）。
//   - "udp-proxy"：走 UDPGW 的代理 UDP 会话。多 = 按 (源地址,目标) 建会话且空闲回收没生效。
//   - "udp-direct"：**本地直连的 UDP NAT 会话**。它压根不过隧道，只是被 tproxy 收进
//     来后本机转发出去。多 = 局域网/私有段/mDNS 之类的流量被劫持后建了本地会话。
//     这一摊最容易被误读成「隧道连接数暴涨」，实际与隧道无关。
//   - "dns"：DNS 隧道连接（每次远端解析一条，用完即关）。
type ConnInfo struct {
	ReadBytes  atomic.Uint64 `json:"read_bytes"`
	WriteBytes atomic.Uint64 `json:"write_bytes"`
	ID         int64         `json:"id"`
	TargetAddr string        `json:"target_addr"`
	TargetHost string        `json:"target_host"`
	ProxyAddr  string        `json:"proxy_addr"`
	StartTime  time.Time     `json:"start_time"`
	Protocol   string        `json:"protocol"` // "tcp" / "udp-proxy" / "udp-direct" / "dns"
}

func (c *ConnInfo) String() string {
	duration := time.Since(c.StartTime).Round(time.Second)
	return fmt.Sprintf("[ID:%d] %s Target:%s | Uptime:%s | ↑%d B | ↓%d B",
		c.ID, c.Protocol, c.TargetAddr, duration, c.WriteBytes.Load(), c.ReadBytes.Load())
}

// ===== 域名活跃度统计 =====

// domainStat is the internal struct for calculation
type domainStat struct {
	currentTxBytes atomic.Uint64
	currentRxBytes atomic.Uint64
	// 上次有流量（或条目创建）的时间戳，calculateAndRank 用于淘汰长期空闲条目，
	// 防止 sync.Map 随域名无限增长。
	lastActiveUnix atomic.Int64
}

// domainStatIdleTTL 连续无流量超过该时长的域名条目会被淘汰；
// 若之后再次出现流量，WrapConn 的 LoadOrStore 会重建条目。
const domainStatIdleTTL = 60 * time.Second

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
	now := time.Now()
	dsm.stats.Range(func(key, value interface{}) bool {
		domain := key.(string)
		stat := value.(*domainStat)
		tx := stat.currentTxBytes.Swap(0)
		rx := stat.currentRxBytes.Swap(0)
		if tx == 0 && rx == 0 {
			// 长期无活动的条目移除；活跃时间戳刚重置过的条目保留一个 TTL 宽限期，
			// 避免与 WrapConn 创建条目的窗口竞争（新建条目可能刚 Swap 完就为 0）。
			if stat.lastActiveUnix.Load() != 0 && now.Sub(time.Unix(stat.lastActiveUnix.Load(), 0)) > domainStatIdleTTL {
				dsm.stats.Delete(key)
			}
			return true
		}
		stat.lastActiveUnix.Store(now.Unix())
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

// ===== 全局流量计数器 =====

type trafficManager struct {
	TxTotal         atomic.Uint64 // 累计上行字节数
	RxTotal         atomic.Uint64 // 累计下行字节数
	ActiveConns     atomic.Int64  // 活跃连接数
	TotalConns      atomic.Int64  // 历史连接总数
	ActiveTcp       atomic.Int64  // 活跃 TCP 隧道连接数
	ActiveUdpProxy  atomic.Int64  // 活跃 UDPGW 代理会话数（过隧道）
	ActiveUdpDirect atomic.Int64  // 活跃本地直连 UDP 会话数（不过隧道）
	ActiveDns       atomic.Int64  // 活跃 DNS 隧道连接数
	connIDCounter   atomic.Int64  // 连接 ID 发生器
	activeMap       sync.Map      // key: int64 (连接 ID), value: *ConnInfo
}

// bumpProtocol 按类别增减分类计数。close 传 -1，open 传 +1。
//
// ⚠️ 两侧必须成对：少减一次会让计数只涨不落，而这个数正是判断"连接数异常"的依据，
// 一旦失真就再也无法归因。
func (m *trafficManager) bumpProtocol(protocol string, delta int64) {
	switch protocol {
	case "udp-proxy":
		m.ActiveUdpProxy.Add(delta)
	case "udp-direct":
		m.ActiveUdpDirect.Add(delta)
	case "dns":
		m.ActiveDns.Add(delta)
	default:
		m.ActiveTcp.Add(delta)
	}
}

var globalTrafficManager = &trafficManager{}

var (
	lastTxTotal   atomic.Uint64
	lastRxTotal   atomic.Uint64
	currentTxRate atomic.Uint64
	currentRxRate atomic.Uint64
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

// bytesPerSecond 计算字节速率，用 128 位乘除避免大流量下 uint64 溢出。
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

// ===== 连接包装层（TrackedConn / TrackedPacketConn） =====

type TrackedConn struct {
	net.Conn
	manager    *trafficManager
	info       *ConnInfo
	domainStat *domainStat // 可为 nil，直读写入时定位 sync.Map
	closeOnce  sync.Once
	closeErr   error
}

func (tc *TrackedConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	tc.recordRead(n)
	return n, err
}

func (tc *TrackedConn) recordRead(n int) {
	if n > 0 {
		tc.manager.RxTotal.Add(uint64(n)) // 计入 downlink
		tc.info.ReadBytes.Add(uint64(n))  // 计入 downlink
		if tc.domainStat != nil {
			tc.domainStat.currentRxBytes.Add(uint64(n))
		}
	}
}

func (tc *TrackedConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	tc.recordWrite(n)
	return n, err
}

func (tc *TrackedConn) recordWrite(n int) {
	if n > 0 {
		tc.manager.TxTotal.Add(uint64(n)) // 计入 uplink
		tc.info.WriteBytes.Add(uint64(n)) // 计入 uplink
		if tc.domainStat != nil {
			tc.domainStat.currentTxBytes.Add(uint64(n))
		}
	}
}

func (tc *TrackedConn) CloseWrite() error {
	if c, ok := tc.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return fmt.Errorf("connection does not support half-close")
}

func (tc *TrackedConn) Close() error {
	tc.closeOnce.Do(func() {
		if countsTowardActiveTotal(tc.info.Protocol) {
			tc.manager.ActiveConns.Add(-1)
		}
		tc.manager.bumpProtocol(tc.info.Protocol, -1)
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
		tc.manager.RxTotal.Add(uint64(n))
		tc.info.ReadBytes.Add(uint64(n))
	}
	return n, addr, err
}

func (tc *TrackedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = tc.PacketConn.WriteTo(p, addr)
	if n > 0 {
		tc.manager.TxTotal.Add(uint64(n))
		tc.info.WriteBytes.Add(uint64(n))
	}
	return n, err
}

func (tc *TrackedPacketConn) Close() error {
	tc.closeOnce.Do(func() {
		if countsTowardActiveTotal(tc.info.Protocol) {
			tc.manager.ActiveConns.Add(-1)
		}
		tc.manager.bumpProtocol(tc.info.Protocol, -1)
		tc.manager.activeMap.Delete(tc.info.ID)
		tc.closeErr = tc.PacketConn.Close()
	})
	return tc.closeErr
}

// ===== 包装入口 =====

// countsTowardActiveTotal 判定某类连接是否计入 ActiveConns（UI 的「活跃连接数」）。
//
// ActiveConns 的语义是**隧道负载**，所以 udp-direct 被排除：它是「被 tproxy 劫持进来、
// 判定为直连、再由本机原样转发」的会话，从头到尾不过隧道 —— 局域网发现、mDNS、
// DLNA/投屏、私有段 NAS 全属此类。旁路表拿掉 RFC1918 之后（c509a97）这批流量会
// 重新进分流判定，于是在 tproxy 模式下被放大几十倍：把它们算进「连接数」，数字就
// 与隧道实际负载彻底脱钩，排查"为什么 tproxy 是 VPN 的 N 倍"时会被彻底带偏。
//
// 它们仍进 activeMap（UI 连接列表可见、带 udp-direct 标记）并照常统计流量，
// 只是不顶那个总数。
func countsTowardActiveTotal(kind string) bool {
	return kind != "udp-direct"
}

// protocolOfTarget 推断一条被包装连接的类别，供不便显式传参的调用点使用。
//
// 只看目标串的形态：走 UDPGW 的会话一律以 `UDPGW->` 前缀包装（见 socks5.go），
// 所以这个前缀就是代理 UDP 的可靠标记。其余按 TCP 计。
// 不要试图从地址本身推断协议 —— 同一个域名既能走 TCP(DoH) 也能走 UDP(DoT)，
// 而 QUIC 用的还是 UDP 443，地址和 TCP 443 完全一样。
//
// ⚠️ 它**分辨不出** udp-direct：直连 UDP 会话的目标串就是一个普通的 host:port，
// 与 TCP 毫无区别。所以直连分支必须走 WrapConnKind 显式声明，别指望这里兜住。
func protocolOfTarget(targetAddr string) string {
	if strings.HasPrefix(targetAddr, "UDPGW->") {
		return "udp-proxy"
	}
	return "tcp"
}

// WrapConnKind 包装连接并**显式**声明类别，纳入流量统计。
//
// kind 取 "tcp" / "udp-proxy" / "udp-direct" / "dns"。凡是调用方自己清楚类别的
// 一律走这里 —— 类别一旦判错，连接数归因就是反向的，比没有分类更糟。
func WrapConnKind(conn net.Conn, targetAddr string, kind string) net.Conn {
	return wrapConnAs(conn, targetAddr, kind)
}

// WrapConn 包装连接并按目标串推断类别，纳入流量统计。
func WrapConn(conn net.Conn, targetAddr string) net.Conn {
	return wrapConnAs(conn, targetAddr, protocolOfTarget(targetAddr))
}

func wrapConnAs(conn net.Conn, targetAddr string, kind string) net.Conn {
	globalTrafficManager.TotalConns.Add(1)
	if countsTowardActiveTotal(kind) {
		globalTrafficManager.ActiveConns.Add(1)
	}
	id := globalTrafficManager.connIDCounter.Add(1)

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
		Protocol:   kind,
	}
	globalTrafficManager.activeMap.Store(id, info)
	globalTrafficManager.bumpProtocol(kind, 1)

	// 按目标域名聚合活跃度，未解析出域名则不参与排行。
	// 域名条目在 Read/Write 中只做原子累加，命中 sync.Map 即可。
	var stat *domainStat
	if host != "" {
		val, _ := globalDomainStatsManager.stats.LoadOrStore(host, &domainStat{})
		stat = val.(*domainStat)
		stat.lastActiveUnix.Store(time.Now().Unix())
	}

	return &TrackedConn{
		Conn:       conn,
		manager:    globalTrafficManager,
		info:       info,
		domainStat: stat,
	}
}

// WrapPacketConn 包装 UDP 连接，纳入流量统计。
func WrapPacketConn(conn net.PacketConn, sessionName string) net.PacketConn {
	globalTrafficManager.TotalConns.Add(1)
	globalTrafficManager.ActiveConns.Add(1)
	id := globalTrafficManager.connIDCounter.Add(1)

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
		Protocol:   "udp-proxy", // WrapPacketConn 只用于 UDP（net.PacketConn 语义即数据报）
	}
	globalTrafficManager.activeMap.Store(id, info)
	globalTrafficManager.bumpProtocol("udp", 1)

	return &TrackedPacketConn{
		PacketConn: conn,
		manager:    globalTrafficManager,
		info:       info,
	}
}

// ===== GoMobile 宿主回调与导出 API =====

var (
	trafficCb  TrafficCallback
	sysInfoCb  SysInfoCallback
	callbackMu sync.RWMutex
	cpuStatsMu sync.Mutex
)

// TrafficStats 流量统计快照（导出）。
type TrafficStats struct {
	UdpQueueDrops int64
	TxRate        int64
	RxRate        int64
	TxTotal       int64
	RxTotal       int64
	ActiveConns   int64
	TotalConns    int64
}

// SysStats 系统资源快照。
type SysStats struct {
	CpuPercent float64
	MemAllocMB float64
	MemSysMB   float64
	Goroutines int
}

// TrafficCallback GoMobile 流量回调（含 activeConns, totalConns）。
type TrafficCallback interface {
	OnTrafficUpdate(txRate int64, rxRate int64, txTotal int64, rxTotal int64, activeConns int64, totalConns int64)
}

// SysInfoCallback GoMobile 系统信息回调。
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

// GetTrafficStats 返回流量统计快照。
func GetTrafficStats() *TrafficStats {
	return &TrafficStats{
		UdpQueueDrops: uint64ToInt64(udpQueueDrops.Load()),
		TxRate:        uint64ToInt64(currentTxRate.Load()),
		RxRate:        uint64ToInt64(currentRxRate.Load()),
		TxTotal:       uint64ToInt64(globalTrafficManager.TxTotal.Load()),
		RxTotal:       uint64ToInt64(globalTrafficManager.RxTotal.Load()),
		ActiveConns:   globalTrafficManager.ActiveConns.Load(),
		TotalConns:    globalTrafficManager.TotalConns.Load(),
	}
}

// GetSysStats 返回系统资源快照。
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

type connInfoExport struct {
	ID         int64     `json:"id"`
	TargetAddr string    `json:"target_addr"`
	TargetHost string    `json:"target_host"`
	ProxyAddr  string    `json:"proxy_addr"`
	StartTime  time.Time `json:"start_time"`
	ReadBytes  uint64    `json:"read_bytes"`
	WriteBytes uint64    `json:"write_bytes"`
}

// GetActiveConnectionsJSON 返回活跃连接列表的 JSON 字符串。
func GetActiveConnectionsJSON() string {
	var list []connInfoExport
	globalTrafficManager.activeMap.Range(func(key, value interface{}) bool {
		info, ok := value.(*ConnInfo)
		if !ok || info == nil {
			return true
		}
		list = append(list, connInfoExport{
			ID:         info.ID,
			TargetAddr: info.TargetAddr,
			TargetHost: info.TargetHost,
			ProxyAddr:  info.ProxyAddr,
			StartTime:  info.StartTime,
			ReadBytes:  info.ReadBytes.Load(),
			WriteBytes: info.WriteBytes.Load(),
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

// GetDomainActivityJSON 返回域名活跃度排行的 JSON 字符串。
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

// ResetDomainStatsAndCache 按宿主 (Android) 请求重置排行与路由缓存。
func ResetDomainStatsAndCache() {
	if gr := globalRouter.Load(); gr != nil {
		gr.ResetCacheAndStats()
	}
	globalDomainStatsManager.reset()
	zlog.Infof("%s [Stats] ♻️ Domain stats ranking and route cache have been reset per UI request", TAG)
}

// RouterStats 路由统计快照。
type RouterStats struct {
	QueryCount    int64
	CacheHitCount int64
	HitRate       float64
}

// GetRouterStats 返回路由查询统计（Android）。
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

// ===== CPU 占用采样 =====

var (
	lastUtime float64
	lastStime float64
	lastTime  time.Time
)

func getCpuPercent() float64 {
	// 仅 Linux/Android 支持 /proc/self/stat；其它平台恒返回 0，由调用方降级。
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return 0.0
	}
	cpuStatsMu.Lock()
	defer cpuStatsMu.Unlock()

	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0.0
	}
	// /proc/self/stat 的第 2 个字段 comm 是带括号的进程名，可能包含空格；
	// 不能按空白切分全部字段，应先定位右括号再解析后续字段。
	// 右括号之后依次为 state(3), ppid(4), ..., utime(14), stime(15)。
	rparen := bytes.LastIndexByte(data, ')')
	if rparen < 0 {
		return 0.0
	}
	fields := bytes.Fields(data[rparen+1:])
	// rest[0] 对应第 3 个字段，utime 是第 14 个 => rest[11]，stime => rest[12]。
	if len(fields) < 13 {
		return 0.0
	}
	utime, _ := strconv.ParseFloat(string(fields[11]), 64)
	stime, _ := strconv.ParseFloat(string(fields[12]), 64)

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

// init 每秒采样一次流量增量并回调宿主。
func init() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		lastSampleTime := time.Now()
		for range ticker.C {
			now := time.Now()
			elapsed := now.Sub(lastSampleTime)
			lastSampleTime = now

			// 采样计数
			tTx := globalTrafficManager.TxTotal.Load()
			tRx := globalTrafficManager.RxTotal.Load()
			actConns := globalTrafficManager.ActiveConns.Load()
			totConns := globalTrafficManager.TotalConns.Load()

			// 取出上次采样值
			lTx := lastTxTotal.Swap(tTx)
			lRx := lastRxTotal.Swap(tRx)

			// 换算 1 秒速率
			txRate := bytesPerSecond(trafficDelta(tTx, lTx), elapsed)
			rxRate := bytesPerSecond(trafficDelta(tRx, lRx), elapsed)

			// 存储速率
			currentTxRate.Store(txRate)
			currentRxRate.Store(rxRate)

			globalDomainStatsManager.calculateAndRank(elapsed)

			// 每 30 秒把「活跃连接数」按协议拆开打一次。
			// 排查"tproxy 模式的连接数是 VPN 的 N 倍"时，总数本身没有归因能力 ——
			// TCP 短连接风暴与 UDP 会话堆积是两件完全不同的事，修法也不相干。
			// 只在连接数非零时打，避免静默期刷屏。
			if actConns > 0 && now.Unix()%30 == 0 {
				zlog.Infof(
					"%s [ConnStats] active=%d (tcp=%d udp-proxy=%d udp-direct=%d dns=%d) total=%d tx=%d rx=%d",
					TAG, actConns,
					globalTrafficManager.ActiveTcp.Load(),
					globalTrafficManager.ActiveUdpProxy.Load(),
					globalTrafficManager.ActiveUdpDirect.Load(),
					globalTrafficManager.ActiveDns.Load(),
					totConns, txRate, rxRate,
				)
			}

			// 回调 Android 宿主
			// 读取回调指针必须与写入方同样持锁，否则构成 data race。
			callbackMu.RLock()
			tcb := trafficCb
			scb := sysInfoCb
			callbackMu.RUnlock()
			if tcb != nil {
				tcb.OnTrafficUpdate(int64(txRate), int64(rxRate), int64(tTx), int64(tRx), actConns, totConns)
			}
			if scb != nil {
				sys := GetSysStats()
				scb.OnSysInfoUpdate(sys.CpuPercent, sys.MemAllocMB, sys.MemSysMB, sys.Goroutines)
			}
		}
	}()
}
