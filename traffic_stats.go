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
	"sync"
	"sync/atomic"
	"time"
)

// 本文件实现流量统计与连接追踪：TrackedConn/TrackedPacketConn 包装层、
// 全局限速采样、域名活跃度排行，以及暴露给 GoMobile 宿主的回调与 JSON API。

// ConnInfo 单条连接的实时统计（以 json 导出给 Android UI）。
type ConnInfo struct {
	ReadBytes  atomic.Uint64 `json:"read_bytes"`
	WriteBytes atomic.Uint64 `json:"write_bytes"`
	ID         int64         `json:"id"`
	TargetAddr string        `json:"target_addr"`
	TargetHost string        `json:"target_host"`
	ProxyAddr  string        `json:"proxy_addr"`
	StartTime  time.Time     `json:"start_time"`
}

func (c *ConnInfo) String() string {
	duration := time.Since(c.StartTime).Round(time.Second)
	return fmt.Sprintf("[ID:%d] Target:%s | Uptime:%s | ↑%d B | ↓%d B",
		c.ID, c.TargetAddr, duration, c.WriteBytes.Load(), c.ReadBytes.Load())
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
	TxTotal       atomic.Uint64 // 累计上行字节数
	RxTotal       atomic.Uint64 // 累计下行字节数
	ActiveConns   atomic.Int64  // 活跃连接数
	TotalConns    atomic.Int64  // 历史连接总数
	connIDCounter atomic.Int64  // 连接 ID 发生器
	activeMap     sync.Map      // key: int64 (连接 ID), value: *ConnInfo
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
	if n > 0 {
		tc.manager.RxTotal.Add(uint64(n)) // 计入 downlink
		tc.info.ReadBytes.Add(uint64(n))  // 计入 downlink
		if tc.domainStat != nil {
			tc.domainStat.currentRxBytes.Add(uint64(n))
		}
	}
	return n, err
}

func (tc *TrackedConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	if n > 0 {
		tc.manager.TxTotal.Add(uint64(n)) // 计入 uplink
		tc.info.WriteBytes.Add(uint64(n)) // 计入 uplink
		if tc.domainStat != nil {
			tc.domainStat.currentTxBytes.Add(uint64(n))
		}
	}
	return n, err
}

func (tc *TrackedConn) Close() error {
	tc.closeOnce.Do(func() {
		tc.manager.ActiveConns.Add(-1)
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
		tc.manager.ActiveConns.Add(-1)
		tc.manager.activeMap.Delete(tc.info.ID)
		tc.closeErr = tc.PacketConn.Close()
	})
	return tc.closeErr
}

// ===== 包装入口 =====

// WrapConn 包装 TCP 连接，纳入流量统计。
func WrapConn(conn net.Conn, targetAddr string) net.Conn {
	globalTrafficManager.TotalConns.Add(1)
	globalTrafficManager.ActiveConns.Add(1)
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
	}
	globalTrafficManager.activeMap.Store(id, info)

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
	}
	globalTrafficManager.activeMap.Store(id, info)

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
	TxRate      int64
	RxRate      int64
	TxTotal     int64
	RxTotal     int64
	ActiveConns int64
	TotalConns  int64
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
		TxRate:      uint64ToInt64(currentTxRate.Load()),
		RxRate:      uint64ToInt64(currentRxRate.Load()),
		TxTotal:     uint64ToInt64(globalTrafficManager.TxTotal.Load()),
		RxTotal:     uint64ToInt64(globalTrafficManager.RxTotal.Load()),
		ActiveConns: globalTrafficManager.ActiveConns.Load(),
		TotalConns:  globalTrafficManager.TotalConns.Load(),
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
