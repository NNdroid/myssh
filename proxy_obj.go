package myssh

// SshTProxy 是面向 gomobile 的导出门面。
//
//	注意：所有引擎状态（socksServer/sshClient/engineCancel 等包级变量）
//	都是全局共享的；SshTProxy 自身不持有状态，NewSshTProxy 每次返回等价
//	的空壳实例。Android 侧重复创建多个实例、跨实例调用均安全。
//	所有 tunnel 的注册表也挂在包级，重复 Start 前会先隐式 Stop。
type SshTProxy struct{}

// NewSshTProxy 创建门面实例。
func NewSshTProxy() *SshTProxy {
	return &SshTProxy{}
}

// SetEngineCallback 注册引擎状态回调（内部转 registerEngineCallback）。
func (p *SshTProxy) SetEngineCallback(cb EngineCallback) {
	registerEngineCallback(cb)
}

// Start 启动代理引擎，入参为 ProxyConfig 对应的 JSON。返回值：0 成功，<0 失败码。
func (p *SshTProxy) Start(configJson string) int {
	return startSshTProxy(configJson)
}

// Stop 停止引擎并执行 cleanup 清理。
func (p *SshTProxy) Stop() {
	stopSshTProxy()
}

// LoadGlobalConfig 加载全局配置（DNS/Geo 分流），入参为 GlobalConfig 对应的 JSON。
func (p *SshTProxy) LoadGlobalConfig(configJson string) int {
	return loadGlobalConfigFromJson(configJson)
}

// WaitIPv6Egress waits for the current SSH exit capability probe.
// Return values: 1 = IPv6 available, 0 = IPv4-only, -1 = unknown/timeout.
func (p *SshTProxy) WaitIPv6Egress(timeoutMs int) int {
	return waitIPv6EgressMs(timeoutMs)
}

// RegisterSocketMarkHelper 告诉引擎到哪去找 root 侧的 `sockmark` 辅助进程，以及
// 给隧道 socket 打什么 SO_MARK。
//
// 必须在 Start 之前调用 —— Start 会立刻拨 SSH，socket 一建出来首个 SYN 就发出去，
// 届时若 mark 通路还没就绪，SSH 连接会被 tproxy 自己的 TPROXY 抓回本地 socks5。
//
// appPID 传 0 表示由 Go 侧 os.Getpid() 自取。exePath 为空或 mark 为 0 时禁用
// mark 通路（此时 tproxy 侧会回落到按 uid 放行整个 App 的旧策略）。
//
// ⚠️ 参数用 int64 而非 int：gomobile 把 Go 整数映射成 Java `long`（恒 64 位），
// `int` 在 32 位 ABI 上经 JNI 传参会截断。
func (p *SshTProxy) RegisterSocketMarkHelper(exePath string, appPID int64, mark int64) {
	RegisterSocketMarkHelper(exePath, appPID, mark)
}

// ProbeSocketMark 实际跑一次 mark 通路，确认「App 能借到自己的 fd、root 能成功设上 mark」。
//
// 必须在 [SshTProxy.RegisterSocketMarkHelper] 之后、Start 之前调用。
// 返回 1 = 通路可用，规则侧可以走 mark 放行；返回 0 = 不可用，调用方**必须**回落到
// uid 放行（把整个 App 加进 BYPASS_APPS_LIST）—— 代价只是 App 内流量全直连，
// 而不回落会导致隧道 socket 既没 mark 又不在旁路列表，直接落进 TPROXY 死循环。
func (p *SshTProxy) ProbeSocketMark() int64 {
	return ProbeSocketMark()
}

// GetIPv6EgressState returns available, unavailable, or unknown.
func (p *SshTProxy) GetIPv6EgressState() string {
	return ipv6EgressStateName()
}

// PingNodes 批量测延迟，返回 JSON 数组（元素结构见 PingResult）。
func (p *SshTProxy) PingNodes(profilesJson, targetUrl string, timeoutMs int) string {
	return pingNodes(profilesJson, targetUrl, timeoutMs)
}

// SpeedTest 执行上下行吞吐测速（返回 JSON，结构见 SpeedTestResult）：
// 入参 configJson 为 ProxyConfig 对应的 JSON（语义同 pingNodes 的入参），
// downUrl/upUrl 为 Cloudflare speed 测速端点。
func (p *SshTProxy) SpeedTest(configJson, downUrl, upUrl string, upBytes int64, timeoutMs int) string {
	return speedTest(configJson, downUrl, upUrl, upBytes, timeoutMs)
}

// SpeedTestWithProgress exposes directional progress from the test's own SSH connection.
func (p *SshTProxy) SpeedTestWithProgress(configJson, downUrl, upUrl string, upBytes int64, timeoutMs int, cb SpeedTestProgressCallback) string {
	return speedTestWithProgress(configJson, downUrl, upUrl, upBytes, timeoutMs, cb)
}

// WgWait 等待所有后台 goroutine 退出（供 Android 优雅退出时调用）。
func (p *SshTProxy) WgWait() {
	wgWait()
}

// InitCrashOutput redirects fatal runtime crashes to logPath.
// Returns 0 on success, -1 when the crash file cannot be opened.
func (p *SshTProxy) InitCrashOutput(logPath string) int {
	if err := InitCrashOutput(logPath); err != nil {
		return -1
	}
	return 0
}

// TriggerTestCrash triggers a simulated panic in a protected goroutine for testing UI popup.
func (p *SshTProxy) TriggerTestCrash(tag string) {
	SafeGo(tag, func() {
		panic("simulated test panic in Go engine core")
	})
}

// SetLogLevel updates the engine log level dynamically in real-time.
func (p *SshTProxy) SetLogLevel(levelStr string) {
	SetLogLevel(levelStr)
}

// GetSSHHandshakeInfo 返回 addr 最近一次真实 SSH 握手的 JSON（{address, client_version,
// server_version, banner, updated_at}）。addr 无记录时回退到最近一次握手；全无记录返回空串。
// server_version 为 RFC 4253 版本标识行，banner 为认证阶段服务端提示文本（可能为空）。
func (p *SshTProxy) GetSSHHandshakeInfo(addr string) string {
	return getSSHHandshakeInfoJSON(addr)
}

// ─── 状态 / 生命周期 ────────────────────────────────────────────────────────

// GetState returns the last engine state as JSON:
// {"state":"connected","detail":"host:port"}. Unlike the callback, this is safe
// to call at any time — e.g. after an Activity re-registers its callback.
func (p *SshTProxy) GetState() string {
	return engineStateJSON()
}

// IsRunning reports whether the engine is starting, connecting, connected, or
// reconnecting.
func (p *SshTProxy) IsRunning() bool {
	return engineIsRunning()
}

// GetLastError returns {"code":..,"message":..} for the most recent failure, or
// "" when the current start cycle has no error. Use it after Start returns a
// negative code to recover the reason even if no callback was registered yet.
func (p *SshTProxy) GetLastError() string {
	return engineLastErrorJSON()
}

// NotifyNetworkChanged forces an immediate reconnect after the underlying
// Android network changed (Wi-Fi ↔ cellular). Without it the engine only
// notices a dead link on the next keepalive (18s tick + 8s timeout).
func (p *SshTProxy) NotifyNetworkChanged() {
	notifyNetworkChanged()
}

// ClearEngineCallback releases the host callback reference. Call it from
// Activity.onDestroy to avoid leaking an Activity-scoped callback.
func (p *SshTProxy) ClearEngineCallback() {
	clearEngineCallback()
}

// StartResultCallback receives the result of StartAsync.
type StartResultCallback interface {
	OnStartResult(code int, errorJson string)
}

// StartAsync runs Start on a background goroutine so the caller (typically the
// Android main thread) is not blocked by teardown of a previous engine.
func (p *SshTProxy) StartAsync(configJson string, cb StartResultCallback) {
	if cb == nil {
		return
	}
	SafeGo("StartAsync", func() {
		code := startSshTProxy(configJson)
		cb.OnStartResult(code, engineLastErrorJSON())
	})
}

// StopAsync runs Stop on a background goroutine.
func (p *SshTProxy) StopAsync() {
	SafeGo("StopAsync", stopSshTProxy)
}

// ─── 异步探测（阻塞调用不适合 Android 主线程）──────────────────────────────

// PingResultCallback receives the JSON array returned by PingNodes.
type PingResultCallback interface {
	OnPingResult(resultsJson string)
}

// SpeedTestResultCallback receives the JSON object returned by SpeedTest.
type SpeedTestResultCallback interface {
	OnSpeedTestResult(resultJson string)
}

// PingNodesAsync 在后台执行批量测延迟；返回 1 表示已开始，0 表示参数无效。
// 结果始终通过 cb 投递，不会阻塞调用线程。
func (p *SshTProxy) PingNodesAsync(profilesJson, targetUrl string, timeoutMs int, cb PingResultCallback) int {
	if cb == nil {
		return 0
	}
	SafeGo("PingNodesAsync", func() {
		cb.OnPingResult(pingNodes(profilesJson, targetUrl, timeoutMs))
	})
	return 1
}

// SpeedTestAsync 在后台执行上下行测速；返回 1 表示已开始，0 表示参数无效。
func (p *SshTProxy) SpeedTestAsync(configJson, downUrl, upUrl string, upBytes int64, timeoutMs int, cb SpeedTestResultCallback) int {
	if cb == nil {
		return 0
	}
	SafeGo("SpeedTestAsync", func() {
		cb.OnSpeedTestResult(speedTest(configJson, downUrl, upUrl, upBytes, timeoutMs))
	})
	return 1
}

// CancelPing cancels the batch started by PingNodes/PingNodesAsync.
func (p *SshTProxy) CancelPing() {
	CancelPing()
}

// ─── 统计 ──────────────────────────────────────────────────────────────────

// GetTrafficStats returns the current traffic snapshot.
func (p *SshTProxy) GetTrafficStats() *TrafficStats {
	return GetTrafficStats()
}

// GetSysStats returns the current process resource snapshot.
func (p *SshTProxy) GetSysStats() *SysStats {
	return GetSysStats()
}

// GetActiveConnectionsJSON returns the active connection list as JSON.
func (p *SshTProxy) GetActiveConnectionsJSON() string {
	return GetActiveConnectionsJSON()
}

// GetDomainActivityJSON returns the per-domain activity ranking as JSON.
func (p *SshTProxy) GetDomainActivityJSON() string {
	return GetDomainActivityJSON()
}

// RegisterTrafficCallback installs the 1 Hz traffic callback.
func (p *SshTProxy) RegisterTrafficCallback(cb TrafficCallback) {
	RegisterTrafficCallback(cb)
}

// RegisterSysInfoCallback installs the resource callback (sampled every 5s).
func (p *SshTProxy) RegisterSysInfoCallback(cb SysInfoCallback) {
	RegisterSysInfoCallback(cb)
}

// ClearTrafficCallback releases the traffic callback reference.
func (p *SshTProxy) ClearTrafficCallback() {
	RegisterTrafficCallback(nil)
}

// ClearSysInfoCallback releases the sysinfo callback reference.
func (p *SshTProxy) ClearSysInfoCallback() {
	RegisterSysInfoCallback(nil)
}

// GetDroppedEventCount reports callback events dropped because the host could
// not keep up (the dispatch queue is bounded at 512).
func (p *SshTProxy) GetDroppedEventCount() int64 {
	return engineEventsDroppedCount()
}

// ─── 诊断 ──────────────────────────────────────────────────────────────────

// GetGeoSiteTagsJSON returns the GeoSite tag list as JSON.
func (p *SshTProxy) GetGeoSiteTagsJSON() string {
	return GetGeoSiteTagsJSON()
}

// GetGeoIPTagsJSON returns the GeoIP tag list as JSON.
func (p *SshTProxy) GetGeoIPTagsJSON() string {
	return GetGeoIPTagsJSON()
}

// FetchCertInfo probes the target's certificate (TLS or QUIC).
func (p *SshTProxy) FetchCertInfo(target string, useQUIC bool, serverName string, bindInterface string) (*CertInfo, error) {
	return FetchCertInfo(target, useQUIC, serverName, bindInterface)
}

// GetTLSCertFingerprint returns the leaf certificate SHA-256 fingerprint.
func (p *SshTProxy) GetTLSCertFingerprint(target string, serverName string, bindInterface string) (string, error) {
	return GetTLSCertFingerprint(target, serverName, bindInterface)
}

// GetSSHFingerprint returns the SSH host key SHA-256 fingerprint.
func (p *SshTProxy) GetSSHFingerprint(sshAddr string, bindInterface string) (string, error) {
	return GetSSHFingerprint(sshAddr, bindInterface)
}
