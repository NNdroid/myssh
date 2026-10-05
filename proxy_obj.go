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
func (p *SshTProxy) InitCrashOutput(logPath string) {
	_ = InitCrashOutput(logPath)
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
