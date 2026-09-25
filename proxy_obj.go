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
