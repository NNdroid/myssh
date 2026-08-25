package myssh

// SshTProxy 是引擎的对象化句柄。
//
// 说明：底层引擎为单例（全局状态 socksServer/sshClient/engineCancel 等），
// 因此所有 SshTProxy 实例共享同一引擎；NewSshTProxy 返回的是该引擎的句柄。
// 这棵“对象化”主要是为了给 Android 一个类型安全、带回调的入口，
// 而不必再散落地调用一组过程式全局函数。若未来需要多实例并发隧道，
// 则需把全局状态搬进结构体（属长期演进，不在本次范围）。
type SshTProxy struct{}

// NewSshTProxy 创建引擎句柄。
func NewSshTProxy() *SshTProxy {
	return &SshTProxy{}
}

// SetEngineCallback 注册引擎事件回调（等价于 registerEngineCallback）。
func (p *SshTProxy) SetEngineCallback(cb EngineCallback) {
	registerEngineCallback(cb)
}

// Start 启动代理引擎，入参为 ProxyConfig 的 JSON。返回值：0 成功，<0 失败码。
func (p *SshTProxy) Start(configJson string) int {
	return startSshTProxy(configJson)
}

// Stop 停止代理引擎并清理所有连接。
func (p *SshTProxy) Stop() {
	stopSshTProxy()
}

// LoadGlobalConfig 载入全局配置（DNS/Geo 路由等），入参为 GlobalConfig 的 JSON。
func (p *SshTProxy) LoadGlobalConfig(configJson string) int {
	return loadGlobalConfigFromJson(configJson)
}

// PingNodes 测一组节点的真实访问延迟，返回结构化 JSON 数组（见 PingResult）。
func (p *SshTProxy) PingNodes(profilesJson, targetUrl string, timeoutMs int) string {
	return pingNodes(profilesJson, targetUrl, timeoutMs)
}

// WgWait 阻塞等待引擎所有 goroutine 退出（供 Android 主循环使用）。
func (p *SshTProxy) WgWait() {
	wgWait()
}
