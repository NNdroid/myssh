package myssh

// SshTProxy  info 。
//
//	info ： info （ info  socksServer/sshClient/engineCancel  info ），
//	info  SshTProxy  info ；NewSshTProxy  info 。
//	info “ info ” info  Android  info 、 info ，
//	info 。 info tunnel，
//	info （ info ， info ）。
type SshTProxy struct{}

// NewSshTProxy  info 。
func NewSshTProxy() *SshTProxy {
	return &SshTProxy{}
}

// SetEngineCallback  info （ info  registerEngineCallback）。
func (p *SshTProxy) SetEngineCallback(cb EngineCallback) {
	registerEngineCallback(cb)
}

// Start  info ， info  ProxyConfig  info  JSON。 info ：0 successfully，<0 failed info 。
func (p *SshTProxy) Start(configJson string) int {
	return startSshTProxy(configJson)
}

// Stop  info cleanup info 。
func (p *SshTProxy) Stop() {
	stopSshTProxy()
}

// LoadGlobalConfig  info config（DNS/Geo  info ）， info  GlobalConfig  info  JSON。
func (p *SshTProxy) LoadGlobalConfig(configJson string) int {
	return loadGlobalConfigFromJson(configJson)
}

// PingNodes  info ， info  JSON  info （ info  PingResult）。
func (p *SshTProxy) PingNodes(profilesJson, targetUrl string, timeoutMs int) string {
	return pingNodes(profilesJson, targetUrl, timeoutMs)
}

// WgWait  info  goroutine  info （ info  Android  info ）。
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
