//go:build android

package myssh

// Android-only facade methods. Keeping them in a build-tagged file lets the
// non-Android builds stay free of LogReceiver / SocketProtector types while the
// AAR still exposes one consistent SshTProxy entry point.

// SetLogReceiver registers the host log sink.
func (p *SshTProxy) SetLogReceiver(r LogReceiver) {
	SetLogReceiver(r)
}

// ClearLogReceiver releases the host log sink reference (Activity.onDestroy).
func (p *SshTProxy) ClearLogReceiver() {
	ClearLogReceiver()
}

// RegisterProtector registers the VpnService socket protector.
func (p *SshTProxy) RegisterProtector(prot SocketProtector) {
	RegisterProtector(prot)
}

// ClearProtector releases the protector reference.
func (p *SshTProxy) ClearProtector() {
	clearProtector()
}

// GetDroppedLogCount reports log lines dropped because the host receiver could
// not keep up with the 1000-entry buffer.
func (p *SshTProxy) GetDroppedLogCount() int64 {
	return logDroppedCount()
}
