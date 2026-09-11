package kcptun

import (
	"time"

	"github.com/xtaci/smux"
)

// BuildSmuxConfig constructs a smux.Config from CLI parameters and verifies the
// result. Callers can log or wrap the returned error for better diagnostics.
func BuildSmuxConfig(version, maxReceiveBuffer, maxStreamBuffer, maxFrameSize, keepAliveSeconds int) (*smux.Config, error) {
	cfg := smux.DefaultConfig()
	cfg.Version = version
	cfg.MaxReceiveBuffer = maxReceiveBuffer
	cfg.MaxStreamBuffer = maxStreamBuffer
	cfg.MaxFrameSize = maxFrameSize
	cfg.KeepAliveInterval = time.Duration(keepAliveSeconds) * time.Second

	return cfg, smux.VerifyConfig(cfg)
}
