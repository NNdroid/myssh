//go:build android

package myssh

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
)

type SocketProtector interface {
	ProtectSocket(fd int32) bool
}

var (
	globalProtector SocketProtector
	protectorMutex  sync.RWMutex
	protectReqCount uint64 //  info  ID
)

// RegisterProtector  info  Protector
func RegisterProtector(p SocketProtector) {
	protectorMutex.Lock()
	defer protectorMutex.Unlock()
	globalProtector = p
	zlog.Infof("[Protect-Init] ✅ SocketProtector registered (Go layer)")
}

// getProtector  info  Protector
func getProtector() SocketProtector {
	protectorMutex.RLock()
	defer protectorMutex.RUnlock()
	return globalProtector
}

// androidProtectControl  info  VpnService  info  info  info  Control  info 。
//
//	info  Dialer  info  ListenConfig 信息  info 信息 信息 ， info  info  fd 信息  info 。
func androidProtectControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		reqID := atomic.AddUint64(&protectReqCount, 1)

		zlog.Debugf("[Protect-%d] ➡️ Intercepted socket creation request: network=%s, address=%s", reqID, network, address)

		var protectErr error

		err := c.Control(func(fd uintptr) {
			zlog.Debugf("[Protect-%d] 🎯 Successfully obtained Socket FD: %d", reqID, fd)

			protector := getProtector()
			if protector != nil {
				zlog.Debugf("[Protect-%d] ⏳ Calling Java layer ProtectSocket(fd=%d)...", reqID, fd)

				//  info ： info  ProtectSocket  info  JNI  info  Attach  info ！
				success := protector.ProtectSocket(int32(fd))
				if !success {
					zlog.Errorf("[Protect-%d] ❌ Failed: ProtectSocket(fd=%d) returned false", reqID, fd)
					protectErr = fmt.Errorf("failed to protect socket fd: %d, network: %s, address: %s", fd, network, address)
				} else {
					zlog.Debugf("[Protect-%d] ✅ Success: ProtectSocket(fd=%d) protected", reqID, fd)
				}
			} else {
				//zlog.Errorf("[Protect-%d] ⚠️ Severe Warning: getProtector() returned nil! VPN is not initialized, which will cause a traffic infinite loop!", reqID)
			}
		})

		if protectErr != nil {
			zlog.Errorf("[Protect-%d] ❌ Control internal Protect error exit: %v", reqID, protectErr)
			return protectErr
		}
		if err != nil {
			zlog.Errorf("[Protect-%d] ❌ Failed to get Socket FD (c.Control error): %v", reqID, err)
			return err
		}

		zlog.Debugf("[Protect-%d] 🏁 Current Socket processing flow completed", reqID)
		return nil
	}
}

// wrapAndroidProtect  info  protect  info  Dialer
//
//	info  Dialer  info
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("%s [Dialer] 🛡️ Applying VpnService protection mechanism...", TAG)
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	//  info  Dialer， info
	clonedDialer := *dialer
	originalControl := clonedDialer.Control

	zlog.Debugf("[Protect-Wrap] 🔍 Wrapping Dialer... (Control=%v)", originalControl != nil)

	clonedDialer.Control = func(network, address string, c syscall.RawConn) error {
		if err := androidProtectControl()(network, address, c); err != nil {
			return err
		}
		//  info  Control（ info ）
		if originalControl != nil {
			zlog.Debugf("[Protect-Wrap] 🔗 Chaining call to original dialer.Control...")
			origErr := originalControl(network, address, c)
			if origErr != nil {
				zlog.Errorf("[Protect-Wrap] ❌ Original dialer.Control execution error: %v", origErr)
			}
			return origErr
		}
		return nil
	}

	return &clonedDialer
}

// bindDevice  info  Dialer  info 。
//
//	info  Android  info ， info  CAP_NET_RAW  info ， info  SO_BINDTODEVICE。
//
// Android  info  Java  info  VpnService.protect() ( info  wrapAndroidProtect  info )。
//
//	info  (Stub)。
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName != "" {
		zlog.Warnf("%s [Tunnel] ⚠️ Android does not support SO_BINDTODEVICE without root. Ignoring bind request to: %s", TAG, ifaceName)
	}
}
