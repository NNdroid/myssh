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
	protectReqCount uint64 // 用于追踪请求的唯一 ID
)

// RegisterProtector 线程安全地注册 Protector
func RegisterProtector(p SocketProtector) {
	protectorMutex.Lock()
	defer protectorMutex.Unlock()
	globalProtector = p
	zlog.Infof("[Protect-Init] ✅ SocketProtector registered (Go layer)")
}

// getProtector 线程安全地获取 Protector
func getProtector() SocketProtector {
	protectorMutex.RLock()
	defer protectorMutex.RUnlock()
	return globalProtector
}

// wrapAndroidProtect 复制并返回一个具有 protect 能力的新 Dialer
// 避免就地修改 Dialer 引发并发竞争
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("%s [Dialer] 🛡️ Applying VpnService protection mechanism...", TAG)
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	// 浅拷贝一份 Dialer，确保并发安全
	clonedDialer := *dialer
	originalControl := clonedDialer.Control

	zlog.Debugf("[Protect-Wrap] 🔍 Wrapping Dialer... (Control=%v)", originalControl != nil)

	clonedDialer.Control = func(network, address string, c syscall.RawConn) error {
		reqID := atomic.AddUint64(&protectReqCount, 1)

		zlog.Debugf("[Protect-%d] ➡️ Intercepted socket creation request: network=%s, address=%s", reqID, network, address)

		var protectErr error

		err := c.Control(func(fd uintptr) {
			zlog.Debugf("[Protect-%d] 🎯 Successfully obtained Socket FD: %d", reqID, fd)

			protector := getProtector()
			if protector != nil {
				zlog.Debugf("[Protect-%d] ⏳ Calling Java layer ProtectSocket(fd=%d)...", reqID, fd)

				// 注意：底层 ProtectSocket 必须处理 JNI 线程 Attach 逻辑！
				success := protector.ProtectSocket(int32(fd))
				if !success {
					zlog.Errorf("[Protect-%d] ❌ Failed: ProtectSocket(fd=%d) returned false", reqID, fd)
					protectErr = fmt.Errorf("failed to protect socket fd: %d, network: %s, address: %s", fd, network, address)
				} else {
					zlog.Debugf("[Protect-%d] ✅ Success: ProtectSocket(fd=%d) protected", reqID, fd)
				}
			} else {
				zlog.Errorf("[Protect-%d] ⚠️ Severe Warning: getProtector() returned nil! VPN is not initialized, which will cause a traffic infinite loop!", reqID)
			}
		})

		// 优先返回 protect 阶段的错误
		if protectErr != nil {
			zlog.Errorf("[Protect-%d] ❌ Control internal Protect error exit: %v", reqID, protectErr)
			return protectErr
		}
		if err != nil {
			zlog.Errorf("[Protect-%d] ❌ Failed to get Socket FD (c.Control error): %v", reqID, err)
			return err
		}

		// 链式调用原始的 Control（如果有）
		if originalControl != nil {
			zlog.Debugf("[Protect-%d] 🔗 Chaining call to original dialer.Control...", reqID)
			origErr := originalControl(network, address, c)
			if origErr != nil {
				zlog.Errorf("[Protect-%d] ❌ Original dialer.Control execution error: %v", reqID, origErr)
			}
			return origErr
		}

		zlog.Debugf("[Protect-%d] 🏁 Current Socket processing flow completed", reqID)
		return nil
	}

	return &clonedDialer
}

// bindDevice 尝试将 Dialer 绑定到指定的网卡接口。
// 在 Android 平台上，普通应用没有 CAP_NET_RAW 权限，无法直接使用 SO_BINDTODEVICE。
// Android 的底层套接字保护和路由需要依赖 Java 层的 VpnService.protect() (已由 wrapAndroidProtect 处理)。
// 因此这里作为一个安全的降级存根 (Stub)。
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName != "" {
		zlog.Warnf("%s [Tunnel] ⚠️ Android does not support SO_BINDTODEVICE without root. Ignoring bind request to: %s", TAG, ifaceName)
	}
}
