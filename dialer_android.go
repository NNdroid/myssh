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
	zlog.Infof("[Protect-Init] ✅ SocketProtector 已被注册 (Go 层)")
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
	zlog.Debugf("%s [Dialer] 🛡️ 正在应用 VpnService 保护机制...", TAG)
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	// 浅拷贝一份 Dialer，确保并发安全
	clonedDialer := *dialer
	originalControl := clonedDialer.Control

	zlog.Debugf("[Protect-Wrap] 🔍 正在包装 Dialer... (Control=%v)", originalControl != nil)

	clonedDialer.Control = func(network, address string, c syscall.RawConn) error {
		reqID := atomic.AddUint64(&protectReqCount, 1)

		zlog.Debugf("[Protect-%d] ➡️ 拦截到创建 Socket 请求: network=%s, address=%s", reqID, network, address)

		var protectErr error

		err := c.Control(func(fd uintptr) {
			zlog.Debugf("[Protect-%d] 🎯 成功拿到 Socket FD: %d", reqID, fd)

			protector := getProtector()
			if protector != nil {
				zlog.Debugf("[Protect-%d] ⏳ 正在调用 Java 层 ProtectSocket(fd=%d)...", reqID, fd)

				// 注意：底层 ProtectSocket 必须处理 JNI 线程 Attach 逻辑！
				success := protector.ProtectSocket(int32(fd))
				if !success {
					zlog.Errorf("[Protect-%d] ❌ 失败: ProtectSocket(fd=%d) 返回 false", reqID, fd)
					protectErr = fmt.Errorf("failed to protect socket fd: %d, network: %s, address: %s", fd, network, address)
				} else {
					zlog.Debugf("[Protect-%d] ✅ 成功: ProtectSocket(fd=%d) 保护完毕", reqID, fd)
				}
			} else {
				zlog.Errorf("[Protect-%d] ⚠️ 严重警告: getProtector() 返回 nil！VPN 未初始化，将导致流量死循环！", reqID)
			}
		})

		// 优先返回 protect 阶段的错误
		if protectErr != nil {
			zlog.Errorf("[Protect-%d] ❌ Control 内部 Protect 错误退出: %v", reqID, protectErr)
			return protectErr
		}
		if err != nil {
			zlog.Errorf("[Protect-%d] ❌ 获取 Socket FD 失败 (c.Control error): %v", reqID, err)
			return err
		}

		// 链式调用原始的 Control（如果有）
		if originalControl != nil {
			zlog.Debugf("[Protect-%d] 🔗 正在链式调用原始的 dialer.Control...", reqID)
			origErr := originalControl(network, address, c)
			if origErr != nil {
				zlog.Errorf("[Protect-%d] ❌ 原始 dialer.Control 执行报错: %v", reqID, origErr)
			}
			return origErr
		}

		zlog.Debugf("[Protect-%d] 🏁 当前 Socket 处理流程完毕", reqID)
		return nil
	}

	return &clonedDialer
}
