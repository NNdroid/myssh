//go:build android

package myssh

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type SocketProtector interface {
	ProtectSocket(fd int32) bool
}

var (
	globalProtector SocketProtector
	protectorMutex  sync.RWMutex
	protectReqCount atomic.Uint64 // 保护请求自增 ID
)

// RegisterProtector 注册宿主实现的 Protector
func RegisterProtector(p SocketProtector) {
	protectorMutex.Lock()
	defer protectorMutex.Unlock()
	globalProtector = p
	zlog.Infof("[Protect-Init] ✅ SocketProtector registered (Go layer)")
}

// clearProtector 释放宿主引用（Activity.onDestroy 时调用）。
func clearProtector() {
	protectorMutex.Lock()
	globalProtector = nil
	protectorMutex.Unlock()
}

// getProtector 读取当前已注册的 Protector
func getProtector() SocketProtector {
	protectorMutex.RLock()
	defer protectorMutex.RUnlock()
	return globalProtector
}

// protectorNilLogInterval 是「Protector 未注册」告警的最小间隔。
const protectorNilLogInterval = 10 * time.Second

var (
	protectorNilLogAt atomic.Int64  // 上次告警的 unix nano，用于无锁限流
	protectorNilCount atomic.Uint64 // 累计未受保护的 socket 数，附在告警里给宿主看
)

// logProtectorNil 限流记录「Protector 未注册」。
// 该分支在每个新建连接上都会命中，直接打日志会在满速建连时刷爆日志缓冲。
func logProtectorNil(fd uintptr) {
	total := protectorNilCount.Add(1)
	now := time.Now().UnixNano()
	last := protectorNilLogAt.Load()
	if now-last < int64(protectorNilLogInterval) {
		return
	}
	if !protectorNilLogAt.CompareAndSwap(last, now) {
		return
	}
	zlog.Errorf("[Protect] ⚠️ SocketProtector is not registered; socket fd=%d left unprotected (VPN traffic may loop back, %d unprotected sockets so far)", fd, total)
}

// androidProtectControl 返回执行 VpnService 保护流程的 Control 回调。
//
//	挂到 Dialer 或 ListenConfig 的 Control 字段上，即可在拿到 fd 后立即保护。
func androidProtectControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		reqID := protectReqCount.Add(1)

		zlog.Debugf("[Protect-%d] ➡️ Intercepted socket creation request: network=%s, address=%s", reqID, network, address)

		var protectErr error

		err := c.Control(func(fd uintptr) {
			zlog.Debugf("[Protect-%d] 🎯 Successfully obtained Socket FD: %d", reqID, fd)

			protector := getProtector()
			if protector != nil {
				zlog.Debugf("[Protect-%d] ⏳ Calling Java layer ProtectSocket(fd=%d)...", reqID, fd)

				// 注意：本次调用会跨 JNI，完成 Attach 前会阻塞！
				success := protector.ProtectSocket(int32(fd))
				if !success {
					zlog.Errorf("[Protect-%d] ❌ Failed: ProtectSocket(fd=%d) returned false", reqID, fd)
					protectErr = fmt.Errorf("failed to protect socket fd: %d, network: %s, address: %s", fd, network, address)
				} else {
					zlog.Debugf("[Protect-%d] ✅ Success: ProtectSocket(fd=%d) protected", reqID, fd)
				}
			} else {
				// Protector 未注册时 socket 不会被 VpnService 豁免，隧道流量会被
				// 自己的 VPN 抓回来形成回环。每个连接都会走到这里，必须限流。
				logProtectorNil(fd)
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

// wrapAndroidProtect 给 Dialer 套上 protect 保护的包装层
//
//	返回克隆后的新 Dialer，原对象不被修改
func wrapAndroidProtect(dialer *net.Dialer) *net.Dialer {
	zlog.Debugf("%s [Dialer] 🛡️ Applying VpnService protection mechanism...", TAG)
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	// 克隆 Dialer，避免改动调用方持有的实例
	clonedDialer := *dialer
	originalControl := clonedDialer.Control

	zlog.Debugf("[Protect-Wrap] 🔍 Wrapping Dialer... (Control=%v)", originalControl != nil)

	clonedDialer.Control = func(network, address string, c syscall.RawConn) error {
		if err := androidProtectControl()(network, address, c); err != nil {
			return err
		}
		// 串联原 Control（若存在）
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

// bindDevice 是 Android 平台的网卡绑定存根 (Stub)。
//
//	Android 上非 root 无法拿到 CAP_NET_RAW，因此不支持 SO_BINDTODEVICE。
//
// 出站接口选择实际由 Java 层的 VpnService.protect() 完成（见 wrapAndroidProtect）。
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName != "" {
		zlog.Warnf("%s [Tunnel] ⚠️ Android does not support SO_BINDTODEVICE without root. Ignoring bind request to: %s", TAG, ifaceName)
	}
}

// icmpProtectFD 返回 ICMP 载体 socket 的 VpnService 豁免回调：
// 每个 ICMP socket 创建后、首包发出前调用，否则 Echo 流量会被自己的
// VPN 捕获形成回环。
func icmpProtectFD() func(fd int) error {
	return func(fd int) error {
		protector := getProtector()
		if protector == nil {
			// 与拨号路径一致：Protector 未注册时放行并留痕（存在回环风险）。
			zlog.Warnf("[Protect-ICMP] ⚠️ SocketProtector not registered; ICMP socket fd=%d left unprotected", fd)
			return nil
		}
		if !protector.ProtectSocket(int32(fd)) {
			return fmt.Errorf("failed to protect icmp socket fd: %d", fd)
		}
		return nil
	}
}
