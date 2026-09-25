package myssh

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

var (
	Version  = "dev"
	DebugStr = "false"
	Debug    = false
	// TCP 中转 io.CopyBuffer 使用的缓冲池，缓冲区 64KB+1KB
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64*1024+1024)
			return &buf
		},
	}
	// UDP 中转使用的大缓冲池，缓冲区 64KB+1KB（读满/写满）
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64*1024+1024)
			return &buf
		},
	}
	// 常规 MTU 的 UDP 小缓冲池（<=1500bytes 取 2KB），降低分配与 GC 压力
	udpSmallBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 2048)
			return &buf
		},
	}
	// 复用的 bytes.Buffer 池，减少临时分配
	bytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	// 填充数据池
	padPool    []byte
	padPoolLen = 64 * 1024
	// tcp: 逐连接套接字缓冲。
	// 原值 1MB（读+写各 1MB = 每连接 2MB 内核内存）在移动端 / 大量短连接下
	// 会显著放大内存占用，这里降到 256KB：仍足以覆盖高 BDP 长肥管道，
	// 同时把每连接内核内存压到 512KB。
	tcpOptimizeBufferSize   = 256 * 1024
	tcpKeepaliveIntervalSec = 15
)

func init() {
	if DebugStr == "true" {
		Debug = true
	}
	// 初始化填充池
	padPool = make([]byte, padPoolLen)
	// 填充数据仅用于流量混淆；crypto/rand 失败时退化的问题必须留痕便于排查
	// （init 阶段 zlog 尚未初始化，日志会进入 Nop，但保留检查使失败可被发现）。
	if _, err := io.ReadFull(rand.Reader, padPool); err != nil {
		zlog.Warnf("%s [Init] Failed to seed padding pool: %v", TAG, err)
	}
}

func tcpRelay(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr

	defer tcpBufPool.Put(bufPtr)

	// 中转基于 io.CopyBuffer，使用池化缓冲
	// 依赖 src 读到 EOF 时 CopyBuffer 自行结束
	return io.CopyBuffer(dst, src, buf)
}

// relayStream 双向中继一条 TCP 流：
//
//	Linux/Android 优先尝试 splice(2) 零拷贝；
//	对不支持 splice 的 Socket 类型，回退 tcpRelay 纯用户态拷贝。
func relayStream(dst, src net.Conn) (int64, error) {
	if n, err := trySplice(dst, src); err == nil {
		return n, nil
	}
	return tcpRelay(dst, src)
}

// formatSHA256Fingerprint 格式化 SHA-256 指纹为冒号分隔的大写十六进制 (XX:XX:XX:...)
func formatSHA256Fingerprint(raw []byte) string {
	sha256Sum := sha256.Sum256(raw)
	var fpBuilder strings.Builder
	for i, b := range sha256Sum {
		if i > 0 {
			fpBuilder.WriteString(":")
		}
		fmt.Fprintf(&fpBuilder, "%02X", b)
	}
	return fpBuilder.String()
}

// ensureHostPort 为无端口的地址补上默认端口
func ensureHostPort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// MakePeerCertVerifier 构造 TLS 证书指纹校验回调
func MakePeerCertVerifier(verifyFingerprint bool, expectedFingerprint string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificates presented by peer")
		}

		// 无条件先算出实际指纹，无论是否校验都输出日志，
		// 便于用户比对后补配 pin
		actualFingerprint := formatSHA256Fingerprint(rawCerts[0])

		// 输出实际指纹，供 TLS/QUIC 通道的 INFO 日志比对
		zlog.Debugf("%s [Tunnel] Actual certificate fingerprint: %s", TAG, actualFingerprint)

		if !verifyFingerprint {
			return nil // 未启用校验，直接放行
		}

		zlog.Infof("%s [Tunnel] Expected certificate fingerprint: %s", TAG, expectedFingerprint)

		// 归一化后比对：去冒号、去空格、统一大写
		cleanExpected := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(expectedFingerprint, ":", ""), " ", ""))
		cleanActual := strings.ReplaceAll(actualFingerprint, ":", "")

		if cleanExpected != cleanActual {
			return fmt.Errorf("certificate fingerprint mismatch! expected: %s, got: %s", expectedFingerprint, actualFingerprint)
		}

		zlog.Infof("%s [Tunnel] ✅ Peer certificate fingerprint matched successfully", TAG)
		return nil
	}
}

type DumpConn struct {
	net.Conn
	Prefix string
}

func (c *DumpConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		zlog.Debugf("\n--- [%s] ⬇️ Read %d bytes ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

func (c *DumpConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		zlog.Debugf("\n--- [%s] ⬆️ Sent %d bytes ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}
