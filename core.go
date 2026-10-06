package myssh

import (
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
	// relayBufPool 是 TCP/UDP 中转共用的大缓冲池，缓冲区 64KB+1KB。
	// TCP 侧供 io.CopyBuffer 使用，UDP 侧用于读满/写满一个数据报。
	// 原先 tcpBufPool 与 udpBufPool 是两个尺寸完全相同的池——维护两份等价
	// 的池既没有收益（尺寸一致、都走 sync.Pool 的 per-P 缓存），又多一处
	// 需要同步修改的重复声明，故合并为一个。
	relayBufPool = sync.Pool{
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
	// 填充数据池
	padPool    []byte
	padPoolLen = 64 * 1024
	// Socket buffers use OS defaults unless configured per profile.
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
	bufPtr := relayBufPool.Get().(*[]byte)
	buf := *bufPtr

	defer relayBufPool.Put(bufPtr)

	// 中转基于 io.CopyBuffer，使用池化缓冲
	// 依赖 src 读到 EOF 时 CopyBuffer 自行结束
	return io.CopyBuffer(dst, src, buf)
}

// relayStream 双向中继一条 TCP 流：
//
//	Linux/Android 优先尝试 splice(2) 零拷贝；
//	对不支持 splice 的 Socket 类型，回退 tcpRelay 纯用户态拷贝。
func relayStream(dst, src net.Conn) (int64, error) {
	if n, err, handled := trySplice(dst, src); handled {
		return n, err
	}
	return tcpRelay(dst, src)
}

// formatSHA256Fingerprint 格式化 SHA-256 指纹为冒号分隔的大写十六进制 (XX:XX:XX:...)
//
// 用查表 + 预扩容 Builder 一次写完，不走 fmt.Fprintf：证书校验每次握手都
// 会**无条件**先算一遍实际指纹（要打日志供用户比对 pin），逐字节 Fprintf
// 等于 32 次反射式格式化，纯属浪费。改为查表后只分配一次。
func formatSHA256Fingerprint(raw []byte) string {
	const hexDigits = "0123456789ABCDEF"
	sha256Sum := sha256.Sum256(raw)
	var fpBuilder strings.Builder
	fpBuilder.Grow(len(sha256Sum)*3 - 1) // "XX" 加分隔符 ':'，末字节后无冒号
	for i, b := range sha256Sum {
		if i > 0 {
			fpBuilder.WriteByte(':')
		}
		fpBuilder.WriteByte(hexDigits[b>>4])
		fpBuilder.WriteByte(hexDigits[b&0x0F])
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
