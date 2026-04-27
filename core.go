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
	// 用于 TCP io.CopyBuffer 的 64KB 缓冲池
	tcpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 64*1024)
			return &buf
		},
	}
	// 用于 UDP 读取的 64KB 缓冲池
	udpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65536)
			return &buf
		},
	}
	// 用于 XHTTP io.CopyBuffer 的 990KB 缓冲池
	xhttpBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 990*1000)
			return &buf
		},
	}
	// 全局复用的 bytes.Buffer 池，接收响应体
	bytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	// 填充池
	padPool    []byte
	padPoolLen = 64 * 1000
	// tcp
	tcpOptimizeBufferSize = 4 * 1024 * 1024
)

func init() {
	if DebugStr == "true" {
		Debug = true
	}
	// 随机填充池初始化
	padPool = make([]byte, padPoolLen)
	io.ReadFull(rand.Reader, padPool)
}

func tcpRelay(dst io.Writer, src io.Reader) (int64, error) {
	// 1. 从池子里借一块内存
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr

	// 2. 确保在函数退出时还给池子
	defer tcpBufPool.Put(bufPtr)

	// 3. 使用 CopyBuffer，并传入我们复用的内存块
	// 它会一直使用这块内存直到 src 读到 EOF 或出错
	return io.CopyBuffer(dst, src, buf)
}

// MakePeerCertVerifier 验证证书指纹
func MakePeerCertVerifier(verifyFingerprint bool, expectedFingerprint string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificates presented by peer")
		}

		// 无论是否开启验证，都先计算并打印实际的证书指纹，方便用户查看
		sha256Sum := sha256.Sum256(rawCerts[0])
		var actualFPBuilder strings.Builder
		for i, b := range sha256Sum {
			if i > 0 {
				actualFPBuilder.WriteString(":")
			}
			fmt.Fprintf(&actualFPBuilder, "%02X", b)
		}
		actualFingerprint := actualFPBuilder.String()

		// 只要有握手，就打出这个日志
		zlog.Infof("%s [Tunnel] 实际证书指纹: %s", TAG, actualFingerprint)

		if !verifyFingerprint {
			return nil // 如果用户没有开启强制验证，则直接放行
		}

		zlog.Infof("%s [Tunnel] 期盼证书指纹: %s", TAG, expectedFingerprint)

		// 标准化：转大写并移除冒号和空格
		cleanExpected := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(expectedFingerprint, ":", ""), " ", ""))
		cleanActual := strings.ReplaceAll(actualFingerprint, ":", "")

		if cleanExpected != cleanActual {
			zlog.Errorf("%s [Tunnel] ❌ 证书指纹不匹配！期望: %s, 实际: %s", TAG, expectedFingerprint, actualFingerprint)
			return fmt.Errorf("fingerprint mismatch! expected: %s, actual: %s", expectedFingerprint, actualFingerprint)
		}

		zlog.Infof("%s [Tunnel] ✅ 证书指纹校验通过！", TAG)
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
		zlog.Debugf("\n--- [%s] ⬇️ 读取 %d 字节 ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

func (c *DumpConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		zlog.Debugf("\n--- [%s] ⬆️ 发送 %d 字节 ---\n%s\n", c.Prefix, n, hex.Dump(b[:n]))
	}
	return n, err
}

// TuneTCPConn 針對 TCP 連線進行底層 Socket 最佳化
// 1. 關閉 Nagle 演算法 (SetNoDelay) 以保證極低延遲 (適用於 SSH/即時指令)
// 2. 擴大作業系統讀寫緩衝區至 4MB，以適應跨國高 BDP (頻寬延遲乘積) 網路
func TuneTCPConn(conn net.Conn) {
	// 嘗試將 net.Conn 轉型為底層的 *net.TCPConn
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// 關閉 Nagle 演算法
		if err := tcpConn.SetNoDelay(true); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法設定 NoDelay: %v", TAG, err)
		}

		// 設定讀取緩衝區
		if err := tcpConn.SetReadBuffer(tcpOptimizeBufferSize); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法設定 ReadBuffer: %v", TAG, err)
		}

		// 設定寫入緩衝區
		if err := tcpConn.SetWriteBuffer(tcpOptimizeBufferSize); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法設定 WriteBuffer: %v", TAG, err)
		}

		zlog.Debugf("%s [TCP Tune] 已成功套用 Socket 最佳化 (4MB Buffer, NoDelay)", TAG)
	}
}
