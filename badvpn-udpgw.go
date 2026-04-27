package myssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

// ==========================================
// Badvpn UDPGW 协议常量定义
// ==========================================
const (
	BadvpnFlagData      = 0x00 // Badvpn 原生数据包 Flag
	BadvpnFlagKeepalive = 0x01 // Badvpn 原生心跳包 Flag

	BadvpnAtypIPv4   = 0x01 // IPv4 地址
	BadvpnAtypIPv6   = 0x02 // 🌟 Badvpn 原生私有 IPv6 定义 (不同于 SOCKS5 的 0x04)
	BadvpnAtypDomain = 0x03 // 域名地址
)

// BadvpnUdpgwConn 将 SSH TCP 隧道包装为逻辑上的 Badvpn UDPGW 连接
type BadvpnUdpgwConn struct {
	net.Conn
	targetAddressData []byte // 序列化后的目标 IP 或 域名
	targetPortData    []byte // 目标端口 (2字节)
	addressType       byte   // ATYP

	readLock  sync.Mutex
	writeLock sync.Mutex

	uploadCounter   func(int64)
	downloadCounter func(int64)

	closed    chan struct{}
	closeOnce sync.Once
}

// DialBadvpnUdpgw 是基于 SSH 隧道的 Badvpn-UDPGW 协议拨号器
func DialBadvpnUdpgw(sshClient *ssh.Client, udpgwServerAddr string, remoteTarget string) (net.Conn, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("ssh client is not initialized")
	}

	if Debug {
		zlog.Debugf("%s [BADVPN-Dial] 📞 开始拨号 | 服务端: %s | 目标: %s", TAG, udpgwServerAddr, remoteTarget)
	}

	host, portStr, err := net.SplitHostPort(remoteTarget)
	if err != nil {
		return nil, err
	}

	// 1. 域名解析逻辑：优先获取 IPv6
	var targetIP net.IP
	if ip := net.ParseIP(host); ip != nil {
		targetIP = ip
	} else {
		ips := GetCachedIPs(host)
		for _, ip := range ips {
			if ip.To4() == nil {
				targetIP = ip
				if Debug {
					zlog.Debugf("%s [BADVPN-Dial] ⚡ 命中 DNS 缓存 (IPv6): %s", TAG, targetIP.String())
				}
				break
			}
		}
		if targetIP == nil && len(ips) > 0 {
			targetIP = ips[0]
			if Debug {
				zlog.Debugf("%s [BADVPN-Dial] ⚡ 命中 DNS 缓存 (IPv4): %s", TAG, targetIP.String())
			}
		}

		if targetIP == nil {
			targetIP = ResolveOne(host, dns.TypeAAAA)
			if targetIP == nil {
				targetIP = ResolveOne(host, dns.TypeA)
			}
			if Debug && targetIP != nil {
				zlog.Debugf("%s [BADVPN-Dial] ✅ 实时解析成功: %s -> %s", TAG, host, targetIP.String())
			}
		}
	}

	// 2. 建立底层 TCP 隧道
	underlyingConn, err := sshClient.Dial("tcp", udpgwServerAddr)
	if err != nil {
		zlog.Errorf("%s [BADVPN-Dial] ❌ 底层 TCP 连接建立失败: %v", TAG, err)
		return nil, fmt.Errorf("dial badvpn udpgw server failed: %w", err)
	}

	if Debug {
		zlog.Debugf("%s [BADVPN-Dial] 🟢 底层 TCP 隧道建立成功", TAG)
	}

	// 3. 构建 Badvpn 专属地址头
	portValue, _ := strconv.Atoi(portStr)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portValue))

	var addrType byte
	var addrData []byte

	if targetIP != nil {
		if ipv4 := targetIP.To4(); ipv4 != nil {
			addrType = BadvpnAtypIPv4
			addrData = ipv4
		} else {
			addrType = BadvpnAtypIPv6 // 🌟 使用 Badvpn 专属的 0x02
			addrData = targetIP.To16()
		}
	} else {
		addrType = BadvpnAtypDomain
		addrData = append([]byte{byte(len(host))}, []byte(host)...)
	}

	c := &BadvpnUdpgwConn{
		Conn:              underlyingConn,
		addressType:       addrType,
		targetAddressData: addrData,
		targetPortData:    portBytes,
		uploadCounter:     AddTx,
		downloadCounter:   AddRx,
		closed:            make(chan struct{}),
	}

	// 4. 启动后台心跳守护
	go c.keepAliveLoop()

	return c, nil
}

// keepAliveLoop 维持 Badvpn 状态机
func (c *BadvpnUdpgwConn) keepAliveLoop() {
	// Badvpn Keepalive 格式: [LEN: 3] [FLAG: 0x01] [CONN_ID: 1]
	keepalivePkt := []byte{0x00, 0x03, BadvpnFlagKeepalive, 0x00, 0x01}

	// 建立连接后立刻发送心跳注册会话
	c.writeLock.Lock()
	c.Conn.Write(keepalivePkt)
	c.writeLock.Unlock()

	if Debug {
		zlog.Debugf("%s [BADVPN-Daemon] 🚀 已发送初始 Keepalive (Flag: 0x01)，会话注册完毕", TAG)
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.writeLock.Lock()
			c.Conn.Write(keepalivePkt)
			c.writeLock.Unlock()
		case <-c.closed:
			if Debug {
				zlog.Debugf("%s [BADVPN-Daemon] 🛑 连接关闭，守护协程安全退出", TAG)
			}
			return
		}
	}
}

// Write 封装并发送 Badvpn 数据帧
func (c *BadvpnUdpgwConn) Write(payload []byte) (int, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	dataLen := len(payload)
	headerLen := 3 + (1 + len(c.targetAddressData) + 2)
	totalSize := headerLen + dataLen

	bufPtr := udpBufPool.Get().(*[]byte)
	buffer := (*bufPtr)[:cap(*bufPtr)] // 恢复切片最大可用空间
	defer udpBufPool.Put(bufPtr)

	if 2+totalSize > cap(buffer) {
		return 0, fmt.Errorf("payload too large")
	}

	packet := buffer[:2+totalSize]
	binary.BigEndian.PutUint16(packet[0:2], uint16(totalSize))
	packet[2] = BadvpnFlagData                 // 🌟 Badvpn 原生数据包 Flag: 0x00
	binary.BigEndian.PutUint16(packet[3:5], 1) // CONN_ID: 1

	packet[5] = c.addressType
	copy(packet[6:], c.targetAddressData)
	copy(packet[6+len(c.targetAddressData):], c.targetPortData)
	copy(packet[6+len(c.targetAddressData)+2:], payload)

	if _, err := c.Conn.Write(packet); err != nil {
		if Debug {
			zlog.Errorf("%s [BADVPN-Write] ❌ 写入隧道失败: %v", TAG, err)
		}
		return 0, err
	}

	if Debug {
		zlog.Debugf("%s [BADVPN-Write] 📤 上行数据发送 | 净载荷: %d bytes, 总长: %d bytes, ATYP: 0x%02X", TAG, dataLen, totalSize, c.addressType)
	}

	if c.uploadCounter != nil {
		c.uploadCounter(int64(2 + totalSize))
	}
	return dataLen, nil
}

// Read 从 Badvpn 底层连接解析下行数据包
func (c *BadvpnUdpgwConn) Read(b []byte) (int, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()

	sizeBuf := make([]byte, 2)
	for {
		if _, err := io.ReadFull(c.Conn, sizeBuf); err != nil {
			return 0, err
		}
		pLen := binary.BigEndian.Uint16(sizeBuf)

		body := make([]byte, pLen)
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			return 0, err
		}

		flag := body[0]
		switch flag {
		case BadvpnFlagData: // 🌟 Badvpn 数据包 (0x00)
			offset := 3 // 跳过 FLAG(1) + CONN_ID(2)
			if offset >= int(pLen) {
				continue // 畸形包防御
			}

			atyp := body[offset]
			offset++

			switch atyp {
			case BadvpnAtypIPv4:
				offset += 4
			case BadvpnAtypIPv6: // Badvpn 的 0x02
				offset += 16
			case BadvpnAtypDomain:
				offset += int(body[offset]) + 1
			}
			offset += 2 // 跳过 DST.PORT(2)

			if offset > int(pLen) {
				if Debug {
					zlog.Errorf("%s [BADVPN-Read] ❌ 数据包越界截断，安全丢弃", TAG)
				}
				continue
			}

			n := copy(b, body[offset:])
			if Debug {
				zlog.Debugf("%s [BADVPN-Read] 📥 成功解包数据 | 净载荷: %d bytes", TAG, n)
			}
			if c.downloadCounter != nil {
				c.downloadCounter(int64(pLen + 2))
			}
			return n, nil

		case BadvpnFlagKeepalive: // 0x01 心跳回包
			if Debug {
				zlog.Debugf("%s [BADVPN-Read] 💓 收到远端 Keepalive 应答", TAG)
			}
			continue

		default:
			// 捕获 Badvpn 发出的未定义错误或关闭指令
			if Debug {
				zlog.Warnf("%s [BADVPN-Read] ⚠️ 收到异常控制帧/断开指令 (Flag: 0x%02X) | Hex: %X", TAG, flag, body)
			}
			continue
		}
	}
}

// Close 安全关闭连接并退出后台守护协程
func (c *BadvpnUdpgwConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *BadvpnUdpgwConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *BadvpnUdpgwConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *BadvpnUdpgwConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
func (c *BadvpnUdpgwConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *BadvpnUdpgwConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }
