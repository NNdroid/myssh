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

// tun2proxy UDPGW 协议常量定义
const (
	UdpgwFlagKeepalive = 0x01 // 心跳包 (无地址无数据)
	UdpgwFlagData      = 0x02 // 数据包 (含地址和数据)
	UdpgwFlagError     = 0x20 // 错误包 (无地址无数据)

	UdpgwAtypIPv4   = 0x01 // SOCKS5 标准 IPv4
	UdpgwAtypDomain = 0x03 // SOCKS5 标准 Domain
	UdpgwAtypIPv6   = 0x04 // SOCKS5 标准 IPv6
)

// UdpgwConn 将 SSH TCP 隧道包装为逻辑上的 UDPGW 连接
type UdpgwConn struct {
	net.Conn
	targetAddressData []byte // 序列化后的目标 IP
	targetPortData    []byte // 目标端口 (2字节)
	addressType       byte   // ATYP

	readLock  sync.Mutex
	writeLock sync.Mutex

	uploadCounter   func(int64)
	downloadCounter func(int64)

	closed    chan struct{}
	closeOnce sync.Once
}

// DialTun2proxyUdpgw 是基于 SSH 隧道的 UDPGW 协议拨号器
func DialTun2proxyUdpgw(sshClient *ssh.Client, udpgwServerAddr string, remoteTarget string) (net.Conn, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("ssh client is not initialized")
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 📞 开始拨号 | 服务端: %s | 目标: %s", TAG, udpgwServerAddr, remoteTarget)
	}

	host, portStr, err := net.SplitHostPort(remoteTarget)
	if err != nil {
		return nil, err
	}

	var targetIP net.IP
	if ip := net.ParseIP(host); ip != nil {
		targetIP = ip
	} else {
		ips := GetCachedIPs(host)
		for _, ip := range ips {
			if ip.To4() == nil {
				targetIP = ip
				break
			}
		}
		if targetIP == nil && len(ips) > 0 {
			targetIP = ips[0]
		}
		if targetIP == nil {
			targetIP = ResolveOne(host, dns.TypeAAAA)
			if targetIP == nil {
				targetIP = ResolveOne(host, dns.TypeA)
			}
		}
	}

	underlyingConn, err := sshClient.Dial("tcp", udpgwServerAddr)
	if err != nil {
		return nil, fmt.Errorf("dial udpgw server failed: %w", err)
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 🟢 底层 TCP 隧道建立成功", TAG)
	}

	portValue, _ := strconv.Atoi(portStr)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portValue))

	var addrType byte
	var addrData []byte

	if targetIP != nil {
		if ipv4 := targetIP.To4(); ipv4 != nil {
			addrType = UdpgwAtypIPv4
			addrData = ipv4
		} else {
			addrType = UdpgwAtypIPv6 // 🌟 恢复为 SOCKS5 标准 0x04
			addrData = targetIP.To16()
		}
	} else {
		addrType = UdpgwAtypDomain
		addrData = append([]byte{byte(len(host))}, []byte(host)...)
	}

	c := &UdpgwConn{
		Conn:              underlyingConn,
		addressType:       addrType,
		targetAddressData: addrData,
		targetPortData:    portBytes,
		uploadCounter:     AddTx,
		downloadCounter:   AddRx,
		closed:            make(chan struct{}),
	}

	// 启动后台心跳守护
	go c.keepAliveLoop()

	return c, nil
}

func (c *UdpgwConn) keepAliveLoop() {
	// tun2proxy Keepalive 格式: [LEN: 3] [FLAG: 0x01] [CONN_ID: 1]
	keepalivePkt := []byte{0x00, 0x03, UdpgwFlagKeepalive, 0x00, 0x01}

	c.writeLock.Lock()
	c.Conn.Write(keepalivePkt)
	c.writeLock.Unlock()

	if Debug {
		zlog.Debugf("%s [UDPGW-Daemon] 🚀 已发送初始 Keepalive (Flag: 0x01)，会话注册完毕", TAG)
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
			return
		}
	}
}

func (c *UdpgwConn) Write(payload []byte) (int, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	dataLen := len(payload)
	// headerLen = 1(FLAG) + 2(CONN_ID) + 1(ATYP) + addrLen + 2(PORT)
	headerLen := 3 + (1 + len(c.targetAddressData) + 2)
	totalSize := headerLen + dataLen // 不包含 LEN 字段本身的长度

	bufPtr := udpBufPool.Get().(*[]byte)
	buffer := (*bufPtr)[:cap(*bufPtr)]
	defer udpBufPool.Put(bufPtr)

	if 2+totalSize > cap(buffer) {
		return 0, fmt.Errorf("payload too large")
	}

	packet := buffer[:2+totalSize]
	binary.BigEndian.PutUint16(packet[0:2], uint16(totalSize))
	packet[2] = UdpgwFlagData                  // 🌟 tun2proxy 数据包 Flag: 0x02
	binary.BigEndian.PutUint16(packet[3:5], 1) // CONN_ID: 1

	packet[5] = c.addressType
	copy(packet[6:], c.targetAddressData)
	copy(packet[6+len(c.targetAddressData):], c.targetPortData)
	copy(packet[6+len(c.targetAddressData)+2:], payload)

	if _, err := c.Conn.Write(packet); err != nil {
		if Debug {
			zlog.Errorf("%s [UDPGW-Write] ❌ 写入隧道失败: %v", TAG, err)
		}
		return 0, err
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Write] 📤 上行数据发送 | 净载荷: %d bytes, 包装总长: %d bytes, ATYP: 0x%02X", TAG, dataLen, totalSize, c.addressType)
	}

	if c.uploadCounter != nil {
		c.uploadCounter(int64(2 + totalSize))
	}
	return dataLen, nil
}

func (c *UdpgwConn) Read(b []byte) (int, error) {
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
		case UdpgwFlagData: // 0x02 数据包
			offset := 3 // 跳过 FLAG(1) + CONN_ID(2)
			if offset >= int(pLen) {
				continue
			}

			atyp := body[offset]
			offset++

			switch atyp {
			case UdpgwAtypIPv4:
				offset += 4
			case UdpgwAtypIPv6:
				offset += 16
			case UdpgwAtypDomain:
				offset += int(body[offset]) + 1
			}
			offset += 2 // 跳过 DST.PORT(2)

			if offset > int(pLen) {
				if Debug {
					zlog.Errorf("%s [UDPGW-Read] ❌ 数据包越界截断，安全丢弃", TAG)
				}
				continue
			}

			n := copy(b, body[offset:])
			if Debug {
				zlog.Debugf("%s [UDPGW-Read] 📥 成功解包数据 | 净载荷: %d bytes", TAG, n)
			}
			if c.downloadCounter != nil {
				c.downloadCounter(int64(pLen + 2))
			}
			return n, nil

		case UdpgwFlagKeepalive: // 0x01 心跳回包
			if Debug {
				zlog.Debugf("%s [UDPGW-Read] 💓 收到远端 Keepalive 应答", TAG)
			}
			continue

		case UdpgwFlagError: // 0x20 远端错误
			if Debug {
				zlog.Errorf("%s [UDPGW-Read] ❌ 收到远端 UDPGW 报错 (Flag: 0x20)！可能目标不可达或解析失败", TAG)
			}
			continue

		default:
			if Debug {
				zlog.Warnf("%s [UDPGW-Read] ⚠️ 收到未知标识符包 (Flag: 0x%02X)", TAG, flag)
			}
			continue
		}
	}
}

func (c *UdpgwConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *UdpgwConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *UdpgwConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *UdpgwConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
func (c *UdpgwConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *UdpgwConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }
