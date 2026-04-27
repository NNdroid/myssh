package myssh

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// 全局 ConID 分配器 (从 1 开始)
var globalConID uint32 = 0

// 获取下一个唯一的 ConID
func nextConID() uint16 {
	// 使用原子操作递增，防止并发冲突
	id := atomic.AddUint32(&globalConID, 1)
	
	// 如果达到上限 (65535)，则绕回。
	// 注意：badvpn-udpgw 通常不支持 0 作为有效 conid，所以绕回时加 1
	if id > 65535 {
		atomic.CompareAndSwapUint32(&globalConID, id, 1)
		return 1
	}
	return uint16(id)
}

// Badvpn UDPGW 协议常量 (基于 udpgw.c 源码)
const (
	UDPGW_CLIENT_FLAG_KEEPALIVE = 0x01
	UDPGW_CLIENT_FLAG_REBIND    = 0x02
	UDPGW_CLIENT_FLAG_DNS       = 0x04
	UDPGW_CLIENT_FLAG_IPV6      = 0x08
)

type BadvpnUdpgwConn struct {
	net.Conn
	targetIP   net.IP
	targetPort uint16
	isIPv6     bool
	conID      uint16

	writeLock sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once
}

// DialBadvpnUdpgw 初始化基于 SSH 隧道的 Badvpn-UDPGW 连接
func DialBadvpnUdpgw(sshClient *ssh.Client, udpgwServerAddr string, remoteTarget string) (net.Conn, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("ssh client is not initialized")
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 📞 拨号目标: %s -> 服务端: %s\n", TAG, remoteTarget, udpgwServerAddr)
	}

	// udpgw.c 不处理域名，必须预先解析为 IP
	addr, err := net.ResolveUDPAddr("udp", remoteTarget)
	if err != nil {
		zlog.Errorf("%s [UDPGW-Dial] ❌ 解析目标地址失败 (%s): %v", TAG, remoteTarget, err)
		return nil, fmt.Errorf("resolve error: %w", err)
	}
	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] Dialed IP: %s, isIPv6 resolved: %v", TAG, addr.IP, addr.IP.To4() == nil)
	}

	underlyingConn, err := sshClient.Dial("tcp", udpgwServerAddr)
	if err != nil {
		zlog.Errorf("%s [UDPGW-Dial] ❌ SSH 建立 TCP 隧道失败 (%s): %v", TAG, udpgwServerAddr, err)
		return nil, err
	}
	
	// 获取一个唯一的 conID
    uniqueID := nextConID()

	c := &BadvpnUdpgwConn{
		Conn:       underlyingConn,
		targetIP:   addr.IP,
		targetPort: uint16(addr.Port),
		isIPv6:     addr.IP.To4() == nil,
		conID:      uniqueID, // 初始会话 ID
		closed:     make(chan struct{}),
	}
	
	if Debug {
        zlog.Debugf("%s [UDPGW-Dial] 🆕 分配了新的 ConID: %d", TAG, uniqueID)
    }

	go c.keepAliveLoop()
	return c, nil
}

func (c *BadvpnUdpgwConn) writeFrame(payload []byte) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	length := len(payload)
	if length > 0xFFFF {
		err := fmt.Errorf("payload too large: %d bytes", length)
		zlog.Errorf("%s [UDPGW-writeFrame] ❌ 载荷过大: %v", TAG, err)
		return err
	}

	// Badvpn PacketProto 严格要求 2 字节小端序长度
	header := make([]byte, 2)
	binary.LittleEndian.PutUint16(header, uint16(length))

	if Debug {
		zlog.Debugf("%s [UDPGW-writeFrame] 📤 发送帧 | 长度前缀: %X | 载荷长度: %d\n", TAG, header, length)
		zlog.Debugf("%s [UDPGW-writeFrame] 📤 帧内容(Hex): %s\n", TAG, hex.EncodeToString(payload))
	}

	if _, err := c.Conn.Write(header); err != nil {
		zlog.Errorf("%s [UDPGW-writeFrame] ❌ 写入长度前缀失败: %v", TAG, err)
		return err
	}
	if _, err := c.Conn.Write(payload); err != nil {
		zlog.Errorf("%s [UDPGW-writeFrame] ❌ 写入数据载荷失败: %v", TAG, err)
		return err
	}
	return nil
}

func (c *BadvpnUdpgwConn) keepAliveLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		// 构造心跳包: Flags(1) + ConID(2 小端)
		hb := make([]byte, 3)
		hb[0] = UDPGW_CLIENT_FLAG_KEEPALIVE
		// binary.LittleEndian.PutUint16(hb[1:], c.conID)
		// ConID 固定为 0，与 C 语言版客户端对齐
		binary.LittleEndian.PutUint16(hb[1:], 0)

		if Debug {
			zlog.Debugf("%s [UDPGW-keepAliveLoop] 💓 发送 Keepalive (ID: %d)\n", TAG, c.conID)
		}
		if err := c.writeFrame(hb); err != nil {
			zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Keepalive 写入失败: %v\n", TAG, err)
			return
		}

		select {
		case <-ticker.C:
		case <-c.closed:
			return
		}
	}
}

// Write 封装并发送数据。注意：此处不要加锁，writeFrame 会处理并发安全。
func (c *BadvpnUdpgwConn) Write(b []byte) (int, error) {
	addrLen := 4
	var flags byte = 0x00
	ipData := c.targetIP.To4()
	if c.isIPv6 {
		addrLen = 16
		flags |= UDPGW_CLIENT_FLAG_IPV6
		ipData = c.targetIP.To16()
	}

	// 封装格式: Flags(1) + ConID(2) + IPAddr(N) + Port(2) + Payload
	packet := make([]byte, 3+addrLen+2+len(b))

	// 1. Header: Flags 和 ConID (ConID 必须用小端序)
	packet[0] = flags
	binary.LittleEndian.PutUint16(packet[1:3], c.conID)

	copy(packet[3:], ipData) // IP 地址原始字节

	// 端口在 udpgw.c 结构体中通常是网络字节序 (BigEndian)
	binary.BigEndian.PutUint16(packet[3+addrLen:], c.targetPort)

	copy(packet[3+addrLen+2:], b)

	if Debug {
		zlog.Debugf("%s [UDPGW-Write] 📝 写入数据 | 目标: %s:%d | 长度: %d\n", TAG, c.targetIP, c.targetPort, len(b))
	}

	if err := c.writeFrame(packet); err != nil {
		zlog.Errorf("%s [UDPGW-Write] ❌ 发送 UDP 数据帧失败: %v", TAG, err)
		return 0, err
	}
	return len(b), nil
}

func (c *BadvpnUdpgwConn) Read(b []byte) (int, error) {
	for {
		// 1. 严格读取 2 字节小端序长度
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
			zlog.Errorf("%s [UDPGW-Read] ❌ 读取长度前缀失败: %v", TAG, err)
			return 0, err
		}

		pLen := int(binary.LittleEndian.Uint16(lenBuf))

		// 防御性拦截（超大畸形包直接断开，防止 OOM）
		if pLen > 0xFFFF {
			err := fmt.Errorf("invalid packet length: %d", pLen)
			zlog.Errorf("%s [UDPGW-Read] ❌ 畸形包拦截: %v", TAG, err)
			return 0, err
		}

		// 2. 读出完整载荷
		body := make([]byte, pLen)
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			zlog.Errorf("%s [UDPGW-Read] ❌ 读取包体载荷失败 (预期长度: %d): %v", TAG, pLen, err)
			return 0, err
		}

		if Debug {
			zlog.Debugf("%s [UDPGW-Read] 📥 收到回帧 | 长度: %d | Hex: %s\n", TAG, pLen, hex.EncodeToString(body))
		}

		if pLen < 3 {
			continue
		}

		flags := body[0]
		if flags&UDPGW_CLIENT_FLAG_KEEPALIVE != 0 {
			if Debug {
				zlog.Debugf("%s [UDPGW-Read] 💓 收到服务端心跳回包\n", TAG)
			}
			continue
		}

		addrSize := 4
		if flags&UDPGW_CLIENT_FLAG_IPV6 != 0 {
			addrSize = 16
		}

		offset := 3 + addrSize + 2
		if pLen <= offset {
			continue
		}

		n := copy(b, body[offset:])
		if Debug {
			zlog.Debugf("%s [UDPGW-Read] ✅ 提取 UDP Payload: %d bytes\n", TAG, n)
		}
		return n, nil
	}
}

func (c *BadvpnUdpgwConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *BadvpnUdpgwConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *BadvpnUdpgwConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *BadvpnUdpgwConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
func (c *BadvpnUdpgwConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *BadvpnUdpgwConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }
