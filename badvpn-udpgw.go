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

// 全局 ConID 分配器 (从 1 开始自增)
var globalConID atomic.Uint32

// nextConID 分配下一个 ConID
func nextConID() uint16 {
	// 原子自增，线程安全
	id := globalConID.Add(1)

	// 跳过 0 值，避免 0 号 conid（保留值）
	res := uint16(id % 65536)
	if res == 0 {
		id = globalConID.Add(1)
		res = uint16(id % 65536)
	}
	return res
}

// Badvpn UDPGW 协议常量 (对照 udpgw.c 源码)
const (
	UDPGW_CLIENT_FLAG_KEEPALIVE = 0x01
	UDPGW_CLIENT_FLAG_REBIND    = 0x02
	UDPGW_CLIENT_FLAG_DNS       = 0x04
	UDPGW_CLIENT_FLAG_IPV6      = 0x08
)

type BadvpnUdpgwConn struct {
	lastActive atomic.Int64

	net.Conn
	targetIP   net.IP
	targetPort uint16
	isIPv6     bool
	conID      uint16

	writeLock sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once
}

// DialBadvpnUdpgw 经 SSH tunnel 建立 Badvpn-UDPGW 连接
func DialBadvpnUdpgw(sshClient *ssh.Client, udpgwServerAddr string, remoteTarget string) (net.Conn, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("ssh client is not initialized")
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 📞 Dialing target: %s -> Server: %s\n", TAG, remoteTarget, udpgwServerAddr)
	}

	// 按 udpgw.c 语义，目标地址需先解析为 IP
	addr, err := net.ResolveUDPAddr("udp", remoteTarget)
	if err != nil {
		zlog.Errorf("%s [UDPGW-Dial] ❌ Failed to resolve target address (%s): %v", TAG, remoteTarget, err)
		return nil, fmt.Errorf("resolve error: %w", err)
	}
	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] Dialed IP: %s, isIPv6 resolved: %v", TAG, addr.IP, addr.IP.To4() == nil)
	}

	underlyingConn, err := sshClient.Dial("tcp", udpgwServerAddr)
	if err != nil {
		zlog.Errorf("%s [UDPGW-Dial] ❌ SSH failed to establish TCP tunnel, unable to connect to UDPGW server (%s): %v", TAG, udpgwServerAddr, err)
		return nil, fmt.Errorf("ssh dial udpgw server (%s) failed: %w", udpgwServerAddr, err)
	}

	// 分配唯一 conID
	uniqueID := nextConID()

	c := &BadvpnUdpgwConn{
		Conn:       underlyingConn,
		targetIP:   addr.IP,
		targetPort: uint16(addr.Port),
		isIPv6:     addr.IP.To4() == nil,
		conID:      uniqueID, // 唯一连接 ID
		closed:     make(chan struct{}),
	}
	c.lastActive.Store(time.Now().Unix())

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 🆕 Allocated new ConID: %d", TAG, uniqueID)
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
		zlog.Errorf("%s [UDPGW-writeFrame] ❌ Payload too large: %v", TAG, err)
		return err
	}

	var lenBuf [2]byte
	// Badvpn PacketProto 帧长前缀为 2 bytes 小端
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(length))

	if Debug {
		zlog.Debugf("%s [UDPGW-writeFrame] 📤 Sending frame | Length prefix: %X | Payload length: %d\n", TAG, lenBuf[:], length)
		zlog.Debugf("%s [UDPGW-writeFrame] 📤 Frame content (Hex): %s\n", TAG, hex.EncodeToString(payload))
	}

	if _, err := c.Conn.Write(lenBuf[:]); err != nil {
		select {
		case <-c.closed:
			return io.EOF
		default:
		}
		zlog.Errorf("%s [UDPGW-writeFrame] ❌ Failed to write length prefix: %v", TAG, err)
		return err
	}
	if _, err := c.Conn.Write(payload); err != nil {
		select {
		case <-c.closed:
			return io.EOF
		default:
		}
		zlog.Errorf("%s [UDPGW-writeFrame] ❌ Failed to write data payload: %v", TAG, err)
		return err
	}
	return nil
}

func (c *BadvpnUdpgwConn) keepAliveLoop() {
	// 1. 组装 badvpn 心跳帧: Flags(1) + ConID(2 字节小端)
	hb := make([]byte, 3)
	hb[0] = UDPGW_CLIENT_FLAG_KEEPALIVE
	binary.LittleEndian.PutUint16(hb[1:], c.conID)

	// ==========================================
	// 初始"握手 retry"阶段
	// SSH 通道刚建立，这里 retry 3 次
	// ==========================================
	var initialErr error
	for i := 0; i < 3; i++ {
		time.Sleep(time.Duration(i+1) * time.Millisecond * 100) // 递增退避
		initialErr = c.writeFrame(hb)
		if initialErr == nil {
			break // 发送成功，结束 retry 循环
		}
		if Debug {
			zlog.Warnf("%s [UDPGW-keepAliveLoop] ⚠️ Initial Keepalive attempt %d failed: %v", TAG, i+1, initialErr)
		}
	}

	if initialErr != nil {
		zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Failed to send initial Keepalive after retries: %v", TAG, initialErr)
		c.Close() // 彻底失败，关闭连接
		return
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-keepAliveLoop] 🚀 Initial Keepalive sent successfully (ID: %d)", TAG, c.conID)
	}

	// ==========================================
	// 之后每 15 秒发一次心跳
	// ==========================================
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-c.closed:
			return // 收到 closed 信号，正常退出
		}

		// 双向超时检测 (45 秒无活动即判死)
		last := c.lastActive.Load()
		if time.Now().Unix()-last > 45 {
			zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Server heartbeat timeout (45s), connection dead", TAG)
			c.Close() // 判死关闭
			return
		}

		if Debug {
			zlog.Debugf("%s [UDPGW-keepAliveLoop] 💓 Sending Keepalive (ID: %d)\n", TAG, c.conID)
		}

		if err := c.writeFrame(hb); err != nil {
			// 写失败。先检查 channel 是否已 closed，避免把主动关闭误报为错误。
			select {
			case <-c.closed:
				return
			default:
			}

			zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Failed to write Keepalive: %v\n", TAG, err)
			c.Close() // 心跳 abnormal，关闭并广播 closed 信号
			return
		}
	}
}

// Write 组装 UDPGW 上行帧并发送。注意：目标地址在 Dial 时已固定，writeFrame 内部加锁串行化写入。
func (c *BadvpnUdpgwConn) Write(b []byte) (int, error) {
	addrLen := 4
	var flags byte = 0x00
	ipData := c.targetIP.To4()
	if c.isIPv6 {
		addrLen = 16
		flags |= UDPGW_CLIENT_FLAG_IPV6
		ipData = c.targetIP.To16()
	}

	// 帧结构: Flags(1) + ConID(2) + IPAddr(N) + Port(2) + Payload
	packet := make([]byte, 3+addrLen+2+len(b))

	// 1. Header: Flags 与 ConID (ConID 小端)
	packet[0] = flags
	binary.LittleEndian.PutUint16(packet[1:3], c.conID)

	copy(packet[3:], ipData) // IP 地址 N 字节

	// port 字段按 udpgw.c 约定用大端 (BigEndian)
	binary.BigEndian.PutUint16(packet[3+addrLen:], c.targetPort)

	copy(packet[3+addrLen+2:], b)

	if Debug {
		zlog.Debugf("%s [UDPGW-Write] 📝 Writing data | Target: %s:%d | Length: %d\n", TAG, c.targetIP, c.targetPort, len(b))
	}

	if err := c.writeFrame(packet); err != nil {
		select {
		case <-c.closed:
			return 0, io.EOF
		default:
		}
		zlog.Errorf("%s [UDPGW-Write] ❌ Failed to send UDP data frame: %v", TAG, err)
		return 0, err
	}
	return len(b), nil
}

func (c *BadvpnUdpgwConn) Read(b []byte) (int, error) {
	bufPtr := udpBufPool.Get().(*[]byte)
	bodyBuf := (*bufPtr)[:cap(*bufPtr)]
	defer udpBufPool.Put(bufPtr)

	for {
		var lenBuf [2]byte
		// 先读 2 bytes 帧长前缀
		if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
			// 若已主动 closed，静默返回 EOF，不当作错误
			select {
			case <-c.closed:
				return 0, io.EOF
			default:
			}
			zlog.Errorf("%s [UDPGW-Read] ❌ Failed to read length prefix: %v", TAG, err)
			return 0, err
		}

		pLen := int(binary.LittleEndian.Uint16(lenBuf[:]))

		// 帧长合法性检查（防异常包导致 OOM）
		if pLen > 0xFFFF || pLen > len(bodyBuf) {
			err := fmt.Errorf("invalid packet length: %d", pLen)
			zlog.Errorf("%s [UDPGW-Read] ❌ Intercepted malformed packet: %v", TAG, err)
			return 0, err
		}

		// 读取包体
		body := bodyBuf[:pLen]
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			zlog.Errorf("%s [UDPGW-Read] ❌ Failed to read packet payload (Expected length: %d): %v", TAG, pLen, err)
			return 0, err
		}
		// 刷新活跃时间（收到 server 回包），供超时判定使用
		c.lastActive.Store(time.Now().Unix())

		if Debug {
			zlog.Debugf("%s [UDPGW-Read] 📥 Received return frame | Length: %d | Hex: %s\n", TAG, pLen, hex.EncodeToString(body))
		}

		if pLen < 3 {
			continue
		}

		flags := body[0]
		if flags&UDPGW_CLIENT_FLAG_KEEPALIVE != 0 {
			if Debug {
				zlog.Debugf("%s [UDPGW-Read] 💓 Received server heartbeat response\n", TAG)
			}
			continue
		}

		addrSize := 4
		if flags&UDPGW_CLIENT_FLAG_IPV6 != 0 {
			addrSize = 16
		}

		offset := 3 + addrSize + 2
		if pLen < offset {
			continue
		}

		n := copy(b, body[offset:])
		if Debug {
			zlog.Debugf("%s [UDPGW-Read] ✅ Extracted UDP Payload: %d bytes\n", TAG, n)
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
