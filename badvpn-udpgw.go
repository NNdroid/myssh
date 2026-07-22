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

	// 简单的取模绕回，避开 0 作为有效 conid
	res := uint16(id % 65536)
	if res == 0 {
		id = atomic.AddUint32(&globalConID, 1)
		res = uint16(id % 65536)
	}
	return res
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

	lastActive int64
}

// DialBadvpnUdpgw 初始化基于 SSH 隧道的 Badvpn-UDPGW 连接
func DialBadvpnUdpgw(sshClient *ssh.Client, udpgwServerAddr string, remoteTarget string) (net.Conn, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("ssh client is not initialized")
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 📞 Dialing target: %s -> Server: %s\n", TAG, remoteTarget, udpgwServerAddr)
	}

	// udpgw.c 不处理域名，必须预先解析为 IP
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
	atomic.StoreInt64(&c.lastActive, time.Now().Unix())

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
	// Badvpn PacketProto 严格要求 2 字节小端序长度
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
	// 1. 构造 badvpn 专用的心跳包: Flags(1) + ConID(2 小端)
	hb := make([]byte, 3)
	hb[0] = UDPGW_CLIENT_FLAG_KEEPALIVE
	binary.LittleEndian.PutUint16(hb[1:], c.conID)

	// ==========================================
	// 初始心跳的“微延迟重试”机制
	// 给予底层 SSH 异步握手缓冲时间，最多重试 3 次
	// ==========================================
	var initialErr error
	for i := 0; i < 3; i++ {
		time.Sleep(time.Duration(i+1) * time.Millisecond * 100) // 让子弹飞一会儿
		initialErr = c.writeFrame(hb)
		if initialErr == nil {
			break // 成功发送，跳出重试循环
		}
		if Debug {
			zlog.Warnf("%s [UDPGW-keepAliveLoop] ⚠️ Initial Keepalive attempt %d failed: %v", TAG, i+1, initialErr)
		}
	}

	if initialErr != nil {
		zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Failed to send initial Keepalive after retries: %v", TAG, initialErr)
		c.Close() // 彻底连不上，及时止损
		return
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-keepAliveLoop] 🚀 Initial Keepalive sent successfully (ID: %d)", TAG, c.conID)
	}

	// ==========================================
	// 进入常规的 15 秒心跳巡逻
	// ==========================================
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-c.closed:
			return // 收到明确的关闭信号，安全退出
		}

		// 真正的双向超时检测 (45秒没收到任何远端数据，直接判死刑)
		last := atomic.LoadInt64(&c.lastActive)
		if time.Now().Unix()-last > 45 {
			zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Server heartbeat timeout (45s), connection dead", TAG)
			c.Close() // 强制切断假死的底层连接
			return
		}

		if Debug {
			zlog.Debugf("%s [UDPGW-keepAliveLoop] 💓 Sending Keepalive (ID: %d)\n", TAG, c.conID)
		}

		if err := c.writeFrame(hb); err != nil {
			// 规避假报错。如果此时通道已经是合法关闭状态，就安静退出。
			select {
			case <-c.closed:
				return
			default:
			}

			zlog.Errorf("%s [UDPGW-keepAliveLoop] ❌ Failed to write Keepalive: %v\n", TAG, err)
			c.Close() // 因为真正的网络异常断开，连带关闭其他协程
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
		// 严格读取 2 字节小端序长度
		if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
			// 检查是不是正常的关闭，如果是，屏蔽掉可怕的红字报错
			select {
			case <-c.closed:
				return 0, io.EOF
			default:
			}
			zlog.Errorf("%s [UDPGW-Read] ❌ Failed to read length prefix: %v", TAG, err)
			return 0, err
		}

		pLen := int(binary.LittleEndian.Uint16(lenBuf[:]))

		// 防御性拦截（超大畸形包直接断开，防止 OOM）
		if pLen > 0xFFFF || pLen > len(bodyBuf) {
			err := fmt.Errorf("invalid packet length: %d", pLen)
			zlog.Errorf("%s [UDPGW-Read] ❌ Intercepted malformed packet: %v", TAG, err)
			return 0, err
		}

		// 读出完整载荷
		body := bodyBuf[:pLen]
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			zlog.Errorf("%s [UDPGW-Read] ❌ Failed to read packet payload (Expected length: %d): %v", TAG, pLen, err)
			return 0, err
		}
		// 只要读到了完整的包（哪怕是服务器回传的心跳包），就立刻刷新活跃时间
		atomic.StoreInt64(&c.lastActive, time.Now().Unix())

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
