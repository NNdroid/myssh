package myssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

// tun2proxy UDPGW  info
const (
	UdpgwFlagKeepalive = 0x01 //  info  ( info address info )
	UdpgwFlagData      = 0x02 //  info  ( info address info )
	UdpgwFlagError     = 0x20 //  info  ( info address info )

	UdpgwAtypIPv4   = 0x01 // SOCKS5  info  IPv4
	UdpgwAtypDomain = 0x03 // SOCKS5  info  Domain
	UdpgwAtypIPv6   = 0x04 // SOCKS5  info  IPv6
)

// UdpgwConn  info  SSH TCP tunnel info  UDPGW  info
type UdpgwConn struct {
	lastActive atomic.Int64

	net.Conn
	targetAddressData []byte //  info target IP
	targetPortData    []byte // targetport (2bytes)
	addressType       byte   // ATYP

	readLock  sync.Mutex
	writeLock sync.Mutex

	uploadCounter   func(int64)
	downloadCounter func(int64)

	closed    chan struct{}
	closeOnce sync.Once
}

// DialTun2proxyUdpgw  info  SSH tunnel info  UDPGW  info
func DialTun2proxyUdpgw(sshClient *ssh.Client, udpgwServerAddr string, remoteTarget string) (net.Conn, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("ssh client is not initialized")
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 📞 Starting dial | Server: %s | Target: %s", TAG, udpgwServerAddr, remoteTarget)
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
		return nil, fmt.Errorf("dial udpgw server failed (%s): %w", udpgwServerAddr, err)
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Dial] 🟢 Underlying TCP tunnel established successfully", TAG)
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
			addrType = UdpgwAtypIPv6
			addrData = targetIP.To16()
		}
	} else {
		addrType = UdpgwAtypDomain
		//  info ：SOCKS5  info  1 bytes， info  byte()  info
		if len(host) > 255 {
			underlyingConn.Close()
			return nil, fmt.Errorf("domain name too long: %d bytes", len(host))
		}
		addrData = append([]byte{byte(len(host))}, []byte(host)...)
	}

	c := &UdpgwConn{
		Conn:              underlyingConn,
		addressType:       addrType,
		targetAddressData: addrData,
		targetPortData:    portBytes,
		uploadCounter:     nil,
		downloadCounter:   nil,
		closed:            make(chan struct{}),
	}
	c.lastActive.Store(time.Now().Unix())

	//  info
	go c.keepAliveLoop()

	return c, nil
}

func (c *UdpgwConn) keepAliveLoop() {
	// tun2proxy Keepalive  info : [LEN: 3] [FLAG: 0x01] [CONN_ID: 1]
	keepalivePkt := []byte{0x00, 0x03, UdpgwFlagKeepalive, 0x00, 0x01}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	//  info ， info retry 3  info
	var initialErr error
	for i := 0; i < 3; i++ {
		//  info ， info  ( info ， info  SSH  info )
		time.Sleep(time.Duration(i+1) * time.Millisecond * 100)

		c.writeLock.Lock()
		_, initialErr = c.Conn.Write(keepalivePkt)
		c.writeLock.Unlock()

		if initialErr == nil {
			break // successfully info
		}
		if Debug {
			zlog.Warnf("%s [UDPGW-Daemon] ⚠️ Initial Keepalive attempt %d failed: %v", TAG, i+1, initialErr)
		}
	}

	//  info  3  info failed info ， info channel info
	if initialErr != nil {
		zlog.Errorf("%s [UDPGW-Daemon] ❌ Failed to send initial Keepalive after retries: %v", TAG, initialErr)
		c.Close()
		return
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Daemon] 🚀 Initial Keepalive sent successfully", TAG)
	}

	for {
		select {
		case <-ticker.C:
		case <-c.closed:
			return
		}

		// bidirectional info ，45 info downlink info
		last := c.lastActive.Load()
		if time.Now().Unix()-last > 45 {
			zlog.Errorf("%s [UDPGW-Daemon] ❌ Server heartbeat timeout (45s), connection dead", TAG)
			c.Close()
			return
		}

		// send info
		c.writeLock.Lock()
		_, err := c.Conn.Write(keepalivePkt)
		c.writeLock.Unlock()

		//  info closed info
		if err != nil {
			select {
			case <-c.closed:
				return //  info
			default:
			}
			zlog.Errorf("%s [UDPGW-Daemon] ❌ Failed to write Keepalive: %v", TAG, err)
			c.Close()
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
	totalSize := headerLen + dataLen //  info  LEN  info

	bufPtr := udpBufPool.Get().(*[]byte)
	buffer := (*bufPtr)[:cap(*bufPtr)]
	defer udpBufPool.Put(bufPtr)

	if 2+totalSize > cap(buffer) {
		return 0, fmt.Errorf("payload too large")
	}

	packet := buffer[:2+totalSize]
	binary.BigEndian.PutUint16(packet[0:2], uint16(totalSize))
	packet[2] = UdpgwFlagData                  // tun2proxy  info  Flag: 0x02
	binary.BigEndian.PutUint16(packet[3:5], 1) // CONN_ID: 1

	packet[5] = c.addressType
	copy(packet[6:], c.targetAddressData)
	copy(packet[6+len(c.targetAddressData):], c.targetPortData)
	copy(packet[6+len(c.targetAddressData)+2:], payload)

	if _, err := c.Conn.Write(packet); err != nil {
		select {
		case <-c.closed:
			return 0, io.EOF
		default:
		}
		zlog.Errorf("%s [UDPGW-Write] ❌ Failed to write to tunnel: %v", TAG, err)
		return 0, err
	}

	if Debug {
		zlog.Debugf("%s [UDPGW-Write] 📤 Uplink data sent | Payload: %d bytes, Packed length: %d bytes, ATYP: 0x%02X", TAG, dataLen, totalSize, c.addressType)
	}

	if c.uploadCounter != nil {
		c.uploadCounter(int64(2 + totalSize))
	}
	return dataLen, nil
}

func (c *UdpgwConn) Read(b []byte) (int, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()

	bufPtr := udpBufPool.Get().(*[]byte)
	bodyBuf := (*bufPtr)[:cap(*bufPtr)]
	defer udpBufPool.Put(bufPtr)

	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
			select {
			case <-c.closed:
				return 0, io.EOF
			default:
			}
			zlog.Errorf("%s [UDPGW-Read] ❌ Failed to read packet length: %v", TAG, err)
			return 0, err
		}
		pLen := binary.BigEndian.Uint16(lenBuf[:])

		if int(pLen) > len(bodyBuf) {
			zlog.Errorf("%s [UDPGW-Read] ❌ Packet too large, truncated", TAG)
			return 0, fmt.Errorf("packet too large: %d", pLen)
		}

		if pLen == 0 {
			continue //  info ： info discarded， info  body[0]  info  index out of range  info
		}

		body := bodyBuf[:pLen]
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			select {
			case <-c.closed:
				return 0, io.EOF
			default:
			}
			zlog.Errorf("%s [UDPGW-Read] ❌ Failed to read packet payload: %v", TAG, err)
			return 0, err
		}
		//  info （ info 、 info Error）， info ， info
		c.lastActive.Store(time.Now().Unix())

		flag := body[0]
		switch flag {
		case UdpgwFlagData: // 0x02  info
			offset := 3 //  info  FLAG(1) + CONN_ID(2)
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
				if offset >= int(pLen) {
					break //  info ： info ， info ， info  body[offset]  info  Panic
				}
				offset += int(body[offset]) + 1
			}
			offset += 2 //  info  DST.PORT(2)

			if offset > int(pLen) {
				zlog.Errorf("%s [UDPGW-Read] ❌ Packet out of bounds, safely discarded", TAG)
				continue
			}

			n := copy(b, body[offset:])
			if Debug {
				zlog.Debugf("%s [UDPGW-Read] 📥 Successfully unpacked data | Payload: %d bytes", TAG, n)
			}
			if c.downloadCounter != nil {
				c.downloadCounter(int64(pLen + 2))
			}
			return n, nil

		case UdpgwFlagKeepalive: // 0x01  info
			if Debug {
				zlog.Debugf("%s [UDPGW-Read] 💓 Received remote Keepalive response", TAG)
			}
			continue

		case UdpgwFlagError: // 0x20  info
			zlog.Errorf("%s [UDPGW-Read] ❌ Received remote UDPGW error (Flag: 0x20)! Target may be unreachable or resolution failed", TAG)
			//  info ， info 。 info ， info cleanup info 。
			return 0, fmt.Errorf("remote udpgw server reported error (flag 0x20)")

		default:
			if Debug {
				zlog.Warnf("%s [UDPGW-Read] ⚠️ Received packet with unknown flag (Flag: 0x%02X)", TAG, flag)
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
