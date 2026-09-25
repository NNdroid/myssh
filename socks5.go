package myssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
)

// 本文件实现 SOCKS5 入站处理：TCP CONNECT 中继（直连/代理分流）、
// UDP 关联转发（直连 NAT / UDPGW 隧道）与 DNS 劫持。

type SshProxyHandler struct {
	UdpgwAddr    string
	UdpgwVersion string
}

func (h *SshProxyHandler) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		localAddr := c.LocalAddr().(*net.TCPAddr)
		atyp := byte(socks5.ATYPIPv4)
		ip := localAddr.IP.To4()
		if ip == nil {
			atyp = socks5.ATYPIPv6
			ip = localAddr.IP.To16()
		}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))

		rep := socks5.NewReply(socks5.RepSuccess, atyp, ip, portBytes)
		if _, err := rep.WriteTo(c); err != nil {
			return err
		}
		io.Copy(io.Discard, c)
		return nil
	}

	if r.Cmd == socks5.CmdConnect {
		taskTrack()
		defer taskRelease()

		connKey := c.RemoteAddr().String() + "->" + r.Address()
		tcpConnMap.Store(connKey, c)
		defer tcpConnMap.Delete(connKey)

		mu.Lock()
		client := sshClient
		mu.Unlock()

		if client == nil {
			if Debug {
				zlog.Debugf("%s [SOCKS5-TCP] ⚠️ Tunnel is reconnecting, rejecting connection: %s", TAG, r.Address())
			}
			rep := socks5.NewReply(socks5.RepServerFailure, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
			rep.WriteTo(c)
			return fmt.Errorf("ssh client is currently reconnecting")
		}

		target := r.Address()
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			host = target
		}

		var isDirect bool
		var dialHost string
		if gr := globalRouter.Load(); gr != nil {
			res := gr.ShouldDirect(host)
			isDirect = res.IsDirect
			dialHost = res.DialHost
		} else {
			isDirect = false
			dialHost = host
		}

		var remote net.Conn
		var dialErr error

		if isDirect {
			dialTarget := net.JoinHostPort(dialHost, port)
			remote, dialErr = dialProtected(currentEngineCtx(), ProxyConfig{}, "tcp", dialTarget, 5*time.Second)
		} else {
			remote, dialErr = client.Dial("tcp", target)
		}

		if dialErr != nil {
			rep := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
			_, _ = rep.WriteTo(c)
			return dialErr
		}

		// --- Wrap the outbound connection ---
		remote = WrapConn(remote, target)
		// ------------------------------------

		defer remote.Close()
		rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		if _, err := rep.WriteTo(c); err != nil {
			return err
		}

		errc := make(chan error, 2)
		go func() {
			// Proxy -> Client (Rx for local, Tx for proxy logic if viewed from client's download)
			// remote = direct socket or ssh channel (download data)
			// c = local client
			var err error
			if isDirect {
				_, err = relayStream(c, remote)
			} else {
				_, err = tcpRelay(c, remote)
			}
			errc <- err
		}()
		go func() {
			// Client -> Proxy (Tx for local, Rx for proxy logic if viewed from client's upload)
			// c = local client (upload data)
			// remote = direct socket or ssh channel
			var err error
			if isDirect {
				_, err = relayStream(remote, c)
			} else {
				_, err = tcpRelay(remote, c)
			}
			errc <- err
		}()

		<-errc
		remote.Close()
		c.Close()
		<-errc

		return nil
	}

	rep := socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	_, _ = rep.WriteTo(c)
	return fmt.Errorf("unsupported command: %v", r.Cmd)
}

// udpHandleMaxInFlight 软上限：socks5 库对每个 UDP 包都单独起 goroutine 且无
// 并发上限，UDP 洪水下会形成 goroutine 风暴；超限直接丢包——UDP 语义允许
// 丢弃，优先保住进程整体稳定。
const udpHandleMaxInFlight = 1024

var udpHandleInFlight atomic.Int32

func (h *SshProxyHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	// 🛡️ Panic 防护，抵御 UDP abnormal 数据导致的解析崩溃
	defer func() {
		if err := recover(); err != nil {
			zlog.Errorf("%s [SOCKS5-UDP] 💥 Severe crash (Panic) occurred -> Client: %s, Error: %v", TAG, addr.String(), err)
		}
	}()

	if udpHandleInFlight.Add(1) > udpHandleMaxInFlight {
		udpHandleInFlight.Add(-1)
		if Debug {
			zlog.Warnf("%s [SOCKS5-UDP] 🚦 In-flight UDP handlers exceeded %d, dropping packet -> Source: %s", TAG, udpHandleMaxInFlight, addr.String())
		}
		return nil
	}
	defer udpHandleInFlight.Add(-1)
	dstPort := binary.BigEndian.Uint16(d.DstPort)

	// ==========================================
	// 丢弃 UDP 443 (QUIC)，迫使 client 回退 TCP
	// ==========================================
	if dstPort == 443 {
		if Debug {
			zlog.Debugf("%s [SOCKS5-UDP] 🛡️ Intercepted and silently dropped UDP 443 (QUIC) packet -> Source: %s", TAG, addr.String())
		}
		return nil
	}

	// 提取目标地址
	var targetHost string
	switch d.Atyp {
	case socks5.ATYPIPv4, socks5.ATYPIPv6:
		targetHost = net.IP(d.DstAddr).String()
	case socks5.ATYPDomain:
		if len(d.DstAddr) > 1 {
			targetHost = string(d.DstAddr[1:])
		} else {
			targetHost = "unknown_domain"
		}
	default:
		zlog.Warnf("%s [SOCKS5-UDP] ⚠️ Unknown address type: %v", TAG, d.Atyp)
		return nil
	}

	targetAddrStr := net.JoinHostPort(targetHost, strconv.Itoa(int(dstPort)))

	if Debug {
		zlog.Debugf("%s [SOCKS5-UDP] 📨 Received uplink data | Client: %s | Target: %s | Length: %d bytes", TAG, addr.String(), targetAddrStr, len(d.Data))
	}

	// 劫持 DNS
	if dstPort == 53 {
		gc := globalConfig.Load()
		isConfiguredDNS := strings.Contains(gc.LocalDnsServer, targetAddrStr) ||
			strings.Contains(gc.RemoteDnsServer, targetAddrStr)

		if !isConfiguredDNS {
			if Debug {
				zlog.Debugf("%s [SOCKS5-UDP] 🔍 Triggered DNS hijack -> Target: %s", TAG, targetAddrStr)
			}
			reqMsg := new(dns.Msg)
			if err := reqMsg.Unpack(d.Data); err != nil {
				zlog.Errorf("%s [SOCKS5-UDP] ❌ Failed to parse native DNS: %v", TAG, err)
				return err
			}

			if lds := localDnsServer.Load(); lds != nil {
				replyData, err := lds.HandleDNSRequestPacked(reqMsg)
				if err == nil {
					h.sendSocks5UDPResponse(s, addr, d.Atyp, d.DstAddr, d.DstPort, replyData)
				}
				// 无论成功与否，DNS 包都不再进入 UDP 转发路径
				return err
			}
		} else {
			if Debug {
				zlog.Debugf("%s [SOCKS5-UDP] 🛡️ Target is a configured DNS server (%s), skipping hijack and executing standard routing", TAG, targetAddrStr)
			}
		}
	}

	var isDirect bool
	var dialHost string

	if gr := globalRouter.Load(); gr != nil {
		res := gr.ShouldDirect(targetHost)
		isDirect = res.IsDirect
		dialHost = res.DialHost
	} else {
		isDirect = false
	}

	cloneSlice := func(b []byte) []byte {
		c := make([]byte, len(b))
		copy(c, b)
		return c
	}

	// ==========================================
	// 直连流量，建立本地 UDP NAT 会话
	// ==========================================
	if isDirect {
		directTarget := net.JoinHostPort(dialHost, strconv.Itoa(int(dstPort)))
		sessionKey := addr.String() + "<->" + directTarget

		var uc net.Conn
		if val, ok := udpNatMap.Load(sessionKey); ok {
			uc = val.(net.Conn)
			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] ♻️ Reusing local direct session -> %s", TAG, sessionKey)
			}
		} else {
			rawConn, err := dialProtected(currentEngineCtx(), ProxyConfig{}, "udp", directTarget, 5*time.Second)
			if err != nil {
				zlog.Errorf("%s [ROUTER-Direct] ❌ Failed to establish direct UDP: %v", TAG, err)
				return err
			}

			// --- Wrap the outbound connection ---
			uc = WrapConn(rawConn, directTarget)
			// ------------------------------------

			// LoadOrStore 防止并发包为同一 target 重复建连
			actual, loaded := udpNatMap.LoadOrStore(sessionKey, uc)
			if loaded {
				uc.Close() // 输掉了竞争，关掉冗余连接
				uc = actual.(net.Conn)
			} else {
				if Debug {
					zlog.Debugf("%s [ROUTER-Direct] 🟢 Created new local direct session -> %s", TAG, sessionKey)
				}
				taskTrack()
				// 复制地址切片，防止 datagram 复用导致数据竞争
				dstAddrCopy := cloneSlice(d.DstAddr)
				dstPortCopy := cloneSlice(d.DstPort)
				go func(conn net.Conn, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte, clientAddr *net.UDPAddr) {
					defer taskRelease()
					defer conn.Close()
					defer udpNatMap.Delete(key)

					bufPtr := udpSmallBufPool.Get().(*[]byte)
					// 读满整个缓冲，MTU 内一次读完不浪费
					buf := (*bufPtr)[:cap(*bufPtr)]
					defer udpSmallBufPool.Put(bufPtr)

					for {
						conn.SetReadDeadline(time.Now().Add(60 * time.Second))
						n, err := conn.Read(buf)
						if err != nil {
							if Debug {
								zlog.Debugf("%s [ROUTER-Direct] 🔴 Direct downlink read ended -> Session: %s | Reason: %v", TAG, key, err)
							}
							break
						}
						if Debug {
							zlog.Debugf("%s [ROUTER-Direct] 📥 Received downlink direct data -> Session: %s | Length: %d bytes", TAG, key, n)
						}
						h.sendSocks5UDPResponse(s, clientAddr, dstAtyp, dstAddr, dstPortBytes, buf[:n])
					}
				}(uc, sessionKey, d.Atyp, dstAddrCopy, dstPortCopy, addr)
			}
		}

		n, err := uc.Write(d.Data)
		if err != nil {
			if Debug {
				zlog.Errorf("%s [ROUTER-Direct] ❌ Failed to write uplink data -> %s: %v", TAG, sessionKey, err)
			}
		} else {
			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] 📤 Successfully wrote uplink data -> %s | Length: %d bytes", TAG, sessionKey, n)
			}
		}
		return nil
	}

	// ==========================================
	// 代理流量，通过 UDPGW 隧道转发
	// ==========================================
	if h.UdpgwAddr == "" {
		if Debug {
			zlog.Warnf("%s [ROUTER-Proxy] ⚠️ Intercepted UDP packet -> Target: %s | Reason: UDPGW is not configured", TAG, targetAddrStr)
		}
		return nil
	}

	sessionKey := addr.String() + "<->" + targetAddrStr
	var uConn net.Conn

	if val, ok := udpgwMap.Load(sessionKey); ok {
		uConn = val.(net.Conn)
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] ♻️ Reusing proxy session (UDPGW) -> Client: %s", TAG, sessionKey)
		}
	} else {
		// singleflight：同一 UDP sessionKey 的并发 Dial 只执行一次，否则并发
		// channel open 会让 SSH 服务端回复 "unexpected packet in response to
		// channel open" 并直接断开连接。
		result, derr, _ := udpDialGroup.Do(sessionKey, func() (interface{}, error) {
			// 双检等待：进入单飞后可能已有别的调用方建好连接
			if existing, ok := udpgwMap.Load(sessionKey); ok {
				return existing.(net.Conn), nil
			}
			mu.Lock()
			client := sshClient
			mu.Unlock()

			if client == nil {
				if Debug {
					zlog.Warnf("%s [ROUTER-Proxy] ⚠️ Rejected UDP packet -> Target: %s | Reason: SSH is not connected", TAG, targetAddrStr)
				}
				return nil, fmt.Errorf("ssh client not ready")
			}

			var derr2 error
			var dconn net.Conn
			if h.UdpgwVersion == "badvpn" {
				if Debug {
					zlog.Debugf("%s [ROUTER-Proxy] 🚀 Selected Badvpn protocol to establish UDPGW tunnel", TAG)
				}
				dconn, derr2 = DialBadvpnUdpgw(client, h.UdpgwAddr, targetAddrStr)
			} else {
				if Debug {
					zlog.Debugf("%s [ROUTER-Proxy] 🚀 Selected Tun2Proxy protocol to establish UDPGW tunnel", TAG)
				}
				dconn, derr2 = DialTun2proxyUdpgw(client, h.UdpgwAddr, targetAddrStr)
			}
			if derr2 != nil {
				return nil, derr2
			}

			// --- Wrap the UDPGW connection ---
			dconn = WrapConn(dconn, fmt.Sprintf("UDPGW->%s", targetAddrStr))
			// ---------------------------------

			actual, loaded := udpgwMap.LoadOrStore(sessionKey, dconn)
			if loaded {
				dconn.Close()
				return actual.(net.Conn), nil
			}

			if Debug {
				zlog.Debugf("%s [ROUTER-Proxy] 🟢 Created new proxy session (UDPGW) -> Client: %s | Tunnel target: %s", TAG, sessionKey, targetAddrStr)
			}
			taskTrack()
			dstAddrCopy := cloneSlice(d.DstAddr)
			dstPortCopy := cloneSlice(d.DstPort)
			go func(conn net.Conn, clientAddr *net.UDPAddr, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte) {
				defer taskRelease()
				defer conn.Close()
				defer udpgwMap.Delete(key)

				bufPtr := udpBufPool.Get().(*[]byte)
				buf := (*bufPtr)[:cap(*bufPtr)]
				defer udpBufPool.Put(bufPtr)

				for {
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, rerr := conn.Read(buf)
					if rerr != nil {
						if Debug {
							zlog.Debugf("%s [ROUTER-Proxy] 🔴 Proxy downlink read ended -> Session: %s | Reason: %v", TAG, key, rerr)
						}
						break
					}
					if Debug {
						zlog.Debugf("%s [ROUTER-Proxy] 📥 Received downlink proxy data -> Session: %s | Payload: %d bytes", TAG, key, n)
					}
					h.sendSocks5UDPResponse(s, clientAddr, dstAtyp, dstAddr, dstPortBytes, buf[:n])
				}
			}(dconn, addr, sessionKey, d.Atyp, dstAddrCopy, dstPortCopy)

			return dconn, nil
		})
		if derr != nil {
			zlog.Errorf("%s [ROUTER-Proxy] ❌ Failed to establish UDPGW tunnel -> Target: %s | Error: %v", TAG, targetAddrStr, derr)
			// channel open 意外回复说明 SSH 连接已死，触发强制重连
			if isSSHConnectionLost(derr) {
				triggerSSHReconnect()
			}
			return derr
		}
		uConn = result.(net.Conn)
	}

	// 注意：UdpgwConn.Write 自带 UDPGW 帧封装
	n, err := uConn.Write(d.Data)
	if err != nil {
		if Debug {
			zlog.Errorf("%s [ROUTER-Proxy] ❌ Failed to write proxy data -> Session: %s | Error: %v", TAG, sessionKey, err)
		}
		uConn.Close()
		udpgwMap.Delete(sessionKey)
	} else {
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] 📤 Successfully wrote proxy data -> Session: %s | Length: %d bytes", TAG, sessionKey, n)
		}
	}
	return err
}

// sendSocks5UDPResponse 打包 SOCKS5 UDP 回程报文并写回客户端
func (h *SshProxyHandler) sendSocks5UDPResponse(s *socks5.Server, clientAddr *net.UDPAddr, atyp byte, addr []byte, port []byte, data []byte) {
	outLen := 3 + 1 + len(addr) + 2 + len(data)
	outBufPtr := udpBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer udpBufPool.Put(outBufPtr)

	var outPkt []byte
	if outLen <= cap(outBuf) {
		outPkt = outBuf[:outLen]
	} else {
		// 极端情况：直接分配，不阻塞
		outPkt = make([]byte, outLen)
	}

	outPkt[0], outPkt[1], outPkt[2] = 0x00, 0x00, 0x00
	outPkt[3] = atyp
	copy(outPkt[4:], addr)
	copy(outPkt[4+len(addr):], port)
	copy(outPkt[4+len(addr)+2:], data)
	s.UDPConn.WriteToUDP(outPkt, clientAddr)
}
