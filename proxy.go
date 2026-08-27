package myssh

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

const TAG = "[M]"

var (
	sshClient    *ssh.Client
	socksServer  *socks5.Server
	mu           sync.Mutex
	globalConfig atomic.Pointer[GlobalConfig]
	globalRouter atomic.Pointer[GeoRouter]

	//  info
	engineCancel context.CancelFunc

	//  info ： info  Stop  info ， info  goroutine  info  ctx  info 。
	//  info  atomic.Pointer[context.Context]  info  atomic.Value： info  Store  info ，
	//  info  context.Background()(*emptyCtx)  info  WithCancel  info (*cancelCtx)  info  inconsistent store panic。
	engineCtxHolder atomic.Pointer[context.Context]

	//  info
	udpNatMap  sync.Map
	tcpConnMap sync.Map
	udpgwMap   sync.Map //  info  UDP client ->  info  UDPGW  info  TCP  info

	wg sync.WaitGroup

	//  info  singleflight： info  UDP  info  info  UDPGW  info  info ， info  info  info
	//  info  sshClient.Dial  info  info  info ， info  channel open  info  info  "unexpected packet"  info
	udpDialGroup singleflight.Group
)

// init  info  globalConfig  info  nil  info ， info  startSshTProxy  info
// loadGlobalConfigFromJson  info ，DNS  info / info  globalConfig.Load()  info  nil  info  panic。
//
//	info  globalConfig  info （ info ）， info 。
func init() {
	globalConfig.Store(&GlobalConfig{})
}

// ----- tunnel info  ( info mode) -----

// currentEngineCtx  info ， info ； info  Background。
func currentEngineCtx() context.Context {
	if v := engineCtxHolder.Load(); v != nil {
		return *v
	}
	return context.Background()
}

type TunnelHandler func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error)

type TunnelProtocol struct {
	Network string        //  info : "tcp", "udp",  info  "none"
	Handler TunnelHandler //  info
}

var tunnelRegistry = make(map[string]TunnelProtocol)

// RegisterTunnel  info tunnel info tunnel info 。
// name  info （ info  "h2"/"grpc"），network  info （"tcp"/"udp"/"none"），handler  info 。
func RegisterTunnel(name string, network string, handler TunnelHandler) {
	tunnelRegistry[name] = TunnelProtocol{
		Network: network,
		Handler: handler,
	}
}

// GetTunnel  info tunnel info ； info 。
func GetTunnel(name string) (TunnelProtocol, error) {
	if proto, ok := tunnelRegistry[name]; ok {
		return proto, nil
	}
	return TunnelProtocol{}, fmt.Errorf("unsupported tunnel type: %s", name)
}

// -----  info config -----

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// ----- SOCKS5  info  -----

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
		wg.Add(1)
		defer wg.Done()

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

func (h *SshProxyHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	// 🛡️ Panic  info ， info  UDP abnormal info
	defer func() {
		if err := recover(); err != nil {
			zlog.Errorf("%s [SOCKS5-UDP] 💥 Severe crash (Panic) occurred -> Client: %s, Error: %v", TAG, addr.String(), err)
		}
	}()
	dstPort := binary.BigEndian.Uint16(d.DstPort)

	// ==========================================
	//  info  UDP 443 (QUIC)  info client info  TCP
	// ==========================================
	if dstPort == 443 {
		if Debug {
			zlog.Debugf("%s [SOCKS5-UDP] 🛡️ Intercepted and silently dropped UDP 443 (QUIC) packet -> Source: %s", TAG, addr.String())
		}
		return nil
	}

	//  info targetaddress
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

	//  info  DNS
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
				replyMsg, err := lds.HandleDnsRequest(reqMsg)
				if err == nil && replyMsg != nil {
					replyData, _ := replyMsg.Pack()
					h.sendSocks5UDPResponse(s, addr, d.Atyp, d.DstAddr, d.DstPort, replyData)
				}
				//  info ， info  DNS  info  UDP  info
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
	//  info ， info  UDP  info
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

			//  info  LoadOrStore  info target info
			actual, loaded := udpNatMap.LoadOrStore(sessionKey, uc)
			if loaded {
				uc.Close() //  info ， info
				uc = actual.(net.Conn)
			} else {
				if Debug {
					zlog.Debugf("%s [ROUTER-Direct] 🟢 Created new local direct session -> %s", TAG, sessionKey)
				}
				wg.Add(1)
				//  info address info ， info
				dstAddrCopy := cloneSlice(d.DstAddr)
				dstPortCopy := cloneSlice(d.DstPort)
				go func(conn net.Conn, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte, clientAddr *net.UDPAddr) {
					defer wg.Done()
					defer conn.Close()
					defer udpNatMap.Delete(key)

					bufPtr := udpSmallBufPool.Get().(*[]byte)
					//  info ， info  cap  info ， info  0  info
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
	//  info ， info  UDPGW  info
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
		// singleflight： info  UDP  info  sessionKey  info  info  Dial  info ， info  info  SSH  info
		// concurrent channel open  info  info  "unexpected packet in response to channel open"  info
		result, derr, _ := udpDialGroup.Do(sessionKey, func() (interface{}, error) {
			//  info  info ： info  info  info  info  info
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
			wg.Add(1)
			dstAddrCopy := cloneSlice(d.DstAddr)
			dstPortCopy := cloneSlice(d.DstPort)
			go func(conn net.Conn, clientAddr *net.UDPAddr, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte) {
				defer wg.Done()
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
			// channel open  info  info  SSH  info  info ， info  info  info  info
			if isSSHConnectionLost(derr) {
				triggerSSHReconnect()
			}
			return derr
		}
		uConn = result.(net.Conn)
	}

	//  info ：UdpgwConn.Write  info  UDPGW  info
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

// info  SOCKS5 UDP  info
func (h *SshProxyHandler) sendSocks5UDPResponse(s *socks5.Server, clientAddr *net.UDPAddr, atyp byte, addr []byte, port []byte, data []byte) {
	outLen := 3 + 1 + len(addr) + 2 + len(data)
	outBufPtr := udpBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer udpBufPool.Put(outBufPtr)

	var outPkt []byte
	if outLen <= cap(outBuf) {
		outPkt = outBuf[:outLen]
	} else {
		//  info ： info ， info
		outPkt = make([]byte, outLen)
	}

	outPkt[0], outPkt[1], outPkt[2] = 0x00, 0x00, 0x00
	outPkt[3] = atyp
	copy(outPkt[4:], addr)
	copy(outPkt[4+len(addr):], port)
	copy(outPkt[4+len(addr)+2:], data)
	s.UDPConn.WriteToUDP(outPkt, clientAddr)
}

// -----  info  -----

func wgWait() {
	zlog.Infof("%s [Core] Waiting for all background tasks to exit completely...", TAG)
	wg.Wait()
	zlog.Infof("%s [Core] ✅ All background tasks safely cleaned up, program can exit safely", TAG)
}

func killActiveProxyConnections() {
	count := 0
	tcpConnMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			count++
		}
		tcpConnMap.Delete(key)
		return true
	})
	if count > 0 {
		zlog.Infof("%s [AutoSSH] 🧹 Cleaned up %d residual TCP proxy sessions due to disconnection", TAG, count)
	}
}

// isSSHConnectionLost  info  error  info  SSH  info  info 。
// golang.org/x/crypto/ssh  info  openChannel  info  info  SSH  info  info  info
// channel open  info  info  ch.msg  info  info  info  info  <nil>  info
//
//	info  info  "unexpected packet in response to channel open"  info  info  info
func isSSHConnectionLost(err error) bool {
	if err == nil {
		return false
	}
	//  info  channel open  info  info  SSH  info  info  info  info  info
	if strings.Contains(err.Error(), "unexpected packet in response to channel open") {
		return true
	}
	return false
}

// triggerSSHReconnect  info  SSH  info  info  info  info  info  AutoSSH  info  info 。
//
//	info  udpgwMap/tcpConnMap  info  info  info  info  SSH 信息 信息 信息 信息 信息 信息 信息
//
// 信息 sshClient 信息 信息  client.Close() 信息 信息  AutoSSH 信息  client.Wait() 信息 信息 信息 信息
func triggerSSHReconnect() {
	mu.Lock()
	client := sshClient
	sshClient = nil
	mu.Unlock()

	if client == nil {
		return
	}

	zlog.Warnf("%s [AutoSSH] 🔥 SSH connection lost during UDPGW tunnel establishment, forcing reconnect...", TAG)

	// 信息 udpgw 信息 （信息 SSH 信息 信息 信息 信息 信息 信息）
	udpgwMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		udpgwMap.Delete(key)
		return true
	})

	// 信息 TCP 信息
	killActiveProxyConnections()

	// 信息 SSH 信息 信息  AutoSSH 信息  client.Wait() 信息 信息 信息 信息
	client.Close()
}

func maintainKeepAlive(ctx context.Context, client *ssh.Client) {
	//  info  18  info
	ticker := time.NewTicker(18 * time.Second)
	defer ticker.Stop()

	type keepAliveResult struct {
		err      error
		duration time.Duration
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resCh := make(chan keepAliveResult, 1)

			go func() {
				start := time.Now() // 🌟  info
				// send SSH  info
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				duration := time.Since(start) // 🌟  info

				resCh <- keepAliveResult{
					err:      err,
					duration: duration,
				}
			}()

			select {
			case <-ctx.Done():
				return

			case res := <-resCh:
				if res.err != nil {
					zlog.Warnf("%s [AutoSSH] ⚠️ Failed to send heartbeat: %v (Preparing to disconnect and rebuild)", TAG, res.err)
					client.Close()
					return
				}
				zlog.Infof("%s [AutoSSH] 💓 Heartbeat normal | Latency: %dms", TAG, res.duration.Milliseconds())

			case <-time.After(8 * time.Second):
				zlog.Warnf("%s [AutoSSH] ⚠️ Heartbeat response timed out severely (suspected network freeze), forcibly cutting off and rebuilding", TAG)
				client.Close()
				return
			}
		}
	}
}

// startSshTProxy  info  AutoSSH mode info ： info  DNS  info 、SOCKS5  info ，
//
//	info  SSH tunnel info 。 info  0  info Started successfully， info  0  info 。
func startSshTProxy(configJson string) int {
	stopSshTProxy()

	PrintAndroidUserInfo()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ Failed to parse config JSON: %v", TAG, err)
		emitError(-1, "config parse failed: "+err.Error())
		emitState(StateError, err.Error())
		return -1
	}

	var ctx context.Context
	ctx, engineCancel = context.WithCancel(context.Background())
	engineCtxHolder.Store(&ctx)

	emitState(StateStarting, "")
	zlog.Infof("%s [Core] ==================== Starting proxy engine (AutoSSH mode) ====================", TAG)

	//  info  DNS  info
	NewLocalDnsServer(cfg.UdpgwAddr, cfg.UdpgwVersion)

	//  info  DNS  info
	if lds := localDnsServer.Load(); lds != nil {
		lds.Start(cfg.DnsAddr)
	}

	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		zlog.Errorf("%s [SOCKS5] ❌ Failed to create SOCKS5 server instance: %v", TAG, err)
		emitError(-4, err.Error())
		emitState(StateError, err.Error())
		return -4
	}

	mu.Lock()
	socksServer = srv
	mu.Unlock()

	handler := &SshProxyHandler{
		UdpgwAddr:    cfg.UdpgwAddr, //  info config info ， info disable UDPGW
		UdpgwVersion: cfg.UdpgwVersion,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 proxy service started: %s", TAG, cfg.LocalAddr)
		if err := srv.ListenAndServe(handler); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			zlog.Errorf("%s [SOCKS5] ❌ Service exited abnormally: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 service has completely stopped", TAG)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				zlog.Infof("%s [AutoSSH] Received global stop signal, daemon exiting", TAG)
				return
			default:
			}

			zlog.Infof("%s [AutoSSH] 🔄 Attempting to establish tunnel and SSH connection...", TAG)
			emitState(StateConnecting, cfg.SshAddr)
			emitNodeEvent(cfg.SshAddr, NodeEventConnecting, "")
			client, _, err := DialNode(ctx, cfg, false)
			if err != nil {
				zlog.Errorf("%s [AutoSSH] ❌ Connection failed: %v", TAG, err)
				emitState(StateReconnecting, err.Error())
				emitNodeEvent(cfg.SshAddr, NodeEventFailed, err.Error())
				time.Sleep(3 * time.Second)
				continue
			}

			mu.Lock()
			sshClient = client
			mu.Unlock()
			zlog.Infof("%s [AutoSSH] ✅ SSH tunnel established successfully, global traffic taken over!", TAG)
			emitState(StateConnected, cfg.SshAddr)
			emitNodeEvent(cfg.SshAddr, NodeEventConnected, "")

			go maintainKeepAlive(ctx, client)

			err = client.Wait()
			zlog.Warnf("%s [AutoSSH] ⚠️ Tunnel disconnected (%v), preparing to reconnect automatically...", TAG, err)
			emitState(StateReconnecting, err.Error())

			mu.Lock()
			sshClient = nil
			mu.Unlock()

			killActiveProxyConnections()

			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	return 0
}

// stopSshTProxy  info ， info cleanup info  SSH/ info 、DNS  info  SOCKS5  info 。
func stopSshTProxy() {
	mu.Lock()
	defer mu.Unlock()

	if engineCancel != nil {
		engineCancel()
		engineCancel = nil
	}
	b := context.Background()
	engineCtxHolder.Store(&b)

	zlog.Infof("%s [Core] Stopping resources...", TAG)
	emitState(StateStopped, "")

	if lds := localDnsServer.Load(); lds != nil {
		lds.Stop()
	}
	localDnsServer.Store(nil)

	if socksServer != nil {
		socksServer.Shutdown()
		socksServer = nil
	}
	if sshClient != nil {
		sshClient.Close()
		sshClient = nil
	}

	killActiveProxyConnections()

	udpSessionCount := 0
	udpNatMap.Range(func(key, value interface{}) bool {
		//  info ： info  value.(*net.UDPConn)， info  TrackedConn
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			udpSessionCount++
		}
		udpNatMap.Delete(key)
		return true
	})
	if udpSessionCount > 0 {
		zlog.Infof("%s [Core] Forcibly disconnected %d active UDP sessions", TAG, udpSessionCount)
	}

	udpgwSessionCount := 0
	udpgwMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			udpgwSessionCount++
		}
		udpgwMap.Delete(key)
		return true
	})
	if udpgwSessionCount > 0 {
		zlog.Infof("%s [Core] Forcibly disconnected %d UDPGW proxy sessions", TAG, udpgwSessionCount)
	}

	zlog.Infof("%s [Core] All active SSH/Proxy connections destroyed", TAG)
}

func dialSSH(ctx context.Context, conn net.Conn, cfg ProxyConfig, isPing bool) (*ssh.Client, error) {
	var sshAuthMethod []ssh.AuthMethod
	if cfg.AuthType == "password" {
		sshAuthMethod = []ssh.AuthMethod{
			ssh.Password(cfg.Pass),
		}
	} else {
		signer, err := parsePrivateKeySshSigner([]byte(cfg.PrivateKey), []byte(cfg.PrivateKeyPassphrase))
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}
		sshAuthMethod = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	var hostKeyCallback ssh.HostKeyCallback
	if isPing {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fpSHA256 := ssh.FingerprintSHA256(key)
			fpMD5 := ssh.FingerprintLegacyMD5(key)
			algo := key.Type()
			pubKey := string(ssh.MarshalAuthorizedKey(key))
			zlog.Debugf("%s [SSH-Handshake] ==== SSH Host Key Info ====", TAG)
			zlog.Debugf("%s [SSH-Handshake] Host: %s", TAG, hostname)
			zlog.Debugf("%s [SSH-Handshake] Remote: %s", TAG, remote.String())
			zlog.Debugf("%s [SSH-Handshake] Algorithm: %s", TAG, algo)
			zlog.Debugf("%s [SSH-Handshake] Fingerprint (SHA256): %s", TAG, fpSHA256)
			zlog.Debugf("%s [SSH-Handshake] Fingerprint (MD5): %s", TAG, fpMD5)
			zlog.Debugf("%s [SSH-Handshake] PublicKey: %s", TAG, pubKey)
			zlog.Debugf("%s [SSH-Handshake] ===========================", TAG)
			if cfg.VerifySSHFingerprint {
				if !(fpMD5 == cfg.ServerSSHFingerprint || fpSHA256 == cfg.ServerSSHFingerprint) {
					return fmt.Errorf("host key [%s,%s] mismatch: %s", fpMD5, fpSHA256, cfg.ServerSSHFingerprint)
				}
			}
			return nil
		}
	}

	timeout := 15 * time.Second
	if isPing {
		if d, ok := ctx.Deadline(); ok {
			timeout = time.Until(d)
		} else {
			timeout = 5 * time.Second
		}
	}

	sshConfig := &ssh.ClientConfig{
		User: cfg.User,
		Auth: sshAuthMethod,
		BannerCallback: func(message string) error {
			if !isPing {
				zlog.Warnf("===== SSH Banner START =====\n%s\n===== SSH Banner END =====", message)
			}
			return nil
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
			},
		},
		HostKeyAlgorithms: []string{
			"ssh-ed25519",
			"ecdsa-sha2-nistp256",
			"rsa-sha2-512",
			"rsa-sha2-256",
		},
	}

	scc, chans, reqs, err := ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
	if err != nil {
		return nil, err
	}

	if !isPing {
		cv := string(scc.ClientVersion())
		sv := string(scc.ServerVersion())
		zlog.Warnf("%s [SSH-Handshake] SSH ClientVersion: %s", TAG, cv)
		zlog.Warnf("%s [SSH-Handshake] SSH ServerVersion: %s", TAG, sv)
	}

	client := ssh.NewClient(scc, chans, reqs)
	return client, nil
}
