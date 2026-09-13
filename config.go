package myssh

import (
	"encoding/json"
	"os"
)

type ProxyConfig struct {
	LocalAddr            string `json:"local_addr"`              // 本地 SOCKS5/HTTP 监听地址 host:port
	SshAddr              string `json:"ssh_addr"`                // SSH 服务端地址 host:port（隧道最终要打通的目标）
	User                 string `json:"user"`                    // SSH 登录用户名
	AuthType             string `json:"auth_type"`               // SSH 认证方式："password" 用 Pass；其它按公钥（PrivateKey）
	PrivateKey           string `json:"private_key"`             // SSH 私钥（PEM）；auth_type != "password" 时使用
	PrivateKeyPassphrase string `json:"private_key_passphrase"`  // 私钥口令；无口令留空
	Pass                 string `json:"pass"`                    // SSH 密码；auth_type == "password" 时使用
	VerifySSHFingerprint bool   `json:"verify_ssh_finger_print"` // 是否校验 SSH 主机密钥指纹（TOFU/pin）
	ServerSSHFingerprint string `json:"server_ssh_finger_print"` // 期望的 SSH 主机密钥 SHA-256 指纹；上项开启时必填
	TunnelType           string `json:"tunnel_type"`             // 传输类型：raw/websocket/http/h2/grpc/h3/webtransport/masque/quic/xhttp/kcptun/udp_custom/dns_custom/icmp_custom
	// TunnelTLSEnabled 是合并型隧道（raw/websocket/h2/grpc/xhttp）的 TLS
	// 开关；固定 TLS 的类型（h3/quic/wt/masque 等）与无 TLS 概念的类型
	// （kcp/udp_custom/...）忽略它。
	TunnelTLSEnabled             bool   `json:"tunnel_tls_enabled"`              // 合并型隧道（raw/websocket/h2/grpc/xhttp）的 TLS 开关
	ProxyAddr                    string `json:"proxy_addr"`                      // 代理/隧道服务端 endpoint（http(s)://host:port 或 host:port；udp_custom 可为端口范围）
	ProxyAuthRequired            bool   `json:"proxy_auth_required"`             // 是否启用代理层鉴权
	ProxyAuthToken               string `json:"proxy_auth_token"`                // Bearer/PSK token（h2 家族、xhttp）
	ProxyAuthUser                string `json:"proxy_auth_user"`                 // Basic 鉴权用户名（websocket/http）
	ProxyAuthPass                string `json:"proxy_auth_pass"`                 // Basic 鉴权密码（websocket/http）
	CustomHost                   string `json:"custom_host"`                     // 覆盖请求 Host 头（伪装 / CDN 前置）
	ServerName                   string `json:"server_name"`                     // TLS SNI（Server Name Indication）
	HttpPayload                  string `json:"http_payload"`                    // http 隧道的自定义请求头 / CONNECT 模板
	CustomPath                   string `json:"custom_path"`                     // 覆盖请求路径（各类型默认路径不同）
	UdpgwAddr                    string `json:"udpgw_addr"`                      // UDPGW 上游地址（UDP / DNS 转发），可空
	DisableStatusCheck           bool   `json:"disable_status_check"`            // 跳过 http 隧道的连通性状态探测
	Alpn                         string `json:"alpn"`                            // ALPN 协议列表（逗号分隔）；仅 xhttp 读取，其余固定
	VerifyCertificateFingerprint bool   `json:"verify_certificate_finger_print"` // 是否启用 TLS 证书指纹 pinning
	ServerCertificateFingerprint string `json:"server_certificate_finger_print"` // 期望的服务端叶子证书 SHA-256 指纹
	DnsAddr                      string `json:"dns_addr"`                        // 远端 DNS 地址
	UdpgwVersion                 string `json:"udpgw_version"`                   // UDPGW 方言："badvpn"；其它/空 = tun2socks 默认帧
	BindInterface                string `json:"bind_interface"`                  // 出站绑定网卡；空 = 不绑定

	// DNS Custom（SSH-over-DNS）隧道 config
	DnsTunnelDomain    string   `json:"dns_tunnel_domain"`     // 隧道根域名，如 "tunnel.example.com"
	DnsTunnelServers   []string `json:"dns_tunnel_servers"`    // DNS 上游地址列表（可多条），scheme：udp(默认)/tcp:///tls:///dot:///https://
	DnsTunnelType      string   `json:"dns_tunnel_type"`       // 承载记录类型：txt(默认)/null/cname/a
	DnsTunnelPublicKey string   `json:"dns_tunnel_public_key"` // Noise 服务端公钥；可空
	DnsTunnelEDNS0     bool     `json:"dns_tunnel_edns0"`      // announce 1232-byte DNS answers; server must match
	DnsTunnelPsk       string   `json:"dns_tunnel_psk"`        // PSK auth secret for dns servers configured with psks; empty = anonymous
	DnsTunnelMarker    string   `json:"dns_tunnel_marker"`     // custom tunnel marker label; both ends must agree; empty = default

	// KCP (kcptun protocol) tunnel config
	KcpPassword     string `json:"kcp_password"`      // kcptun key
	KcpCrypt        string `json:"kcp_crypt"`         // kcptun crypt: null/none/aes-128/aes-192/aes/aes-128-gcm/sm4/tea/xtea/salsa20/blowfish/twofish/cast5/3des/xor
	KcpMode         string `json:"kcp_mode"`          // ""/normal/fast(default)/fast2/fast3
	KcpDataShards   int    `json:"kcp_data_shards"`   // FEC data shards (default 10)
	KcpParityShards int    `json:"kcp_parity_shards"` // FEC parity shards (default 3)
	KcpSndWnd       int    `json:"kcp_sndwnd"`        // send window (default 128)
	KcpRcvWnd       int    `json:"kcp_rcvwnd"`        // receive window (default 512)
	KcpMtu          int    `json:"kcp_mtu"`           // MTU (default 1350)
	KcpNoComp       bool   `json:"kcp_nocomp"`        // disable session-level Snappy
	KcpSmuxVer      int    `json:"kcp_smuxver"`       // SMUX version 1/2 (default 2)
	KcpKeepAlive    int    `json:"kcp_keepalive"`     // seconds (default 10)

	// UDP Custom 隧道 config
	UdpCustomPsk        string `json:"udp_custom_psk"`         // 预共享密钥（PSK 鉴权）
	UdpCustomMagic      string `json:"udp_custom_magic"`       // 4 字节魔数（支持 0x/十六进制），默认 "UDPC"
	UdpCustomPublicKey  string `json:"udp_custom_public_key"`  // Noise 服务端公钥（hex/base64），可空
	UdpCustomPaths      int    `json:"udp_custom_paths"`       // UDP Custom multipath path count (client-selected random ports); 0 => 32
	UdpCustomSockets    int    `json:"udp_custom_sockets"`     // local UDP sockets; 0 => 1
	UdpCustomSendWindow int    `json:"udp_custom_send_window"` // in-flight frames; 0 => SDK default 256
	UdpCustomMaxPkt     int    `json:"udp_custom_max_pkt"`     // largest v2 record on the wire (UDP payload bytes); 0 => SDK default 1450; probe ceiling when MtuProbe on
	UdpCustomMtuProbe   string `json:"udp_custom_mtu_probe"`   // auto path-MTU probing: ""/auto (default: enabled), "on" (force enable), "off" (pin MaxPkt verbatim)

	// ICMP Custom tunnel (SSH-over-ICMP) config
	IcmpCustomPsk        string `json:"icmp_custom_psk"`         // ICMP Custom PSK (mandatory)
	IcmpCustomMagic      string `json:"icmp_custom_magic"`       // 4-byte record magic as 8 hex chars; empty = SDK MagicDefault
	IcmpCustomPublicKey  string `json:"icmp_custom_public_key"`  // server Noise static key (hex 64 / base64); empty = PSK-only
	IcmpCustomMtuMode    string `json:"icmp_custom_mtu_mode"`    // ""/probe (default), auto, fixed
	IcmpCustomMaxPayload int    `json:"icmp_custom_max_payload"` // complete-record ceiling; 0 = SDK default
	IcmpCustomPaceMS     int    `json:"icmp_custom_pace_ms"`     // outbound packet spacing; 0 = SDK default
	IcmpCustomIdRange    string `json:"icmp_custom_id_range"`    // echo identifier pool, e.g. "1000-1999"

	// XHTTP tunnel (xhttp/xhttpc) config
	XhttpChunkSizeKB int    `json:"xhttp_chunk_size_kb"` // upstream request body in KB; default 256, range 16-900
	XhttpStreamMode  string `json:"xhttp_stream_mode"`   // downlink transport: ""/"auto" (default: streaming with polling fallback), "stream", "poll"

	// Resume/2 空闲心跳间隔（毫秒）。0 表示使用默认 25000ms。
	// 在 CDN/反代 idle 阈值之前主动发 KEEPALIVE 帧保活主流，避免空闲流被掐断。
	HeartbeatIntervalMs int `json:"heartbeat_interval_ms"` // 空闲心跳保活间隔(ms)；0→默认 25000；仅 h2 家族

	// h2tunnel 家族（h2/grpc/h3/webtransport/masque）新增调优（padding 现覆盖全部 h2tunnel 传输）：
	// PaddingMinBytes 出站记录填充下限：0 => myssh 默认 1420；负数 => 关闭填充；正数 => 该下限（须 >16）。上限由 h2tunnel 自动取 min+25%。
	// MasqueAlpn 仅 masque 有效：SDK 取值 ""(auto)/"h2"/"h3"；配置面 "h3,h2"(或空/auto)=>auto、"h3"=>h3、"h2"=>h2。
	PaddingMinBytes int    `json:"padding_min_bytes"` // 填充下限字节；0→默认1420，负→关闭，正→按值(>16)；仅 h2 家族
	MasqueAlpn      string `json:"masque_alpn"`       // masque 承载 ALPN："h3,h2"→auto / h3 / h2；仅 masque
}

type GlobalConfig struct {
	LocalDnsServer  string   `json:"local_dns_server"`  // 本地 DNS 监听地址（默认 223.5.5.5:53 由 loadGlobalConfig 回填）
	RemoteDnsServer string   `json:"remote_dns_server"` // 远端 DNS 服务器（默认 8.8.8.8:53 由 loadGlobalConfig 回填）
	GeoSiteFilePath string   `json:"geosite_filepath"`  // geosite.dat 路径（域名分流规则，默认 "geosite.dat"）
	GeoIPFilePath   string   `json:"geoip_filepath"`    // geoip.dat 路径（IP 分流规则，默认 "geoip.dat"）
	DirectSiteTags  []string `json:"direct_site_tags"`  // 命中即直连的 geosite 标签集合
	DirectIPTags    []string `json:"direct_ip_tags"`    // 命中即直连的 geoip 标签集合
}

func loadGlobalConfigFromJson(configJson string) int {
	var cfg GlobalConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Config] ❌ Failed to parse global config JSON: %v\nInput JSON content: %s", TAG, err, configJson)
		return -2
	}
	return loadGlobalConfig(cfg)
}

func loadGlobalConfig(cfg GlobalConfig) int {
	// 注意：不要在这里持有全局 mu——geosite/geoip 的 IO+解析可能耗时数百毫秒，
	// 会把 TCPHandle 里对 sshClient 的读取一并阻塞。函数内部只操作局部变量和
	// atomic 存储（globalRouter/globalConfig），本身无需加锁。
	if cfg.LocalDnsServer == "" {
		cfg.LocalDnsServer = "223.5.5.5:53"
	}
	if cfg.RemoteDnsServer == "" {
		cfg.RemoteDnsServer = "8.8.8.8:53"
	}
	if cfg.GeoSiteFilePath == "" {
		cfg.GeoSiteFilePath = "geosite.dat"
	}
	if cfg.GeoIPFilePath == "" {
		cfg.GeoIPFilePath = "geoip.dat"
	}

	zlog.Infof("%s [Config] ✅ Global config applied: LocalDNS=[%s], RemoteDNS=[%s]", TAG, cfg.LocalDnsServer, cfg.RemoteDnsServer)

	gr := newGeoRouter()
	if _, err := os.Stat(cfg.GeoSiteFilePath); err == nil {
		if err := gr.LoadGeoSite(cfg.GeoSiteFilePath, cfg.DirectSiteTags); err != nil {
			zlog.Errorf("%s [Config] ❌ Failed to load GeoSite: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoSite loaded successfully", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ GeoSite file not found (%s), direct domain routing disabled", TAG, cfg.GeoSiteFilePath)
	}

	if _, err := os.Stat(cfg.GeoIPFilePath); err == nil {
		if err := gr.LoadGeoIP(cfg.GeoIPFilePath, cfg.DirectIPTags); err != nil {
			zlog.Errorf("%s [Config] ❌ Failed to load GeoIP: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoIP loaded successfully", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ GeoIP file not found (%s), direct IP routing disabled", TAG, cfg.GeoIPFilePath)
	}

	globalRouter.Store(gr)
	globalConfig.Store(&cfg)

	return 0
}
