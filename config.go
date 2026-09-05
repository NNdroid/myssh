package myssh

import (
	"encoding/json"
	"os"
)

type ProxyConfig struct {
	LocalAddr                    string `json:"local_addr"`
	SshAddr                      string `json:"ssh_addr"`
	User                         string `json:"user"`
	AuthType                     string `json:"auth_type"`
	PrivateKey                   string `json:"private_key"`
	PrivateKeyPassphrase         string `json:"private_key_passphrase"`
	Pass                         string `json:"pass"`
	VerifySSHFingerprint         bool   `json:"verify_ssh_finger_print"`
	ServerSSHFingerprint         string `json:"server_ssh_finger_print"`
	TunnelType                   string `json:"tunnel_type"`
	ProxyAddr                    string `json:"proxy_addr"`
	ProxyAuthRequired            bool   `json:"proxy_auth_required"`
	ProxyAuthToken               string `json:"proxy_auth_token"`
	ProxyAuthUser                string `json:"proxy_auth_user"`
	ProxyAuthPass                string `json:"proxy_auth_pass"`
	CustomHost                   string `json:"custom_host"`
	ServerName                   string `json:"server_name"`
	HttpPayload                  string `json:"http_payload"`
	CustomPath                   string `json:"custom_path"`
	UdpgwAddr                    string `json:"udpgw_addr"` //  info  UDPGW
	DisableStatusCheck           bool   `json:"disable_status_check"`
	Alpn                         string `json:"alpn"`
	VerifyCertificateFingerprint bool   `json:"verify_certificate_finger_print"`
	ServerCertificateFingerprint string `json:"server_certificate_finger_print"`
	DnsAddr                      string `json:"dns_addr"`
	UdpgwVersion                 string `json:"udpgw_version"`
	BindInterface                string `json:"bind_interface"`

	// DNS tunnel（SSH-over-DNS） info config
	DnsTunnelDomain    string   `json:"dns_tunnel_domain"`     //  info tunnel info ， info  "tunnel.example.com"
	DnsTunnelServers   []string `json:"dns_tunnel_servers"`    //  info  DNS  info address（ info ），support udp(default)/tcp:///tls:///dot:///https://
	DnsTunnelType      string   `json:"dns_tunnel_type"`       //  info ：txt(default)/null/cname/a
	DnsTunnelPublicKey string   `json:"dns_tunnel_public_key"` // Noise  info
	DnsTunnelEDNS0     bool     `json:"dns_tunnel_edns0"`      // announce 1232-byte DNS answers; server must match

	// KCP tunnel（SSH-over-KCP） info config
	KcpPassword     string `json:"kcp_password"`      // KCP  info  ( info  BlockCrypt  info )
	KcpCrypt        string `json:"kcp_crypt"`         // KCP  info : none(default)/aes/aes-128/chacha20/salsa20/sm4
	KcpNoDelay      bool   `json:"kcp_nodelay"`       //  info enable info mode (nodelay=1, interval=10ms, resend=2, nc=1)
	KcpDataShards   int    `json:"kcp_data_shards"`   // FEC  info  (default 10)
	KcpParityShards int    `json:"kcp_parity_shards"` // FEC  info  (default 3)

	// UDP Custom  info config
	UdpCustomPsk        string `json:"udp_custom_psk"`         // UDP Custom  info  (PSK)
	UdpCustomMagic      string `json:"udp_custom_magic"`       // UDP Custom  info  4 bytes info  (default "UDPC")
	UdpCustomPublicKey  string `json:"udp_custom_public_key"`  // UDP Custom Noise  info
	UdpCustomPaths      int    `json:"udp_custom_paths"`       // UDP Custom multipath path count (client-selected random ports); 0 => 32
	UdpCustomSockets    int    `json:"udp_custom_sockets"`     // local UDP sockets; 0 => 1
	UdpCustomSendWindow int    `json:"udp_custom_send_window"` // in-flight frames; 0 => SDK default 256

	//  info  Noise  info
	NoisePublicKey string `json:"noise_public_key"` //  info  Noise  info

	// XHTTP tunnel (xhttp/xhttpc) config
	XhttpChunkSizeKB int `json:"xhttp_chunk_size_kb"` // upstream request body in KB; default 256, range 16-900

	// Resume/2 空闲心跳间隔（毫秒）。0 表示使用默认 25000ms。
	// 在 CDN/反代 idle 阈值之前主动发 KEEPALIVE 帧保活主流，避免空闲流被掐断。
	HeartbeatIntervalMs int `json:"heartbeat_interval_ms"`
}

type GlobalConfig struct {
	LocalDnsServer  string   `json:"local_dns_server"`
	RemoteDnsServer string   `json:"remote_dns_server"`
	GeoSiteFilePath string   `json:"geosite_filepath"`
	GeoIPFilePath   string   `json:"geoip_filepath"`
	DirectSiteTags  []string `json:"direct_site_tags"`
	DirectIPTags    []string `json:"direct_ip_tags"`
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
	mu.Lock()
	defer mu.Unlock()

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
