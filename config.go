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
	UdpgwAddr                    string `json:"udpgw_addr"` // 留空则不开启 UDPGW
	DisableStatusCheck           bool   `json:"disable_status_check"`
	Alpn                         string `json:"alpn"`
	VerifyCertificateFingerprint bool   `json:"verify_certificate_finger_print"`
	ServerCertificateFingerprint string `json:"server_certificate_finger_print"`
	DnsAddr                      string `json:"dns_addr"`
	UdpgwVersion                 string `json:"udpgw_version"`
	BindInterface                string `json:"bind_interface"`
}

type GlobalConfig struct {
	LocalDnsServer  string   `json:"local_dns_server"`
	RemoteDnsServer string   `json:"remote_dns_server"`
	GeoSiteFilePath string   `json:"geosite_filepath"`
	GeoIPFilePath   string   `json:"geoip_filepath"`
	DirectSiteTags  []string `json:"direct_site_tags"`
	DirectIPTags    []string `json:"direct_ip_tags"`
}

func LoadGlobalConfigFromJson(configJson string) int {
	if err := json.Unmarshal([]byte(configJson), &globalConfig); err != nil {
		zlog.Errorf("%s [Config] ❌ 解析全局配置 JSON 失败: %v\n传入的JSON内容: %s", TAG, err, configJson)
		return -2
	}
	return loadGlobalConfig(globalConfig)
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

	zlog.Infof("%s [Config] ✅ 已应用全局配置: LocalDNS=[%s], RemoteDNS=[%s]", TAG, cfg.LocalDnsServer, cfg.RemoteDnsServer)

	globalRouter = newGeoRouter()

	if _, err := os.Stat(cfg.GeoSiteFilePath); err == nil {
		if err := globalRouter.LoadGeoSite(cfg.GeoSiteFilePath, cfg.DirectSiteTags); err != nil {
			zlog.Errorf("%s [Config] ❌ 加载 GeoSite 失败: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoSite 加载成功", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ 未找到 GeoSite 文件 (%s)，域名直连分流已禁用", TAG, cfg.GeoSiteFilePath)
	}

	if _, err := os.Stat(cfg.GeoIPFilePath); err == nil {
		if err := globalRouter.LoadGeoIP(cfg.GeoIPFilePath, cfg.DirectIPTags); err != nil {
			zlog.Errorf("%s [Config] ❌ 加载 GeoIP 失败: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoIP 加载成功", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ 未找到 GeoIP 文件 (%s)，IP直连分流已禁用", TAG, cfg.GeoIPFilePath)
	}

	return 0
}
