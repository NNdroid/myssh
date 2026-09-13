package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"myssh"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	dbMu sync.Mutex
)

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type Profile struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	SshAddr               string `json:"sshAddr"`
	User                  string `json:"user"`
	Pass                  string `json:"pass"`
	AuthType              string `json:"authType"`
	PrivateKey            string `json:"privateKey"`
	KeyPass               string `json:"keyPass"`
	TunnelType            string `json:"tunnelType"`
	TunnelTLSEnabled      bool   `json:"tunnelTLSEnabled"`
	ProxyAddr             string `json:"proxyAddr"`
	CustomHost            string `json:"customHost"`
	ServerName            string `json:"serverName"`
	CustomPath            string `json:"customPath"`
	EnableCustomPath      bool   `json:"enableCustomPath"`
	ProxyAuthRequired     bool   `json:"proxyAuthRequired"`
	ProxyAuthToken        string `json:"proxyAuthToken"`
	ProxyAuthUser         string `json:"proxyAuthUser"`
	ProxyAuthPass         string `json:"proxyAuthPass"`
	HttpPayload           string `json:"httpPayload"`
	UdpgwVersion          string `json:"udpgwVersion"`
	UdpgwAddr             string `json:"udpgwAddr"`
	DisableStatusCheck    bool   `json:"disableStatusCheck"`
	VerifyFingerprint     bool   `json:"verifyFingerprint"`
	ServerFingerprint     string `json:"serverFingerprint"`
	VerifyCertFingerprint bool   `json:"verifyCertFingerprint"`
	ServerCertFingerprint string `json:"serverCertFingerprint"`
	Alpn                  string `json:"alpn"`
	BindInterface         string `json:"bindInterface"`
	DnsTunnelDomain       string `json:"dnsTunnelDomain"`
	DnsTunnelServers      string `json:"dnsTunnelServers"`
	DnsTunnelType         string `json:"dnsTunnelType"`
	KcpPassword           string `json:"kcpPassword"`
	KcpCrypt              string `json:"kcpCrypt"`
	KcpMode               string `json:"kcpMode"`
	KcpDataShards         int    `json:"kcpDataShards"`
	KcpParityShards       int    `json:"kcpParityShards"`
	KcpSndWnd             int    `json:"kcpSndWnd"`
	KcpRcvWnd             int    `json:"kcpRcvWnd"`
	KcpMtu                int    `json:"kcpMtu"`
	KcpNoComp             bool   `json:"kcpNoComp"`
	KcpSmuxVer            int    `json:"kcpSmuxVer"`
	KcpKeepAlive          int    `json:"kcpKeepAlive"`
	UdpCustomPsk          string `json:"udpCustomPsk"`
	UdpCustomMagic        string `json:"udpCustomMagic"`
	UdpCustomPublicKey    string `json:"udpCustomPublicKey"`
	UdpCustomPaths        int    `json:"udpCustomPaths"`
	UdpCustomSockets      int    `json:"udpCustomSockets"`
	UdpCustomSendWindow   int    `json:"udpCustomSendWindow"`
	DnsTunnelPublicKey    string `json:"dnsTunnelPublicKey"`
	DnsTunnelEDNS0        bool   `json:"dnsTunnelEDNS0"`
	DnsTunnelPsk          string `json:"dnsTunnelPsk"`
	DnsTunnelMarker       string `json:"dnsTunnelMarker"`
	XhttpChunkSizeKB      int    `json:"xhttpChunkSizeKB"`
	XhttpStreamMode       string `json:"xhttpStreamMode"`
	HeartbeatIntervalMs   int    `json:"heartbeatIntervalMs"`
	IcmpCustomPsk         string `json:"icmpCustomPsk"`
	IcmpCustomMagic       string `json:"icmpCustomMagic"`
	IcmpCustomPublicKey   string `json:"icmpCustomPublicKey"`
	IcmpCustomMtuMode     string `json:"icmpCustomMtuMode"`
	IcmpCustomMaxPayload  int    `json:"icmpCustomMaxPayload"`
	IcmpCustomPaceMS      int    `json:"icmpCustomPaceMS"`
	IcmpCustomIdRange     string `json:"icmpCustomIdRange"`
	MasqueAlpn            string `json:"masqueAlpn"`
	PaddingMinBytes       int    `json:"paddingMinBytes"`
	UdpCustomMaxPkt       int    `json:"udpCustomMaxPkt"`
	UdpCustomMtuProbe     string `json:"udpCustomMtuProbe"`
	DnsOverride           bool   `json:"dnsOverride"`
	RemoteDns             string `json:"remoteDns"`
	LocalDns              string `json:"localDns"`
	RoutingOverride       bool   `json:"routingOverride"`
	GeositeDirect         string `json:"geositeDirect"`
	GeoipDirect           string `json:"geoipDirect"`
	TotalTx               int64  `json:"totalTx"`
	TotalRx               int64  `json:"totalRx"`
}

type Settings struct {
	LocalAddr       string   `json:"local_addr"`
	DnsAddr         string   `json:"dns_addr"`
	LocalDnsServer  string   `json:"local_dns_server"`
	RemoteDnsServer string   `json:"remote_dns_server"`
	GeoSiteFilePath string   `json:"geosite_filepath"`
	GeoIPFilePath   string   `json:"geoip_filepath"`
	DirectSiteTags  []string `json:"direct_site_tags"`
	DirectIPTags    []string `json:"direct_ip_tags"`
	UdpgwAddr       string   `json:"udpgw_addr"`
	UdpgwVersion    string   `json:"udpgw_version"`
}

func InitDB(dbPath string) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	if db != nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}

	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	// 数据库包含明文凭据：收紧文件权限（0600）；Windows 忽略失败。
	if err := os.Chmod(dbPath, 0o600); err != nil {
		zap.L().Sugar().Warnf("[DB] ⚠️ Failed to tighten db file permissions: %v", err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS profiles (
		id TEXT PRIMARY KEY,
		name TEXT, sshAddr TEXT, user TEXT, pass TEXT, authType TEXT, privateKey TEXT, keyPass TEXT,
		tunnelType TEXT, proxyAddr TEXT, customHost TEXT, serverName TEXT, customPath TEXT, enableCustomPath BOOLEAN,
		proxyAuthRequired BOOLEAN, proxyAuthToken TEXT, proxyAuthUser TEXT, proxyAuthPass TEXT, httpPayload TEXT,
		udpgwVersion TEXT, udpgwAddr TEXT, disableStatusCheck BOOLEAN, verifyFingerprint BOOLEAN,
		serverFingerprint TEXT, verifyCertFingerprint BOOLEAN, serverCertFingerprint TEXT, alpn TEXT,
		bindInterface TEXT,
		dnsOverride BOOLEAN, remoteDns TEXT, localDns TEXT, 
		routingOverride BOOLEAN, geositeDirect TEXT, geoipDirect TEXT,
		totalTx INTEGER, totalRx INTEGER,
		dnsTunnelDomain TEXT DEFAULT '', dnsTunnelServers TEXT DEFAULT '', dnsTunnelType TEXT DEFAULT '',
		kcpPassword TEXT DEFAULT '', kcpCrypt TEXT DEFAULT 'aes', kcpMode TEXT DEFAULT 'fast',
		kcpDataShards INTEGER DEFAULT 10, kcpParityShards INTEGER DEFAULT 3,
		kcpSndWnd INTEGER DEFAULT 128, kcpRcvWnd INTEGER DEFAULT 512, kcpMtu INTEGER DEFAULT 1350,
		kcpNoComp BOOLEAN DEFAULT 0, kcpSmuxVer INTEGER DEFAULT 2, kcpKeepAlive INTEGER DEFAULT 10,
		udpCustomPsk TEXT DEFAULT '', udpCustomMagic TEXT DEFAULT 'UDPC',
		udpCustomPublicKey TEXT DEFAULT '', udpCustomPaths INTEGER DEFAULT 32,
		udpCustomSockets INTEGER DEFAULT 1, udpCustomSendWindow INTEGER DEFAULT 256,
		dnsTunnelPublicKey TEXT DEFAULT '', dnsTunnelEDNS0 BOOLEAN DEFAULT 0,
		xhttpChunkSizeKB INTEGER DEFAULT 256, xhttpStreamMode TEXT DEFAULT '', heartbeatIntervalMs INTEGER DEFAULT 25000,
		icmpCustomPsk TEXT DEFAULT '', icmpCustomMagic TEXT DEFAULT '', icmpCustomPublicKey TEXT DEFAULT '',
		icmpCustomMtuMode TEXT DEFAULT '', icmpCustomMaxPayload INTEGER DEFAULT 0,
		icmpCustomPaceMS INTEGER DEFAULT 0, icmpCustomIdRange TEXT DEFAULT '',
		tunnelTLSEnabled BOOLEAN, dnsTunnelPsk TEXT DEFAULT '', dnsTunnelMarker TEXT DEFAULT '',
		masqueAlpn TEXT DEFAULT '', paddingMinBytes INTEGER DEFAULT 0,
		udpCustomMaxPkt INTEGER DEFAULT 0, udpCustomMtuProbe TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		local_addr TEXT,
		dns_addr TEXT,
		local_dns_server TEXT,
		remote_dns_server TEXT,
		geosite_filepath TEXT,
		geoip_filepath TEXT,
		direct_site_tags TEXT,
		direct_ip_tags TEXT,
		udpgw_addr TEXT,
		udpgw_version TEXT
	);
	INSERT OR IGNORE INTO settings (id, local_addr, dns_addr, local_dns_server, remote_dns_server, geosite_filepath, geoip_filepath, direct_site_tags, direct_ip_tags, udpgw_addr, udpgw_version)
	VALUES (1, '127.0.0.1:1080', '127.0.0.1:5353', '223.5.5.5:53', '8.8.8.8:53', 'geosite.dat', 'geoip.dat', 'cn', 'cn', '127.0.0.1:7300', 'badvpn');
	`)

	// Perform migrations for existing DB
	migrations := []string{
		"ALTER TABLE profiles ADD COLUMN dnsOverride BOOLEAN DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN remoteDns TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN localDns TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN routingOverride BOOLEAN DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN geositeDirect TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN geoipDirect TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN totalTx INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN totalRx INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelDomain TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelServers TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelType TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN kcpPassword TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN kcpCrypt TEXT DEFAULT 'aes';",
		"ALTER TABLE profiles ADD COLUMN kcpNoDelay BOOLEAN DEFAULT 1;",
		"ALTER TABLE profiles ADD COLUMN kcpMode TEXT DEFAULT 'fast';",
		"ALTER TABLE profiles ADD COLUMN kcpSndWnd INTEGER DEFAULT 128;",
		"ALTER TABLE profiles ADD COLUMN kcpRcvWnd INTEGER DEFAULT 512;",
		"ALTER TABLE profiles ADD COLUMN kcpMtu INTEGER DEFAULT 1350;",
		"ALTER TABLE profiles ADD COLUMN kcpNoComp BOOLEAN DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN kcpSmuxVer INTEGER DEFAULT 2;",
		"ALTER TABLE profiles ADD COLUMN kcpKeepAlive INTEGER DEFAULT 10;",
		"ALTER TABLE profiles ADD COLUMN kcpDataShards INTEGER DEFAULT 10;",
		"ALTER TABLE profiles ADD COLUMN kcpParityShards INTEGER DEFAULT 3;",
		"ALTER TABLE profiles ADD COLUMN udpCustomPsk TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN udpCustomMagic TEXT DEFAULT 'UDPC';",
		"ALTER TABLE profiles ADD COLUMN udpCustomPublicKey TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN udpCustomPaths INTEGER DEFAULT 32;",
		"ALTER TABLE profiles ADD COLUMN udpCustomSockets INTEGER DEFAULT 1;",
		"ALTER TABLE profiles ADD COLUMN udpCustomSendWindow INTEGER DEFAULT 256;",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelPublicKey TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelEDNS0 BOOLEAN DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN xhttpChunkSizeKB INTEGER DEFAULT 256;",
		"ALTER TABLE profiles ADD COLUMN heartbeatIntervalMs INTEGER DEFAULT 25000;",
		"ALTER TABLE profiles ADD COLUMN xhttpStreamMode TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN icmpCustomPsk TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN icmpCustomMagic TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN icmpCustomPublicKey TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN icmpCustomMtuMode TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN icmpCustomMaxPayload INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN icmpCustomPaceMS INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN icmpCustomIdRange TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN tunnelTLSEnabled BOOLEAN;",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelPsk TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN dnsTunnelMarker TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN masqueAlpn TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN paddingMinBytes INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN udpCustomMaxPkt INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN udpCustomMtuProbe TEXT DEFAULT '';",
		"ALTER TABLE settings ADD COLUMN udpgw_addr TEXT DEFAULT '127.0.0.1:7300';",
		"ALTER TABLE settings ADD COLUMN udpgw_version TEXT DEFAULT 'badvpn';",
		"ALTER TABLE settings ADD COLUMN geosite_filepath TEXT DEFAULT 'geosite.dat';",
		"ALTER TABLE settings ADD COLUMN geoip_filepath TEXT DEFAULT 'geoip.dat';",
		"ALTER TABLE settings ADD COLUMN direct_site_tags TEXT DEFAULT 'cn';",
		"ALTER TABLE settings ADD COLUMN direct_ip_tags TEXT DEFAULT 'cn';",
	}
	for _, query := range migrations {
		db.Exec(query) // Ignore errors (column already exists)
	}

	return err
}

func GetProfiles() ([]Profile, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	rows, err := db.Query("SELECT id, name, sshAddr, user, pass, authType, privateKey, keyPass, tunnelType, proxyAddr, customHost, serverName, customPath, enableCustomPath, proxyAuthRequired, proxyAuthToken, proxyAuthUser, proxyAuthPass, httpPayload, udpgwVersion, udpgwAddr, disableStatusCheck, verifyFingerprint, serverFingerprint, verifyCertFingerprint, serverCertFingerprint, alpn, bindInterface, dnsOverride, remoteDns, localDns, routingOverride, geositeDirect, geoipDirect, totalTx, totalRx, dnsTunnelDomain, dnsTunnelServers, dnsTunnelType, kcpPassword, kcpCrypt, kcpMode, kcpSndWnd, kcpRcvWnd, kcpMtu, kcpNoComp, kcpSmuxVer, kcpKeepAlive, kcpDataShards, kcpParityShards, udpCustomPsk, udpCustomMagic, udpCustomPublicKey, udpCustomPaths, udpCustomSockets, udpCustomSendWindow, dnsTunnelPublicKey, dnsTunnelEDNS0, xhttpChunkSizeKB, xhttpStreamMode, heartbeatIntervalMs, icmpCustomPsk, icmpCustomMagic, icmpCustomPublicKey, icmpCustomMtuMode, icmpCustomMaxPayload, icmpCustomPaceMS, icmpCustomIdRange, tunnelTLSEnabled, dnsTunnelPsk, dnsTunnelMarker, masqueAlpn, paddingMinBytes, udpCustomMaxPkt, udpCustomMtuProbe FROM profiles")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 初始化为空切片：nil 会被序列化成 JSON null，前端 Array.isArray 判断会失败。
	profiles := []Profile{}
	for rows.Next() {
		var p Profile
		var tlsNull sql.NullBool
		if err := rows.Scan(&p.ID, &p.Name, &p.SshAddr, &p.User, &p.Pass, &p.AuthType, &p.PrivateKey, &p.KeyPass, &p.TunnelType, &p.ProxyAddr, &p.CustomHost, &p.ServerName, &p.CustomPath, &p.EnableCustomPath, &p.ProxyAuthRequired, &p.ProxyAuthToken, &p.ProxyAuthUser, &p.ProxyAuthPass, &p.HttpPayload, &p.UdpgwVersion, &p.UdpgwAddr, &p.DisableStatusCheck, &p.VerifyFingerprint, &p.ServerFingerprint, &p.VerifyCertFingerprint, &p.ServerCertFingerprint, &p.Alpn, &p.BindInterface, &p.DnsOverride, &p.RemoteDns, &p.LocalDns, &p.RoutingOverride, &p.GeositeDirect, &p.GeoipDirect, &p.TotalTx, &p.TotalRx, &p.DnsTunnelDomain, &p.DnsTunnelServers, &p.DnsTunnelType, &p.KcpPassword, &p.KcpCrypt, &p.KcpMode, &p.KcpSndWnd, &p.KcpRcvWnd, &p.KcpMtu, &p.KcpNoComp, &p.KcpSmuxVer, &p.KcpKeepAlive, &p.KcpDataShards, &p.KcpParityShards, &p.UdpCustomPsk, &p.UdpCustomMagic, &p.UdpCustomPublicKey, &p.UdpCustomPaths, &p.UdpCustomSockets, &p.UdpCustomSendWindow, &p.DnsTunnelPublicKey, &p.DnsTunnelEDNS0, &p.XhttpChunkSizeKB, &p.XhttpStreamMode, &p.HeartbeatIntervalMs, &p.IcmpCustomPsk, &p.IcmpCustomMagic, &p.IcmpCustomPublicKey, &p.IcmpCustomMtuMode, &p.IcmpCustomMaxPayload, &p.IcmpCustomPaceMS, &p.IcmpCustomIdRange, &tlsNull, &p.DnsTunnelPsk, &p.DnsTunnelMarker, &p.MasqueAlpn, &p.PaddingMinBytes, &p.UdpCustomMaxPkt, &p.UdpCustomMtuProbe); err != nil {
			return nil, err
		}
		p.TunnelTLSEnabled = tlsNull.Bool
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func GetProfile(id string) (*Profile, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	var p Profile
	var tlsNull sql.NullBool
	err := db.QueryRow("SELECT id, name, sshAddr, user, pass, authType, privateKey, keyPass, tunnelType, proxyAddr, customHost, serverName, customPath, enableCustomPath, proxyAuthRequired, proxyAuthToken, proxyAuthUser, proxyAuthPass, httpPayload, udpgwVersion, udpgwAddr, disableStatusCheck, verifyFingerprint, serverFingerprint, verifyCertFingerprint, serverCertFingerprint, alpn, bindInterface, dnsOverride, remoteDns, localDns, routingOverride, geositeDirect, geoipDirect, totalTx, totalRx, dnsTunnelDomain, dnsTunnelServers, dnsTunnelType, kcpPassword, kcpCrypt, kcpMode, kcpSndWnd, kcpRcvWnd, kcpMtu, kcpNoComp, kcpSmuxVer, kcpKeepAlive, kcpDataShards, kcpParityShards, udpCustomPsk, udpCustomMagic, udpCustomPublicKey, udpCustomPaths, udpCustomSockets, udpCustomSendWindow, dnsTunnelPublicKey, dnsTunnelEDNS0, xhttpChunkSizeKB, xhttpStreamMode, heartbeatIntervalMs, icmpCustomPsk, icmpCustomMagic, icmpCustomPublicKey, icmpCustomMtuMode, icmpCustomMaxPayload, icmpCustomPaceMS, icmpCustomIdRange, tunnelTLSEnabled, dnsTunnelPsk, dnsTunnelMarker, masqueAlpn, paddingMinBytes, udpCustomMaxPkt, udpCustomMtuProbe FROM profiles WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.SshAddr, &p.User, &p.Pass, &p.AuthType, &p.PrivateKey, &p.KeyPass, &p.TunnelType, &p.ProxyAddr, &p.CustomHost, &p.ServerName, &p.CustomPath, &p.EnableCustomPath, &p.ProxyAuthRequired, &p.ProxyAuthToken, &p.ProxyAuthUser, &p.ProxyAuthPass, &p.HttpPayload, &p.UdpgwVersion, &p.UdpgwAddr, &p.DisableStatusCheck, &p.VerifyFingerprint, &p.ServerFingerprint, &p.VerifyCertFingerprint, &p.ServerCertFingerprint, &p.Alpn, &p.BindInterface, &p.DnsOverride, &p.RemoteDns, &p.LocalDns, &p.RoutingOverride, &p.GeositeDirect, &p.GeoipDirect, &p.TotalTx, &p.TotalRx, &p.DnsTunnelDomain, &p.DnsTunnelServers, &p.DnsTunnelType, &p.KcpPassword, &p.KcpCrypt, &p.KcpMode, &p.KcpSndWnd, &p.KcpRcvWnd, &p.KcpMtu, &p.KcpNoComp, &p.KcpSmuxVer, &p.KcpKeepAlive, &p.KcpDataShards, &p.KcpParityShards, &p.UdpCustomPsk, &p.UdpCustomMagic, &p.UdpCustomPublicKey, &p.UdpCustomPaths, &p.UdpCustomSockets, &p.UdpCustomSendWindow, &p.DnsTunnelPublicKey, &p.DnsTunnelEDNS0, &p.XhttpChunkSizeKB, &p.XhttpStreamMode, &p.HeartbeatIntervalMs, &p.IcmpCustomPsk, &p.IcmpCustomMagic, &p.IcmpCustomPublicKey, &p.IcmpCustomMtuMode, &p.IcmpCustomMaxPayload, &p.IcmpCustomPaceMS, &p.IcmpCustomIdRange, &tlsNull, &p.DnsTunnelPsk, &p.DnsTunnelMarker, &p.MasqueAlpn, &p.PaddingMinBytes, &p.UdpCustomMaxPkt, &p.UdpCustomMtuProbe)
	if err != nil {
		return nil, err
	}
	p.TunnelTLSEnabled = tlsNull.Bool
	return &p, nil
}

func AddProfile(p Profile) (string, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	if p.ID == "" {
		p.ID = generateUUID()
	}

	_, err := db.Exec("INSERT INTO profiles (id, name, sshAddr, user, pass, authType, privateKey, keyPass, tunnelType, proxyAddr, customHost, serverName, customPath, enableCustomPath, proxyAuthRequired, proxyAuthToken, proxyAuthUser, proxyAuthPass, httpPayload, udpgwVersion, udpgwAddr, disableStatusCheck, verifyFingerprint, serverFingerprint, verifyCertFingerprint, serverCertFingerprint, alpn, bindInterface, dnsOverride, remoteDns, localDns, routingOverride, geositeDirect, geoipDirect, totalTx, totalRx, dnsTunnelDomain, dnsTunnelServers, dnsTunnelType, kcpPassword, kcpCrypt, kcpMode, kcpSndWnd, kcpRcvWnd, kcpMtu, kcpNoComp, kcpSmuxVer, kcpKeepAlive, kcpDataShards, kcpParityShards, udpCustomPsk, udpCustomMagic, udpCustomPublicKey, udpCustomPaths, udpCustomSockets, udpCustomSendWindow, dnsTunnelPublicKey, dnsTunnelEDNS0, xhttpChunkSizeKB, xhttpStreamMode, heartbeatIntervalMs, icmpCustomPsk, icmpCustomMagic, icmpCustomPublicKey, icmpCustomMtuMode, icmpCustomMaxPayload, icmpCustomPaceMS, icmpCustomIdRange, tunnelTLSEnabled, dnsTunnelPsk, dnsTunnelMarker, masqueAlpn, paddingMinBytes, udpCustomMaxPkt, udpCustomMtuProbe) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		p.ID, p.Name, p.SshAddr, p.User, p.Pass, p.AuthType, p.PrivateKey, p.KeyPass, p.TunnelType, p.ProxyAddr, p.CustomHost, p.ServerName, p.CustomPath, p.EnableCustomPath, p.ProxyAuthRequired, p.ProxyAuthToken, p.ProxyAuthUser, p.ProxyAuthPass, p.HttpPayload, p.UdpgwVersion, p.UdpgwAddr, p.DisableStatusCheck, p.VerifyFingerprint, p.ServerFingerprint, p.VerifyCertFingerprint, p.ServerCertFingerprint, p.Alpn, p.BindInterface, p.DnsOverride, p.RemoteDns, p.LocalDns, p.RoutingOverride, p.GeositeDirect, p.GeoipDirect, p.TotalTx, p.TotalRx, p.DnsTunnelDomain, p.DnsTunnelServers, p.DnsTunnelType, p.KcpPassword, p.KcpCrypt, p.KcpMode, p.KcpSndWnd, p.KcpRcvWnd, p.KcpMtu, p.KcpNoComp, p.KcpSmuxVer, p.KcpKeepAlive, p.KcpDataShards, p.KcpParityShards, p.UdpCustomPsk, p.UdpCustomMagic, p.UdpCustomPublicKey, p.UdpCustomPaths, p.UdpCustomSockets, p.UdpCustomSendWindow, p.DnsTunnelPublicKey, p.DnsTunnelEDNS0, p.XhttpChunkSizeKB, p.XhttpStreamMode, p.HeartbeatIntervalMs, p.IcmpCustomPsk, p.IcmpCustomMagic, p.IcmpCustomPublicKey, p.IcmpCustomMtuMode, p.IcmpCustomMaxPayload, p.IcmpCustomPaceMS, p.IcmpCustomIdRange, p.TunnelTLSEnabled, p.DnsTunnelPsk, p.DnsTunnelMarker, p.MasqueAlpn, p.PaddingMinBytes, p.UdpCustomMaxPkt, p.UdpCustomMtuProbe)
	if err != nil {
		return "", err
	}
	return p.ID, nil
}

func UpdateProfile(id string, p Profile) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("UPDATE profiles SET name=?, sshAddr=?, user=?, pass=?, authType=?, privateKey=?, keyPass=?, tunnelType=?, proxyAddr=?, customHost=?, serverName=?, customPath=?, enableCustomPath=?, proxyAuthRequired=?, proxyAuthToken=?, proxyAuthUser=?, proxyAuthPass=?, httpPayload=?, udpgwVersion=?, udpgwAddr=?, disableStatusCheck=?, verifyFingerprint=?, serverFingerprint=?, verifyCertFingerprint=?, serverCertFingerprint=?, alpn=?, bindInterface=?, dnsOverride=?, remoteDns=?, localDns=?, routingOverride=?, geositeDirect=?, geoipDirect=?, totalTx=?, totalRx=?, dnsTunnelDomain=?, dnsTunnelServers=?, dnsTunnelType=?, kcpPassword=?, kcpCrypt=?, kcpMode=?, kcpSndWnd=?, kcpRcvWnd=?, kcpMtu=?, kcpNoComp=?, kcpSmuxVer=?, kcpKeepAlive=?, kcpDataShards=?, kcpParityShards=?, udpCustomPsk=?, udpCustomMagic=?, udpCustomPublicKey=?, udpCustomPaths=?, udpCustomSockets=?, udpCustomSendWindow=?, dnsTunnelPublicKey=?, dnsTunnelEDNS0=?, xhttpChunkSizeKB=?, xhttpStreamMode=?, heartbeatIntervalMs=?, icmpCustomPsk=?, icmpCustomMagic=?, icmpCustomPublicKey=?, icmpCustomMtuMode=?, icmpCustomMaxPayload=?, icmpCustomPaceMS=?, icmpCustomIdRange=?, tunnelTLSEnabled=?, dnsTunnelPsk=?, dnsTunnelMarker=?, masqueAlpn=?, paddingMinBytes=?, udpCustomMaxPkt=?, udpCustomMtuProbe=? WHERE id=?",
		p.Name, p.SshAddr, p.User, p.Pass, p.AuthType, p.PrivateKey, p.KeyPass, p.TunnelType, p.ProxyAddr, p.CustomHost, p.ServerName, p.CustomPath, p.EnableCustomPath, p.ProxyAuthRequired, p.ProxyAuthToken, p.ProxyAuthUser, p.ProxyAuthPass, p.HttpPayload, p.UdpgwVersion, p.UdpgwAddr, p.DisableStatusCheck, p.VerifyFingerprint, p.ServerFingerprint, p.VerifyCertFingerprint, p.ServerCertFingerprint, p.Alpn, p.BindInterface, p.DnsOverride, p.RemoteDns, p.LocalDns, p.RoutingOverride, p.GeositeDirect, p.GeoipDirect, p.TotalTx, p.TotalRx, p.DnsTunnelDomain, p.DnsTunnelServers, p.DnsTunnelType, p.KcpPassword, p.KcpCrypt, p.KcpMode, p.KcpSndWnd, p.KcpRcvWnd, p.KcpMtu, p.KcpNoComp, p.KcpSmuxVer, p.KcpKeepAlive, p.KcpDataShards, p.KcpParityShards, p.UdpCustomPsk, p.UdpCustomMagic, p.UdpCustomPublicKey, p.UdpCustomPaths, p.UdpCustomSockets, p.UdpCustomSendWindow, p.DnsTunnelPublicKey, p.DnsTunnelEDNS0, p.XhttpChunkSizeKB, p.XhttpStreamMode, p.HeartbeatIntervalMs, p.IcmpCustomPsk, p.IcmpCustomMagic, p.IcmpCustomPublicKey, p.IcmpCustomMtuMode, p.IcmpCustomMaxPayload, p.IcmpCustomPaceMS, p.IcmpCustomIdRange, p.TunnelTLSEnabled, p.DnsTunnelPsk, p.DnsTunnelMarker, p.MasqueAlpn, p.PaddingMinBytes, p.UdpCustomMaxPkt, p.UdpCustomMtuProbe, id)
	return err
}

func DeleteProfile(id string) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("DELETE FROM profiles WHERE id=?", id)
	return err
}

func GetSettings() (*Settings, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	var s Settings
	var directSiteTags, directIPTags string
	err := db.QueryRow("SELECT local_addr, dns_addr, local_dns_server, remote_dns_server, geosite_filepath, geoip_filepath, direct_site_tags, direct_ip_tags, udpgw_addr, udpgw_version FROM settings WHERE id = 1").
		Scan(&s.LocalAddr, &s.DnsAddr, &s.LocalDnsServer, &s.RemoteDnsServer, &s.GeoSiteFilePath, &s.GeoIPFilePath, &directSiteTags, &directIPTags, &s.UdpgwAddr, &s.UdpgwVersion)
	if err != nil {
		return nil, err
	}
	s.DirectSiteTags = filterEmptyTags(strings.Split(directSiteTags, ","))
	s.DirectIPTags = filterEmptyTags(strings.Split(directIPTags, ","))
	return &s, nil
}

// filterEmptyTags 过滤 CSV 拆分产生的空元素（空串/纯空白），避免把空 tag
// 送进路由匹配。
func filterEmptyTags(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// checkHostPort 校验 "host:port" 形态的地址配置：空值放行（运行时用默认），
// 非空则必须带合法端口（1-65535）。
func checkHostPort(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be host:port (got %q)", field, value)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("%s has an invalid port %q", field, port)
	}
	return nil
}

// validateSettings 在落库前校验设置项的格式与枚举值——错误配置推迟到
// 启动代理时才报错的话，排查成本会高得多。
func validateSettings(s *Settings) error {
	for field, value := range map[string]string{
		"local_addr":        s.LocalAddr,
		"dns_addr":          s.DnsAddr,
		"local_dns_server":  s.LocalDnsServer,
		"remote_dns_server": s.RemoteDnsServer,
		"udpgw_addr":        s.UdpgwAddr,
	} {
		if err := checkHostPort(field, value); err != nil {
			return err
		}
	}
	switch strings.ToLower(strings.TrimSpace(s.UdpgwVersion)) {
	case "", "badvpn", "tun2proxy":
	default:
		return fmt.Errorf("udpgw_version must be badvpn or tun2proxy (got %q)", s.UdpgwVersion)
	}
	return nil
}

func UpdateSettings(s Settings) error {
	if err := validateSettings(&s); err != nil {
		return err
	}
	dbMu.Lock()
	defer dbMu.Unlock()

	directSiteTags := strings.Join(s.DirectSiteTags, ",")
	directIPTags := strings.Join(s.DirectIPTags, ",")
	_, err := db.Exec("UPDATE settings SET local_addr=?, dns_addr=?, local_dns_server=?, remote_dns_server=?, geosite_filepath=?, geoip_filepath=?, direct_site_tags=?, direct_ip_tags=?, udpgw_addr=?, udpgw_version=? WHERE id=1",
		s.LocalAddr, s.DnsAddr, s.LocalDnsServer, s.RemoteDnsServer, s.GeoSiteFilePath, s.GeoIPFilePath, directSiteTags, directIPTags, s.UdpgwAddr, s.UdpgwVersion)
	return err
}

func (p *Profile) ToProxyConfig(s *Settings) (string, error) {
	tunnelType := p.TunnelType
	if tunnelType == "" {
		tunnelType = "base"
	}
	if tunnelType == "vaydns" || tunnelType == "dns" {
		tunnelType = "dns_custom"
	}

	udpgwAddr := s.UdpgwAddr
	udpgwVersion := s.UdpgwVersion
	dnsAddr := s.DnsAddr
	if p.DnsOverride {
		udpgwAddr = p.UdpgwAddr
		udpgwVersion = p.UdpgwVersion
		if p.LocalDns != "" {
			dnsAddr = p.LocalDns
		}
	}

	var dnsServers []string
	if p.DnsTunnelServers != "" {
		for _, srv := range strings.Split(p.DnsTunnelServers, ",") {
			srv = strings.TrimSpace(srv)
			if srv != "" {
				dnsServers = append(dnsServers, srv)
			}
		}
	}

	config := myssh.ProxyConfig{
		LocalAddr:                    s.LocalAddr,
		SshAddr:                      p.SshAddr,
		User:                         p.User,
		AuthType:                     p.AuthType,
		PrivateKey:                   p.PrivateKey,
		PrivateKeyPassphrase:         p.KeyPass,
		Pass:                         p.Pass,
		VerifySSHFingerprint:         p.VerifyFingerprint,
		ServerSSHFingerprint:         p.ServerFingerprint,
		TunnelType:                   tunnelType,
		ProxyAddr:                    p.ProxyAddr,
		ProxyAuthRequired:            p.ProxyAuthRequired,
		ProxyAuthToken:               p.ProxyAuthToken,
		ProxyAuthUser:                p.ProxyAuthUser,
		ProxyAuthPass:                p.ProxyAuthPass,
		CustomHost:                   p.CustomHost,
		ServerName:                   p.ServerName,
		HttpPayload:                  p.HttpPayload,
		CustomPath:                   p.CustomPath,
		UdpgwAddr:                    udpgwAddr,
		DisableStatusCheck:           p.DisableStatusCheck,
		Alpn:                         p.Alpn,
		VerifyCertificateFingerprint: p.VerifyCertFingerprint,
		ServerCertificateFingerprint: p.ServerCertFingerprint,
		DnsAddr:                      dnsAddr,
		UdpgwVersion:                 udpgwVersion,
		BindInterface:                p.BindInterface,
		DnsTunnelDomain:              p.DnsTunnelDomain,
		DnsTunnelServers:             dnsServers,
		DnsTunnelType:                p.DnsTunnelType,
		DnsTunnelPublicKey:           p.DnsTunnelPublicKey,
		DnsTunnelEDNS0:               p.DnsTunnelEDNS0,
		DnsTunnelPsk:                 p.DnsTunnelPsk,
		DnsTunnelMarker:              p.DnsTunnelMarker,
		KcpPassword:                  p.KcpPassword,
		KcpCrypt:                     p.KcpCrypt,
		KcpMode:                      p.KcpMode,
		KcpSndWnd:                    p.KcpSndWnd,
		KcpRcvWnd:                    p.KcpRcvWnd,
		KcpMtu:                       p.KcpMtu,
		KcpNoComp:                    p.KcpNoComp,
		KcpSmuxVer:                   p.KcpSmuxVer,
		KcpKeepAlive:                 p.KcpKeepAlive,
		KcpDataShards:                p.KcpDataShards,
		KcpParityShards:              p.KcpParityShards,
		UdpCustomPsk:                 p.UdpCustomPsk,
		UdpCustomMagic:               p.UdpCustomMagic,
		UdpCustomPublicKey:           p.UdpCustomPublicKey,
		UdpCustomPaths:               p.UdpCustomPaths,
		UdpCustomSockets:             p.UdpCustomSockets,
		UdpCustomSendWindow:          p.UdpCustomSendWindow,
		XhttpChunkSizeKB:             p.XhttpChunkSizeKB,
		XhttpStreamMode:              p.XhttpStreamMode,
		HeartbeatIntervalMs:          p.HeartbeatIntervalMs,
		IcmpCustomPsk:                p.IcmpCustomPsk,
		IcmpCustomMagic:              p.IcmpCustomMagic,
		IcmpCustomPublicKey:          p.IcmpCustomPublicKey,
		IcmpCustomMtuMode:            p.IcmpCustomMtuMode,
		IcmpCustomMaxPayload:         p.IcmpCustomMaxPayload,
		IcmpCustomPaceMS:             p.IcmpCustomPaceMS,
		IcmpCustomIdRange:            p.IcmpCustomIdRange,
		TunnelTLSEnabled:             p.TunnelTLSEnabled,
		MasqueAlpn:                   p.MasqueAlpn,
		PaddingMinBytes:              p.PaddingMinBytes,
		UdpCustomMaxPkt:              p.UdpCustomMaxPkt,
		UdpCustomMtuProbe:            p.UdpCustomMtuProbe,
	}

	b, err := json.Marshal(config)
	return string(b), err
}

func BuildProxyConfigJSON(profileID string) (string, error) {
	p, err := GetProfile(profileID)
	if err != nil {
		return "", err
	}
	s, err := GetSettings()
	if err != nil {
		return "", err
	}
	return p.ToProxyConfig(s)
}

func BuildGlobalConfigJSON(profileID string) (string, error) {
	p, err := GetProfile(profileID)
	if err != nil {
		return "", err
	}
	s, err := GetSettings()
	if err != nil {
		return "", err
	}

	remoteDns := s.RemoteDnsServer
	localDns := s.LocalDnsServer
	if p.DnsOverride {
		remoteDns = p.RemoteDns
		localDns = p.LocalDns
	}

	geositeDirect := s.DirectSiteTags
	geoipDirect := s.DirectIPTags
	if p.RoutingOverride {
		geositeDirect = strings.Split(p.GeositeDirect, ",")
		geoipDirect = strings.Split(p.GeoipDirect, ",")
	}

	config := myssh.GlobalConfig{
		LocalDnsServer:  localDns,
		RemoteDnsServer: remoteDns,
		GeoSiteFilePath: s.GeoSiteFilePath,
		GeoIPFilePath:   s.GeoIPFilePath,
		DirectSiteTags:  geositeDirect,
		DirectIPTags:    geoipDirect,
	}

	b, err := json.Marshal(config)
	return string(b), err
}
