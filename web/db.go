package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"myssh"

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
	Type                  string `json:"type"`
	UdpgwVersion          string `json:"udpgwVersion"`
	UdpgwAddr             string `json:"udpgwAddr"`
	DisableStatusCheck    bool   `json:"disableStatusCheck"`
	VerifyFingerprint     bool   `json:"verifyFingerprint"`
	ServerFingerprint     string `json:"serverFingerprint"`
	VerifyCertFingerprint bool   `json:"verifyCertFingerprint"`
	ServerCertFingerprint string `json:"serverCertFingerprint"`
	Alpn                  string `json:"alpn"`
	BindInterface         string `json:"bindInterface"`
	DnsOverride           bool   `json:"dnsOverride"`
	RemoteDns             string `json:"remoteDns"`
	LocalDns              string `json:"localDns"`
	RoutingOverride       bool   `json:"routingOverride"`
	GeositeDirect         string `json:"geositeDirect"`
	GeoipDirect           string `json:"geoipDirect"`
	AppFilterOverride     bool   `json:"appFilterOverride"`
	FilterApps            string `json:"filterApps"`
	FilterMode            int    `json:"filterMode"`
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

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS profiles (
		id TEXT PRIMARY KEY,
		name TEXT, sshAddr TEXT, user TEXT, pass TEXT, authType TEXT, privateKey TEXT, keyPass TEXT,
		tunnelType TEXT, proxyAddr TEXT, customHost TEXT, serverName TEXT, customPath TEXT, enableCustomPath BOOLEAN,
		proxyAuthRequired BOOLEAN, proxyAuthToken TEXT, proxyAuthUser TEXT, proxyAuthPass TEXT, httpPayload TEXT,
		type TEXT, udpgwVersion TEXT, udpgwAddr TEXT, disableStatusCheck BOOLEAN, verifyFingerprint BOOLEAN,
		serverFingerprint TEXT, verifyCertFingerprint BOOLEAN, serverCertFingerprint TEXT, alpn TEXT,
		bindInterface TEXT,
		dnsOverride BOOLEAN, remoteDns TEXT, localDns TEXT, 
		routingOverride BOOLEAN, geositeDirect TEXT, geoipDirect TEXT,
		appFilterOverride BOOLEAN, filterApps TEXT, filterMode INTEGER, totalTx INTEGER, totalRx INTEGER
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
		"ALTER TABLE profiles ADD COLUMN appFilterOverride BOOLEAN DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN filterApps TEXT DEFAULT '';",
		"ALTER TABLE profiles ADD COLUMN filterMode INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN totalTx INTEGER DEFAULT 0;",
		"ALTER TABLE profiles ADD COLUMN totalRx INTEGER DEFAULT 0;",
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

	rows, err := db.Query("SELECT id, name, sshAddr, user, pass, authType, privateKey, keyPass, tunnelType, proxyAddr, customHost, serverName, customPath, enableCustomPath, proxyAuthRequired, proxyAuthToken, proxyAuthUser, proxyAuthPass, httpPayload, type, udpgwVersion, udpgwAddr, disableStatusCheck, verifyFingerprint, serverFingerprint, verifyCertFingerprint, serverCertFingerprint, alpn, bindInterface, dnsOverride, remoteDns, localDns, routingOverride, geositeDirect, geoipDirect, appFilterOverride, filterApps, filterMode, totalTx, totalRx FROM profiles")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []Profile
	for rows.Next() {
		var p Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.SshAddr, &p.User, &p.Pass, &p.AuthType, &p.PrivateKey, &p.KeyPass, &p.TunnelType, &p.ProxyAddr, &p.CustomHost, &p.ServerName, &p.CustomPath, &p.EnableCustomPath, &p.ProxyAuthRequired, &p.ProxyAuthToken, &p.ProxyAuthUser, &p.ProxyAuthPass, &p.HttpPayload, &p.Type, &p.UdpgwVersion, &p.UdpgwAddr, &p.DisableStatusCheck, &p.VerifyFingerprint, &p.ServerFingerprint, &p.VerifyCertFingerprint, &p.ServerCertFingerprint, &p.Alpn, &p.BindInterface, &p.DnsOverride, &p.RemoteDns, &p.LocalDns, &p.RoutingOverride, &p.GeositeDirect, &p.GeoipDirect, &p.AppFilterOverride, &p.FilterApps, &p.FilterMode, &p.TotalTx, &p.TotalRx); err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func GetProfile(id string) (*Profile, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	var p Profile
	err := db.QueryRow("SELECT id, name, sshAddr, user, pass, authType, privateKey, keyPass, tunnelType, proxyAddr, customHost, serverName, customPath, enableCustomPath, proxyAuthRequired, proxyAuthToken, proxyAuthUser, proxyAuthPass, httpPayload, type, udpgwVersion, udpgwAddr, disableStatusCheck, verifyFingerprint, serverFingerprint, verifyCertFingerprint, serverCertFingerprint, alpn, bindInterface, dnsOverride, remoteDns, localDns, routingOverride, geositeDirect, geoipDirect, appFilterOverride, filterApps, filterMode, totalTx, totalRx FROM profiles WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.SshAddr, &p.User, &p.Pass, &p.AuthType, &p.PrivateKey, &p.KeyPass, &p.TunnelType, &p.ProxyAddr, &p.CustomHost, &p.ServerName, &p.CustomPath, &p.EnableCustomPath, &p.ProxyAuthRequired, &p.ProxyAuthToken, &p.ProxyAuthUser, &p.ProxyAuthPass, &p.HttpPayload, &p.Type, &p.UdpgwVersion, &p.UdpgwAddr, &p.DisableStatusCheck, &p.VerifyFingerprint, &p.ServerFingerprint, &p.VerifyCertFingerprint, &p.ServerCertFingerprint, &p.Alpn, &p.BindInterface, &p.DnsOverride, &p.RemoteDns, &p.LocalDns, &p.RoutingOverride, &p.GeositeDirect, &p.GeoipDirect, &p.AppFilterOverride, &p.FilterApps, &p.FilterMode, &p.TotalTx, &p.TotalRx)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func AddProfile(p Profile) (string, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	if p.ID == "" {
		p.ID = generateUUID()
	}

	_, err := db.Exec("INSERT INTO profiles (id, name, sshAddr, user, pass, authType, privateKey, keyPass, tunnelType, proxyAddr, customHost, serverName, customPath, enableCustomPath, proxyAuthRequired, proxyAuthToken, proxyAuthUser, proxyAuthPass, httpPayload, type, udpgwVersion, udpgwAddr, disableStatusCheck, verifyFingerprint, serverFingerprint, verifyCertFingerprint, serverCertFingerprint, alpn, bindInterface, dnsOverride, remoteDns, localDns, routingOverride, geositeDirect, geoipDirect, appFilterOverride, filterApps, filterMode, totalTx, totalRx) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		p.ID, p.Name, p.SshAddr, p.User, p.Pass, p.AuthType, p.PrivateKey, p.KeyPass, p.TunnelType, p.ProxyAddr, p.CustomHost, p.ServerName, p.CustomPath, p.EnableCustomPath, p.ProxyAuthRequired, p.ProxyAuthToken, p.ProxyAuthUser, p.ProxyAuthPass, p.HttpPayload, p.Type, p.UdpgwVersion, p.UdpgwAddr, p.DisableStatusCheck, p.VerifyFingerprint, p.ServerFingerprint, p.VerifyCertFingerprint, p.ServerCertFingerprint, p.Alpn, p.BindInterface, p.DnsOverride, p.RemoteDns, p.LocalDns, p.RoutingOverride, p.GeositeDirect, p.GeoipDirect, p.AppFilterOverride, p.FilterApps, p.FilterMode, p.TotalTx, p.TotalRx)
	if err != nil {
		return "", err
	}
	return p.ID, nil
}

func UpdateProfile(id string, p Profile) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	_, err := db.Exec("UPDATE profiles SET name=?, sshAddr=?, user=?, pass=?, authType=?, privateKey=?, keyPass=?, tunnelType=?, proxyAddr=?, customHost=?, serverName=?, customPath=?, enableCustomPath=?, proxyAuthRequired=?, proxyAuthToken=?, proxyAuthUser=?, proxyAuthPass=?, httpPayload=?, type=?, udpgwVersion=?, udpgwAddr=?, disableStatusCheck=?, verifyFingerprint=?, serverFingerprint=?, verifyCertFingerprint=?, serverCertFingerprint=?, alpn=?, bindInterface=?, dnsOverride=?, remoteDns=?, localDns=?, routingOverride=?, geositeDirect=?, geoipDirect=?, appFilterOverride=?, filterApps=?, filterMode=?, totalTx=?, totalRx=? WHERE id=?",
		p.Name, p.SshAddr, p.User, p.Pass, p.AuthType, p.PrivateKey, p.KeyPass, p.TunnelType, p.ProxyAddr, p.CustomHost, p.ServerName, p.CustomPath, p.EnableCustomPath, p.ProxyAuthRequired, p.ProxyAuthToken, p.ProxyAuthUser, p.ProxyAuthPass, p.HttpPayload, p.Type, p.UdpgwVersion, p.UdpgwAddr, p.DisableStatusCheck, p.VerifyFingerprint, p.ServerFingerprint, p.VerifyCertFingerprint, p.ServerCertFingerprint, p.Alpn, p.BindInterface, p.DnsOverride, p.RemoteDns, p.LocalDns, p.RoutingOverride, p.GeositeDirect, p.GeoipDirect, p.AppFilterOverride, p.FilterApps, p.FilterMode, p.TotalTx, p.TotalRx, id)
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
	s.DirectSiteTags = strings.Split(directSiteTags, ",")
	s.DirectIPTags = strings.Split(directIPTags, ",")
	return &s, nil
}

func UpdateSettings(s Settings) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	directSiteTags := strings.Join(s.DirectSiteTags, ",")
	directIPTags := strings.Join(s.DirectIPTags, ",")
	_, err := db.Exec("UPDATE settings SET local_addr=?, dns_addr=?, local_dns_server=?, remote_dns_server=?, geosite_filepath=?, geoip_filepath=?, direct_site_tags=?, direct_ip_tags=?, udpgw_addr=?, udpgw_version=? WHERE id=1",
		s.LocalAddr, s.DnsAddr, s.LocalDnsServer, s.RemoteDnsServer, s.GeoSiteFilePath, s.GeoIPFilePath, directSiteTags, directIPTags, s.UdpgwAddr, s.UdpgwVersion)
	return err
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

	udpgwAddr := s.UdpgwAddr
	udpgwVersion := s.UdpgwVersion
	if p.DnsOverride {
		udpgwAddr = p.UdpgwAddr
		udpgwVersion = p.UdpgwVersion
	}

	localAddr := s.LocalAddr
	if localAddr == "" {
		localAddr = "127.0.0.1:1080"
	}
	dnsAddr := s.DnsAddr
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:5353"
	}

	config := myssh.ProxyConfig{
		LocalAddr:                    localAddr,
		SshAddr:                      p.SshAddr,
		User:                         p.User,
		AuthType:                     p.AuthType,
		PrivateKey:                   p.PrivateKey,
		PrivateKeyPassphrase:         p.KeyPass,
		Pass:                         p.Pass,
		VerifySSHFingerprint:         p.VerifyFingerprint,
		ServerSSHFingerprint:         p.ServerFingerprint,
		TunnelType:                   p.TunnelType,
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
	}

	b, err := json.Marshal(config)
	return string(b), err
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
