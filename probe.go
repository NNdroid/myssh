package myssh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// 本文件实现宿主 UI 使用的探测类工具：进程环境诊断、SSH 服务器探测、
// TLS/QUIC 证书抓取与详情导出（均以 JSON 面向 gomobile/CLI）。

// PrintAndroidUserInfo 打印 Go 进程在 Android/Linux 下的用户信息。
func PrintAndroidUserInfo() {
	realUid := os.Getuid()
	realGid := os.Getgid()

	// Android UID 结构: UID = (UserID * 100000) + AppBaseID
	androidUserId := realUid / 100000
	appBaseId := realUid % 100000

	var username, homeDir string
	u, err := user.Current()
	if err != nil {
		zlog.Warn("user.Current() failed (Normal on highly customized Android)", zap.Error(err))
		username = "unknown"
		homeDir = "unknown"
	} else {
		username = u.Username
		homeDir = u.HomeDir
	}

	zlog.Info("========== GO PROCESS USER INFO ==========",
		zap.Int("real_linux_uid", realUid),
		zap.Int("real_linux_gid", realGid),
		zap.Int("android_user_id", androidUserId),
		zap.Int("app_base_id", appBaseId),
		zap.String("username", username),
		zap.String("home_dir", homeDir),
	)
}

// CertInfo 服务端证书摘要（QUIC 或 TLS 抓取）。
type CertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	SANs       string `json:"sans"`
	Raw        []byte `json:"raw_der"`
	Protocol   string `json:"protocol"`
	IsVerified bool   `json:"is_verified"`
}

// FetchCertInfo 通过 TLS 或 QUIC 抓取 server 证书信息。
func FetchCertInfo(target string, useQUIC bool) (*CertInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := ensureHostPort(target, "443")
	host, _, _ := net.SplitHostPort(addr)

	var peerCerts []*x509.Certificate
	var protocol string
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "http/1.1"},
	}

	if useQUIC {
		protocol = "QUIC"
		baseConn, err := dialProtected(ctx, ProxyConfig{}, "udp", addr, 8*time.Second)
		if err != nil {
			return nil, err
		}
		udpConn, ok := baseConn.(*net.UDPConn)
		if !ok {
			baseConn.Close()
			return nil, fmt.Errorf("expected *net.UDPConn, got %T", baseConn)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		conn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsConfig, nil)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		defer conn.CloseWithError(0, "")
		peerCerts = conn.ConnectionState().TLS.PeerCertificates
	} else {
		protocol = "TLS"
		dialer := newProtectedDialer(ProxyConfig{}, 8*time.Second)
		baseConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		conn, err := newChromeUConn(ctx, baseConn, host, []string{"h3", "http/1.1"}, nil, false)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		peerCerts = conn.ConnectionState().PeerCertificates
	}

	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no cert")
	}

	cert := peerCerts[0]
	_, verifyErr := cert.Verify(x509.VerifyOptions{DNSName: host})

	return &CertInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore.Unix(),
		NotAfter:   cert.NotAfter.Unix(),
		SANs:       strings.Join(cert.DNSNames, ","),
		Raw:        cert.Raw,
		Protocol:   protocol,
		IsVerified: verifyErr == nil,
	}, nil
}

// SSHServerDetails SSH 服务器探测结果。
type SSHServerDetails struct {
	Address           string `json:"address"`
	Banner            string `json:"banner"`
	KeyType           string `json:"key_type"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	FingerprintMD5    string `json:"fingerprint_md5"`
	LatencyMs         int64  `json:"latency_ms"`
}

// probeSSHServer 探测：与 SSH 服务器完成版本/密钥交换后即断开。
func probeSSHServer(sshAddr string) (*SSHServerDetails, error) {
	if strings.TrimSpace(sshAddr) == "" {
		return nil, fmt.Errorf("empty sshAddr")
	}
	addr := ensureHostPort(sshAddr, "22")

	startTime := time.Now()
	var capturedKey ssh.PublicKey
	// 用户认证 banner（SSH_MSG_USERAUTH_BANNER，MOTD/服务器提示）在认证流程中、
	// 认证结果判定**之前**下发 —— 所以假凭据认证失败也能收到。没有 BannerCallback
	// 时这块信息直接丢失，WebUI「SSH 详情」的 banner 会永远是空（2026-09-15 修复）。
	var capturedBanner string
	config := &ssh.ClientConfig{
		User: "probe",
		Auth: []ssh.AuthMethod{
			ssh.Password("probe"),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			capturedKey = key
			return nil
		},
		BannerCallback: func(message string) error {
			capturedBanner = message
			return nil
		},
		Timeout: 6 * time.Second,
	}

	dialer := wrapAndroidProtect(&net.Dialer{Timeout: 6 * time.Second})
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	latencyMs := time.Since(startTime).Milliseconds()

	var serverVersion string
	if sshConn != nil {
		serverVersion = string(sshConn.ServerVersion())
		sshConn.Close()
	}
	_ = chans
	_ = reqs

	if capturedKey == nil {
		return nil, fmt.Errorf("failed to retrieve ssh host key")
	}

	// 优先用户认证 banner（真正的 MOTD/提示）；没发 banner 的服务器退回版本标识行，
	// 保证探测总能给出点信息 —— 但不再把 banner 恒空。
	banner := strings.TrimRight(capturedBanner, "\r\n")
	if banner == "" {
		banner = serverVersion
	}

	return &SSHServerDetails{
		Address:           addr,
		Banner:            banner,
		KeyType:           capturedKey.Type(),
		FingerprintSHA256: ssh.FingerprintSHA256(capturedKey),
		FingerprintMD5:    ssh.FingerprintLegacyMD5(capturedKey),
		LatencyMs:         latencyMs,
	}, nil
}

// GetSSHFingerprint 返回 SSH 服务器主机密钥的 SHA256 指纹。
func GetSSHFingerprint(sshAddr string) (string, error) {
	details, err := probeSSHServer(sshAddr)
	if err != nil {
		return "", err
	}
	return details.FingerprintSHA256, nil
}

// GetSSHServerDetailsJSON 返回 SSH 服务器探测结果的 JSON 字符串。
func GetSSHServerDetailsJSON(sshAddr string) (string, error) {
	details, err := probeSSHServer(sshAddr)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TLSCertDetails TLS 证书详情。
type TLSCertDetails struct {
	Target             string   `json:"target"`
	SNI                string   `json:"sni"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBefore          int64    `json:"not_before"`
	NotAfter           int64    `json:"not_after"`
	DaysRemaining      int      `json:"days_remaining"`
	IsExpired          bool     `json:"is_expired"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	TLSVersion         string   `json:"tls_version"`
	NegotiatedProtocol string   `json:"negotiated_protocol"`
	LatencyMs          int64    `json:"latency_ms"`
}

// probeTLSCert 探测：抓取 target TLS/HTTPS 服务端叶子证书详情。
func probeTLSCert(target string, serverName string) (*TLSCertDetails, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := ensureHostPort(target, "443")
	host, _, _ := net.SplitHostPort(addr)

	sni := strings.TrimSpace(serverName)
	if sni == "" {
		sni = host
	}

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	dialer := wrapAndroidProtect(&net.Dialer{Timeout: 6 * time.Second})
	baseConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := newChromeUConn(ctx, baseConn, sni, []string{"h2", "http/1.1"}, nil, false)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	latencyMs := time.Since(startTime).Milliseconds()
	connState := conn.ConnectionState()
	peerCerts := connState.PeerCertificates
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no certificate presented by server")
	}

	cert := peerCerts[0]
	var tlsVerStr string
	switch connState.Version {
	case tls.VersionTLS13:
		tlsVerStr = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVerStr = "TLS 1.2"
	case tls.VersionTLS11:
		tlsVerStr = "TLS 1.1"
	case tls.VersionTLS10:
		tlsVerStr = "TLS 1.0"
	default:
		tlsVerStr = fmt.Sprintf("0x%04X", connState.Version)
	}

	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	isExpired := time.Now().After(cert.NotAfter)

	return &TLSCertDetails{
		Target:             addr,
		SNI:                sni,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.Unix(),
		NotAfter:           cert.NotAfter.Unix(),
		DaysRemaining:      daysRemaining,
		IsExpired:          isExpired,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ips,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		FingerprintSHA256:  formatSHA256Fingerprint(cert.Raw),
		TLSVersion:         tlsVerStr,
		NegotiatedProtocol: connState.NegotiatedProtocol,
		LatencyMs:          latencyMs,
	}, nil
}

// GetTLSCertFingerprint 返回 target TLS/HTTPS/WSS 证书的 SHA256 指纹（格式: XX:XX:XX:...）。
func GetTLSCertFingerprint(target string, serverName string) (string, error) {
	details, err := probeTLSCert(target, serverName)
	if err != nil {
		return "", err
	}
	return details.FingerprintSHA256, nil
}

// GetTLSCertDetailsJSON 返回 TLS 证书探测结果的 JSON 字符串。
func GetTLSCertDetailsJSON(target string, serverName string) (string, error) {
	details, err := probeTLSCert(target, serverName)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
