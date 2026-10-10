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

// probeConfig 把宿主传入的出站网卡绑定转成探测用的 ProxyConfig。
//
// 只取 BindInterface：探测是一条独立的短连接，不参与路由/DNS/隧道配置。这个
// 参数在 Android 上无效（bindDevice 在 Android 无 root 时是 no-op），但在
// Linux(root)/桌面平台的 myssh 内建 Web 服务里是真实生效的——探测必须与隧道走
// 同一条出口，否则在这些部署里会出现「隧道通、探测连不上」。
func probeConfig(bindInterface string) ProxyConfig {
	return ProxyConfig{BindInterface: bindInterface}
}

// FetchCertInfo 通过 TLS 或 QUIC 抓取 target 地址的证书信息。
//
// target 只作拨号地址；serverName 是发往 SNI 的值，与节点握手共用
// effectiveServerName 的规则（trim 后原样透传，空即不发 SNI）。要拿与 myssh
// 握手逐字一致的指纹就传节点的 server_name。bindInterface 与隧道出口保持一致。
// 本函数与 GetTLSCertFingerprint / GetTLSCertDetailsJSON 的区别只在输出结构
// （CertInfo vs TLSCertDetails）和 QUIC 支持。
func FetchCertInfo(target string, useQUIC bool, serverName string, bindInterface string) (*CertInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := ensureHostPort(target, "443")
	host, _, _ := net.SplitHostPort(addr)

	var peerCerts []*x509.Certificate
	var protocol string
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// SNI 与运行时握手共用 effectiveServerName（空即不发、不回落 host），见其注释。
	sni := effectiveServerName(serverName)

	if useQUIC {
		protocol = "QUIC"
		// 走 dialUDP 而非裸 Dialer：IP4P 形态的 proxy_addr 必须在这里解开
		// （见 probeTLSCert 的同款注释），否则 QUIC 探测同样连不上。
		baseConn, err := dialUDP(ctx, probeConfig(bindInterface), addr)
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
		tlsConfig := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         quicALPN,
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
		// 必须走 dialTCP（见 probeTLSCert 注释）；ALPN 与运行时共用 chromeALPN。
		baseConn, err := dialTCP(ctx, probeConfig(bindInterface), addr)
		if err != nil {
			return nil, err
		}
		conn, err := newChromeUConn(ctx, baseConn, sni, chromeALPN, nil, false)
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
func probeSSHServer(sshAddr string, bindInterface string) (*SSHServerDetails, error) {
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

	// 与运行时共用 dialSocket 的 IP4P 解析，否则 IP4P 形态的 ssh_addr 探测必败
	// （见 probeTLSCert 的注释）。ctx 复用同一个 6s 预算，与 config.Timeout 对齐。
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()
	conn, err := dialTCP(ctx, probeConfig(bindInterface), addr)
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
func GetSSHFingerprint(sshAddr string, bindInterface string) (string, error) {
	details, err := probeSSHServer(sshAddr, bindInterface)
	if err != nil {
		return "", err
	}
	return details.FingerprintSHA256, nil
}

// GetSSHServerDetailsJSON 返回 SSH 服务器探测结果的 JSON 字符串。
func GetSSHServerDetailsJSON(sshAddr string, bindInterface string) (string, error) {
	details, err := probeSSHServer(sshAddr, bindInterface)
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
func probeTLSCert(target string, serverName string, bindInterface string) (*TLSCertDetails, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := ensureHostPort(target, "443")

	// SNI 与运行时握手共用 effectiveServerName：空即不发，不回落 host（见其注释）。
	// 这是「获取指纹」写下的 pin 能在真连接时校验通过的前提。
	sni := effectiveServerName(serverName)

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	// 必须走 dialTCP 而不能用裸 net.Dialer——这是「raw+TLS 无法获取证书」的根因。
	//
	// 运行时隧道的拨号是 dialTunnel → dialTCP → dialSocket → resolveIP4PDialAddress，
	// 会解开 IP4P 形态的地址：proxy_addr 写成 [2001::<port><ipv4>]:0 或指向 IP4P AAAA
	// 的域名时，真实目标是从地址里解出的 IPv4:port。裸 Dialer 拿到的还是那个端口 0
	// 的 IPv6 字面量，connect 必然失败（且失败在握手之前，连证书都拿不到）。
	// 于是表现就是：隧道能连、SSH 能通，唯独「获取指纹/详情」永远报错。
	// dialTCP 还顺带与运行时一致地应用了出口网卡绑定与 socket 调优。
	baseConn, err := dialTCP(ctx, probeConfig(bindInterface), addr)
	if err != nil {
		return nil, err
	}
	conn, err := newChromeUConn(ctx, baseConn, sni, chromeALPN, nil, false)
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
func GetTLSCertFingerprint(target string, serverName string, bindInterface string) (string, error) {
	details, err := probeTLSCert(target, serverName, bindInterface)
	if err != nil {
		return "", err
	}
	return details.FingerprintSHA256, nil
}

// GetTLSCertDetailsJSON 返回 TLS 证书探测结果的 JSON 字符串。
//
// 指纹与详情都由 probeTLSCert 的同一次握手产生（fingerprint_sha256 就是指纹），
// 宿主侧一次调用即可同时拿到两者，不必再单独打一次握手取指纹。
func GetTLSCertDetailsJSON(target string, serverName string, bindInterface string) (string, error) {
	details, err := probeTLSCert(target, serverName, bindInterface)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
