// +build tools

package myssh

import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
	"errors"
	"golang.org/x/crypto/ssh"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
	"github.com/quic-go/quic-go"
)

// CheckIfKeyEncrypted 供 Android 调用
// 返回值: 
// 0 - 不需要密码
// 1 - 需要密码
// 2 - 格式错误
func CheckIfKeyEncrypted(key string) int {
	keyBytes := []byte(key)
	_, err := ssh.ParsePrivateKey(keyBytes)
	
	if err == nil {
		return 0 // 解析成功，无需密码
	}

	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return 1 // 需要密码
	}

	return 2 // 格式非法或其他错误
}

// ValidatePassphrase 示例：带密码解析并测试是否通过
func ValidatePassphrase(key string, pass string) bool {
	_, err := ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
	return err == nil
}

type CertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	// 🌟 安卓端不认识 time.Time，必须转为 Unix 时间戳 (int64)
	NotBefore  int64  `json:"not_before"` 
	NotAfter   int64  `json:"not_after"`
	// 🌟 []string 在 AAR 中会变成难以使用的 Proxy 对象
	// 建议直接返回逗号分隔的字符串，安卓端 split 即可
	SANs       string `json:"sans"`
	Raw        []byte `json:"raw_der"`
	Protocol   string `json:"protocol"`
	IsVerified bool   `json:"is_verified"`
}

// FetchCertInfo 尝试通过 TLS 或 QUIC 获取服务器证书信息
// useQUIC: 为 true 时强制走 QUIC (UDP 443)，否则走常规 TLS (TCP 443)
func FetchCertInfo(target string, useQUIC bool) (*CertInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := target
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = target + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)

	var peerCerts []*x509.Certificate
	var protocol string
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // 为了拿到证书必须跳过验证
		NextProtos:         []string{"h3", "http/1.1"},
	}

	if useQUIC {
		protocol = "QUIC"
		conn, err := quic.DialAddr(ctx, addr, tlsConfig, nil)
		if err != nil {
			return nil, err
		}
		defer conn.CloseWithError(0, "")
		peerCerts = conn.ConnectionState().TLS.PeerCertificates
	} else {
		protocol = "TLS"
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
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
		NotBefore:  cert.NotBefore.Unix(), // 🌟 秒级时间戳
		NotAfter:   cert.NotAfter.Unix(),
		SANs:       strings.Join(cert.DNSNames, ","), // 🌟 逗号拼接
		Raw:        cert.Raw,
		Protocol:   protocol,
		IsVerified: verifyErr == nil,
	}, nil
}