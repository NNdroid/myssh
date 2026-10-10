package myssh

import (
	"context"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// 本文件集中 uTLS（Chrome ClientHello 指纹伪装）的构造与握手辅助函数。

// effectiveServerName 把节点配置的 server_name 解析成实际发往 SNI 的值。
//
// SNI 解析的**唯一**入口：运行时握手（buildUTLSConfig）与证书探测
// （probeTLSCert / FetchCertInfo）都必须经过它。规则只有一条——trim 后原样
// 透传，空即不发 SNI。
//
// 刻意**不**回落连接目标 host。server_name 是用户显式声明的伪装身份，host 只是
// 拨号地址，两者是否相等由用户自己决定。探测与运行时此前各写一套解析：探测端在
// 空值时回落 host，运行时直接透传空值。于是 server_name 留空且目标是域名时，两端
// 握手到不同的虚拟主机——探测发 SNI=host 拿到 host 匹配的证书，运行时不发 SNI
// 拿到服务器默认证书，「获取」按钮写下的 pin 在真连接时校验失败。规则收在这一处，
// 任何一端再自行回落 host 都会重新引入这个错位。
//
// uTLS 会自行丢弃非法 SNI（IP 字面量按 RFC 6066 §3 不发），所以这里不预判 IP：
// 只要不把空值悄悄换成 host，两端行为就恒等。
func effectiveServerName(serverName string) string {
	return strings.TrimSpace(serverName)
}

func buildUTLSConfig(cfg ProxyConfig, alpn []string) *utls.Config {
	c := &utls.Config{
		ServerName:            effectiveServerName(cfg.ServerName),
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
	}
	if len(alpn) > 0 {
		c.NextProtos = alpn
	}
	return c
}

func handshakeUTLS(ctx context.Context, conn net.Conn, utlsConfig *utls.Config) (*utls.UConn, error) {
	uConn := utls.UClient(conn, utlsConfig, utls.HelloChrome_Auto)
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uConn, nil
}

// newChromeUConn 在一条已建立的 TCP 连接上完成 uTLS（Chrome 指纹）握手，
// 供 DoT 上游与证书探测等复用——把这几处原本裸用 crypto/tls 的 ClientHello
// 也伪装成 Chrome 指纹，避免被按“Go 客户端”画像封锁/限速。
//
// serverName 传已解析过的有效值（见 effectiveServerName）。本函数是纯粹的
// 握手终点，不做 SNI 解析，也不拿连接目标兜底——解析规则只在 effectiveServerName。
//
// 注意：uTLS 内置 Chrome 指纹的 ALPN 是模板里硬编码的 ["h2","http/1.1"]，
// ApplyPreset 只会用 Config.ServerName 覆盖 SNI，并不会用 Config.NextProtos
// 覆盖 ALPN（见 u_parrots.ApplyPreset 无 ALPNExtension 分支）。因此若像
// DoT 那样必须协商 "dot"，直接设 Config.NextProtos 无效——必须取出 Chrome
// spec、就地改写其 ALPNExtension，再走 HelloCustom + ApplyPreset。其余扩展、
// 曲线、压缩顺序全部保持 Chrome 原样，只有协议列表随需求替换。
//   - alpn 为空时沿用 Chrome spec 默认协议列表；
//   - sessionCache 非 nil 时启用 TLS 1.3 会话复用，DoT 借此让上游连接池命中后省一次握手；
//   - strictVerify=false 时跳过系统根校验（探测场景：先拿证书再由调用方自行
//     Verify），true 时维持与 crypto/tls 一致的正常校验语义。
func newChromeUConn(ctx context.Context, conn net.Conn, serverName string, alpn []string, sessionCache utls.ClientSessionCache, strictVerify bool) (*utls.UConn, error) {
	conf := &utls.Config{ServerName: serverName}
	if !strictVerify {
		conf.InsecureSkipVerify = true
	}
	if sessionCache != nil {
		conf.ClientSessionCache = sessionCache
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(alpn) > 0 {
		for _, ext := range spec.Extensions {
			if a, ok := ext.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = alpn
			}
		}
	}

	uConn := utls.UClient(conn, conf, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, err
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return uConn, nil
}
