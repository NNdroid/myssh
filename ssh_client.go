package myssh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// 本文件承载 SSH 客户端侧逻辑：拨号配置（算法白名单/认证）、
// 主机密钥三档校验语义，以及供 UI 展示的握手信息缓存。

// ─────────────────────────────────────────────────────────────────────────────
// SSH 握手信息（供 UI 展示服务器标识）
//
// 两类 banner 语义不同，切勿混为一谈：
//   ServerVersion —— RFC 4253 版本标识行（如 SSH-2.0-OpenSSH_9.6），版本交换阶段即确定；
//   Banner        —— SSH_MSG_USERAUTH_BANNER 认证阶段文本（服务端自定义提示 / MOTD），可能为空。
// ─────────────────────────────────────────────────────────────────────────────

// SSHHandshakeInfo 一次真实 SSH 握手中可对外展示的信息。
type SSHHandshakeInfo struct {
	Address       string `json:"address"`
	ClientVersion string `json:"client_version"`
	ServerVersion string `json:"server_version"`
	Banner        string `json:"banner"`
	UpdatedAt     int64  `json:"updated_at"`
}

var (
	sshHandshakeMu    sync.Mutex
	sshHandshakeCache = make(map[string]*SSHHandshakeInfo)
	sshHandshakeLast  *SSHHandshakeInfo
)

// sshHandshakeCacheMax 限制按 addr 索引的握手缓存条目数。节点地址集合会随
// 多节点切换 / 动态端口变化而增长，旧实现只增不删 → 无界增长。
const sshHandshakeCacheMax = 64

// ensureHandshakeCacheBudget 在缓存达到上限时整表重置。必须在持有
// sshHandshakeMu 时调用。重置不影响"最近一次握手"展示：sshHandshakeLast
// 仍指向已捕获的条目。
func ensureHandshakeCacheBudget() {
	if len(sshHandshakeCache) >= sshHandshakeCacheMax {
		sshHandshakeCache = make(map[string]*SSHHandshakeInfo)
	}
}

// recordSSHHandshakeVersion 记录握手中的版本标识行（认证成功后才可达）。
func recordSSHHandshakeVersion(addr, clientVersion, serverVersion string) {
	sshHandshakeMu.Lock()
	defer sshHandshakeMu.Unlock()
	ensureHandshakeCacheBudget()
	info := sshHandshakeCache[addr]
	if info == nil {
		info = &SSHHandshakeInfo{Address: addr}
		sshHandshakeCache[addr] = info
	}
	info.ClientVersion = clientVersion
	info.ServerVersion = serverVersion
	info.UpdatedAt = time.Now().UnixMilli()
	sshHandshakeLast = info
}

// recordSSHHandshakeBanner 记录认证阶段 banner（服务端未配置时为空，此时保留旧值）。
func recordSSHHandshakeBanner(addr, banner string) {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return
	}
	sshHandshakeMu.Lock()
	defer sshHandshakeMu.Unlock()
	ensureHandshakeCacheBudget()
	info := sshHandshakeCache[addr]
	if info == nil {
		info = &SSHHandshakeInfo{Address: addr}
		sshHandshakeCache[addr] = info
	}
	info.Banner = banner
	info.UpdatedAt = time.Now().UnixMilli()
	sshHandshakeLast = info
}

// getSSHHandshakeInfoJSON 返回 addr 最近一次真实握手的 JSON；
// addr 无记录时回退到最近一次握手，保证节点切换后仍能展示当前连接的信息；全无记录返回 ""。
func getSSHHandshakeInfoJSON(addr string) string {
	sshHandshakeMu.Lock()
	info := sshHandshakeCache[addr]
	if info == nil {
		info = sshHandshakeLast
	}
	var snapshot SSHHandshakeInfo
	if info != nil {
		snapshot = *info
	}
	sshHandshakeMu.Unlock()

	if info == nil {
		return ""
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	return string(data)
}

// checkSSHHostKey 实现 SSH 主机密钥校验的三档语义：
//
//  1. VerifySSHFingerprint=true：指纹必须与配置一致（MD5 或 SHA256）；
//  2. VerifySSHFingerprint=false 但已记录过指纹（TOFU pin 非空）：指纹必须
//     与首连时一致，防止已知主机被静默替换——这是默认开启的中间人防线；
//  3. 首连（pin 为空）：放行并告警，宿主应在连接成功后回写指纹完成 pin。
//     重置信任 = 清空配置中的指纹字段。
func checkSSHHostKey(cfg ProxyConfig, key ssh.PublicKey) error {
	fpSHA256 := ssh.FingerprintSHA256(key)
	fpMD5 := ssh.FingerprintLegacyMD5(key)

	if cfg.VerifySSHFingerprint {
		if !(fpMD5 == cfg.ServerSSHFingerprint || fpSHA256 == cfg.ServerSSHFingerprint) {
			return fmt.Errorf("host key [%s,%s] mismatch: %s", fpMD5, fpSHA256, cfg.ServerSSHFingerprint)
		}
		return nil
	}

	pinned := strings.TrimSpace(cfg.ServerSSHFingerprint)
	if pinned == "" {
		zlog.Warnf("%s [SSH-Handshake] ⚠️ Host key verification is DISABLED — accepted %s on first sight (TOFU). Pin this fingerprint via the profile's fingerprint field to detect MITM.", TAG, fpSHA256)
		return nil
	}
	if !(fpMD5 == pinned || fpSHA256 == pinned) {
		return fmt.Errorf("host key CHANGED since first connection (pinned %s, got [%s,%s]) — possible MITM; if the server was rebuilt, clear the stored fingerprint to re-trust", pinned, fpMD5, fpSHA256)
	}
	return nil
}

// dialSSH 在已建立的隧道连接上完成 SSH 握手并返回客户端。
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
			return checkSSHHostKey(cfg, key)
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
			// 认证阶段 banner（服务端自定义提示 / MOTD）：捕获供 UI 展示，探测路径同样记录
			recordSSHHandshakeBanner(cfg.SshAddr, message)
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

	cv := string(scc.ClientVersion())
	sv := string(scc.ServerVersion())
	// 版本标识行：认证已通过，记入缓存供连接详情面板展示
	recordSSHHandshakeVersion(cfg.SshAddr, cv, sv)

	if !isPing {
		zlog.Warnf("%s [SSH-Handshake] SSH ClientVersion: %s", TAG, cv)
		zlog.Warnf("%s [SSH-Handshake] SSH ServerVersion: %s", TAG, sv)
	}

	client := ssh.NewClient(scc, chans, reqs)
	return client, nil
}
