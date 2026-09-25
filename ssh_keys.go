package myssh

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// 本文件集中 SSH 私钥解析工具，供 gomobile 宿主在保存配置前预校验。

// CheckIfKeyEncrypted 检查私钥加密状态（供 Android 调用）。
//
// 返回值:
//
// 0 - 未加密
// 1 - 已加密（需要口令）
// 2 - 格式错误
func CheckIfKeyEncrypted(key string) int {
	keyBytes := []byte(key)
	_, err := ssh.ParsePrivateKey(keyBytes)

	if err == nil {
		return 0
	}

	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return 1
	}

	return 2
}

// ValidatePassphrase 校验私钥口令是否正确。
func ValidatePassphrase(key string, pass string) bool {
	_, err := ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
	return err == nil
}

// parsePrivateKeySshSigner 解析 SSH 私钥为签名器；带口令时在
// PassphraseMissingError 上自动重试带口令解析。
func parsePrivateKeySshSigner(privateKey []byte, passphrase []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(privateKey)
	// 口令保护 (Passphrase)
	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return ssh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
	}
	return signer, err
}
