package myssh

import (
	"errors"
	"golang.org/x/crypto/ssh"
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