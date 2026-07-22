package myssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func generateTestKey(t *testing.T, password string) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	if password != "" {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		assert.NoError(t, err)
	}

	return string(pem.EncodeToMemory(block))
}

func TestCheckIfKeyEncrypted(t *testing.T) {
	unencryptedKey := generateTestKey(t, "")
	encryptedKey := generateTestKey(t, "password123")
	invalidKey := "invalid-key-data"

	assert.Equal(t, 0, CheckIfKeyEncrypted(unencryptedKey), "Should return 0 for unencrypted key")
	assert.Equal(t, 1, CheckIfKeyEncrypted(encryptedKey), "Should return 1 for encrypted key")
	assert.Equal(t, 2, CheckIfKeyEncrypted(invalidKey), "Should return 2 for invalid key")
}

func TestValidatePassphrase(t *testing.T) {
	encryptedKey := generateTestKey(t, "password123")

	assert.True(t, ValidatePassphrase(encryptedKey, "password123"), "Should validate correct passphrase")
	assert.False(t, ValidatePassphrase(encryptedKey, "wrongpassword"), "Should fail with wrong passphrase")
}

func TestTrafficDelta(t *testing.T) {
	assert.Equal(t, uint64(50), trafficDelta(100, 50))
	assert.Equal(t, uint64(0), trafficDelta(50, 100), "Should return 0 when current < previous")
	assert.Equal(t, uint64(0), trafficDelta(100, 100))
}

func TestBytesPerSecond(t *testing.T) {
	assert.Equal(t, uint64(100), bytesPerSecond(100, time.Second))
	assert.Equal(t, uint64(200), bytesPerSecond(100, 500*time.Millisecond))
	assert.Equal(t, uint64(0), bytesPerSecond(0, time.Second))
}
