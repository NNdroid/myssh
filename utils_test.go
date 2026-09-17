package myssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
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

func TestDecodeIP4PIP(t *testing.T) {
	t.Run("valid literal", func(t *testing.T) {
		ip, port, ok := decodeIP4PIP(net.ParseIP("2001::3039:102:304"))
		assert.True(t, ok)
		assert.Equal(t, "1.2.3.4", ip.String())
		assert.Equal(t, uint16(12345), port)
	})

	t.Run("edge ports", func(t *testing.T) {
		if _, port, ok := decodeIP4PIP(net.ParseIP("2001::0:1.2.3.4")); !ok || port != 0 {
			t.Fatalf("expected port 0, got %d ok=%v", port, ok)
		}
		if _, port, ok := decodeIP4PIP(net.ParseIP("2001::FFFF:1.2.3.4")); !ok || port != 65535 {
			t.Fatalf("expected port 65535, got %d ok=%v", port, ok)
		}
	})

	t.Run("not IP4P", func(t *testing.T) {
		for _, s := range []string{
			"2001:db8::1",          // not 2001::/80
			"1.2.3.4",              // IPv4
			"2001:1::3039:102:304", // second group non-zero
			"::3039:102:304",       // missing prefix
			"",
		} {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if _, _, ok := decodeIP4PIP(ip); ok {
				t.Errorf("expected %q to be rejected", s)
			}
		}
	})
}

func TestResolveIP4PDialAddress(t *testing.T) {
	dialer := &net.Dialer{Timeout: time.Second}
	ctx := context.Background()

	t.Run("literal IP4P resolves", func(t *testing.T) {
		addr, ok, err := resolveIP4PDialAddress(ctx, dialer, "tcp", "[2001::3039:102:304]:0")
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "1.2.3.4:12345", addr)
	})

	t.Run("plain IPv6 literal passes through", func(t *testing.T) {
		addr, ok, err := resolveIP4PDialAddress(ctx, dialer, "tcp", "[2001:db8::1]:443")
		assert.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, "[2001:db8::1]:443", addr)
	})

	t.Run("v6 network rejected for IPv4 result", func(t *testing.T) {
		for _, network := range []string{"tcp6", "udp6"} {
			_, ok, err := resolveIP4PDialAddress(ctx, dialer, network, "[2001::3039:102:304]:0")
			assert.Error(t, err)
			assert.False(t, ok)
		}
	})

	t.Run("malformed address passes through", func(t *testing.T) {
		addr, ok, err := resolveIP4PDialAddress(ctx, dialer, "tcp", "not-a-hostport")
		assert.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, "not-a-hostport", addr)
	})
}
