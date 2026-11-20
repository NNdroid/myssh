package myssh

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadGlobalConfigFromJson(t *testing.T) {
	initLoggerIfNeed()

	validJson := "{\"local_dns_server\":\"1.1.1.1:53\",\"remote_dns_server\":\"8.8.8.8:53\",\"geosite_filepath\":\"test_geosite.dat\",\"geoip_filepath\":\"test_geoip.dat\"}"
	invalidJson := "{\"local_dns_server\":\"1.1.1.1:53\","

	assert.Equal(t, 0, loadGlobalConfigFromJson(validJson), "Should successfully load valid JSON")
	assert.Equal(t, -2, loadGlobalConfigFromJson(invalidJson), "Should fail on invalid JSON")

	emptyJson := "{}"
	globalConfig.Store(&GlobalConfig{}) // Reset global state
	assert.Equal(t, 0, loadGlobalConfigFromJson(emptyJson), "Should successfully load empty JSON")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "223.5.5.5:53", globalConfig.Load().LocalDnsServer, "Should set default LocalDnsServer")
	assert.Equal(t, "8.8.8.8:53", globalConfig.Load().RemoteDnsServer, "Should set default RemoteDnsServer")
	assert.Equal(t, "geosite.dat", globalConfig.Load().GeoSiteFilePath, "Should set default GeoSiteFilePath")
	assert.Equal(t, "geoip.dat", globalConfig.Load().GeoIPFilePath, "Should set default GeoIPFilePath")
}

// initLoggerIfNeed 兼容保留：zlog 现为 atomic 包装、包级默认即 Nop，
// 无需再手动初始化；调用点众多，保留空函数避免改动面扩大。
func initLoggerIfNeed() {}
