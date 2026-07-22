package myssh

import (
	"go.uber.org/zap"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadGlobalConfigFromJson(t *testing.T) {
	initLoggerIfNeed()

	validJson := "{\"local_dns_server\":\"1.1.1.1:53\",\"remote_dns_server\":\"8.8.8.8:53\",\"geosite_filepath\":\"test_geosite.dat\",\"geoip_filepath\":\"test_geoip.dat\"}"
	invalidJson := "{\"local_dns_server\":\"1.1.1.1:53\","

	assert.Equal(t, 0, LoadGlobalConfigFromJson(validJson), "Should successfully load valid JSON")
	assert.Equal(t, -2, LoadGlobalConfigFromJson(invalidJson), "Should fail on invalid JSON")

	emptyJson := "{}"
	globalConfig = GlobalConfig{} // Reset global state
	assert.Equal(t, 0, LoadGlobalConfigFromJson(emptyJson), "Should successfully load empty JSON")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "223.5.5.5:53", globalConfig.LocalDnsServer, "Should set default LocalDnsServer")
	assert.Equal(t, "8.8.8.8:53", globalConfig.RemoteDnsServer, "Should set default RemoteDnsServer")
	assert.Equal(t, "geosite.dat", globalConfig.GeoSiteFilePath, "Should set default GeoSiteFilePath")
	assert.Equal(t, "geoip.dat", globalConfig.GeoIPFilePath, "Should set default GeoIPFilePath")
}

func initLoggerIfNeed() {
	if zlog == nil {
		zlog = zap.NewNop().Sugar()
	}
}
