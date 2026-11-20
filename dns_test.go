package myssh

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocalDnsServerInit(t *testing.T) {
	server := NewLocalDnsServer("127.0.0.1:0", "v2")
	assert.NotNil(t, server, "Server instance should not be nil")

	if server != nil {
		server.Stop()
	}
}
