package myssh

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain  info  goleak  info  goroutine  info 。
//
// IgnoreCurrent()  info 「 info 」 info  goroutine（ info  init  info
//
//	info ： info 、DNS  info cleanup info 、GeoRouter  info ），
//	info 「 info 」 info ， info 。
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreCurrent(),
		goleak.IgnoreTopFunction("github.com/quic-go/quic-go.(*Transport).listen"),
		goleak.IgnoreTopFunction("github.com/quic-go/quic-go.(*Transport).runSendQueue"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
