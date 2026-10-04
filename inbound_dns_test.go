package myssh

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestInterceptedDNSReplyUsesLocalCacheForEveryPort53ClientQuery(t *testing.T) {
	old := localDnsServer.Load()
	defer localDnsServer.Store(old)

	req := new(dns.Msg)
	req.SetQuestion("cache.example.", dns.TypeA)
	req.Id = 0x1234

	cached := new(dns.Msg)
	cached.SetReply(req)
	cached.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "cache.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("203.0.113.10").To4(),
		},
	}

	localDnsServer.Store(&LocalDnsServer{cache: map[string]dnsCacheEntry{
		dns.Fqdn("cache.example") + "-" + strconv.Itoa(int(dns.TypeA)): {
			msg:       cached,
			expiresAt: time.Now().Add(time.Minute),
			cachedAt:  time.Now(),
			ips:       []net.IP{net.ParseIP("203.0.113.10")},
		},
	}})

	wire, err := req.Pack()
	require.NoError(t, err)
	replyWire, handled, err := interceptedDNSReply(wire)
	require.NoError(t, err)
	require.True(t, handled)

	reply := new(dns.Msg)
	require.NoError(t, reply.Unpack(replyWire))
	require.Equal(t, req.Id, reply.Id)
	require.Len(t, reply.Answer, 1)
	require.Equal(t, "203.0.113.10", reply.Answer[0].(*dns.A).A.String())
}

func TestInterceptedDNSReplyDoesNotLeakMalformedPort53Payload(t *testing.T) {
	_, handled, err := interceptedDNSReply([]byte{0x01, 0x02, 0x03})
	require.True(t, handled)
	require.Error(t, err)
}

func TestInterceptedDNSReplyHonorsExplicitIPv4OnlyPolicy(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))

	req := new(dns.Msg)
	req.SetQuestion("v6.example.", dns.TypeAAAA)
	wire, err := req.Pack()
	require.NoError(t, err)

	replyWire, handled, err := interceptedDNSReply(wire)
	require.NoError(t, err)
	require.True(t, handled)

	reply := new(dns.Msg)
	require.NoError(t, reply.Unpack(replyWire))
	require.Equal(t, dns.RcodeSuccess, reply.Rcode)
	require.Empty(t, reply.Answer)
}

func TestInterceptedDNSReplyFallsBackOnlyWhenDNSCoreIsAbsent(t *testing.T) {
	old := localDnsServer.Load()
	localDnsServer.Store(nil)
	defer localDnsServer.Store(old)

	req := new(dns.Msg)
	req.SetQuestion("startup.example.", dns.TypeA)
	wire, err := req.Pack()
	require.NoError(t, err)

	replyWire, handled, err := interceptedDNSReply(wire)
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, replyWire)
}
