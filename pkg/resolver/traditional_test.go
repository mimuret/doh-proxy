package resolver_test

import (
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/mimuret/doh-proxy/pkg/resolver"
	"github.com/stretchr/testify/assert"
)

func TestTraditionalResolv(t *testing.T) {
	udpServer := startServer("udp", HelloServer)
	defer udpServer.Shutdown()
	tcpServer := startServer("tcp", HelloServer)
	defer tcpServer.Shutdown()

	r := resolver.NewTraditional("127.0.0.1:10053", 3, 2000, false)
	m := new(dns.Msg).
		SetQuestion("example.jp.", dns.TypeTXT)

	msg, err := r.Resolv(m)

	assert.Nil(t, err, "failed to resolv msg: %+v", err)
	if assert.NotNil(t, msg) {
		assert.False(t, msg.MsgHdr.Truncated)
	}
}

func TestTraditionalResolvTruncated(t *testing.T) {
	udpServer := startServer("udp", TrancateServerUDP)
	defer udpServer.Shutdown()
	tcpServer := startServer("tcp", TrancateServerTCP)
	defer tcpServer.Shutdown()

	r := resolver.NewTraditional("127.0.0.1:10053", 3, 2000, false)
	m := new(dns.Msg).
		SetQuestion("example.jp.", dns.TypeTXT)
	msg, err := r.Resolv(m)

	assert.Nil(t, err, "failed to resolv msg: %+v", err)
	if assert.NotNil(t, msg) {
		assert.False(t, msg.MsgHdr.Truncated)
	}
}

func TestTraditionalResolvEDNS0(t *testing.T) {
	udpServer := startServer("udp", TrancateServerEDNS0)
	defer udpServer.Shutdown()
	tcpServer := startServer("tcp", TrancateServerTCP)
	defer tcpServer.Shutdown()

	r := resolver.NewTraditional("127.0.0.1:10053", 3, 2000, false)
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			m := new(dns.Msg).
				SetQuestion("example.jp.", dns.TypeTXT).
				SetEdns0(4096, true)
			msg, err := r.Resolv(m)

			assert.Nil(t, err, "failed to resolv msg: %+v", err)
			if assert.NotNil(t, msg) {
				assert.False(t, msg.MsgHdr.Truncated)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
