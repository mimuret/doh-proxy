package domain_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mimuret/doh-proxy/pkg/domain"
)

func TestNewRecIP(t *testing.T) {

	testcases := []struct {
		useXFF   bool
		all      bool
		onError  bool
		networks string
		raise    bool
	}{
		{
			true, false, false, "", false,
		},
		{
			true, false, false, "127.0.0.0/12", false,
		},
		{
			true, false, false, "127.0.0.1/12", false,
		},
		{
			true, false, false, "127.0.0.1/12,192.168.0.0/24", false,
		},
		{
			true, false, false, "127.0.0.1/12,192.168.0.0/24,2001:db8::/48", false,
		},
		{
			true, false, false, "127.0.0.1/12,127.0.0.1", true,
		},
		{
			true, false, false, "127.0.0.1/12,", true,
		},
	}

	for i, tc := range testcases {
		_, err := domain.NewRecIP(tc.useXFF, tc.all, tc.onError, tc.networks)
		if tc.raise {
			assert.Error(t, err, "[%d] must raise error", i)
		} else {
			assert.NoError(t, err, "[%d] must raise error", i)
		}
	}
}

type dummyReciever struct {
	requestID  string
	remoteIP   net.IP
	remotePort uint16
	data       []byte
	header     map[string][]byte
}

func (d *dummyReciever) RequestID() string        { return d.requestID }
func (d *dummyReciever) RemoteIP() net.IP         { return d.remoteIP }
func (d *dummyReciever) RemotePort() uint16       { return d.remotePort }
func (d *dummyReciever) Data() []byte             { return d.data }
func (d *dummyReciever) Header(key string) []byte { return d.header[key] }
func (d *dummyReciever) SetHeader(string, string) {}
func (d *dummyReciever) SetBody([]byte) error     { return nil }
func (d *dummyReciever) SetStatusCode(code int)   {}

func TestRecIPRemoteIP(t *testing.T) {
	rec4 := &dummyReciever{
		remoteIP:   net.ParseIP("192.168.0.1"),
		remotePort: 8080,
		header: map[string][]byte{
			"X-Forwarded-For":  []byte("192.0.2.1"),
			"X-Forwarded-Port": []byte("443"),
		},
	}
	rec6 := &dummyReciever{
		remoteIP:   net.ParseIP("2001:db8:8080::1"),
		remotePort: 8080,
		header: map[string][]byte{
			"X-Forwarded-For":  []byte("2001:db8:443::1"),
			"X-Forwarded-Port": []byte("443"),
		},
	}
	testcases := []struct {
		rec      *dummyReciever
		useXFF   bool
		all      bool
		onError  bool
		networks string
		allIP    net.IP
		errIP    net.IP
	}{
		{
			rec4, false, false, false, "", net.ParseIP("255.255.255.255"), net.ParseIP("255.255.255.255"),
		},
		{
			rec6, false, false, false, "", net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
		},
		{
			rec4, false, true, false, "", net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.1"),
		},
		{
			rec6, false, true, false, "", net.ParseIP("2001:db8:8080::1"), net.ParseIP("2001:db8:8080::1"),
		},
		{
			rec4, false, false, true, "", net.ParseIP("255.255.255.255"), net.ParseIP("192.168.0.1"),
		},
		{
			rec6, false, false, true, "", net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), net.ParseIP("2001:db8:8080::1"),
		},
		{
			rec4, false, false, false, "192.168.0.0/24", net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.1"),
		},
		{
			rec6, false, false, false, "2001:db8:8080::/64", net.ParseIP("2001:db8:8080::1"), net.ParseIP("2001:db8:8080::1"),
		},
		{
			rec4, false, false, false, "192.0.2.1/24", net.ParseIP("255.255.255.255"), net.ParseIP("255.255.255.255"),
		},
		{
			rec6, false, false, false, "2001:db8:443::/64", net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
		},
		{
			rec4, true, false, false, "", net.ParseIP("255.255.255.255"), net.ParseIP("255.255.255.255"),
		},
		{
			rec6, true, false, false, "", net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
		},
		{
			rec4, true, true, false, "", net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1"),
		},
		{
			rec6, true, true, false, "", net.ParseIP("2001:db8:443::1"), net.ParseIP("2001:db8:443::1"),
		},
		{
			rec4, true, false, true, "", net.ParseIP("255.255.255.255"), net.ParseIP("192.0.2.1"),
		},
		{
			rec6, true, false, true, "", net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), net.ParseIP("2001:db8:443::1"),
		},
		{
			rec4, true, false, false, "192.168.0.0/24", net.ParseIP("255.255.255.255"), net.ParseIP("255.255.255.255"),
		},
		{
			rec6, true, false, false, "2001:db8:8080::/64", net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"), net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
		},
		{
			rec4, true, false, false, "192.0.2.1/24", net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1"),
		},
		{
			rec6, true, false, false, "2001:db8:443::/64", net.ParseIP("2001:db8:443::1"), net.ParseIP("2001:db8:443::1"),
		},
	}

	for i, tc := range testcases {
		recip, err := domain.NewRecIP(tc.useXFF, tc.all, tc.onError, tc.networks)
		assert.NoError(t, err)
		remoteIP := recip.RemoteIP(tc.rec, false)
		errRemoteIP := recip.RemoteIP(tc.rec, true)
		assert.True(t, remoteIP.Equal(tc.allIP), "[%d] failed to get remote ip on normal, %s != %s", i, remoteIP, tc.allIP)
		assert.True(t, errRemoteIP.Equal(tc.errIP), "[%d] failed to get remote ip on error, %s != %s", i, errRemoteIP, tc.errIP)
	}
}
