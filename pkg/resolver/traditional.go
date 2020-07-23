package resolver

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/mimuret/doh-proxy/pkg/domain"
)

type Traditional struct {
	host        string
	port        string
	retry       uint
	useTCPOnly  bool
	timeoutMsec uint
}

type request struct {
	msg         *dns.Msg
	useTCP      bool
	retryCount  uint
	timeoutMsec uint
	done        chan struct{}
}

func NewTraditional(host string, retry uint, timeoutMsec uint, useTCPOnly bool) *Traditional {
	return &Traditional{
		host:        host,
		retry:       retry,
		timeoutMsec: timeoutMsec,
		useTCPOnly:  useTCPOnly,
	}
}

func (t *Traditional) Resolv(msg *dns.Msg) (*dns.Msg, *domain.ResolvError) {
	req := &request{
		msg:         msg,
		useTCP:      false,
		retryCount:  t.retry,
		timeoutMsec: t.timeoutMsec,
	}
	return t.resolv(req)
}

func (t *Traditional) resolv(req *request) (*dns.Msg, *domain.ResolvError) {
	c := new(dns.Client)

	c.DialTimeout = time.Duration(req.timeoutMsec) * time.Millisecond
	if req.useTCP || t.useTCPOnly {
		c.Net = "tcp"
	} else {
		c.Net = "udp"
	}
	r, _, err := c.Exchange(req.msg, t.host)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			req.timeoutMsec *= 2
		}
		if req.retryCount > 0 {
			req.retryCount--
			return t.resolv(req)
		}
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return nil, &domain.ResolvError{fmt.Errorf("timeout error timeout(msec): %d: %w", req.timeoutMsec, err), domain.ResolvErrCodeTimeout}
		}
		return nil, &domain.ResolvError{fmt.Errorf("failed to get dns response: %w", err), domain.ResolvErrCodeUnKnown}
	}
	if r.Truncated {
		if c.Net == "tcp" {
			return r, nil
		}
		req.useTCP = true
		return t.resolv(req)
	}
	return r, nil
}
