package resolver

import (
	"errors"
	"time"

	"github.com/miekg/dns"
)

type Traditional struct {
	host string
}

func NewTraditional(host string) *Traditional {
	return &Traditional{
		host: host,
	}
}

func (t *Traditional) Resolv(msg *dns.Msg) (*dns.Msg, error) {
	return t.resolv(msg, false)
}

func (t *Traditional) resolv(msg *dns.Msg, useTCP bool) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Net = "udp"
	c.DialTimeout = 2 * time.Second
	c.ReadTimeout = 2 * time.Second
	c.WriteTimeout = 1 * time.Second
	if useTCP {
		c.Net = "tcp"
	}
	r, _, err := c.Exchange(msg, t.host)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		if c.Net == "tcp" {
			return nil, errors.New("got truncated message on TCP (64kiB limit exceeded?)")
		}
		return t.resolv(msg, true)
	}
	return r, nil
}
