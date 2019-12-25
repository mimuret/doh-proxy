package logger

import (
	"encoding/base64"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/mimuret/doh-proxy/pkg/domain"
)

type Stdout struct {
	recIP bool
	level domain.LoggerLevel
}

func NewStdout(level domain.LoggerLevel, recIP bool) *Stdout {
	return &Stdout{
		level: level,
		recIP: recIP,
	}
}
func (l *Stdout) Logging(level domain.LoggerLevel, msg *dns.Msg, mtype dnstap.Message_Type, ip net.IP, port uint32) {
	if l.level < level {
		return
	}
	bs, err := msg.Pack()
	if err != nil {
		return
	}
	var family dnstap.SocketFamily
	if strings.Contains(ip.String(), ":") {
		family = dnstap.SocketFamily_INET6
	} else {
		family = dnstap.SocketFamily_INET
	}
	if !l.recIP {
		if family == dnstap.SocketFamily_INET {
			ip = net32
		} else {
			ip = net128
		}
	}
	log.WithFields(log.Fields{
		"QueryAddress": ip,
		"QueryPort":    port,
		"QueryMessage": msg.String(),
		"QueryBase64":  base64.RawURLEncoding.EncodeToString(bs),
	}).Info()
}
