package querylogger

import (
	"encoding/base64"
	"encoding/json"
	"net"

	log "github.com/sirupsen/logrus"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/mimuret/doh-proxy/pkg/domain"
)

type Stdout struct {
	level domain.LoggerLevel
}

func NewStdout(level domain.LoggerLevel) *Stdout {
	return &Stdout{
		level: level,
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
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		return
	}

	qlog.WithFields(log.Fields{
		"Type":         "querylog",
		"QueryAddress": ip,
		"QueryPort":    port,
		"QueryMessage": string(jsonMsg),
		"QueryBase64":  base64.RawURLEncoding.EncodeToString(bs),
	}).Info()
}
