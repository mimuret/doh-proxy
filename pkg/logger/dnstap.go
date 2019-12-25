package logger

import (
	"net"
	"strings"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/gogo/protobuf/proto"
	"github.com/miekg/dns"
	"github.com/mimuret/doh-proxy/pkg/domain"
	"github.com/mimuret/dtap"
)

var dnstapType = dnstap.Dnstap_MESSAGE

const outputChannelSize = 10000
const outputChannelFlush = 7000
const protobufSize = 1024 * 1024

var (
	strVersion   = []byte("0.1.0")
	strXFF       = []byte("X-Forwarded-For")
	strXFP       = []byte("X-Forwarded-Port")
	flushTimeout = 1 * time.Second
	net128       = net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")
	net32        = net.ParseIP("255.255.255.255")
)

var (
	CQ  = dnstap.Message_CLIENT_QUERY
	CR  = dnstap.Message_CLIENT_RESPONSE
	TCP = dnstap.SocketProtocol_TCP
)

type DNSTAP struct {
	recIP  bool
	output *dtap.DnstapOutput
	level  domain.LoggerLevel
}

func NewDNSTAP(level domain.LoggerLevel, output *dtap.DnstapOutput, recIP bool) *DNSTAP {
	return &DNSTAP{
		output: output,
		recIP:  recIP,
		level:  level,
	}
}
func (l *DNSTAP) Logging(level domain.LoggerLevel, msg *dns.Msg, mtype dnstap.Message_Type, ip net.IP, port uint32) {
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
	now := time.Now()
	timeSec := uint64(now.Unix())
	timeNsec := uint32(now.Nanosecond())
	tapMsg := &dnstap.Message{
		Type:           &mtype,
		QueryTimeSec:   &timeSec,
		QueryTimeNsec:  &timeNsec,
		SocketFamily:   &family,
		SocketProtocol: &TCP,
		QueryAddress:   ip,
		QueryPort:      &port,
		QueryMessage:   bs,
	}
	dnstapFrame := &dnstap.Dnstap{
		Type:    &dnstapType,
		Message: tapMsg,
	}
	frame, err := proto.Marshal(dnstapFrame)
	if err != nil {
		return
	}
	l.output.SetMessage(frame)
}
