package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/valyala/fasthttp"
)

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

type Generator struct {
	RemoteAddr net.IP
	RemotePort uint32
	Family     dnstap.SocketFamily
	Protocol   dnstap.SocketProtocol
	TimeSec    uint64
	TimeNsec   uint32
	Nsid       []byte
	Query      *dnstap.Dnstap
}

func NewGenerator(ctx *fasthttp.RequestCtx, recIP, useXFF bool) *Generator {
	var family dnstap.SocketFamily
	remote_addr, _ := ctx.RemoteAddr().(*net.TCPAddr)
	ip := remote_addr.IP
	port := remote_addr.Port

	if useXFF {
		if xff := ctx.Request.Header.PeekBytes(strXFF); xff != nil {
			ip = net.ParseIP(string(xff))
			port = 0
			if xfp := ctx.Request.Header.PeekBytes(strXFP); xfp != nil {
				port, _ = strconv.Atoi(string(xfp))
			}
		}
	}

	if strings.Contains(ip.String(), ":") {
		family = dnstap.SocketFamily_INET6
	} else {
		family = dnstap.SocketFamily_INET
	}
	if !recIP {
		if family == dnstap.SocketFamily_INET {
			ip = net32
		} else {
			ip = net128
		}
	}
	return &Generator{
		RemoteAddr: ip,
		RemotePort: uint32(port),
		Family:     family,
		Protocol:   dnstap.SocketProtocol_TCP,
		TimeSec:    uint64(ctx.ConnTime().Unix()),
		TimeNsec:   uint32(ctx.ConnTime().Nanosecond()),
	}
}

func (g *Generator) SetNSID(dnsMsg dns.Msg) {
	if len(dnsMsg.Extra) > 0 && dnsMsg.Extra[0].Header().Rrtype == dns.TypeOPT {
		if opt, ok := dnsMsg.Extra[0].(*dns.OPT); ok {
			for _, o := range opt.Option {
				if nsid, ok := o.(*dns.EDNS0_NSID); ok {
					g.Nsid = []byte(nsid.String())
					return
				}
			}
		}
	}
	return
}

func (g *Generator) ClientQuery(msg []byte) *dnstap.Message {
	t := dnstap.Message_CLIENT_QUERY
	return &dnstap.Message{
		Type:           &t,
		QueryTimeSec:   &g.TimeSec,
		QueryTimeNsec:  &g.TimeNsec,
		SocketFamily:   &g.Family,
		SocketProtocol: &g.Protocol,
		QueryAddress:   g.RemoteAddr,
		QueryPort:      &g.RemotePort,
		QueryMessage:   msg,
	}
}
func (g *Generator) ClientResponse(msg []byte) *dnstap.Message {
	t := dnstap.Message_CLIENT_RESPONSE
	return &dnstap.Message{
		Type:             &t,
		ResponseTimeSec:  &g.TimeSec,
		ResponseTimeNsec: &g.TimeNsec,
		SocketFamily:     &g.Family,
		SocketProtocol:   &g.Protocol,
		QueryAddress:     g.RemoteAddr,
		QueryPort:        &g.RemotePort,
		ResponseMessage:  msg,
	}
}
