package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"strconv"
	"time"

	"github.com/mimuret/dtap"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var dnstapType = dnstap.Dnstap_MESSAGE

type Proxy struct {
	host     string
	dnstap   bool
	recIP    bool
	useXFF   bool
	timeout  time.Duration
	addr     *net.UDPAddr
	output   *dtap.DnstapOutput
	identity []byte
}

func (p *Proxy) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
	var g *Generator
	if p.dnstap {
		g = NewGenerator(ctx, p.recIP, p.useXFF)
	}

	if !bytes.Equal(ctx.Path(), strDnsPath) {
		ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		return
	}
	var dnsMsg []byte
	var err error
	if ctx.IsGet() {
		dnsMsgBase64 := ctx.QueryArgs().PeekBytes(strDns)

		if dnsMsgBase64 == nil {
			ctx.Error("bad request", fasthttp.StatusBadRequest)
			return
		}
		dlen := base64.URLEncoding.DecodedLen(len(dnsMsgBase64))
		dnsMsg = make([]byte, dlen)
		_, err = base64.URLEncoding.Decode(dnsMsg, dnsMsgBase64)
		if err != nil {
			ctx.Error("failed to decode query.", fasthttp.StatusBadRequest)
			return
		}
	} else if ctx.IsPost() {
		dnsMsg = ctx.PostBody()
	} else {
		ctx.Error("Unsupported method", fasthttp.StatusBadRequest)
		return
	}
	if dnsMsg == nil || len(dnsMsg) == 0 {
		ctx.Error("bad request", fasthttp.StatusBadRequest)
		return
	}
	msg := dns.Msg{}
	if err := msg.Unpack(dnsMsg); err != nil {
		ctx.Error("bad request", fasthttp.StatusBadRequest)
		return
	}
	if p.dnstap {
		tapMsg := g.ClientQuery(dnsMsg)
		dnstap := &dnstap.Dnstap{
			Type:     &dnstapType,
			Identity: p.identity,
			Message:  tapMsg,
		}

		frame, err := proto.Marshal(dnstap)

		if err == nil {
			p.output.SetMessage(frame)
		}
	}
	log.WithFields(log.Fields{
		"func": "HandleFastHTTP",
		"msg":  dnsMsg,
	}).Debug("start proxy query")
	c := new(dns.Client)
	c.Net = "udp"
	r, _, err := c.Exchange(&msg, p.host)

	if err != nil {
		log.WithFields(log.Fields{
			"func": "HandleFastHTTP",
		}).Debug("failed to dns query")
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	log.WithFields(log.Fields{
		"func": "HandleFastHTTP",
	}).Debug("Success to send dns message")

	ctx.Response.Header.SetContentTypeBytes(strDnsContentType)
	recvBuf, err := r.Pack()

	if err != nil {
		log.WithFields(log.Fields{
			"func": "HandleFastHTTP",
		}).Debug("pack query")
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	ctx.Response.SetBody(recvBuf)

	// parse ttl
	if len(r.Answer) > 0 {
		ctx.Response.Header.SetBytesK(strDnsCacheControl, strconv.FormatUint(uint64(r.Answer[0].Header().Ttl), 10))
	} else if len(r.Ns) > 0 {
		ctx.Response.Header.SetBytesK(strDnsCacheControl, strconv.FormatUint(uint64(r.Ns[0].Header().Ttl), 10))
	}
	if p.dnstap {
		tapMsg := g.ClientResponse(recvBuf)
		dnstap := &dnstap.Dnstap{
			Type:     &dnstapType,
			Identity: p.identity,
			Message:  tapMsg,
		}

		frame, err := proto.Marshal(dnstap)

		if err == nil {
			p.output.SetMessage(frame)
		}
	}
	return
}
