package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
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
	if dnsMsg == nil {
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
	conn, err := net.Dial("udp", p.host)
	if err != nil {
		log.WithFields(log.Fields{
			"func":  "HandleFastHTTP",
			"msg":   dnsMsg,
			"Error": err,
		}).Debug("failed to open tcp socket.")
		ctx.Error("failed to open tcp socket.", fasthttp.StatusInternalServerError)
		return
	}
	defer conn.Close()
	log.WithFields(log.Fields{
		"func": "HandleFastHTTP",
	}).Debug("connection success")

	if _, err := conn.Write(dnsMsg); err != nil {
		log.WithFields(log.Fields{
			"func": "HandleFastHTTP",
		}).Debug("failed to write dns query")
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
	}
	log.WithFields(log.Fields{
		"func": "HandleFastHTTP",
	}).Debug("Success to send dns message")

	ctx.Response.Header.SetContentTypeBytes(strDnsContentType)

	recvBuf := []byte{}
	var size int
	for {
		l := make([]byte, bufferSize)
		n, err := conn.Read(l)
		recvBuf = append(recvBuf, l[0:n]...)
		size += n
		if n != bufferSize {
			break
		}
		if err != nil {
			log.WithFields(log.Fields{
				"func": "HandleFastHTTP",
			}).Debug("failt to read message")
		}
	}
	log.WithFields(log.Fields{
		"func": "HandleFastHTTP",
	}).Debug("Success to receive dns message")

	if err != nil {
		log.WithFields(log.Fields{
			"func": "HandleFastHTTP",
		}).Debug("failed to write dns query")
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	ctx.Response.SetBody(recvBuf)

	// parse ttl
	msg := dns.Msg{}
	err = msg.Unpack(recvBuf)
	if err != nil {
		data := ""
		for _, v := range recvBuf {
			data += fmt.Sprintf("%x", v)
		}
		log.WithFields(log.Fields{
			"func": "HandleFastHTTP",
			"data": data,
		}).Debug("failed to parse query")
		ctx.Error("failed to parse query.", fasthttp.StatusInternalServerError)
		return
	}
	if len(msg.Answer) > 0 {
		ctx.Response.Header.SetBytesK(strDnsCacheControl, strconv.FormatUint(uint64(msg.Answer[0].Header().Ttl), 10))
	} else if len(msg.Ns) > 0 {
		ctx.Response.Header.SetBytesK(strDnsCacheControl, strconv.FormatUint(uint64(msg.Ns[0].Header().Ttl), 10))
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
