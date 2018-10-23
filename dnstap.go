package main

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
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

func NewGenerator(ctx *fasthttp.RequestCtx) *Generator {
	var family dnstap.SocketFamily
	remote_addr, _ := ctx.RemoteAddr().(*net.TCPAddr)
	ip := remote_addr.IP
	port := remote_addr.Port

	if xff := ctx.Request.Header.PeekBytes(strXFF); xff != nil {
		ip = net.ParseIP(string(xff))
		port = 0
		if xfp := ctx.Request.Header.PeekBytes(strXFP); xfp != nil {
			port, _ = strconv.Atoi(string(xfp))
		}
	}

	if strings.Contains(ip.String(), ":") {
		family = dnstap.SocketFamily_INET6
	} else {
		family = dnstap.SocketFamily_INET
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

type FrameStreamSockOutput struct {
	socket        string
	OutputChannel chan []byte
	buffer        *bytes.Buffer
	enc           *framestream.Encoder
}

func NewFrameStreamSockOutput(socket string) *FrameStreamSockOutput {
	return &FrameStreamSockOutput{
		socket:        socket,
		OutputChannel: make(chan []byte, outputChannelSize),
	}
}
func (o *FrameStreamSockOutput) newConnect() error {
	w, err := net.Dial("unix", o.socket)
	if err != nil {
		return err
	}
	o.enc, err = framestream.NewEncoder(w, &framestream.EncoderOptions{ContentType: dnstap.FSContentType, Bidirectional: true})
	if err != nil {
		return err
	}
	return nil
}

func (o *FrameStreamSockOutput) RunOutputLoop(ctx context.Context) {
	ticker := time.NewTicker(flushTimeout)
	wait := true
	for {
		if wait {
			select {
			case <-ticker.C:
				log.WithFields(log.Fields{
					"func": "RunOutputLoop",
				}).Debug("flush new connects")
				o.channelFlush()
				if err := o.newConnect(); err == nil {
					wait = false
				}
			case <-ctx.Done():
				break
			}
		} else {
			select {
			case frame := <-o.OutputChannel:
				if _, err := o.enc.Write(frame); err != nil {
					wait = true
				}
			case <-ticker.C:
				o.enc.Flush()
			case <-ctx.Done():
				break
			}
		}
	}
	o.Close()
}
func (o *FrameStreamSockOutput) channelFlush() {
	for len(o.OutputChannel) > outputChannelFlush {
		<-o.OutputChannel
	}
}
func (o *FrameStreamSockOutput) Close() {
	close(o.OutputChannel)
	o.enc.Flush()
	o.enc.Close()
}
