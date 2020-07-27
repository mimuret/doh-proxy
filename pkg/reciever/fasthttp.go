package reciever

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"

	"github.com/google/uuid"

	"github.com/mimuret/doh-proxy/pkg/domain"
	"github.com/valyala/fasthttp"
)

var (
	strDnsPath = []byte("/dns-query")
	strDns     = []byte("dns")
	strServer  = []byte("server")
)

type FastHTTP struct {
	ctr    domain.DohController
	listen string
	server *fasthttp.Server
}

func NewFastHTTP(ctr domain.DohController) *FastHTTP {
	return &FastHTTP{
		ctr: ctr,
	}
}
func (p *FastHTTP) StartServer(serverName string, listeners []net.Listener) {
	p.server = &fasthttp.Server{
		Handler: p.HandleFastHTTP,
		Name:    serverName,
	}
	for _, ln := range listeners {
		go func(ln net.Listener) {
			p.server.Serve(ln)
		}(ln)
	}
}

func (p *FastHTTP) Shutdown(_ context.Context) error {
	return p.server.Shutdown()
}

func (p *FastHTTP) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
	if !bytes.Equal(ctx.Path(), strDnsPath) {
		ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		return
	}
	fctx := NewFastHTTPContext(ctx)
	p.ctr.ServeDoH(fctx)
}

type FastHTTPContext struct {
	ctx        *fasthttp.RequestCtx
	reqId      string
	remoteIP   net.IP
	remotePort uint16
}

func NewFastHTTPContext(ctx *fasthttp.RequestCtx) *FastHTTPContext {
	var reqId string
	reqIdBytes := ctx.Request.Header.Peek("x-request-id")
	if reqIdBytes == nil {
		reqId = uuid.New().String()
	} else {
		reqId = string(reqIdBytes)
	}
	return &FastHTTPContext{
		ctx:   ctx,
		reqId: reqId,
	}
}
func (p *FastHTTPContext) RequestID() string {
	return p.reqId
}
func (p *FastHTTPContext) RemoteIP() net.IP {
	remote_addr, _ := p.ctx.RemoteAddr().(*net.TCPAddr)
	return remote_addr.IP
}
func (p *FastHTTPContext) RemotePort() uint16 {
	remote_addr, _ := p.ctx.RemoteAddr().(*net.TCPAddr)
	return uint16(remote_addr.Port)
}
func (p *FastHTTPContext) Header(name string) []byte {
	return p.ctx.Request.Header.Peek(name)
}
func (p *FastHTTPContext) Data() []byte {
	if p.ctx.IsGet() {
		dnsMsgBase64 := p.ctx.QueryArgs().PeekBytes(strDns)
		if dnsMsgBase64 == nil {
			return nil
		}
		dlen := base64.RawURLEncoding.DecodedLen(len(dnsMsgBase64))
		dnsMsg := make([]byte, dlen)
		if _, err := base64.RawURLEncoding.Decode(dnsMsg, dnsMsgBase64); err != nil {
			return nil
		}
		return dnsMsg
	} else if p.ctx.IsPost() {
		dnsMsg := p.ctx.PostBody()
		return dnsMsg
	}
	return nil
}

func (c *FastHTTPContext) SetHeader(key, val string) {
	c.ctx.Response.Header.Set(key, val)
}

func (c *FastHTTPContext) SetStatusCode(code int) {
	c.ctx.Response.SetStatusCode(code)
}
func (c *FastHTTPContext) SetBody(body []byte) error {
	c.ctx.Response.SetBody(body)
	return nil
}
