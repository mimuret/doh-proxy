package reciever

import (
	"bytes"
	"encoding/base64"
	"net"
	"strconv"

	"github.com/mimuret/doh-proxy/pkg/domain"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var (
	strDnsPath         = []byte("/dns-query")
	strDns             = []byte("dns")
	strDnsContentType  = []byte("application/dns-message")
	strDnsCacheControl = []byte("cache-control")
	strServer          = []byte("server")
)

type FastHTTP struct {
	ctr    *domain.Controller
	listen string
}

func NewFastHTTP(ctr *domain.Controller) *FastHTTP {
	return &FastHTTP{
		ctr: ctr,
	}
}
func (p *FastHTTP) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
	if !bytes.Equal(ctx.Path(), strDnsPath) {
		ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		return
	}
	fctx := NewFastHTTPContext(ctx)
	res, ttl, err := p.ctr.Resolv(fctx)
	if err == domain.ErrorBadRequest {
		ctx.Error("bad request", fasthttp.StatusBadRequest)
		return
	}
	if err != nil {
		log.Error(err.Error())
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	// parse ttl
	ctx.Response.Header.SetBytesK(strDnsCacheControl, strconv.FormatUint(uint64(ttl), 10))
	ctx.Response.Header.SetContentTypeBytes(strDnsContentType)

	ctx.Response.SetBody(res)

}

type FastHTTPContext struct {
	ctx *fasthttp.RequestCtx
}

func NewFastHTTPContext(ctx *fasthttp.RequestCtx) *FastHTTPContext {
	return &FastHTTPContext{
		ctx: ctx,
	}
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
