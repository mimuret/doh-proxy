package reciever

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/mimuret/doh-proxy/pkg/domain"
)

type NetHTTP struct {
	ctr    domain.DohController
	listen string
	server *http.Server
}

func NewNetHTTP(ctr domain.DohController) *FastHTTP {
	return &FastHTTP{
		ctr: ctr,
	}
}

func (p *NetHTTP) StartServer(serverName string, listeners []net.Listener) {
	p.server = &http.Server{Handler: p}
	for _, ln := range listeners {
		go func(ln net.Listener) {
			p.server.Serve(ln)
		}(ln)
	}
}
func (p *NetHTTP) Shutdown(ctx context.Context) error {
	return p.server.Shutdown(ctx)
}

func (r *NetHTTP) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	nctx := NewNetHTTPContext(w, req)
	r.ctr.ServeDoH(nctx)
}

type NetHTTPContext struct {
	w     http.ResponseWriter
	req   *http.Request
	reqId string
}

func NewNetHTTPContext(w http.ResponseWriter, req *http.Request) *NetHTTPContext {
	reqId := req.Header.Get("x-request-id")
	if reqId == "" {
		reqId = uuid.New().String()
	}
	return &NetHTTPContext{
		w:     w,
		req:   req,
		reqId: reqId,
	}
}
func (c *NetHTTPContext) RequestID() string {
	return c.reqId
}
func (c *NetHTTPContext) RemoteIP() net.IP {
	addr, _, _ := net.SplitHostPort(c.req.RemoteAddr)
	return net.ParseIP(addr)
}
func (c *NetHTTPContext) RemotePort() uint16 {
	_, portStr, _ := net.SplitHostPort(c.req.RemoteAddr)
	port, _ := strconv.Atoi(portStr)
	return uint16(port)
}
func (c *NetHTTPContext) Header(name string) []byte {
	val := c.req.Header.Get(name)
	return []byte(val)
}

func (c *NetHTTPContext) Data() []byte {
	switch c.req.Method {
	case "GET":
		err := c.req.ParseForm()
		if err != nil {
			return nil
		}
		dnsMsgBase64 := c.req.Form.Get("dns")
		if dnsMsgBase64 == "" {
			return nil
		}
		dnsMsgBase64Bs := []byte(dnsMsgBase64)

		dlen := base64.RawURLEncoding.DecodedLen(len(dnsMsgBase64Bs))
		dnsMsg := make([]byte, dlen)
		if _, err := base64.RawURLEncoding.Decode(dnsMsg, dnsMsgBase64Bs); err != nil {
			return nil
		}
		return dnsMsg
	case "POST":
		r, err := c.req.GetBody()
		if err != nil {
			return nil
		}
		defer r.Close()
		dnsMsg, err := ioutil.ReadAll(r)
		if err != nil {
			return nil
		}
		return dnsMsg
	}
	return nil
}

func (c *NetHTTPContext) SetHeader(key, val string) {
	c.w.Header().Set(key, val)
}

func (c *NetHTTPContext) SetStatusCode(code int) {
	c.w.WriteHeader(code)
}

func (c *NetHTTPContext) SetBody(body []byte) error {
	_, err := c.w.Write(body)
	return err
}
