package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

const bufferSize = 4096

var (
	strDnsPath         = []byte("/dns-query")
	strDns             = []byte("dns")
	strDnsContentType  = []byte("application/dns-message")
	strDnsCacheControl = []byte("cache-control")
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	rootCmd := &cobra.Command{
		Use: "doh-proxy",
		Run: serv,
	}

	rootCmd.PersistentFlags().StringP("proxy-addr", "", "127.0.0.1:53", "endpoint resolver")
	rootCmd.PersistentFlags().DurationP("timeout", "", 3, "timeout value when resolv name.")
	rootCmd.PersistentFlags().BoolP("http", "", true, "enable http server")
	rootCmd.PersistentFlags().StringP("http-listen", "", ":80", "http listen address")
	rootCmd.PersistentFlags().BoolP("https", "", true, "enable https server")
	rootCmd.PersistentFlags().BoolP("https-tls-key", "", true, "tls key")
	rootCmd.PersistentFlags().BoolP("https-tls-cert", "", true, "tls cert")
	rootCmd.PersistentFlags().StringP("https-listen", "", ":443", "https listen address")

	if err := rootCmd.Execute(); err != nil {
		log.WithFields(log.Fields{
			"Type":  "rabsrv",
			"Func":  "main",
			"Error": err,
		}).Fatal("failed to parse flag")
	}
	os.Exit(0)
}

func serv(cb *cobra.Command, args []string) {
	var err error
	p := Proxy{}
	p.host, _ = cb.PersistentFlags().GetString("proxy-addr")
	p.timeout, _ = cb.PersistentFlags().GetDuration("timeout")

	p.addr, err = net.ResolveUDPAddr("udp", p.host)
	if err != nil {
		log.Fatalf("can't resolv udp addr %s\n", p.host)
	}
	p.timeout = p.timeout * time.Second
	if enable, _ := cb.PersistentFlags().GetBool("http"); enable {
		listen, _ := cb.PersistentFlags().GetString("http-listen")
		if err := fasthttp.ListenAndServe(listen, p.HandleFastHTTP); err != nil {
			log.WithFields(log.Fields{
				"func":  "serv",
				"Error": err,
			}).Fatal("error in ListenAndServe")
		}
	}
	if enable, _ := cb.PersistentFlags().GetBool("https"); enable {
		listen, _ := cb.PersistentFlags().GetString("https-listen")
		tlsKey, _ := cb.PersistentFlags().GetString("https-tls-key")
		tlsCert, _ := cb.PersistentFlags().GetString("https-tls-cert")
		fasthttp.ListenAndServe(listen, p.HandleFastHTTP)
		if err := fasthttp.ListenAndServeTLS(listen, tlsCert, tlsKey, p.HandleFastHTTP); err != nil {
			log.WithFields(log.Fields{
				"func":  "serv",
				"Error": err,
			}).Fatal("error in ListenAndServeTLS")
		}
	}
	select {}
}

type Proxy struct {
	host    string
	timeout time.Duration
	addr    *net.UDPAddr
}

func (p *Proxy) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
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
	log.WithFields(log.Fields{
		"func": "HandleFastHTTP",
	}).Debug("Success to send dns message")

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

	if err != nil {
		log.WithFields(log.Fields{
			"func": "HandleFastHTTP",
		}).Debug("failed to write dns query")
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
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
	return
}
