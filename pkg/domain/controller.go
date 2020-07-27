package domain

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	clog = log.WithField("Package", "controller")
)

type Controller struct {
	ri      ResolvInterface
	loggers []LoggingInterface
	recIP   *RecIP
}

func NewController(ri ResolvInterface, loggers []LoggingInterface, recIP *RecIP) *Controller {
	return &Controller{ri: ri,
		loggers: loggers,
		recIP:   recIP,
	}
}

type resolvReq struct {
	RecieverInterface
	ip   net.IP
	port uint32
}

func (c *Controller) ServeDoH(re RecieverInterface) {
	res, ttl, scode, derr := c.serve(re)
	slog := clog.WithFields(log.Fields{
		"RequestID":  re.RequestID(),
		"StatusCode": scode,
		"RemoteAddr": c.recIP.RemoteIP(re, false),
		"RemotePort": c.recIP.RemotePort(re),
	})
	if derr != nil {
		re.SetStatusCode(scode)
		if scode == http.StatusBadRequest {
			slog.WithError(derr).WithFields(log.Fields{
				"RemoteAddr": c.recIP.RemoteIP(re, true),
			}).Warn("Bad request")
		} else {
			slog.WithError(derr).WithFields(log.Fields{
				"RemoteAddr": c.recIP.RemoteIP(re, true),
			}).Error("resolv runtime error")
		}
		return
	}
	// parse ttl
	re.SetHeader("content-type", "application/dns-message")
	re.SetHeader("cache-control", strconv.FormatUint(uint64(ttl), 10))
	err := re.SetBody(res)
	if err != nil {
		slog.WithError(err).WithFields(log.Fields{
			"StatusCode": http.StatusInternalServerError,
			"RemoteAddr": c.recIP.RemoteIP(re, true),
		}).Error("failed to write body")
		re.SetStatusCode(http.StatusInternalServerError)
		return
	}
	slog.WithFields(log.Fields{
		"RemoteAddr": c.recIP.RemoteIP(re, false),
		"RemotePort": c.recIP.RemotePort(re),
	}).Info("success")

}

func (c *Controller) serve(re RecieverInterface) ([]byte, uint32, int, *Error) {
	scode := http.StatusOK
	res, ttl, derr := c.resolv(re)
	if derr != nil {
		var rerr *ResolvError
		scode = http.StatusInternalServerError
		if derr.Code == ErrCodeBadRequest {
			scode = http.StatusBadRequest
		} else if derr.Code == ErrCodeResolvError && errors.As(derr, &rerr) && rerr.Code == ResolvErrCodeTimeout {
			scode = http.StatusRequestTimeout
		}
	}
	return res, ttl, scode, derr
}

func (c *Controller) resolv(re RecieverInterface) ([]byte, uint32, *Error) {
	remoteIP := c.recIP.RemoteIP(re, false)
	errRemoteIP := c.recIP.RemoteIP(re, true)
	remotePort := c.recIP.RemotePort(re)
	dnsMsg := re.Data()
	if dnsMsg == nil {
		return nil, 0, &Error{fmt.Errorf("failed to get request data"), ErrCodeBadRequest}
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(dnsMsg); err != nil {
		return nil, 0, &Error{fmt.Errorf("failed to parse dns message: %w", err), ErrCodeBadRequest}
	}
	c.logging(TraceLevel, msg, dnstap.Message_CLIENT_QUERY, remoteIP, remotePort)
	res, rerr := c.ri.Resolv(msg)
	if rerr != nil {
		c.logging(ErrorLevel, msg, dnstap.Message_TOOL_QUERY, errRemoteIP, remotePort)
		return nil, 0, &Error{fmt.Errorf("failed to resolv: %w", rerr), ErrCodeResolvError}
	}
	c.logging(TraceLevel, res, dnstap.Message_CLIENT_RESPONSE, remoteIP, remotePort)
	resbody, err := res.Pack()
	if err != nil {
		c.logging(ErrorLevel, res, dnstap.Message_TOOL_RESPONSE, errRemoteIP, remotePort)
		return nil, 0, &Error{fmt.Errorf("failed to pack dns message: %w", err), ErrCodeInternalServerError}
	}
	var ttl uint32
	if len(res.Answer) > 0 {
		ttl = res.Answer[0].Header().Ttl
	} else if len(res.Ns) > 0 {
		ttl = res.Ns[0].Header().Ttl
	}
	return resbody, ttl, nil
}

func (c *Controller) logging(level LoggerLevel, msg *dns.Msg, mtype dnstap.Message_Type, ip net.IP, port uint32) {
	for _, logger := range c.loggers {
		go logger.Logging(level, msg, mtype, ip, port)
	}
}
