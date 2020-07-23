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
	strXFF = "X-Forwarded-For"
	strXFP = "X-Forwarded-Port"
)

type Controller struct {
	ri      ResolvInterface
	loggers []LoggingInterface
	useXFF  bool
}

func NewController(ri ResolvInterface, loggers []LoggingInterface, useXFF bool) *Controller {
	return &Controller{ri: ri,
		loggers: loggers,
		useXFF:  useXFF,
	}
}

func (c *Controller) ServeDoH(re RecieverInterface) {
	res, ttl, derr := c.resolv(re)
	if derr != nil {
		switch derr.Code {
		case ErrCodeBadRequest:
			re.SetStatusCode(http.StatusBadRequest)
			return
		case ErrCodeResolvError:
			var rerr *ResolvError
			if errors.As(derr, &rerr) {
				switch rerr.Code {
				case ResolvErrCodeTimeout:
					re.SetStatusCode(http.StatusRequestTimeout)
				}
			}
		}
		log.Error(derr)
		re.SetStatusCode(http.StatusInternalServerError)
		return
	}

	// parse ttl
	re.SetHeader("content-type", "application/dns-message")
	re.SetHeader("cache-control", strconv.FormatUint(uint64(ttl), 10))
	err := re.SetBody(res)
	if err != nil {
		log.Error(fmt.Errorf("can't write body: %w", err))
		re.SetStatusCode(http.StatusInternalServerError)
	}
}

func (c *Controller) resolv(re RecieverInterface) ([]byte, uint32, *Error) {
	dnsMsg := re.Data()
	if dnsMsg == nil {
		return nil, 0, &Error{fmt.Errorf("failed to get request data"), ErrCodeInternalServerError}
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(dnsMsg); err != nil {
		return nil, 0, &Error{fmt.Errorf("failed to parse dns message: %w", err), ErrCodeInternalServerError}
	}
	remoteIP := re.RemoteIP()
	remotePort := uint32(re.RemotePort())
	if c.useXFF {
		if xff := re.Header(strXFF); xff != nil {
			remoteIP = net.ParseIP(string(xff))
			if xfp := re.Header(strXFP); xfp != nil {
				if port, err := strconv.Atoi(string(xfp)); err == nil {
					remotePort = uint32(port)
				}
			}
		}
	}
	c.logging(TraceLevel, msg, dnstap.Message_CLIENT_QUERY, remoteIP, remotePort)
	res, rerr := c.ri.Resolv(msg)
	if rerr != nil {
		c.logging(ErrorLevel, msg, dnstap.Message_TOOL_QUERY, remoteIP, remotePort)
		return nil, 0, &Error{fmt.Errorf("failed to resolv: %w", rerr), ErrCodeResolvError}
	}
	c.logging(TraceLevel, res, dnstap.Message_CLIENT_RESPONSE, remoteIP, remotePort)
	resbody, err := res.Pack()
	if err != nil {
		c.logging(ErrorLevel, res, dnstap.Message_TOOL_RESPONSE, remoteIP, remotePort)
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
