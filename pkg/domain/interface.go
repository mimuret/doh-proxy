package domain

import (
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type LoggerLevel uint16

const (
	PanicLevel LoggerLevel = iota
	FatalLevel
	ErrorLevel
	WarnLevel
	InfoLevel
	DebugLevel
	TraceLevel
)

type RecieverInterface interface {
	RemoteIP() net.IP
	RemotePort() uint16
	Data() []byte
	Header(string) []byte
	SetHeader(string, string)
	SetBody([]byte) error
	SetStatusCode(code int)
}

type LoggingInterface interface {
	Logging(LoggerLevel, *dns.Msg, dnstap.Message_Type, net.IP, uint32)
}

type MetricsInterface interface {
	IncQueryCount()
}

type DohController interface {
	ServeDoH(RecieverInterface)
}

type ResolvInterface interface {
	Resolv(*dns.Msg) (*dns.Msg, *ResolvError)
}

type ResolvErrorCode string

const (
	ResolvErrCodeTimeout  ResolvErrorCode = "TimeoutError"
	ResolvErrCodeUnKnown                  = "UnKnownError"
	ResolvConnectionError                 = "ConnectionError"
)

type ResolvError struct {
	Err  error
	Code ResolvErrorCode
}

func (e *ResolvError) Unwrap() error { return e.Err }
func (e *ResolvError) Error() string {
	return "doh-proxy(resolv): " + e.Err.Error()
}
