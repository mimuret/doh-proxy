package domain

import (
	"fmt"
	"net"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

var (
	ErrorBadRequest          = fmt.Errorf("bad request")
	ErrorInternalServerError = fmt.Errorf("Internal Server Error")
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
}

type ResolvInterface interface {
	Resolv(*dns.Msg) (*dns.Msg, error)
}

type LoggingInterface interface {
	Logging(LoggerLevel, *dns.Msg, dnstap.Message_Type, net.IP, uint32)
}

type MetricsInterface interface {
	IncQueryCount()
}
