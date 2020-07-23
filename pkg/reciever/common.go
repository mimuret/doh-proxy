package reciever

import (
	"net"
	"strings"

	"github.com/mimuret/doh-proxy/pkg/domain"
)

func GetReciever(name string, ctr domain.DohController) Reciever {
	switch name {
	case "nethttp":
		return NewNetHTTP(ctr)
	case "fasthttp":
		return NewFastHTTP(ctr)
	}
	return nil
}

func StartServer(serverName, listen string, rec Reciever) error {
	var listeners []net.Listener
	for _, addr := range strings.Split(listen, ",") {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		listeners = append(listeners, ln)
	}
	rec.StartServer(serverName, listeners)
	return nil
}
