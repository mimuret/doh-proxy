package domain

import (
	"net"
	"strconv"
	"strings"
)

var (
	strXFF = "X-Forwarded-For"
	strXFP = "X-Forwarded-Port"
	net128 = net.ParseIP("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")
	net32  = net.ParseIP("255.255.255.255")
)

type RecIP struct {
	useXFF   bool
	all      bool
	onError  bool
	networks []*net.IPNet
}

func NewRecIP(useXFF, all, onError bool, netStr string) (*RecIP, error) {
	recip := &RecIP{
		useXFF:  useXFF,
		all:     all,
		onError: onError,
	}
	if netStr != "" {
		for _, s := range strings.Split(netStr, ",") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, err
			}
			recip.networks = append(recip.networks, n)
		}
	}
	return recip, nil
}

func (r *RecIP) Contains(ip net.IP) bool {
	for _, n := range r.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *RecIP) RemoteIP(rec RecieverInterface, onError bool) net.IP {
	remoteIP := rec.RemoteIP()
	if r.useXFF {
		if xff := rec.Header(strXFF); xff != nil {
			remoteIP = net.ParseIP(string(xff))
		}
	}
	if r.all || r.onError && onError || r.Contains(remoteIP) {
		return remoteIP
	}
	if remoteIP.To4() != nil {
		return net32
	}
	return net128
}

func (r *RecIP) RemotePort(rec RecieverInterface) uint32 {
	remotePort := uint32(rec.RemotePort())
	if r.useXFF {
		if xfp := rec.Header(strXFP); xfp != nil {
			if port, err := strconv.Atoi(string(xfp)); err == nil {
				remotePort = uint32(port)
			}
		}
	}
	return remotePort
}
