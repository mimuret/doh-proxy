package domain

import "github.com/miekg/dns"

func init() {
	// not parse all RDATA
	dns.TypeToRR = map[uint16]func() dns.RR{
		dns.TypeOPT: func() dns.RR { return new(dns.OPT) },
	}
}
