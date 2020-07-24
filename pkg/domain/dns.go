package domain

import "github.com/miekg/dns"

func init() {
	// not parse all RDATA
	dns.TypeToRR = map[uint16]func() dns.RR{
		dns.TypeOPT:   func() dns.RR { return new(dns.OPT) },
		dns.TypeA:     func() dns.RR { return new(dns.A) },
		dns.TypeAAAA:  func() dns.RR { return new(dns.AAAA) },
		dns.TypeCNAME: func() dns.RR { return new(dns.CNAME) },
		dns.TypeNS:    func() dns.RR { return new(dns.NS) },
		dns.TypeSOA:   func() dns.RR { return new(dns.SOA) },
		dns.TypeTXT:   func() dns.RR { return new(dns.TXT) },
	}
}
