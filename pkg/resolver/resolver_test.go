package resolver_test

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

func HelloServer(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	m.Answer = make([]dns.RR, 1)
	m.Answer[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello world !!!!!"}}
	w.WriteMsg(m)
}

func TrancateServerUDP(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	for i := 0; i < 100; i++ {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello world !!!!!"}})
		m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP(fmt.Sprintf("127.0.0.%d", i)).To4()})
	}
	m.Truncate(512)
	w.WriteMsg(m)
}

func TrancateServerEDNS0(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	for i := 0; i < 100; i++ {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello world !!!!!"}})
		m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP(fmt.Sprintf("127.0.0.%d", i)).To4()})
	}
	m.Truncate(4096)
	w.WriteMsg(m)
}

func TrancateServerTCP(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	for i := 0; i < 100; i++ {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello world !!!!!"}})
		m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP(fmt.Sprintf("127.0.0.%d", i)).To4()})
	}

	w.WriteMsg(m)
}

func testServer(udp, tcp dns.HandlerFunc) (*dns.Server, *dns.Server) {
	udpSv := startServer("udp", udp)
	tcpSv := startServer("tcp", tcp)
	return udpSv, tcpSv
}

func startServer(proto string, handle dns.HandlerFunc) *dns.Server {
	startCh := make(chan struct{})
	s := &dns.Server{Addr: "127.0.0.1:10053", Net: proto, ReadTimeout: time.Hour, WriteTimeout: time.Hour, NotifyStartedFunc: func() {
		close(startCh)
	}}
	mux := dns.NewServeMux()
	mux.Handle(".", handle)
	s.Handler = mux
	go func() {
		s.ListenAndServe()
	}()

	<-startCh

	return s
}
