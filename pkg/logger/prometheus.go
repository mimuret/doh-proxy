package logger

import (
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/mimuret/doh-proxy/pkg/domain"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	TotalQueries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "doh_queries_total",
		Help: "The total number of queries",
	})
	TotalQueriesByTypes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "doh_query_types_total",
		Help: "The total number of queries by qtype",
	}, []string{"type"})
)

type Prometheus struct {
	listen string
}

func NewPrometheus(listen string) *Prometheus {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(listen, nil)
	if err != nil {
		log.Fatal(err)
	}
	return &Prometheus{}
}

func (l *Prometheus) Logging(level domain.LoggerLevel, msg *dns.Msg, mtype dnstap.Message_Type, ip net.IP, port uint32) {
	if mtype == dnstap.Message_CLIENT_QUERY {
		TotalQueries.Inc()
		qtype := dns.TypeToString[msg.Question[0].Qtype]
		TotalQueriesByTypes.With(prometheus.Labels{"type": qtype}).Inc()
	}
}
