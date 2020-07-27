package querylogger

import (
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
	TotalResponseByRcode = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "doh_response_rcode_total",
		Help: "The total number of response by rcode",
	}, []string{"rcode"})
)

type Prometheus struct {
	listen string
}

func NewPrometheus(listen string) *Prometheus {
	return &Prometheus{listen}
}

func (l *Prometheus) Start() {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(l.listen, nil)
	if err != nil {
		qlog.WithError(err).Error("failed to start metrics server")
	}
}

func (l *Prometheus) Logging(level domain.LoggerLevel, msg *dns.Msg, mtype dnstap.Message_Type, ip net.IP, port uint32) {
	if mtype == dnstap.Message_CLIENT_QUERY {
		TotalQueries.Inc()
		qtype := dns.TypeToString[msg.Question[0].Qtype]
		TotalQueriesByTypes.With(prometheus.Labels{"type": qtype}).Inc()
	}
	if mtype == dnstap.Message_CLIENT_RESPONSE {
		rcode := dns.RcodeToString[msg.Rcode]
		TotalResponseByRcode.With(prometheus.Labels{"rcode": rcode}).Inc()
	}
}
