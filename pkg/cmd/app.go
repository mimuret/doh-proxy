package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"strings"
	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"

	"github.com/mimuret/doh-proxy/pkg/domain"
	"github.com/mimuret/doh-proxy/pkg/querylogger"
	"github.com/mimuret/doh-proxy/pkg/reciever"
	"github.com/mimuret/doh-proxy/pkg/resolver"
	"github.com/mimuret/dtap"
	"github.com/spf13/cobra"
)

var (
	alog = log.WithFields(log.Fields{"Package": "cmd"})
)

type app struct {
	version string
	commit  string
	date    string
	builtBy string
	viper   *viper.Viper
}

func newApp(version, commit, date, builtBy string) *app {
	v := viper.New()
	v.SetEnvPrefix("DOH_PROXY")
	v.SetEnvKeyReplacer(strings.NewReplacer("-","_"))
	v.AutomaticEnv()
	return &app{version, commit, date, builtBy, v}
}

func (a *app) Version(b *cobra.Command, args []string) {
	fmt.Printf("doh-proxy version v%s (commitid: %s), build by %s on %s\n", a.version, a.commit, a.builtBy, a.date)
}

func (a *app) Serve(cb *cobra.Command, args []string) {
	loglevel := a.viper.GetString("log-level")
	alog.WithFields(log.Fields{
		"log-level": loglevel,
	}).Info("set log-level")
	SetLogLevel(loglevel)

	// query logger setting
	loggers := []domain.LoggingInterface{}
	queryLogLevel := domain.InfoLevel
	if a.viper.GetString("querylog-level") == "trace" {
		queryLogLevel = domain.TraceLevel
	}
	stdlogger := querylogger.NewStdout(queryLogLevel)
	loggers = append(loggers, stdlogger)
	if a.viper.GetBool("dnstap") {
		sockFile := a.viper.GetString("dnstap-socket")
		output := dtap.NewDnstapFstrmUnixSockOutput(&dtap.OutputUnixSocketConfig{
			Path:       sockFile,
			BufferSize: a.viper.GetUint("dnstap-buffer"),
		})
		dnstap := querylogger.NewDNSTAP(domain.TraceLevel, output)
		loggers = append(loggers, dnstap)
	}
	alog.Debug("logger created")

	// metrics
	metricsServerListen := a.viper.GetString("metrics-listen")
	metricsLogger := querylogger.NewPrometheus(metricsServerListen)
	go func() {
		metricsLogger.Start()
	}()
	loggers = append(loggers, metricsLogger)

	alog.Debug("metrics created")

	// resolver(proxy client)
	host := a.viper.GetString("proxy-addr")
	timeout := a.viper.GetUint("timeout")
	retry := a.viper.GetUint("retry")
	tcpOnly := a.viper.GetBool("tcp-only")
	ri := resolver.NewTraditional(host, retry, timeout, tcpOnly)

	alog.Debug("resolver created")

	// controller
	useXFF := a.viper.GetBool("dnstap-usexff")
	recAll := a.viper.GetBool("recip")
	recOnError := a.viper.GetBool("recip-error")
	recNetworks := a.viper.GetString("recip-net")
	recip, err := domain.NewRecIP(useXFF, recAll, recOnError, recNetworks)
	if err != nil {
		alog.WithError(err).Fatal("can't create recip")
	}
	ctr := domain.NewController(ri, loggers, recip)

	alog.Debug("controller created")

	// http server
	rTypeStr := a.viper.GetString("reciever-type")
	rec := reciever.GetReciever(rTypeStr, ctr)
	if rec == nil {
		alog.Fatal("can't create reciever")
	}
	listen := a.viper.GetString("http-listen")
	serverName := a.viper.GetString("server-name")

	alog.Debug("reciever created")

	// start http server
	if err := reciever.StartServer(serverName, listen, rec); err != nil {
		alog.WithError(err).Fatal("can't create reciever")
	}

	sigTermCh := make(chan os.Signal, 1)
	sigQuitCh := make(chan os.Signal, 1)
	signal.Notify(sigTermCh, syscall.SIGTERM)
	signal.Notify(sigQuitCh, syscall.SIGQUIT)
	alog.Info("start server")
	select {
	case <-sigQuitCh:
		rec.Shutdown(context.Background())
	case <-sigTermCh:
	}

}

func SetLogLevel(logLevel string) {
	switch logLevel {
	case "panic":
		log.SetLevel(log.PanicLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "trace":
		log.SetLevel(log.TraceLevel)
	}
}
