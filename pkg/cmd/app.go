package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"

	"github.com/mimuret/doh-proxy/pkg/domain"
	"github.com/mimuret/doh-proxy/pkg/logger"
	"github.com/mimuret/doh-proxy/pkg/reciever"
	"github.com/mimuret/doh-proxy/pkg/resolver"
	"github.com/mimuret/dtap"
	"github.com/spf13/cobra"
)

type app struct {
	viper *viper.Viper
}

func newApp() *app {
	v := viper.New()
	v.SetEnvPrefix("DOH_PROXY")
	v.AutomaticEnv()
	return &app{v}
}

func (a *app) Serve(cb *cobra.Command, args []string) {
	loglevel := a.viper.GetString("log-level")
	log.WithFields(log.Fields{
		"func":      "serv",
		"log-level": loglevel,
	}).Info("set log-level")
	SetLogLevel(loglevel)

	// logger setting
	recIP := a.viper.GetBool("recip")
	loggers := []domain.LoggingInterface{}
	stdlogger := logger.NewStdout(domain.InfoLevel, recIP)
	loggers = append(loggers, stdlogger)
	if a.viper.GetBool("dnstap") {
		sockFile := a.viper.GetString("dnstap-socket")
		output := dtap.NewDnstapFstrmUnixSockOutput(&dtap.OutputUnixSocketConfig{
			Path:       sockFile,
			BufferSize: a.viper.GetUint("dnstap-buffer"),
		})
		dnstap := logger.NewDNSTAP(domain.TraceLevel, output, recIP)
		loggers = append(loggers, dnstap)
	}

	// metrics
	metricsServerListen := a.viper.GetString("metrics-listen")
	metricsLogger := logger.NewPrometheus(metricsServerListen)
	loggers = append(loggers, metricsLogger)

	// resolver(proxy client)
	host := a.viper.GetString("proxy-addr")
	timeout := a.viper.GetUint("timeout")
	retry := a.viper.GetUint("retry")
	tcpOnly := a.viper.GetBool("tcp-only")
	ri := resolver.NewTraditional(host, retry, timeout, tcpOnly)

	// controller
	useXFF := a.viper.GetBool("dnstap-usexff")
	ctr := domain.NewController(ri, loggers, useXFF)

	// http server
	rTypeStr := a.viper.GetString("reciever-type")
	rec := reciever.GetReciever(rTypeStr, ctr)
	if rec == nil {
		log.WithFields(log.Fields{
			"func": "serv",
		}).Fatal("can't create reciever")
	}
	listen := a.viper.GetString("http-listen")
	serverName := a.viper.GetString("server-name")

	// start http server
	if err := reciever.StartServer(serverName, listen, rec); err != nil {
		log.WithFields(log.Fields{
			"func": "serv",
			"err":  err,
		}).Fatal("can't create reciever")
	}

	sigTermCh := make(chan os.Signal, 1)
	sigQuitCh := make(chan os.Signal, 1)
	signal.Notify(sigTermCh, syscall.SIGTERM)
	signal.Notify(sigQuitCh, syscall.SIGQUIT)
	log.WithFields(log.Fields{
		"func": "serv",
	}).Info("start server")
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
