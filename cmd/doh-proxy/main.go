package main

import (
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/mimuret/doh-proxy/pkg/domain"
	"github.com/mimuret/doh-proxy/pkg/logger"
	"github.com/mimuret/doh-proxy/pkg/reciever"
	"github.com/mimuret/doh-proxy/pkg/resolver"
	"github.com/mimuret/dtap"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

const bufferSize = 4096

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	rootCmd := &cobra.Command{
		Use: "doh-proxy",
		Run: serv,
	}
	rootCmd.PersistentFlags().StringP("log-level", "", "info", "log level (default:info)")
	rootCmd.PersistentFlags().StringP("proxy-addr", "", "127.0.0.1:53", "endpoint resolver address")
	rootCmd.PersistentFlags().DurationP("timeout", "", 3, "timeout value when resolv name.")
	rootCmd.PersistentFlags().StringP("http-listen", "", ":80", "http listen address adn port,comma separated.")
	rootCmd.PersistentFlags().BoolP("recip", "", false, "enable record remote IP.")
	rootCmd.PersistentFlags().BoolP("dnstap", "", false, "enable dnstap")
	rootCmd.PersistentFlags().StringP("dnstap-socket", "", "/var/run/dnstap.sock", "dnstap socket path.")

	if err := rootCmd.Execute(); err != nil {
		log.WithFields(log.Fields{
			"Func":  "main",
			"Error": err,
		}).Fatal("failed to parse flag")
	}
	os.Exit(0)
}

func serv(cb *cobra.Command, args []string) {
	if loglevel, _ := cb.PersistentFlags().GetString("log-level"); loglevel != "" {
		log.WithFields(log.Fields{
			"func":      "serv",
			"log-level": loglevel,
		}).Info("set log-level")
		SetLogLevel(loglevel)
	}
	recIP, _ := cb.PersistentFlags().GetBool("recip")
	loggers := []domain.LoggingInterface{}
	stdlogger := logger.NewStdout(domain.InfoLevel, recIP)
	loggers = append(loggers, stdlogger)
	if enableDNSTAP, _ := cb.PersistentFlags().GetBool("dnstap"); enableDNSTAP {
		sockFile, _ := cb.PersistentFlags().GetString("dnstap-socket")
		output := dtap.NewDnstapFstrmUnixSockOutput(&dtap.OutputUnixSocketConfig{
			Path:       sockFile,
			BufferSize: bufferSize,
		})
		dnstap := logger.NewDNSTAP(domain.TraceLevel, output, recIP)
		loggers = append(loggers, dnstap)
	}

	host, _ := cb.PersistentFlags().GetString("proxy-addr")
	ri := resolver.NewTraditional(host)

	useXFF, _ := cb.PersistentFlags().GetBool("dnstap-usexff")

	ctr := domain.NewController(ri, loggers, useXFF)

	re := reciever.NewFastHTTP(ctr)

	listen, _ := cb.PersistentFlags().GetString("http-listen")
	listens := strings.Split(listen, ",")
	for _, addr := range listens {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.WithFields(log.Fields{
				"func":  "serv",
				"Error": err,
			}).Fatal("error in listen addr")
		}
		srv := &fasthttp.Server{
			Handler: re.HandleFastHTTP,
		}
		log.WithFields(log.Fields{
			"func":   "serv",
			"listen": addr,
		}).Info("start http server")
		go func(srv *fasthttp.Server, ln net.Listener) {
			err := srv.Serve(ln)
			if err != nil {
				log.WithFields(log.Fields{
					"func":  "serv",
					"Error": err,
				}).Fatal("error in listen addr")
			}
		}(srv, ln)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	log.WithFields(log.Fields{
		"func": "serv",
	}).Info("start server")
	<-sigCh
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
	}
}
