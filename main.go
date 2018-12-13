package main

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mimuret/dtap"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

const bufferSize = 4096

var (
	strDnsPath         = []byte("/dns-query")
	strDns             = []byte("dns")
	strDnsContentType  = []byte("application/dns-message")
	strDnsCacheControl = []byte("cache-control")
)

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
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	rootCmd.PersistentFlags().StringP("log-level", "", "info", "log level (default:info)")
	rootCmd.PersistentFlags().StringP("proxy-addr", "", "127.0.0.1:53", "endpoint resolver address")
	rootCmd.PersistentFlags().DurationP("timeout", "", 3, "timeout value when resolv name.")
	rootCmd.PersistentFlags().BoolP("http", "", true, "enable http server")
	rootCmd.PersistentFlags().StringP("http-listen", "", ":80", "http listen address adn port,comma separated.")
	rootCmd.PersistentFlags().BoolP("https", "", false, "enable https server")
	rootCmd.PersistentFlags().StringP("https-listen", "", ":443", "https listen address and port,comma separated.")
	rootCmd.PersistentFlags().StringP("https-tls-key", "", "", "tls key")
	rootCmd.PersistentFlags().StringP("https-tls-cert", "", "", "tls cert")
	rootCmd.PersistentFlags().StringP("https-tls-session-ticket-key", "", "", "https session ticket key.")
	rootCmd.PersistentFlags().BoolP("dnstap", "", false, "enable dnstap")
	rootCmd.PersistentFlags().BoolP("dnstap-recip", "", false, "enable record remote IP.")
	rootCmd.PersistentFlags().BoolP("dnstap-usexff", "", false, "record X-Forwarded-For Header.")
	rootCmd.PersistentFlags().StringP("dnstap-socket", "", "/var/run/dnstap.sock", "dnstap socket path.")
	rootCmd.PersistentFlags().StringP("dnstap-identity", "", hostname, "dnstap socket path.")

	if err := rootCmd.Execute(); err != nil {
		log.WithFields(log.Fields{
			"Type":  "rabsrv",
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

	var err error
	p := Proxy{}
	p.host, _ = cb.PersistentFlags().GetString("proxy-addr")
	p.timeout, _ = cb.PersistentFlags().GetDuration("timeout")
	p.addr, err = net.ResolveUDPAddr("udp", p.host)
	p.timeout = p.timeout * time.Second

	if err != nil {
		log.Fatalf("can't resolv udp addr %s\n", p.host)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if enable, _ := cb.PersistentFlags().GetBool("dnstap"); enable {
		sockFile, _ := cb.PersistentFlags().GetString("dnstap-socket")
		p.output = dtap.NewDnstapFstrmUnixSockOutput(&dtap.OutputUnixSocketConfig{
			Path:       sockFile,
			BufferSize: bufferSize,
		})
		if identity, err := cb.PersistentFlags().GetString("dnstap-identity"); err != nil {
			p.identity = []byte(identity)
		}
		if err != nil {
			log.WithFields(log.Fields{
				"func":  "serv",
				"Error": err,
			}).Fatal("error make dnstap stream")
		}
		p.recIP, _ = cb.PersistentFlags().GetBool("dnstap-recip")
		p.useXFF, _ = cb.PersistentFlags().GetBool("dnstap-usexff")
		p.dnstap = true
		log.WithFields(log.Fields{
			"func": "serv",
		}).Info("start DNSTAP outputer")
		go p.output.Run(ctx)
	}
	if enable, _ := cb.PersistentFlags().GetBool("http"); enable {
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
				Handler: p.HandleFastHTTP,
			}
			log.WithFields(log.Fields{
				"func":   "serv",
				"listen": addr,
			}).Info("start http server")
			go func() {
				err := srv.Serve(ln)
				if err != nil {
					log.WithFields(log.Fields{
						"func":  "serv",
						"Error": err,
					}).Fatal("error in listen addr")
				}
			}()
		}
	}
	if enable, _ := cb.PersistentFlags().GetBool("https"); enable {
		listen, _ := cb.PersistentFlags().GetString("https-listen")
		tlsKey, _ := cb.PersistentFlags().GetString("https-tls-key")
		tlsCert, _ := cb.PersistentFlags().GetString("https-tls-cert")
		sessionTicketKey, _ := cb.PersistentFlags().GetString("https-tls-session-ticket-key")
		sessionTicketKeyBytes := []byte(sessionTicketKey)

		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.WithFields(log.Fields{
				"func":     "serv",
				"certFile": tlsCert,
				"keyFile":  tlsKey,
				"Error":    err,
			}).Fatal("cannot load TLS key pair")
		}
		tlsConfig := &tls.Config{
			Certificates:             []tls.Certificate{cert},
			PreferServerCipherSuites: true,
		}
		if sessionTicketKey != "" {
			for i, b := range sessionTicketKeyBytes {
				if i < 32 {
					tlsConfig.SessionTicketKey[i] = b
				} else {
					log.WithFields(log.Fields{
						"func":  "serv",
						"Error": err,
					}).Fatal("https-tls-session-ticket-key ")
				}
			}
		}

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
				Handler: p.HandleFastHTTP,
			}
			log.WithFields(log.Fields{
				"func":   "serv",
				"listen": addr,
			}).Info("start https server")
			go func() {
				tlsLn := tls.NewListener(ln, tlsConfig)
				err = srv.Serve(tlsLn)
				if err != nil {
					log.WithFields(log.Fields{
						"func":  "serv",
						"Error": err,
					}).Fatal("error in listen addr")
				}
			}()
		}
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	log.WithFields(log.Fields{
		"func": "serv",
	}).Info("start server")
	select {
	case <-sigCh:
		cancel()
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
	}
}
