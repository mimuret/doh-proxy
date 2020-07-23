package main

import (
	"os"
	"runtime"

	"github.com/mimuret/doh-proxy/pkg/cmd"

	log "github.com/sirupsen/logrus"
)

const bufferSize = 4096

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	rootCmd := cmd.NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		log.WithFields(log.Fields{
			"Func":  "main",
			"Error": err,
		}).Fatal("failed to parse flag")
	}
}
