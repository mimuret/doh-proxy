package main

import (
	"os"
	"runtime"

	"github.com/mimuret/doh-proxy/pkg/cmd"

	log "github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

var mlog = log.WithField("Package", "main")

const bufferSize = 4096

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	rootCmd := cmd.NewRootCommand(version, commit, date, builtBy)
	if err := rootCmd.Execute(); err != nil {
		mlog.WithError(err).Fatal("failed to parse flags")
	}
}
