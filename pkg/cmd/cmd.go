package cmd

import (
	"github.com/spf13/cobra"
)

func NewRootCommand(version, commit, date, builtBy string) *cobra.Command {
	a := newApp(version, commit, date, builtBy)
	rootCmd := &cobra.Command{
		Use: "doh-proxy",
		Run: a.Serve,
	}
	rootCmd.PersistentFlags().StringP("log-level", "", "info", "log level (default:info)")
	a.viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))

	rootCmd.PersistentFlags().StringP("proxy-addr", "", "127.0.0.1:53", "endpoint resolver address")
	a.viper.BindPFlag("proxy-addr", rootCmd.PersistentFlags().Lookup("proxy-addr"))

	rootCmd.PersistentFlags().UintP("timeout", "", 2, "time second of resolv timeout.")
	a.viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))

	rootCmd.PersistentFlags().UintP("retry", "", 2, "number of resolv retry.")
	a.viper.BindPFlag("retry", rootCmd.PersistentFlags().Lookup("retry"))

	rootCmd.PersistentFlags().BoolP("tcp-only", "", false, "proxy uses tcp only.")
	a.viper.BindPFlag("tcp-only", rootCmd.PersistentFlags().Lookup("tcp-only"))

	rootCmd.PersistentFlags().StringP("http-listen", "", ":80", "http listen address adn port,comma separated.")
	a.viper.BindPFlag("http-listen", rootCmd.PersistentFlags().Lookup("http-listen"))

	rootCmd.PersistentFlags().StringP("server-name", "", "doh-proxy", "server name.")
	a.viper.BindPFlag("server-name", rootCmd.PersistentFlags().Lookup("server-name"))

	rootCmd.PersistentFlags().StringP("reciever-type", "", "fasthttp", "fasthttp|nethttp")
	a.viper.BindPFlag("reciever-type", rootCmd.PersistentFlags().Lookup("reciever-type"))

	rootCmd.PersistentFlags().BoolP("dnstap", "", false, "enable dnstap")
	a.viper.BindPFlag("dnstap", rootCmd.PersistentFlags().Lookup("dnstap"))

	rootCmd.PersistentFlags().BoolP("recip", "", false, "enable record remote IP.")
	a.viper.BindPFlag("recip", rootCmd.PersistentFlags().Lookup("recip"))

	rootCmd.PersistentFlags().BoolP("recip-error", "", false, "enable record remote IP on error.")
	a.viper.BindPFlag("recip-error", rootCmd.PersistentFlags().Lookup("recip-error"))

	rootCmd.PersistentFlags().StringP("recip-net", "", "", "enable record remote IP include network. comma separated.")
	a.viper.BindPFlag("recip-net", rootCmd.PersistentFlags().Lookup("recip-net"))

	rootCmd.PersistentFlags().StringP("dnstap-socket", "", "/var/run/dnstap.sock", "dnstap socket path.")
	a.viper.BindPFlag("dnstap-socket", rootCmd.PersistentFlags().Lookup("dnstap-socket"))

	rootCmd.PersistentFlags().UintP("dnstap-buffer", "", 8192, "dnstap buffer sizes.")
	a.viper.BindPFlag("dnstap-buffer", rootCmd.PersistentFlags().Lookup("dnstap-buffer"))

	rootCmd.PersistentFlags().StringP("querylog-level", "", "error", "(error|trace) querylog output to stdout, error is error only")
	a.viper.BindPFlag("querylog-level", rootCmd.PersistentFlags().Lookup("querylog-level"))

	rootCmd.PersistentFlags().StringP("metrics-listen", "", "127.0.0.1:9000", "listen prometies metrics server.")
	a.viper.BindPFlag("metrics-listen", rootCmd.PersistentFlags().Lookup("metrics-listen"))

	return rootCmd
}
