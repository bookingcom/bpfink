package bpfink

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"os/signal"

	"github.com/bookingcom/bpfink/pkg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// nolint:gochecknoglobals
var cmd = &cobra.Command{
	Use:   "bpfink",
	Short: "FIM reporter",
	RunE: func(cmd *cobra.Command, _ []string) error {
		// https://github.com/spf13/cobra/issues/340
		cmd.SilenceUsage = true
		return runCmd()
	},
}

// Execute executes the root command.
func Execute() error {
	initCmd()
	return cmd.Execute()
}

func runCmd() error {
	config, err := NewConfiguration()
	if err != nil {
		return err
	}

	logger := config.NewLogger()
	logger.Debug().Msg("debug mode activated")
	logger.Debug().Msgf("config: %+v", config)

	metrics, err := config.NewMetrics()
	if err != nil {
		logger.Fatal().Err(err).Msgf("failed to init metrics: %v", err)
	}

	if viper.GetInt("graphite-mode") != 0 {
		metrics.GraphiteMode = viper.GetInt("graphite-mode")
	}

	// increment the host count by 1
	metrics.RecordByInstalledHost()
	// send version metric
	metrics.RecordVersion(Version)
	metrics.RecordBPFMetrics()
	key := make([]byte, keySize)
	if config.GetKeyFile() == "" {
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			logger.Fatal().Msg("failed to create a new key")
		}
		config.SetKey(key)
	} else {
		// readin keyfile
		dat, err := ioutil.ReadFile(config.GetKeyFile())
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to read key file")
		}
		config.SetKey(dat[:16])
	}
	watcher, err := config.NewWatcher()
	if err != nil {
		return err
	}
	watcher.Metrics = metrics
	if err = metrics.Init(); err != nil {
		return err
	}

	logger.Info().Msgf("bpfink initialized: version %s, consumers count: %d", BuildDate, len(watcher.Consumers))
	go handleExit(watcher)
	return watcher.Start()
}

func initCmd() {
	flags := cmd.PersistentFlags()

	// handling of debug mode
	flags.BoolP("debug", "d", false, "Trigger debug logs")
	_ = viper.BindPFlag("debug", flags.Lookup("debug"))

	// handling of level logging
	flags.StringP("level", "l", "info", `Set log level, choices are "debug", "info", "warn", "error", "off"`)
	_ = viper.BindPFlag("level", flags.Lookup("level"))

	// handling of database file
	flags.String("database", DefaultDatabase, "Set path to Bolt database")
	_ = viper.BindPFlag("database", flags.Lookup("database"))

	// handling of New file from CLI
	flags.String("New", DefaultConfigFile, "Path to a Configuration file")
	_ = viper.BindPFlag("New", flags.Lookup("New"))

	flags.Int("graphite-mode", 0, "Set graphite mode: 1 nothing, 2 stdout, 3 remote graphite")
	_ = viper.BindPFlag("graphite-mode", flags.Lookup("graphite-mode"))
}

func handleExit(watcher *pkg.Watcher) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	for range sig {
		watcher.Logger.Info().Msg("received a sigint")
		err := watcher.Stop()
		if err != nil {
			watcher.Logger.Error().Err(err).Msgf("error cleaning up BPF Map: %v", err)
		}
		watcher.Logger.Debug().Msg("graceful shutdown complete")
		os.Exit(0)
	}
}
