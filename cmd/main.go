package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	goMetrics "github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/bookingcom/bpfink/pkg"
)

type (
	//Configuration Struct for bpfink config
	Configuration struct {
		Debug         bool
		Level         string
		Database      string
		BCC           string `mapstructure:"bcc"`
		MetricsConfig struct {
			GraphiteHost       string
			GraphiteMode       int
			NameSpace          string
			CollectionInterval time.Duration
			HostRolePath       string
			HostRoleKey        string
			HostRoleToken      string
		}
		Consumers struct {
			Root    string
			Access  string
			Sudoers string
			Users   struct {
				Shadow, Passwd string
			}
		}
	}
)

const (
	//DefaultConfigFile default config file location
	DefaultConfigFile = "/etc/bpfink.toml"
	//DefaultDatabase default database file location
	DefaultDatabase       = "/var/lib/bpfink.db"
	puppetFileColumnCount = 2
)

func (c Configuration) logger() (logger zerolog.Logger) {
	lvlMap := map[string]zerolog.Level{
		"debug": zerolog.DebugLevel,
		"info":  zerolog.InfoLevel,
		"warn":  zerolog.WarnLevel,
		"error": zerolog.ErrorLevel,
		"off":   zerolog.PanicLevel,
	}

	if c.Debug {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
			With().Timestamp().Logger().Level(lvlMap["debug"])
	} else {
		// We can't use journald from rsyslog as it is way too complicated to find
		// a good documentation on both of those projects
		// logger = zerolog.New(journald.NewJournalDWriter()).Level(lvlMap[c.Level])
		logger = zerolog.New(os.Stderr).Level(lvlMap[c.Level])
	}
	return logger
}

func (c Configuration) consumers(db *pkg.AgentDB) (consumers pkg.BaseConsumers) {
	fs := afero.NewOsFs()
	if c.Consumers.Root != "" {
		fs = afero.NewBasePathFs(fs, c.Consumers.Root)
	}
	if c.Consumers.Access != "" {
		state := &pkg.AccessState{
			AccessListener: pkg.NewAccessListener(
				pkg.AccessFileOpt(fs, c.Consumers.Access, c.logger()),
			),
		}
		consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
	}
	if c.Consumers.Users.Shadow != "" && c.Consumers.Users.Passwd != "" {
		state := &pkg.UsersState{
			UsersListener: pkg.NewUsersListener(func(l *pkg.UsersListener) {
				l.Passwd = c.Consumers.Users.Passwd
				l.Shadow = c.Consumers.Users.Shadow
				l.Fs, l.Logger = fs, c.logger()
			}),
		}
		consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
	}
	return
}

func (c Configuration) metrics() (*pkg.Metrics, error) {
	logger := c.logger()
	metrics := &pkg.Metrics{
		GraphiteHost:    c.MetricsConfig.GraphiteHost,
		Namespace:       c.MetricsConfig.NameSpace,
		GraphiteMode:    c.MetricsConfig.GraphiteMode,
		MetricsInterval: c.MetricsConfig.CollectionInterval,
		Logger:          logger,
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	metrics.Hostname = hostname

	//determine server Role name
	if c.MetricsConfig.HostRolePath != "" {
		file, err := os.Open(c.MetricsConfig.HostRolePath)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			tokens := strings.Split(scanner.Text(), c.MetricsConfig.HostRoleToken)
			if len(tokens) < puppetFileColumnCount {
				continue
			}
			if tokens[0] == c.MetricsConfig.HostRoleKey {
				metrics.RoleName = tokens[1]
				break
			}
		}
		if err = file.Close(); err != nil {
			logger.Error().Err(err)
		}
	}

	metrics.EveryHourRegister = goMetrics.NewPrefixedRegistry(metrics.Namespace)
	metrics.EveryMinuteRegister = goMetrics.NewPrefixedRegistry(metrics.Namespace)

	return metrics, nil
}

func (c Configuration) watcher() (*pkg.Watcher, error) {
	logger := c.logger()
	logger.Debug().Str("db", c.Database).Msg("opening bolt database")
	db, err := bolt.Open(c.Database, 0600, nil)
	if err != nil {
		return nil, err
	}
	logger.Debug().Msg("starting ebpf")
	fim, err := pkg.InitFIM(c.BCC, c.logger())
	if err != nil {
		return nil, err
	}

	database := &pkg.AgentDB{Logger: logger, DB: db}
	consumers := c.consumers(database)

	for _, consumer := range consumers {
		if err := consumer.Init(); err != nil {
			logger.Fatal().Err(err).Msg("failed to init consumer")
		}
	}
	return pkg.NewWatcher(func(w *pkg.Watcher) {
		w.Logger, w.Consumers, w.FIM = logger, consumers.Consumers(), fim
	}), nil

}

func initCmd(cmd *cobra.Command) {
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

	// handling of config file from CLI
	flags.String("config", DefaultConfigFile, "Path to a configuration file")
	_ = viper.BindPFlag("config", flags.Lookup("config"))

	flags.Int("graphite-mode", 0, "Set graphite mode: 1 nothing, 2 stdout, 3 remote graphite")
	_ = viper.BindPFlag("graphite-mode", flags.Lookup("graphite-mode"))
}

func config() (cfg Configuration, err error) {
	path := viper.GetString("config")
	viper.SetConfigFile(path)
	if err = viper.ReadInConfig(); err != nil && (path != DefaultConfigFile || !os.IsNotExist(err)) {
		return
	}
	err = viper.Unmarshal(&cfg)
	return
}

func run() error {
	config, err := config()
	if err != nil {
		return err
	}
	logger := config.logger()
	logger.Debug().Msg("debug mode activated")
	logger.Debug().Msgf("config: %+v", config)

	metrics, err := config.metrics()
	if err != nil {
		logger.Fatal().
			Err(err).
			Msgf("failed to init metrics: %v", err)
	}

	if viper.GetInt("graphite-mode") != 0 {
		metrics.GraphiteMode = viper.GetInt("graphite-mode")
	}

	//increment the host count by 1
	metrics.RecordByInstalledHost()
	err = metrics.RecordBPFMetrics()
	if err != nil {
		logger.Fatal().Err(err).Msg("error starting bpf metrics")
	}

	watcher, err := config.watcher()
	if err != nil {
		return err
	}
	if err = metrics.Init(); err != nil {
		return err
	}

	go handleExit(watcher)
	return watcher.Start()
}

func handleExit(watcher *pkg.Watcher) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	for {
		select {
		case <-sig:
			watcher.Logger.Info().Msg("received a sigint")
			err := watcher.Stop()
			if err != nil {
				watcher.Logger.Error().Err(err).Msgf("error cleaning up BPF Map: %v", err)
			}
			watcher.Logger.Debug().Msg("graceful shutdown complete")
			os.Exit(0)
		case err := <-watcher.Errors:
			fmt.Printf("bcc error: %+v\n", err)
		}
	}
}

func main() {
	cmd := &cobra.Command{
		Use:   "bpfink",
		Short: "FIM reporter",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// https://github.com/spf13/cobra/issues/340
			cmd.SilenceUsage = true
			return run()
		},
	}

	initCmd(cmd)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
