package main

import (
	"bufio"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	goMetrics "github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	bolt "go.etcd.io/bbolt"

	"github.com/bookingcom/bpfink/pkg"
)

// nolint:gochecknoglobals
var (
	BuildDate          = "(development)"
	Version            string
	MetricsInitialised struct {
		metrics *pkg.Metrics
		err     error
		Once    sync.Once
	}
)

type (
	// Configuration Struct for bpfink config
	Configuration struct {
		Debug         bool
		Level         string
		Database      string
		Keyfile       string
		key           []byte
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
			Sudoers []string
			Users   struct {
				Shadow, Passwd string
			}
			Generic  []string
			Excludes []string
		}
	}
	// filesToMonitor is the struct for watching files, used for generic and sudoers consumers
	FileInfo struct {
		File  string
		IsDir bool
	}
	LogHook struct {
		metric *pkg.Metrics
	}
)

const (
	// DefaultConfigFile default config file location
	DefaultConfigFile = "/etc/bpfink.toml"
	// DefaultDatabase default database file location
	DefaultDatabase       = "/var/lib/bpfink.db"
	puppetFileColumnCount = 2
	keySize               = 16
)

// LogHook to send a graphite metric for each log entry
func (h LogHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	// Send log type metric
	h.metric.RecordByLogTypes(level.String())
	// Send version in each log entry
	e.Str("version", Version)
}

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

	// Add hook to logger if there is no error with metrics initialization
	metrics, err := c.metrics()
	if err == nil {
		logger = logger.Hook(LogHook{metric: metrics})
	}
	return logger
}

func (c Configuration) consumers(db *pkg.AgentDB) (consumers pkg.BaseConsumers) {
	fs := afero.NewOsFs()
	var existingConsumersFiles = make(map[string]bool)

	if c.Consumers.Root != "" {
		fs = afero.NewBasePathFs(fs, c.Consumers.Root)
	}
	if c.Consumers.Access != "" {
		if !c.isFileToBeExcluded(c.Consumers.Access, existingConsumersFiles) {
			state := &pkg.AccessState{
				AccessListener: pkg.NewAccessListener(
					pkg.AccessFileOpt(fs, c.Consumers.Access, c.logger()),
				),
			}
			consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			existingConsumersFiles[c.Consumers.Access] = true
		}
	}
	if c.Consumers.Users.Shadow != "" && c.Consumers.Users.Passwd != "" {
		if !c.isFileToBeExcluded(c.Consumers.Users.Shadow, existingConsumersFiles) || !c.isFileToBeExcluded(c.Consumers.Users.Passwd, existingConsumersFiles) {
			state := &pkg.UsersState{
				UsersListener: pkg.NewUsersListener(func(l *pkg.UsersListener) {
					l.Passwd = c.Consumers.Users.Passwd
					l.Shadow = c.Consumers.Users.Shadow
					l.Fs, l.Logger = fs, c.logger()
				}),
			}
			consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			existingConsumersFiles[c.Consumers.Users.Shadow] = true
			existingConsumersFiles[c.Consumers.Users.Passwd] = true
		}
	}
	if len(c.Consumers.Sudoers) > 0 {
		//get list of files to watch
		sudoersFiles := c.getListOfFiles(fs, c.Consumers.Sudoers)
		for _, sudoersFile := range sudoersFiles {
			if !c.isFileToBeExcluded(sudoersFile.File, existingConsumersFiles) {
				state := &pkg.SudoersState{
					SudoersListener: pkg.NewSudoersListener(
						pkg.SudoersFileOpt(fs, sudoersFile.File, c.logger()),
					),
				}
				consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
				existingConsumersFiles[sudoersFile.File] = true
			}
		}
	}
	if len(c.Consumers.Generic) > 0 {
		genericFiles := c.getListOfFiles(fs, c.Consumers.Generic)
		for _, genericFile := range genericFiles {
			if !c.isFileToBeExcluded(genericFile.File, existingConsumersFiles) {
				genericFile := genericFile
				state := &pkg.GenericState{
					GenericListener: pkg.NewGenericListener(func(l *pkg.GenericListener) {
						l.File = genericFile.File
						l.IsDir = genericFile.IsDir
						l.Key = c.key
						l.Fs = fs
						l.Logger = c.logger()
					}),
				}
				consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			}
		}
	}
	return consumers
}

/* 	Checks if file belongs to exclusion list or is already assigned to a consumer and excludes it accordingly
true: if file needs to be excluded
false: otherwise
*/
func (c Configuration) isFileToBeExcluded(file string, existingConsumersFiles map[string]bool) bool {
	logger := c.logger()
	isFileExcluded := false

	for _, excludeFile := range c.Consumers.Excludes {
		if strings.HasPrefix(file, excludeFile) {
			logger.Debug().Msgf("File belongs to exclusion list, excluding from monitoring: %v", file)
			isFileExcluded = true
			break
		}
	}

	return isFileExcluded || existingConsumersFiles[file]
}

// Gets list of files to be monitored from all files/dirs listed in the config
func (c Configuration) getListOfFiles(fs afero.Fs, pathList []string) []FileInfo {
	logger := c.logger()
	var filesToMonitor []FileInfo
	for _, fullPath := range pathList {
		fullPath := fullPath
		pkgFile := pkg.NewFile(func(file *pkg.File) {
			file.Fs, file.Path, file.Logger = fs, fullPath, logger
		})

		PathFull := ""
		if baseFile, ok := pkgFile.Fs.(*afero.BasePathFs); ok {
			PathFull, _ = baseFile.RealPath(fullPath)
		}
		if PathFull == "" {
			PathFull = fullPath
		}
		logger.Debug().Msgf("file to watch: %v", PathFull)
		PathFull, fi := c.resolvePath(PathFull)
		if PathFull == "" {
			continue // could not resolve the file. skip for now.
		}

		switch mode := fi.Mode(); {
		case mode.IsDir():
			logger.Debug().Msg("Path is a dir")
			err := filepath.Walk(PathFull, func(path string, info os.FileInfo, err error) error {
				walkPath, resolvedInfo := c.resolvePath(path)
				if walkPath == "" {
					return nil // path could not be resolved skip for now
				}
				isDir := resolvedInfo.IsDir()
				logger.Debug().Msgf("Path: %v", path)
				filesToMonitor = append(filesToMonitor, FileInfo{File: path, IsDir: isDir})
				return nil
			})
			if err != nil {
				logger.Error().Err(err).Msgf("error walking dir: %v", PathFull)
			}
		case mode.IsRegular():
			logger.Debug().Msg("Path is a file")
			logger.Debug().Msgf("Path: %v", PathFull)
			filesToMonitor = append(filesToMonitor, FileInfo{File: PathFull, IsDir: false})
		default:
			logger.Debug().Msg("Path is a dir")
		}
	}
	return filesToMonitor
}

func (c Configuration) resolvePath(pathFull string) (string, os.FileInfo) {
	logger := c.logger()
	fi, err := os.Lstat(pathFull)
	if err != nil {
		logger.Error().Err(err).Msgf("error getting file stat: %v", pathFull)
		return "", nil
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return "", nil
	}
	logger.Debug().Msgf("is symlink: %v", fi.Mode()&os.ModeSymlink != 0)
	if fi.Mode()&os.ModeSymlink != 0 {
		linkPath, err := os.Readlink(pathFull)
		if err != nil {
			logger.Error().Err(err).Msgf("error reading link: %v", pathFull)
			return "", nil
		}
		logger.Debug().Msgf("resolved link: %v", linkPath)

		if len(linkPath) > 0 && string(linkPath[0]) != "/" { // dont resolve absolute paths
			linkBasePath := filepath.Dir(pathFull)
			logger.Debug().Msgf("linkBasePath: %v", linkBasePath)
			absLinkPath := filepath.Join(linkBasePath, linkPath)

			linkPath = absLinkPath
			logger.Debug().Msgf("full link path: %v", absLinkPath)
		}

		fileInfo, err := os.Stat(linkPath)
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Error().Err(err).Msgf("error getting file stat for readLinked file: %v, %v", linkPath, pathFull)
			}
			return "", nil
		}
		fi = fileInfo
		pathFull = linkPath
	}
	logger.Debug().Msgf("isDir: %v", fi.IsDir())
	if fi.Mode()&os.ModeIrregular == 0 || fi.Mode()&os.ModeDir == 0 {
		logger.Debug().Msgf("isDir: %v", fi.IsDir())
		return pathFull, fi
	}
	return "", nil
}

// Singleton function that initializes metrics
func (c Configuration) metrics() (*pkg.Metrics, error) {
	MetricsInitialised.Once.Do(func() {
		logger := zerolog.New(os.Stderr).Level(zerolog.DebugLevel)
		metrics := &pkg.Metrics{
			GraphiteHost:    c.MetricsConfig.GraphiteHost,
			Namespace:       c.MetricsConfig.NameSpace,
			GraphiteMode:    c.MetricsConfig.GraphiteMode,
			MetricsInterval: c.MetricsConfig.CollectionInterval,
			Logger:          logger,
		}

		hostname, err := os.Hostname()
		if err != nil {
			MetricsInitialised.metrics, MetricsInitialised.err = nil, err
			return
		}
		metrics.Hostname = hostname

		// determine server Role name
		if c.MetricsConfig.HostRolePath != "" {
			file, err := os.Open(c.MetricsConfig.HostRolePath)
			if err != nil {
				MetricsInitialised.metrics, MetricsInitialised.err = nil, err
				return
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
				MetricsInitialised.metrics, MetricsInitialised.err = nil, err
				return
			}
		}
		metrics.EveryHourRegister = goMetrics.NewPrefixedRegistry(metrics.Namespace)
		metrics.EveryMinuteRegister = goMetrics.NewPrefixedRegistry(metrics.Namespace)

		MetricsInitialised.metrics, MetricsInitialised.err = metrics, nil
	})

	return MetricsInitialised.metrics, MetricsInitialised.err
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
		w.Logger, w.Consumers, w.FIM, w.Database, w.Key, w.Excludes, w.Sudoers = logger, consumers.Consumers(), fim, database, c.key, c.Consumers.Excludes, c.Consumers.Sudoers
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
		logger.Fatal().Err(err).Msgf("failed to init metrics: %v", err)
	}

	if viper.GetInt("graphite-mode") != 0 {
		metrics.GraphiteMode = viper.GetInt("graphite-mode")
	}

	// increment the host count by 1
	metrics.RecordByInstalledHost()
	// send version metric
	metrics.RecordVersion(Version)
	err = metrics.RecordBPFMetrics()
	if err != nil {
		logger.Fatal().Err(err).Msg("error starting bpf metrics")
	}
	key := make([]byte, keySize)
	if config.Keyfile == "" {
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			logger.Fatal().Msg("failed to create a new key")
		}
		config.key = key
	} else {
		// readin keyfile
		dat, err := ioutil.ReadFile(config.Keyfile)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to read key file")
		}
		config.key = dat[:16]
	}
	watcher, err := config.watcher()
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
