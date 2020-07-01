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
	"time"

	goMetrics "github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	bolt "go.etcd.io/bbolt"

	"github.com/bookingcom/bpfink/pkg"
)

var BuildDate = "(development)" //nolint:gochecknoglobals

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
)

const (
	// DefaultConfigFile default config file location
	DefaultConfigFile = "/etc/bpfink.toml"
	// DefaultDatabase default database file location
	DefaultDatabase       = "/var/lib/bpfink.db"
	puppetFileColumnCount = 2
	keySize               = 16
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
		if !c.fileBelongsToExclusionList(c.Consumers.Access) {
			state := &pkg.AccessState{
				AccessListener: pkg.NewAccessListener(
					pkg.AccessFileOpt(fs, c.Consumers.Access, c.logger()),
				),
			}
			consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
		}
	}
	if c.Consumers.Users.Shadow != "" && c.Consumers.Users.Passwd != "" {
		if !c.fileBelongsToExclusionList(c.Consumers.Users.Shadow) || !c.fileBelongsToExclusionList(c.Consumers.Users.Passwd) {
			state := &pkg.UsersState{
				UsersListener: pkg.NewUsersListener(func(l *pkg.UsersListener) {
					l.Passwd = c.Consumers.Users.Passwd
					l.Shadow = c.Consumers.Users.Shadow
					l.Fs, l.Logger = fs, c.logger()
				}),
			}
			consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
		}
	}
	if len(c.Consumers.Sudoers) > 0 {
		//get list of files to watch
		sudoersFiles := c.getListOfFiles(fs, "sudoers")
		for _, sudoersFile := range sudoersFiles {
			if !c.fileBelongsToExclusionList(sudoersFile.File) {
				state := &pkg.SudoersState{
					SudoersListener: pkg.NewSudoersListener(
						pkg.SudoersFileOpt(fs, sudoersFile.File, c.logger()),
					),
				}
				consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			}
		}
	}
	if len(c.Consumers.Generic) > 0 {
		genericFiles := c.getListOfFiles(fs, "generic")
		for _, genericFile := range genericFiles {
			if !c.fileBelongsToExclusionList(genericFile.File) {
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

/* 	Checks if file belongs to exclusion list
true: if file needs to be excluded and hence does not create consumer
false: otherwise
*/
func (c Configuration) fileBelongsToExclusionList(file string) bool {
	logger := c.logger()
	for _, excludeFile := range c.Consumers.Excludes {
		if strings.HasPrefix(file, excludeFile) {
			logger.Debug().Msgf("File belongs to exclusion list, excluding from monitoring: %v", file)
			return true
		}
	}
	return false
}

// Gets list of files to be monitored from all files/dirs listed in the config
func (c Configuration) getListOfFiles(fs afero.Fs, consumerType string) []FileInfo {
	logger := c.logger()
	var filesToMonitor []FileInfo
	var pathList []string
	switch consumerType {
	case "sudoers":
		pathList = c.Consumers.Sudoers
	case "generic":
		pathList = c.Consumers.Generic
	}
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
		if c.checkIgnored(PathFull, fs) {
			continue // skip ignored file
		}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			logger.Debug().Msg("Path is a dir")
			err := filepath.Walk(PathFull, func(path string, info os.FileInfo, err error) error {
				if c.checkIgnored(path, fs) {
					return nil // skip for now
				}
				walkPath, resolvedInfo := c.resolvePath(path)
				if walkPath == "" {
					return nil // path could not be resolved skip for now
				}
				isDir := resolvedInfo.IsDir()
				if c.checkIgnored(walkPath, fs) {
					return nil // skip for now
				}

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
			logger.Error().Err(err).Msgf("error getting file stat for readLinked file: %v, %v", linkPath, pathFull)
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

func (c Configuration) checkIgnored(path string, fs afero.Fs) bool {
	logger := c.logger()
	base, ok := fs.(*afero.BasePathFs)
	if !ok {
		logger.Error().Msg("Could not type assert")
		return false
	}

	passwdFilePath, _ := base.RealPath(c.Consumers.Users.Passwd)
	shodowFilePath, _ := base.RealPath(c.Consumers.Users.Shadow)
	accessFilePath, _ := base.RealPath(c.Consumers.Access)

	switch path {
	case passwdFilePath:
		return true
	case shodowFilePath:
		return true
	case accessFilePath:
		return true
	default:
		// If file belongs to exclusion list, ignore it
		if c.fileBelongsToExclusionList(path) {
			return true
		}
		// Get file stat
		fi, err := os.Stat(path)
		if err != nil {
			logger.Error().Err(err).Msgf("error getting file stat: %v", path)
			return true
		}
		// If file is a socket, ignore it
		if fi.Mode()&os.ModeSocket != 0 {
			return true
		}
		return false
	}
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

	// determine server Role name
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
		logger.Fatal().
			Err(err).
			Msgf("failed to init metrics: %v", err)
	}

	if viper.GetInt("graphite-mode") != 0 {
		metrics.GraphiteMode = viper.GetInt("graphite-mode")
	}

	// increment the host count by 1
	metrics.RecordByInstalledHost()
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
