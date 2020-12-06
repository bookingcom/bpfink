package bpfink

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/bookingcom/bpfink/pkg"
	goMetrics "github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	bolt "go.etcd.io/bbolt"
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

func NewConfiguration() (IConfiguration, error) {
	path := viper.GetString("config")
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil && (path != DefaultConfigFile || !os.IsNotExist(err)) {
		return nil, err
	}

	var cfg Configuration
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c Configuration) NewLogger() zerolog.Logger {
	if c.logger != nil {
		return *c.logger
	}

	var logger zerolog.Logger
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
		// NewLogger = zerolog.New(journald.NewJournalDWriter()).Level(lvlMap[c.Level])
		logger = zerolog.New(os.Stderr).Level(lvlMap[c.Level])
	}

	// Add hook to NewLogger if there is no error with metrics initialization
	metrics, err := c.NewMetrics()
	if err == nil {
		logger = logger.Hook(LogHook{metric: metrics})
	}

	return logger
}

// Singleton function that initializes metrics
func (c Configuration) NewMetrics() (*pkg.Metrics, error) {
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

func (c Configuration) NewWatcher() (*pkg.Watcher, error) {
	var genericDiffPaths []string
	c.logger.Debug().Str("db", c.Database).Msg("opening bolt database")
	db, err := bolt.Open(c.Database, 0600, nil)
	if err != nil {
		return nil, err
	}
	c.logger.Debug().Msg("starting ebpf")
	fim, err := pkg.InitFIM(c.BCC, *c.logger)
	if err != nil {
		return nil, err
	}

	database := &pkg.AgentDB{Logger: *c.logger, DB: db}
	consumers := c.initConsumers(database, &genericDiffPaths)

	for _, consumer := range consumers {
		if err := consumer.Init(); err != nil {
			c.logger.Error().Err(err).Msg("failed to init consumer")
		}
	}
	return pkg.NewWatcher(func(w *pkg.Watcher) {
		w.Logger, w.Consumers, w.FIM, w.Database, w.Key, w.Excludes, w.GenericDiff = *c.logger, consumers.Consumers(), fim, database, c.key, c.compileRegex(c.Consumers.Excludes), genericDiffPaths
	}), nil
}

// Keys
func (c Configuration) GetKeyFile() string {
	return c.Keyfile
}

func (c Configuration) SetKey(key []byte) {
	c.key = key
}

/*
Initialises all the consumers along with pre-populating genericDiffPaths used by watcher
*/
func (c Configuration) initConsumers(db *pkg.AgentDB, genericDiffPaths *[]string) (consumers pkg.BaseConsumers) {
	fs := afero.NewOsFs()
	var existingConsumersFiles = make(map[string]bool)
	listOfRegexpsExcludes := c.compileRegex(c.Consumers.Excludes)

	if c.Consumers.Root != "" {
		fs = afero.NewBasePathFs(fs, c.Consumers.Root)
	}
	if c.Consumers.Access != "" {
		if !c.isFileToBeExcluded(c.Consumers.Access, existingConsumersFiles, listOfRegexpsExcludes) {
			state := &pkg.AccessState{
				AccessListener: pkg.NewAccessListener(
					pkg.AccessFileOpt(fs, c.Consumers.Access, *c.logger),
				),
			}
			consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			existingConsumersFiles[c.Consumers.Access] = true
		}
	}
	if c.Consumers.Users.Shadow != "" && c.Consumers.Users.Passwd != "" {
		if !c.isFileToBeExcluded(c.Consumers.Users.Shadow, existingConsumersFiles, listOfRegexpsExcludes) ||
			!c.isFileToBeExcluded(c.Consumers.Users.Passwd, existingConsumersFiles, listOfRegexpsExcludes) {
			state := &pkg.UsersState{
				UsersListener: pkg.NewUsersListener(func(l *pkg.UsersListener) {
					l.Passwd = c.Consumers.Users.Passwd
					l.Shadow = c.Consumers.Users.Shadow
					l.Fs, l.Logger = fs, *c.logger
				}),
			}
			consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			existingConsumersFiles[c.Consumers.Users.Shadow] = true
			existingConsumersFiles[c.Consumers.Users.Passwd] = true
		}
	}
	if len(c.Consumers.GenericDiff) > 0 {
		//get list of files to watch
		genericDiffFiles := c.getListOfFiles(fs, c.Consumers.GenericDiff)
		for _, genericDiffFile := range genericDiffFiles {
			if !c.isFileToBeExcluded(genericDiffFile.File, existingConsumersFiles, listOfRegexpsExcludes) {
				state := &pkg.GenericDiffState{
					GenericDiffListener: pkg.NewGenericDiffListener(
						pkg.GenericDiffFileOpt(fs, genericDiffFile.File, *c.logger),
					),
				}
				consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
				existingConsumersFiles[genericDiffFile.File] = true
				//this variable is used by watcher to get the complete list of paths to monitor, instead of the list from the config
				*genericDiffPaths = append(*genericDiffPaths, genericDiffFile.File)
			}
		}
	}
	if len(c.Consumers.Generic) > 0 {
		genericFiles := c.getListOfFiles(fs, c.Consumers.Generic)
		for _, genericFile := range genericFiles {
			if !c.isFileToBeExcluded(genericFile.File, existingConsumersFiles, listOfRegexpsExcludes) {
				genericFile := genericFile
				state := &pkg.GenericState{
					GenericListener: pkg.NewGenericListener(func(l *pkg.GenericListener) {
						l.File = genericFile.File
						l.IsDir = genericFile.IsDir
						l.Key = c.key
						l.Fs = fs
						l.Logger = *c.logger
					}),
				}
				consumers = append(consumers, &pkg.BaseConsumer{AgentDB: db, ParserLoader: state})
			}
		}
	}
	return consumers
}

// Gets list of regexp objects from regexp paths
func (c Configuration) compileRegex(listofPaths []string) []*regexp.Regexp {
	var regexpObjects []*regexp.Regexp
	for _, path := range listofPaths {
		reg, err := regexp.Compile(path)
		if err != nil {
			c.logger.Error().Err(err).Msgf("Error while compiling regex: %v", err)
			continue
		}
		regexpObjects = append(regexpObjects, reg)
	}
	return regexpObjects
}

/* 	Checks if file belongs to exclusion list or is already assigned to a consumer and excludes it accordingly
true: if file needs to be excluded
false: otherwise
*/
func (c Configuration) isFileToBeExcluded(file string, existingConsumersFiles map[string]bool, listOfRegexpsExcludes []*regexp.Regexp) bool {
	isFileExcluded := false
	for _, excludeRegexp := range listOfRegexpsExcludes {
		matches := excludeRegexp.MatchString(file)
		if matches {
			c.logger.Debug().Msgf("File belongs to exclusion list, excluding from monitoring: %v", file)
			isFileExcluded = true
			break
		}
	}
	return isFileExcluded || existingConsumersFiles[file]
}

// Gets the full list of paths to monitor
func (c Configuration) getCompleteListOfPaths(pathList []string) []string {
	var completePathList []string
	for _, path := range pathList {
		completePath, err := filepath.Glob(path)
		if err != nil {
			c.logger.Error().Err(err).Msgf("Error getting complete list of paths to register: %v", err)
			continue
		}
		completePathList = append(completePathList, completePath...)
	}
	return completePathList
}

// Gets list of files to be monitored from all files/dirs listed in the config
func (c Configuration) getListOfFiles(fs afero.Fs, pathList []string) []FileInfo {
	var filesToMonitor []FileInfo
	completeListOfPaths := c.getCompleteListOfPaths(pathList)

	for _, fullPath := range completeListOfPaths {
		fullPath := fullPath
		pkgFile := pkg.NewFile(func(file *pkg.File) {
			file.Fs, file.Path, file.Logger = fs, fullPath, *c.logger
		})

		PathFull := ""
		if baseFile, ok := pkgFile.Fs.(*afero.BasePathFs); ok {
			PathFull, _ = baseFile.RealPath(fullPath)
		}
		if PathFull == "" {
			PathFull = fullPath
		}
		c.logger.Debug().Msgf("file to watch: %v", PathFull)
		PathFull, fi := c.resolvePath(PathFull)
		if PathFull == "" {
			continue // could not resolve the file. skip for now.
		}

		switch mode := fi.Mode(); {
		case mode.IsDir():
			c.logger.Debug().Msg("Path is a dir")
			err := filepath.Walk(PathFull, func(path string, info os.FileInfo, err error) error {
				walkPath, resolvedInfo := c.resolvePath(path)
				if walkPath == "" {
					return nil // path could not be resolved skip for now
				}
				isDir := resolvedInfo.IsDir()
				c.logger.Debug().Msgf("Path: %v", path)
				filesToMonitor = append(filesToMonitor, FileInfo{File: path, IsDir: isDir})
				return nil
			})
			if err != nil {
				c.logger.Error().Err(err).Msgf("error walking dir: %v", PathFull)
			}
		case mode.IsRegular():
			c.logger.Debug().Msg("Path is a file")
			c.logger.Debug().Msgf("Path: %v", PathFull)
			filesToMonitor = append(filesToMonitor, FileInfo{File: PathFull, IsDir: false})
		default:
			c.logger.Debug().Msg("Path is a dir")
		}
	}
	return filesToMonitor
}

func (c Configuration) resolvePath(pathFull string) (string, os.FileInfo) {
	fi, err := os.Lstat(pathFull)
	if err != nil {
		c.logger.Error().Err(err).Msgf("error getting file stat: %v", pathFull)
		return "", nil
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return "", nil
	}
	c.logger.Debug().Msgf("is symlink: %v", fi.Mode()&os.ModeSymlink != 0)
	if fi.Mode()&os.ModeSymlink != 0 {
		linkPath, err := os.Readlink(pathFull)
		if err != nil {
			c.logger.Error().Err(err).Msgf("error reading link: %v", pathFull)
			return "", nil
		}
		c.logger.Debug().Msgf("resolved link: %v", linkPath)

		if len(linkPath) > 0 && string(linkPath[0]) != "/" { // dont resolve absolute paths
			linkBasePath := filepath.Dir(pathFull)
			c.logger.Debug().Msgf("linkBasePath: %v", linkBasePath)
			absLinkPath := filepath.Join(linkBasePath, linkPath)

			linkPath = absLinkPath
			c.logger.Debug().Msgf("full link path: %v", absLinkPath)
		}

		fileInfo, err := os.Stat(linkPath)
		if err != nil {
			if !os.IsNotExist(err) {
				c.logger.Error().Err(err).Msgf("error getting file stat for readLinked file: %v, %v", linkPath, pathFull)
			}
			return "", nil
		}
		if fileInfo.Mode()&os.ModeSocket != 0 {
			return "", nil
		}

		fi = fileInfo
		pathFull = linkPath
	}
	c.logger.Debug().Msgf("isDir: %v", fi.IsDir())
	if fi.Mode()&os.ModeIrregular == 0 || fi.Mode()&os.ModeDir == 0 {
		c.logger.Debug().Msgf("isDir: %v", fi.IsDir())
		return pathFull, fi
	}
	return "", nil
}

// LogHook to send a graphite metric for each log entry
func (h LogHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	// Send log type metric
	h.metric.RecordByLogTypes(level.String())
	// Send version in each log entry
	e.Str("version", Version)
}
