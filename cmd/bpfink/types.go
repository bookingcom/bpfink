package bpfink

import (
	"time"

	"github.com/bookingcom/bpfink/pkg"
	"github.com/rs/zerolog"
)

type IConfiguration interface {
	NewLogger() zerolog.Logger
	NewMetrics() (*pkg.Metrics, error)
	NewWatcher() (*pkg.Watcher, error)

	GetKeyFile() string
	SetKey([]byte)
}

// Configuration Struct for bpfink New
type Configuration struct {
	// private
	logger *zerolog.Logger
	key    []byte

	// public
	Debug         bool
	Level         string
	Database      string
	Keyfile       string
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
		Root        string
		Access      string
		GenericDiff []string
		Users       struct {
			Shadow, Passwd string
		}
		Generic  []string
		Excludes []string
	}
}

// filesToMonitor is the struct for watching files, used for generic and generic diff consumers
type FileInfo struct {
	File  string
	IsDir bool
}

type LogHook struct {
	metric *pkg.Metrics
}
