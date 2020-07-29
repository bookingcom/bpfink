package pkg

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	graphite "github.com/cyberdelia/go-metrics-graphite"
	goMetrics "github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
)

// Metrics struct defining configs for graphite metrics
type Metrics struct {
	GraphiteHost        string
	Namespace           string
	GraphiteMode        int
	MetricsInterval     time.Duration
	EveryHourRegister   goMetrics.Registry
	EveryMinuteRegister goMetrics.Registry
	Hostname            string
	RoleName            string
	Logger              zerolog.Logger
	mux                 sync.Mutex
	missedCount         map[string]int64
	hitCount            map[string]int64
}

type bpfMetrics struct {
	hitRate    int64
	missedRate int64
}

const (
	graphiteOff = iota + 1
	graphiteStdout
	graphiteRemote
	provbeVfsWrite  = "pvfs_write"
	provbeVfsRename = "pvfs_rename"
	provbeVfsUnlink = "pvfs_unlink"
	provbeVfsRmDir  = "pvfs_rmdir"
	pdonePathCreate = "pdone_path_create"
	pdoDentryOpen   = "pdo_dentry_open"
)

var defaultRolename = "unknown_role" // nolint:gochecknoglobals

// Init method to start up graphite metrics
func (m *Metrics) Init() error {
	m.missedCount = make(map[string]int64)
	m.hitCount = make(map[string]int64)
	m.Logger.Debug().Msgf("fake metrics: %v", m.GraphiteMode)
	switch m.GraphiteMode {
	case graphiteOff:

	case graphiteStdout:
		go goMetrics.Log(m.EveryHourRegister, 30*time.Second, log.New(os.Stderr, "METRICS_HOUR: ", log.Lmicroseconds))
		go goMetrics.Log(m.EveryMinuteRegister, 30*time.Second, log.New(os.Stderr, "METRICS_MINUTE: ", log.Lmicroseconds))

	case graphiteRemote:
		addr, err := net.ResolveTCPAddr("tcp", m.GraphiteHost)
		if err != nil {
			return err
		}
		go graphite.Graphite(m.EveryHourRegister, time.Minute*30, "", addr)
		go graphite.Graphite(m.EveryMinuteRegister, time.Second*30, "", addr)
	}

	return nil
}

// RecordByLogTypes sends count of different types of logs
func (m *Metrics) RecordByLogTypes(logType string) {
	// If rolename is not empty, override the defaultRolename
	if m.RoleName != "" {
		defaultRolename = m.RoleName
	}
	metricName := fmt.Sprintf("log_level.%s.by_role.%s.%s.count.minutely", logType, quote(defaultRolename), quote(m.Hostname))
	goMetrics.GetOrRegisterCounter(metricName, m.EveryMinuteRegister).Inc(1)
}

// RecordByEventsCaught sends count of number of events caught by ebpf
func (m *Metrics) RecordByEventsCaught() {
	// If rolename is not empty, override the defaultRolename
	if m.RoleName != "" {
		defaultRolename = m.RoleName
	}
	metricName := fmt.Sprintf("bpf.events_caught.by_role.%s.%s.count.minutely", quote(defaultRolename), quote(m.Hostname))
	goMetrics.GetOrRegisterCounter(metricName, m.EveryMinuteRegister).Inc(1)
}

// RecordByInstalledHost graphite metric to show how manay host have bpfink installed
func (m *Metrics) RecordByInstalledHost() {
	// If rolename is not empty, override the defaultRolename
	if m.RoleName != "" {
		defaultRolename = m.RoleName
	}
	metricName := fmt.Sprintf("installed.by_role.%s.%s.count.hourly", quote(defaultRolename), quote(m.Hostname))
	goMetrics.GetOrRegisterGauge(metricName, m.EveryHourRegister).Update(int64(1))
}

// RecordBPFMetrics send metrics for BPF hits and misses per probe
func (m *Metrics) RecordBPFMetrics() error {
	go func() {
		for range time.Tick(m.MetricsInterval) {
			BPFMetrics, err := m.fetchBPFMetrics()
			if err != nil {
				m.Logger.Error().Err(err).Msg("error fetching bpf metrics")
			}
			for key := range BPFMetrics {
				// If rolename is not empty, override the defaultRolename
				if m.RoleName != "" {
					defaultRolename = m.RoleName
				}
				vfsHit := fmt.Sprintf("bpf.by_role.%s.%s.kprobe.hit_rate.minutely", quote(defaultRolename), key)
				vfsMiss := fmt.Sprintf("bpf.by_role.%s.%s.kprobe.miss_rate.minutely", quote(defaultRolename), key)
				goMetrics.GetOrRegisterGauge(vfsHit, m.EveryMinuteRegister).Update(BPFMetrics[key].hitRate)
				goMetrics.GetOrRegisterGauge(vfsMiss, m.EveryMinuteRegister).Update(BPFMetrics[key].missedRate)
			}
		}
	}()
	return nil
}

func (m *Metrics) fetchBPFMetrics() (map[string]bpfMetrics, error) {
	BPFMetrics := make(map[string]bpfMetrics)

	file, err := os.Open("/sys/kernel/debug/tracing/kprobe_profile")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		tokens := strings.Fields(line)

		if strings.Contains(tokens[0], provbeVfsWrite) {
			bpfMetric, err := m.parseBPFLine(tokens, provbeVfsWrite)
			if err != nil {
				return nil, err
			}
			BPFMetrics[provbeVfsWrite] = *bpfMetric
		}

		if strings.Contains(tokens[0], provbeVfsRename) {
			bpfMetric, err := m.parseBPFLine(tokens, provbeVfsRename)
			if err != nil {
				return nil, err
			}
			BPFMetrics[provbeVfsRename] = *bpfMetric
		}

		if strings.Contains(tokens[0], provbeVfsUnlink) {
			bpfMetric, err := m.parseBPFLine(tokens, provbeVfsUnlink)
			if err != nil {
				return nil, err
			}
			BPFMetrics[provbeVfsUnlink] = *bpfMetric
		}

		if strings.Contains(tokens[0], provbeVfsRmDir) {
			bpfMetric, err := m.parseBPFLine(tokens, provbeVfsRmDir)
			if err != nil {
				return nil, err
			}
			BPFMetrics[provbeVfsRmDir] = *bpfMetric
		}

		if strings.Contains(tokens[0], pdonePathCreate) {
			bpfMetric, err := m.parseBPFLine(tokens, pdonePathCreate)
			if err != nil {
				return nil, err
			}
			BPFMetrics[pdonePathCreate] = *bpfMetric
		}

		if strings.Contains(tokens[0], pdoDentryOpen) {
			bpfMetric, err := m.parseBPFLine(tokens, pdoDentryOpen)
			if err != nil {
				return nil, err
			}
			BPFMetrics[pdoDentryOpen] = *bpfMetric
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return BPFMetrics, nil
}

func (m *Metrics) parseBPFLine(tokens []string, probeName string) (*bpfMetrics, error) {
	currentHit, err := strconv.ParseInt(tokens[1], 10, 64)
	if err != nil {
		return nil, err
	}
	currentMiss, err := strconv.ParseInt(tokens[2], 10, 64)
	if err != nil {
		return nil, err
	}
	m.mux.Lock()
	if m.hitCount == nil {
		m.hitCount = make(map[string]int64)
	}
	if m.missedCount == nil {
		m.missedCount = make(map[string]int64)
	}
	hitRate := currentHit - m.hitCount[probeName]
	missedRate := currentMiss - m.missedCount[probeName]
	m.hitCount[probeName] = currentHit
	m.missedCount[probeName] = currentMiss
	m.mux.Unlock()
	return &bpfMetrics{
		hitRate:    hitRate,
		missedRate: missedRate,
	}, nil
}

func quote(str string) string {
	underscorePrecedes := false
	quotedString := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r):
			underscorePrecedes = false
			return unicode.ToLower(r)
		case unicode.IsDigit(r):
			underscorePrecedes = false
			return r
		case underscorePrecedes:
			return -1
		default:
			underscorePrecedes = true
			// maintain - in hostnames
			if string(r) == "-" {
				return r
			}
			return '_'
		}
	}, str)

	return strings.Trim(quotedString, "_")
}
