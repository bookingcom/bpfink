package pkg

import (
	"math"
	"testing"

	goMetrics "github.com/rcrowley/go-metrics"
)

func InitMetrics() Metrics {
	return Metrics{
		EveryMinuteRegister: goMetrics.NewPrefixedRegistry("security.piv.bpfink."),
		EveryHourRegister:   goMetrics.NewPrefixedRegistry("security.piv.bpfink."),
		Hostname:            "test_host",
	}
}

func TestLogMetric(t *testing.T) {
	m := InitMetrics()
	defer m.EveryMinuteRegister.UnregisterAll()
	m.RecordByLogTypes("warn")
	m.RecordByLogTypes("error")
	m.RecordByLogTypes("error")

	testIfMetricsAreExpected(t, m.EveryMinuteRegister, map[string]float64{
		"security.piv.bpfink.log_level.warn.by_role.unknown_role.test_host.count.minutely":  1,
		"security.piv.bpfink.log_level.error.by_role.unknown_role.test_host.count.minutely": 2,
	})
}

func TestInstalledHostMetric(t *testing.T) {
	m := InitMetrics()
	defer m.EveryHourRegister.UnregisterAll()
	m.RecordByInstalledHost()

	testIfMetricsAreExpected(t, m.EveryHourRegister, map[string]float64{
		"security.piv.bpfink.installed.by_role.unknown_role.test_host.count.hourly": 1,
	})
}

func TestEventsCaughtMetric(t *testing.T) {
	m := InitMetrics()
	defer m.EveryMinuteRegister.UnregisterAll()
	m.RecordByEventsCaught()
	m.RecordByEventsCaught()

	testIfMetricsAreExpected(t, m.EveryMinuteRegister, map[string]float64{
		"security.piv.bpfink.bpf.events_caught.by_role.unknown_role.test_host.count.minutely": 2,
	})
}

func TestVersionMetric(t *testing.T) {
	m := InitMetrics()
	defer m.EveryHourRegister.UnregisterAll()
	m.RecordVersion("0.1.12")

	testIfMetricsAreExpected(t, m.EveryHourRegister, map[string]float64{
		"security.piv.bpfink.installed.by_role.unknown_role.test_host.version.hourly": 112,
	})
}

func testIfMetricsAreExpected(t *testing.T, registry goMetrics.Registry, expectedMetrics map[string]float64) {
	actualMetrics := registry.GetAll()
	if len(expectedMetrics) != len(actualMetrics) {
		t.Errorf("We expect %d metrics but got %d", len(expectedMetrics), len(actualMetrics))
	}

	registry.Each(func(metricName string, metricValue interface{}) {
		if expectedValue, ok := expectedMetrics[metricName]; !ok {
			t.Errorf("Unexpected metric %s with value %v", metricName, metricValue)
		} else {
			var metricValueFloat64 float64
			switch metric := metricValue.(type) {
			case goMetrics.Gauge:
				metricValueFloat64 = float64(metric.Value())
			case goMetrics.GaugeFloat64:
				metricValueFloat64 = metric.Value()
			case goMetrics.Counter:
				metricValueFloat64 = float64(metric.Count())
			default:
				t.Fatalf("%s has unexpected type: %T", metricName, metric)
			}

			if math.Abs(metricValueFloat64-expectedValue) > 1e-9 {
				t.Errorf("%s has unexpected value %f, expected %f", metricName, metricValueFloat64, expectedValue)
			}
		}
	})
}
