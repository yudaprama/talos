package metrics

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // Import sqlite3 driver for tests
)

func newTestMetrics(t *testing.T) *Metrics {
	t.Helper()
	return New(prometheus.NewRegistry())
}

// TestRecordVerification tests the RecordVerification method
func TestRecordVerification(t *testing.T) {
	t.Parallel()

	t.Run("records successful verification", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordVerification("talos", true, false, 0.001)

		assert.Equal(t, 1, int(testutil.ToFloat64(m.VerificationAttempts.WithLabelValues("talos", "success"))))
	})

	t.Run("records failed verification", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordVerification("talos", false, false, 0.002)

		assert.Equal(t, 1, int(testutil.ToFloat64(m.VerificationAttempts.WithLabelValues("talos", "failure"))))
	})

	t.Run("records cache hit", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordVerification("talos", true, true, 0.0005)

		assert.Equal(t, 1, int(testutil.ToFloat64(m.CacheHits)))
		assert.Equal(t, 0, int(testutil.ToFloat64(m.CacheMisses)))
	})

	t.Run("records cache miss", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordVerification("talos", true, false, 0.001)

		assert.Equal(t, 0, int(testutil.ToFloat64(m.CacheHits)))
		assert.Equal(t, 1, int(testutil.ToFloat64(m.CacheMisses)))
	})

	t.Run("records verification latency", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordVerification("talos", true, false, 0.001)
		m.RecordVerification("talos", true, false, 0.005)
		m.RecordVerification("talos", true, false, 0.010)

		assert.Positive(t, testutil.CollectAndCount(m.VerificationLatency))
	})

	t.Run("records different verification types", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		for _, vType := range []string{"talos", "imported", "jwt", "macaroon"} {
			m.RecordVerification(vType, true, false, 0.001)
		}

		assert.Equal(t, 4, testutil.CollectAndCount(m.VerificationAttempts))
	})
}

// TestVerificationLatency_Buckets tests histogram bucket configuration
func TestVerificationLatency_Buckets(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	// Record observations in each bucket range
	m.RecordVerification("talos", true, false, 0.0005) // < 1ms
	m.RecordVerification("talos", true, false, 0.003)  // 1-5ms
	m.RecordVerification("talos", true, false, 0.007)  // 5-10ms
	m.RecordVerification("talos", true, false, 0.015)  // 10-25ms
	m.RecordVerification("talos", true, false, 0.030)  // 25-50ms
	m.RecordVerification("talos", true, false, 0.075)  // 50-100ms
	m.RecordVerification("talos", true, false, 0.15)   // 100-250ms
	m.RecordVerification("talos", true, false, 0.35)   // 250-500ms
	m.RecordVerification("talos", true, false, 0.75)   // 500ms-1s

	assert.Positive(t, testutil.CollectAndCount(m.VerificationLatency))
}

// TestVerificationLatency_HighLatencyBuckets ensures the histogram exposes
// buckets beyond 1 second so operators can see tail latency in the 1s–10s range.
func TestVerificationLatency_HighLatencyBuckets(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	// Record one observation so the histogram emits a metric with bucket metadata.
	m.RecordVerification("talos", true, false, 0.5)

	ch := make(chan prometheus.Metric, 4)
	m.VerificationLatency.Collect(ch)
	close(ch)

	wantBuckets := map[float64]bool{2.5: false, 5: false, 10: false}
	var found bool
	for metric := range ch {
		pb := &dto.Metric{}
		require.NoError(t, metric.Write(pb))
		if pb.Histogram == nil {
			continue
		}
		found = true
		for _, b := range pb.Histogram.Bucket {
			if _, ok := wantBuckets[b.GetUpperBound()]; ok {
				wantBuckets[b.GetUpperBound()] = true
			}
		}
	}
	require.True(t, found, "expected at least one histogram metric")
	for upper, present := range wantBuckets {
		assert.True(t, present, "VerificationLatency histogram must include bucket %v", upper)
	}
}

// TestAPIKeysCreated tests the APIKeysCreated counter
func TestAPIKeysCreated(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.APIKeysCreated.Inc()

	assert.Equal(t, 1, int(testutil.ToFloat64(m.APIKeysCreated)))
}

// TestBatchImportRequests tests the BatchImportRequests counter
func TestBatchImportRequests(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.BatchImportRequests.Inc()

	assert.Equal(t, 1, int(testutil.ToFloat64(m.BatchImportRequests)))
}

// TestBatchImportKeyCount tests the BatchImportKeyCount histogram
func TestBatchImportKeyCount(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.BatchImportKeyCount.Observe(10)
	m.BatchImportKeyCount.Observe(100)

	assert.Positive(t, testutil.CollectAndCount(m.BatchImportKeyCount))
}

// TestBatchImportPartialFailures tests the BatchImportPartialFailures counter
func TestBatchImportPartialFailures(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.BatchImportPartialFailures.Inc()

	assert.Equal(t, 1, int(testutil.ToFloat64(m.BatchImportPartialFailures)))
}

// TestRecordBatchImportOutcome tests per-key success/failure counters
func TestRecordBatchImportOutcome(t *testing.T) {
	t.Parallel()

	t.Run("records succeeded keys", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordBatchImportOutcome(5, nil)

		assert.Equal(t, 5, int(testutil.ToFloat64(m.BatchImportKeysSucceeded)))
	})

	t.Run("records failed keys by error code", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordBatchImportOutcome(0, map[string]int{
			"ALREADY_EXISTS":      3,
			"INVALID_ARGUMENT":    2,
			"FAILED_PRECONDITION": 1,
			"INTERNAL":            1,
		})

		assert.Equal(t, 0.0, testutil.ToFloat64(m.BatchImportKeysSucceeded))
		assert.Equal(t, 3.0, testutil.ToFloat64(m.BatchImportKeysFailed.WithLabelValues("ALREADY_EXISTS")))
		assert.Equal(t, 2.0, testutil.ToFloat64(m.BatchImportKeysFailed.WithLabelValues("INVALID_ARGUMENT")))
		assert.Equal(t, 1.0, testutil.ToFloat64(m.BatchImportKeysFailed.WithLabelValues("FAILED_PRECONDITION")))
		assert.Equal(t, 1.0, testutil.ToFloat64(m.BatchImportKeysFailed.WithLabelValues("INTERNAL")))
	})

	t.Run("records mixed outcome", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordBatchImportOutcome(10, map[string]int{
			"ALREADY_EXISTS": 5,
		})

		assert.Equal(t, 10.0, testutil.ToFloat64(m.BatchImportKeysSucceeded))
		assert.Equal(t, 5.0, testutil.ToFloat64(m.BatchImportKeysFailed.WithLabelValues("ALREADY_EXISTS")))
	})

	t.Run("skips zero counts", func(t *testing.T) {
		t.Parallel()
		m := newTestMetrics(t)

		m.RecordBatchImportOutcome(0, map[string]int{
			"ALREADY_EXISTS": 0,
		})

		assert.Equal(t, 0.0, testutil.ToFloat64(m.BatchImportKeysSucceeded))
		// WithLabelValues initializes to 0 so we just check it hasn't incremented
		assert.Equal(t, 0.0, testutil.ToFloat64(m.BatchImportKeysFailed.WithLabelValues("ALREADY_EXISTS")))
	})
}

// TestAPIKeysRevoked tests the APIKeysRevoked counter
func TestAPIKeysRevoked(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.APIKeysRevoked.WithLabelValues("REVOCATION_REASON_UNSPECIFIED").Inc()

	assert.Equal(t, 1.0, testutil.ToFloat64(m.APIKeysRevoked.WithLabelValues("REVOCATION_REASON_UNSPECIFIED")))
}

// TestAPIKeysRotated tests the APIKeysRotated counter
func TestAPIKeysRotated(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.APIKeysRotated.Inc()

	assert.Equal(t, 1.0, testutil.ToFloat64(m.APIKeysRotated))
}

// TestTokensMinted tests the TokensMinted counter
func TestTokensMinted(t *testing.T) {
	t.Parallel()
	m := newTestMetrics(t)

	m.TokensMinted.Inc()

	assert.Equal(t, 1.0, testutil.ToFloat64(m.TokensMinted))
}

// TestNewDBStatsCollector tests DBStatsCollector creation
func TestNewDBStatsCollector(t *testing.T) {
	t.Run("creates collector with database/sql", func(t *testing.T) {
		t.Parallel()
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		collector := NewDBStatsCollector(db, nil, "test")
		require.NotNil(t, collector)
		assert.NotNil(t, collector.db)
		assert.Nil(t, collector.pool)
		assert.Equal(t, "test", collector.namespace)
	})

	t.Run("creates collector with nil database (no panic)", func(t *testing.T) {
		t.Parallel()
		collector := NewDBStatsCollector(nil, nil, "test")
		require.NotNil(t, collector)
		assert.Nil(t, collector.db)
		assert.Nil(t, collector.pool)
	})

	t.Run("collector has correct namespace", func(t *testing.T) {
		t.Parallel()
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		collector := NewDBStatsCollector(db, nil, "talos")
		assert.Equal(t, "talos", collector.namespace)
	})
}

// TestDBStatsCollector_Describe tests the Describe method
func TestDBStatsCollector_Describe(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	collector := NewDBStatsCollector(db, nil, "test")

	descChan := make(chan *prometheus.Desc, 20)
	collector.Describe(descChan)
	close(descChan)

	descCount := 0
	for range descChan {
		descCount++
	}

	assert.Greater(t, descCount, 5, "Should have multiple metric descriptors")
}

// TestDBStatsCollector_Collect tests the Collect method
func TestDBStatsCollector_Collect(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	collector := NewDBStatsCollector(db, nil, "test")

	metricChan := make(chan prometheus.Metric, 20)
	collector.Collect(metricChan)
	close(metricChan)

	metricCount := 0
	for range metricChan {
		metricCount++
	}

	assert.Greater(t, metricCount, 5, "Should collect multiple metrics from db.Stats()")
}

// TestDBStatsCollector_MetricsContent tests actual metric values
func TestDBStatsCollector_MetricsContent(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	collector := NewDBStatsCollector(db, nil, "test")

	registry := prometheus.NewRegistry()
	err = registry.Register(collector)
	require.NoError(t, err)

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	assert.NotEmpty(t, metricFamilies, "Should gather metric families")

	foundMaxOpenConns := false
	for _, mf := range metricFamilies {
		if mf.GetName() == "test_db_max_open_connections" {
			foundMaxOpenConns = true
			if len(mf.GetMetric()) > 0 {
				value := mf.GetMetric()[0].GetGauge().GetValue()
				assert.InDelta(t, float64(10), value, 0.001, "Max open connections should be 10")
			}
		}
	}

	assert.True(t, foundMaxOpenConns, "Should find max_open_connections metric")
}

// TestDBStatsCollector_NilDB tests collector behavior with nil database
func TestDBStatsCollector_NilDB(t *testing.T) {
	t.Parallel()
	collector := NewDBStatsCollector(nil, nil, "test")

	descChan := make(chan *prometheus.Desc, 20)
	collector.Describe(descChan)
	close(descChan)

	metricChan := make(chan prometheus.Metric, 20)
	collector.Collect(metricChan)
	close(metricChan)

	metricCount := 0
	for range metricChan {
		metricCount++
	}

	assert.Equal(t, 0, metricCount, "Should collect no metrics with nil database")
}

// reviewed - @aeneasr - 2026-03-27
