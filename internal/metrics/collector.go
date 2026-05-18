// Package metrics provides Prometheus metrics collection for API key operations.
package metrics

import (
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metrics for Talos API key operations.
// Create with New and inject as a dependency — do not use package-level globals.
type Metrics struct {
	// APIKeysCreated tracks the total number of API keys created.
	APIKeysCreated prometheus.Counter
	// BatchImportRequests tracks total batch import requests.
	BatchImportRequests prometheus.Counter
	// BatchImportKeyCount tracks the number of keys per batch import request.
	BatchImportKeyCount prometheus.Histogram
	// BatchImportPartialFailures tracks batch import requests with mixed outcomes.
	BatchImportPartialFailures prometheus.Counter
	// BatchImportKeysSucceeded tracks the total number of individual keys
	// successfully imported across all batch requests.
	BatchImportKeysSucceeded prometheus.Counter
	// BatchImportKeysFailed tracks the total number of individual keys that
	// failed import, labelled by error code (e.g. "ALREADY_EXISTS", "INVALID_ARGUMENT").
	BatchImportKeysFailed *prometheus.CounterVec
	// APIKeysRevoked tracks the total number of API keys revoked, labelled by reason.
	APIKeysRevoked *prometheus.CounterVec
	// APIKeysRotated tracks the total number of API keys rotated.
	APIKeysRotated prometheus.Counter
	// VerificationAttempts tracks the total number of verification attempts.
	VerificationAttempts *prometheus.CounterVec
	// VerificationLatency tracks verification latency in seconds.
	VerificationLatency *prometheus.HistogramVec
	// TokensMinted tracks the total number of JWT tokens minted.
	TokensMinted prometheus.Counter
	// CacheHits tracks the total number of cache hits.
	CacheHits prometheus.Counter
	// CacheMisses tracks the total number of cache misses.
	CacheMisses prometheus.Counter
	// CacheErrors tracks the total number of cache read/write errors, labelled by operation.
	CacheErrors *prometheus.CounterVec
	// KeyServiceLoads tracks the total number of signing key load attempts, labelled by result.
	KeyServiceLoads *prometheus.CounterVec
	// KeyServiceLoadDuration tracks signing key load latency in seconds.
	KeyServiceLoadDuration prometheus.Histogram
	// KeyServiceKeysLoaded tracks the number of signing keys loaded in the last successful fetch.
	KeyServiceKeysLoaded prometheus.Gauge
}

// New creates and registers all Talos metrics with the given registerer.
// Panics if any metric name is already registered — pass prometheus.NewRegistry()
// in tests to get an isolated registry.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		APIKeysCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_keys_created_total",
			Help: "Total number of API keys created",
		}),
		BatchImportRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_batch_import_requests_total",
			Help: "Total number of batch import requests",
		}),
		BatchImportKeyCount: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "talos_batch_import_key_count",
			Help:    "Number of keys in each batch import request",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
		}),
		BatchImportPartialFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_batch_import_partial_failures_total",
			Help: "Total number of batch import requests with at least one success and one failure",
		}),
		BatchImportKeysSucceeded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_batch_import_keys_succeeded_total",
			Help: "Total number of individual keys successfully imported across all batch requests",
		}),
		BatchImportKeysFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "talos_batch_import_keys_failed_total",
			Help: "Total number of individual keys that failed import, by error code",
		}, []string{"error_code"}),
		APIKeysRevoked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "talos_keys_revoked_total",
			Help: "Total number of API keys revoked",
		}, []string{"reason"}),
		APIKeysRotated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_keys_rotated_total",
			Help: "Total number of API keys rotated",
		}),
		VerificationAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "talos_verifications_total",
			Help: "Total number of verification attempts",
		}, []string{"type", "result"}),
		VerificationLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "talos_verification_duration_seconds",
			Help:    "Verification latency in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"type", "cache_hit"}),
		TokensMinted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_tokens_minted_total",
			Help: "Total number of JWT tokens minted",
		}),
		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_cache_hits_total",
			Help: "Total number of cache hits",
		}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "talos_cache_misses_total",
			Help: "Total number of cache misses",
		}),
		CacheErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "talos_cache_errors_total",
			Help: "Total number of cache operation errors",
		}, []string{"operation"}),
		KeyServiceLoads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "talos_keyservice_load_total",
			Help: "Total number of signing key load attempts",
		}, []string{"result"}),
		KeyServiceLoadDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "talos_keyservice_load_duration_seconds",
			Help:    "Signing key load latency in seconds",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}),
		KeyServiceKeysLoaded: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "talos_keyservice_keys_loaded",
			Help: "Number of signing keys loaded in the last successful fetch",
		}),
	}
	reg.MustRegister(
		m.APIKeysCreated,
		m.BatchImportRequests,
		m.BatchImportKeyCount,
		m.BatchImportPartialFailures,
		m.BatchImportKeysSucceeded,
		m.BatchImportKeysFailed,
		m.APIKeysRevoked,
		m.APIKeysRotated,
		m.VerificationAttempts,
		m.VerificationLatency,
		m.TokensMinted,
		m.CacheHits,
		m.CacheMisses,
		m.CacheErrors,
		m.KeyServiceLoads,
		m.KeyServiceLoadDuration,
		m.KeyServiceKeysLoaded,
	)
	return m
}

// KeyServiceMetricsAdapter adapts Metrics to the crypto.KeyServiceMetrics interface.
type KeyServiceMetricsAdapter struct {
	m *Metrics
}

// NewKeyServiceMetricsAdapter creates an adapter for crypto.KeyServiceMetrics.
func NewKeyServiceMetricsAdapter(m *Metrics) *KeyServiceMetricsAdapter {
	return &KeyServiceMetricsAdapter{m: m}
}

// RecordKeyLoad records a key load attempt.
func (a *KeyServiceMetricsAdapter) RecordKeyLoad(result string, durationSeconds float64) {
	a.m.KeyServiceLoads.WithLabelValues(result).Inc()
	a.m.KeyServiceLoadDuration.Observe(durationSeconds)
}

// SetKeysLoaded sets the gauge for loaded signing keys.
func (a *KeyServiceMetricsAdapter) SetKeysLoaded(count float64) {
	a.m.KeyServiceKeysLoaded.Set(count)
}

// RecordBatchImportOutcome records per-key batch import results.
// succeeded is the count of keys that imported successfully.
// failedByCode maps error code labels (e.g. "ALREADY_EXISTS") to their counts.
func (m *Metrics) RecordBatchImportOutcome(succeeded int, failedByCode map[string]int) {
	if succeeded > 0 {
		m.BatchImportKeysSucceeded.Add(float64(succeeded))
	}
	for code, count := range failedByCode {
		if count > 0 {
			m.BatchImportKeysFailed.WithLabelValues(code).Add(float64(count))
		}
	}
}

// RecordVerification records a verification attempt.
func (m *Metrics) RecordVerification(verType string, success bool, cacheHit bool, latencySeconds float64) {
	result := "success"
	if !success {
		result = "failure"
	}

	m.VerificationAttempts.WithLabelValues(verType, result).Inc()

	cacheStr := "miss"
	if cacheHit {
		cacheStr = "hit"
		m.CacheHits.Inc()
	} else {
		m.CacheMisses.Inc()
	}

	m.VerificationLatency.WithLabelValues(verType, cacheStr).Observe(latencySeconds)
}

// DBStatsCollector collects database statistics for Prometheus
// Works with both database/sql and pgxpool
type DBStatsCollector struct {
	db        *sql.DB
	pool      *pgxpool.Pool
	namespace string

	// Metric descriptors
	maxOpenConnections *prometheus.Desc
	openConnections    *prometheus.Desc
	inUse              *prometheus.Desc
	idle               *prometheus.Desc
	waitCount          *prometheus.Desc
	waitDuration       *prometheus.Desc
	maxIdleClosed      *prometheus.Desc
	maxIdleTimeClosed  *prometheus.Desc
	maxLifetimeClosed  *prometheus.Desc

	// pgxpool-specific
	acquireCount         *prometheus.Desc
	acquireDuration      *prometheus.Desc
	acquiredConns        *prometheus.Desc
	canceledAcquireCount *prometheus.Desc
	constructingConns    *prometheus.Desc
	emptyAcquireCount    *prometheus.Desc
	idleConns            *prometheus.Desc
	maxConns             *prometheus.Desc
	totalConns           *prometheus.Desc
}

// NewDBStatsCollector creates a new database statistics collector
// Supports both database/sql (db != nil) and pgxpool (pool != nil)
// namespace is typically the service name, e.g., "talos"
func NewDBStatsCollector(db *sql.DB, pool *pgxpool.Pool, namespace string) *DBStatsCollector {
	var labels []string

	return &DBStatsCollector{
		db:        db,
		pool:      pool,
		namespace: namespace,

		maxOpenConnections: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "max_open_connections"),
			"Maximum number of open connections to the database.",
			labels, nil,
		),
		openConnections: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "open_connections"),
			"The number of established connections both in use and idle.",
			labels, nil,
		),
		inUse: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "in_use_connections"),
			"The number of connections currently in use.",
			labels, nil,
		),
		idle: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "idle_connections"),
			"The number of idle connections.",
			labels, nil,
		),
		waitCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "wait_count_total"),
			"The total number of connections waited for.",
			labels, nil,
		),
		waitDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "wait_duration_seconds_total"),
			"The total time blocked waiting for a new connection.",
			labels, nil,
		),
		maxIdleClosed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "max_idle_closed_total"),
			"The total number of connections closed due to SetMaxIdleConns.",
			labels, nil,
		),
		maxIdleTimeClosed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "max_idle_time_closed_total"),
			"The total number of connections closed due to SetConnMaxIdleTime.",
			labels, nil,
		),
		maxLifetimeClosed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "max_lifetime_closed_total"),
			"The total number of connections closed due to SetConnMaxLifetime.",
			labels, nil,
		),

		// pgxpool-specific metrics
		acquireCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "acquire_count_total"),
			"Cumulative count of successful acquires from the pool.",
			labels, nil,
		),
		acquireDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "acquire_duration_seconds_total"),
			"Total duration of all successful acquires from the pool.",
			labels, nil,
		),
		acquiredConns: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "acquired_connections"),
			"Number of currently acquired connections in the pool.",
			labels, nil,
		),
		canceledAcquireCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "canceled_acquire_count_total"),
			"Cumulative count of acquires from the pool that were canceled by a context.",
			labels, nil,
		),
		constructingConns: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "constructing_connections"),
			"Number of connections with construction in progress in the pool.",
			labels, nil,
		),
		emptyAcquireCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "empty_acquire_count_total"),
			"Cumulative count of successful acquires from the pool that waited for a connection to be released or constructed.",
			labels, nil,
		),
		idleConns: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "idle_connections_pool"),
			"Number of currently idle connections in the pool.",
			labels, nil,
		),
		maxConns: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "max_connections_pool"),
			"Maximum size of the pool.",
			labels, nil,
		),
		totalConns: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "db", "total_connections_pool"),
			"Total number of resources currently in the pool (acquired + idle + constructing).",
			labels, nil,
		),
	}
}

// Describe implements prometheus.Collector
func (c *DBStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.maxOpenConnections

	ch <- c.openConnections

	ch <- c.inUse

	ch <- c.idle

	ch <- c.waitCount

	ch <- c.waitDuration

	ch <- c.maxIdleClosed

	ch <- c.maxIdleTimeClosed

	ch <- c.maxLifetimeClosed

	if c.pool != nil {
		ch <- c.acquireCount

		ch <- c.acquireDuration

		ch <- c.acquiredConns

		ch <- c.canceledAcquireCount

		ch <- c.constructingConns

		ch <- c.emptyAcquireCount

		ch <- c.idleConns

		ch <- c.maxConns

		ch <- c.totalConns
	}
}

// Collect implements prometheus.Collector
func (c *DBStatsCollector) Collect(ch chan<- prometheus.Metric) {
	// Collect database/sql stats if available
	if c.db != nil {
		stats := c.db.Stats()

		ch <- prometheus.MustNewConstMetric(
			c.maxOpenConnections,
			prometheus.GaugeValue,
			float64(stats.MaxOpenConnections),
		)

		ch <- prometheus.MustNewConstMetric(
			c.openConnections,
			prometheus.GaugeValue,
			float64(stats.OpenConnections),
		)

		ch <- prometheus.MustNewConstMetric(
			c.inUse,
			prometheus.GaugeValue,
			float64(stats.InUse),
		)

		ch <- prometheus.MustNewConstMetric(
			c.idle,
			prometheus.GaugeValue,
			float64(stats.Idle),
		)

		ch <- prometheus.MustNewConstMetric(
			c.waitCount,
			prometheus.CounterValue,
			float64(stats.WaitCount),
		)

		ch <- prometheus.MustNewConstMetric(
			c.waitDuration,
			prometheus.CounterValue,
			stats.WaitDuration.Seconds(),
		)

		ch <- prometheus.MustNewConstMetric(
			c.maxIdleClosed,
			prometheus.CounterValue,
			float64(stats.MaxIdleClosed),
		)

		ch <- prometheus.MustNewConstMetric(
			c.maxIdleTimeClosed,
			prometheus.CounterValue,
			float64(stats.MaxIdleTimeClosed),
		)

		ch <- prometheus.MustNewConstMetric(
			c.maxLifetimeClosed,
			prometheus.CounterValue,
			float64(stats.MaxLifetimeClosed),
		)
	}

	// Collect pgxpool stats if available
	if c.pool != nil {
		stats := c.pool.Stat()

		ch <- prometheus.MustNewConstMetric(
			c.acquireCount,
			prometheus.CounterValue,
			float64(stats.AcquireCount()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.acquireDuration,
			prometheus.CounterValue,
			stats.AcquireDuration().Seconds(),
		)

		ch <- prometheus.MustNewConstMetric(
			c.acquiredConns,
			prometheus.GaugeValue,
			float64(stats.AcquiredConns()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.canceledAcquireCount,
			prometheus.CounterValue,
			float64(stats.CanceledAcquireCount()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.constructingConns,
			prometheus.GaugeValue,
			float64(stats.ConstructingConns()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.emptyAcquireCount,
			prometheus.CounterValue,
			float64(stats.EmptyAcquireCount()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.idleConns,
			prometheus.GaugeValue,
			float64(stats.IdleConns()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.maxConns,
			prometheus.GaugeValue,
			float64(stats.MaxConns()),
		)

		ch <- prometheus.MustNewConstMetric(
			c.totalConns,
			prometheus.GaugeValue,
			float64(stats.TotalConns()),
		)
	}
}

// reviewed - @aeneasr - 2026-03-27
