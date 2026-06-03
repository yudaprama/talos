// Package cache provides caching interfaces and implementations for API key verification.
package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/cockroachdb/errors"
)

// Metrics provides cache performance statistics.
// Satisfied by ristretto.Metrics and custom cache implementations.
type Metrics interface {
	Hits() uint64
	Misses() uint64
	Ratio() float64
	KeysAdded() uint64
	KeysEvicted() uint64
	KeysUpdated() uint64
	CostAdded() uint64
	CostEvicted() uint64
	String() string
}

// Cache is a type-safe cache interface for storing values of type T.
// Implementations handle serialization internally.
// Network ID is extracted from context for multi-tenant key isolation.
type Cache[T any] interface {
	// Get returns (value, true, nil) on hit, (zero, false, nil) on miss,
	// or (zero, false, error) on failure.
	Get(ctx context.Context, key string) (T, bool, error)

	// Set stores a value under key. If ttl is 0, the cache's default TTL is
	// used.
	//
	// key is the value's stable identifier — the API key's key_id. Keying by
	// key_id (rather than the raw secret) lets callers that hold only the
	// key_id — admin mutations and the self-revoke path never have the raw
	// secret — invalidate the entry via Delete.
	Set(ctx context.Context, key string, value T, ttl time.Duration) error

	// Delete removes the value previously stored under key. Delete on an
	// unknown key is a no-op (returns nil).
	//
	// Invalidation is immediate with a shared backing store (redis) and on the
	// local replica for an in-memory store. Cross-replica in-memory eviction is
	// not possible without pub/sub; such entries expire at their TTL.
	Delete(ctx context.Context, key string) error

	Close() error
	Metrics() Metrics

	// Wait blocks until pending async writes are visible to subsequent Get
	// calls. Test-only; a no-op for synchronous backends.
	Wait()
}

// Config contains common cache configuration.
type Config struct {
	Type string        // "memory" or "redis"
	TTL  time.Duration // Default TTL for cache entries

	// Memory cache
	MemoryMaxSize     int64
	MemoryNumCounters int64

	// Redis cache
	RedisAddrs           []string
	RedisPassword        string
	RedisDB              int
	RedisPoolSize        int
	RedisMinIdleConns    int
	RedisConnMaxIdleTime time.Duration
	RedisConnMaxLifetime time.Duration
	RedisTimeout         time.Duration
	RedisTLSEnabled      bool
}

// RedisTLSConfig builds a *tls.Config initialized from the system cert pool
// with TLS 1.2 as the minimum version. Callers must check cfg.RedisTLSEnabled
// before calling — this helper always builds a config and only errors when the
// system cert pool cannot be loaded. Shared between cache and rate-limiter
// Redis constructors so TLS behavior stays consistent.
func (cfg *Config) RedisTLSConfig() (*tls.Config, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "load system TLS cert pool")
	}
	return &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// reviewed - @aeneasr - 2026-03-25
