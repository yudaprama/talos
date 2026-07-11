package cache

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

// MemoryCache is an in-process, type-safe cache backed by ristretto.
//
// Values are gob-encoded so any exported struct (e.g. db.IssuedApiKey) round-trips
// losslessly — no JSON tags required. Intended for single-instance OSS deployments:
// cross-replica invalidation is not possible, so entries expire at their TTL
// (see cache.go docs on Delete semantics).
//
// This replaces the upstream commercial-only "memory" backend, which gated the
// cache behind a license. In this fork the in-memory backend is freely available.
type MemoryCache[T any] struct {
	c         *ristretto.Cache[string, []byte]
	namespace string
}

// NewMemoryCache creates an in-process cache. namespace isolates entries between
// logical backends (OSS uses a single tenant, so it is typically a constant).
func NewMemoryCache[T any](cfg *Config, namespace string) (*MemoryCache[T], error) {
	maxSize := cfg.MemoryMaxSize
	if maxSize <= 0 {
		maxSize = 64 * 1024 * 1024 // 64 MB default
	}
	numCounters := cfg.MemoryNumCounters
	if numCounters <= 0 {
		numCounters = 1000
	}

	rc, err := ristretto.NewCache[string, []byte](&ristretto.Config[string, []byte]{
		NumCounters: numCounters,
		MaxCost:     maxSize,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("create ristretto cache: %w", err)
	}
	return &MemoryCache[T]{c: rc, namespace: namespace}, nil
}

func (m *MemoryCache[T]) fullKey(key string) string {
	return m.namespace + ":" + key
}

// Get returns (value, true, nil) on hit, (zero, false, nil) on miss,
// or (zero, false, error) if decoding fails.
func (m *MemoryCache[T]) Get(_ context.Context, key string) (T, bool, error) {
	var zero T
	raw, found := m.c.Get(m.fullKey(key))
	if !found {
		return zero, false, nil
	}
	var v T
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&v); err != nil {
		return zero, false, fmt.Errorf("decode cache entry: %w", err)
	}
	return v, true, nil
}

// Set stores value under key with the given TTL. A ttl of 0 falls back to the
// cache's default TTL via ristretto's own semantics (no per-entry expiry).
func (m *MemoryCache[T]) Set(_ context.Context, key string, value T, ttl time.Duration) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(value); err != nil {
		return fmt.Errorf("encode cache entry: %w", err)
	}
	cost := int64(buf.Len())
	if cost < 1 {
		cost = 1
	}
	// ristretto drops the set when over capacity; that is not an error, the
	// entry simply is not cached and the next lookup falls through to the DB.
	if ttl > 0 {
		m.c.SetWithTTL(m.fullKey(key), buf.Bytes(), cost, ttl)
	} else {
		m.c.Set(m.fullKey(key), buf.Bytes(), cost)
	}
	return nil
}

// Delete removes the entry under key. Unknown keys are a no-op.
func (m *MemoryCache[T]) Delete(_ context.Context, key string) error {
	m.c.Del(m.fullKey(key))
	return nil
}

// Close releases the underlying ristretto resources.
func (m *MemoryCache[T]) Close() error {
	m.c.Close()
	return nil
}

// Metrics returns the ristretto metrics, which satisfy the cache.Metrics interface.
func (m *MemoryCache[T]) Metrics() Metrics {
	return m.c.Metrics
}

// Wait blocks until pending async writes are visible to subsequent Get calls.
func (m *MemoryCache[T]) Wait() {
	m.c.Wait()
}

var _ Cache[any] = (*MemoryCache[any])(nil)

// reviewed - @aeneasr - 2026-03-25
