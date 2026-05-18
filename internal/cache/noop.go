package cache

import (
	"context"
	"time"
)

type noopMetrics struct{}

func (m *noopMetrics) Hits() uint64        { return 0 }
func (m *noopMetrics) Misses() uint64      { return 0 }
func (m *noopMetrics) Ratio() float64      { return 0 }
func (m *noopMetrics) KeysAdded() uint64   { return 0 }
func (m *noopMetrics) KeysEvicted() uint64 { return 0 }
func (m *noopMetrics) KeysUpdated() uint64 { return 0 }
func (m *noopMetrics) CostAdded() uint64   { return 0 }
func (m *noopMetrics) CostEvicted() uint64 { return 0 }
func (m *noopMetrics) String() string      { return "noop cache" }

// NoopCache is a cache that does nothing. Get always returns not found.
type NoopCache[T any] struct{}

// NewNoopCache returns a new NoopCache.
func NewNoopCache[T any]() *NoopCache[T] {
	return &NoopCache[T]{}
}

// Get always returns the zero value and false (cache miss).
func (n *NoopCache[T]) Get(_ context.Context, _ string) (T, bool, error) {
	var zero T
	return zero, false, nil
}

// Set is a no-op that always returns nil.
func (n *NoopCache[T]) Set(_ context.Context, _ string, _ T, _ time.Duration) error {
	return nil
}

// Delete is a no-op that always returns nil.
func (n *NoopCache[T]) Delete(_ context.Context, _ string) error {
	return nil
}

// Close is a no-op that always returns nil.
func (n *NoopCache[T]) Close() error {
	return nil
}

// Metrics returns zero-valued metrics.
func (n *NoopCache[T]) Metrics() Metrics {
	return &noopMetrics{}
}

// Wait is a no-op; NoopCache has no async writes to wait for.
func (n *NoopCache[T]) Wait() {}

// Verify NoopCache implements Cache[T] (using any as example type)
var _ Cache[any] = (*NoopCache[any])(nil)

// reviewed - @aeneasr - 2026-03-25
