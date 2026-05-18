// Package registrytypes defines types shared between internal/ and commercial/
// packages for dependency injection. Moving these types to internal/ ensures
// that internal/ never imports commercial/, preserving the edition boundary.
package registrytypes

import (
	"context"
	"net/http"

	"github.com/ory-corp/talos/internal/cache"
	"github.com/ory-corp/talos/internal/logger"
	"github.com/ory-corp/talos/internal/persistence"
	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	"github.com/ory-corp/talos/internal/ratelimit"
	"github.com/ory/x/contextx"
)

// RegisterDatabaseMetricsFunc is a callback to register database-specific metrics
type RegisterDatabaseMetricsFunc func(driver persistence.Persister, log *logger.Logger)

// HTTPMiddlewareFunc returns HTTP middleware for network enrichment
// Contextualizer is created internally by Options() and closed over by the returned middleware
type HTTPMiddlewareFunc func() func(http.Handler) http.Handler

// CacheFactory creates a typed cache for API keys from configuration.
// The namespace is used to prefix cache keys for logical separation.
type CacheFactory func(ctx context.Context, _ *cache.Config, namespace string) (cache.Cache[db.IssuedApiKey], error)

// RateLimiterFactory creates a rate limiter based on configuration.
// The context controls the lifetime of background goroutines for memory-based limiters.
type RateLimiterFactory func(ctx context.Context, backend string, config *cache.Config) (ratelimit.Limiter, error)

// FeatureOptions contains all proprietary feature factories
type FeatureOptions struct {
	// Contextualizer resolves tenant-specific network IDs and config providers.
	Contextualizer contextx.Contextualizer

	// CacheFactories maps cache type names to factory functions
	// Factory creates Cache[db.IssuedApiKey] directly - each backend handles its own serialization
	CacheFactories map[string]CacheFactory

	// DriverFactories maps database driver names to factory functions
	DriverFactories map[string]persistence.Factory

	// RegisterDatabaseMetrics registers database-specific metrics collectors
	// Enterprise: Registers Postgres/MySQL pool metrics
	// OSS: No-op (SQLite doesn't have pool metrics)
	RegisterDatabaseMetrics RegisterDatabaseMetricsFunc

	// HTTPMiddleware returns HTTP middleware for network context enrichment
	// Contextualizer is created internally by Options() and closed over
	// Enterprise: Returns NetworkEnricherMiddleware with contextualizer
	// OSS: Returns no-op middleware
	HTTPMiddleware HTTPMiddlewareFunc

	// RateLimiterFactory creates a rate limiter for API key enforcement
	// Commercial: Returns memory or redis limiter based on config
	// OSS: Not set (nil) - Public uses NoopLimiter
	RateLimiterFactory RateLimiterFactory
}
