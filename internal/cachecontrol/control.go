// Package cachecontrol provides context-based cache control directives.
package cachecontrol

import (
	"context"
	"time"
)

type contextKey int

const (
	cacheControlKey contextKey = iota
)

// CacheStatus represents the outcome of a cache lookup.
type CacheStatus string

// CacheStatus values reported for cache lookups.
const (
	// CacheHit indicates the lookup returned a cached entry.
	CacheHit CacheStatus = "HIT"
	// CacheMiss indicates no cached entry was found.
	CacheMiss CacheStatus = "MISS"
	// CacheSkip indicates the cache was bypassed via the Cache-Control header.
	CacheSkip CacheStatus = "SKIP"
)

// CacheControl represents cache control directives extracted from HTTP headers.
type CacheControl struct {
	NoCache bool // Skip cache reads (Cache-Control: no-cache or Pragma: no-cache)
	NoStore bool // Skip cache writes and reads (Cache-Control: no-store)
}

// WithCacheControl returns a new context with cache control directives set.
func WithCacheControl(ctx context.Context, cc CacheControl) context.Context {
	return context.WithValue(ctx, cacheControlKey, cc)
}

// FromContext extracts cache control directives from context.
// Returns zero-value CacheControl if not present.
func FromContext(ctx context.Context) CacheControl {
	if cc, ok := ctx.Value(cacheControlKey).(CacheControl); ok {
		return cc
	}
	return CacheControl{}
}

// ShouldBypassCache returns true if cache reads should be bypassed.
// This occurs when either NoCache or NoStore is set.
func ShouldBypassCache(ctx context.Context) bool {
	cc := FromContext(ctx)
	return cc.NoCache || cc.NoStore
}

const (
	// minCacheDuration is the minimum positive cache TTL. Any expiry less than
	// this distance in the future produces a TTL of zero (don't cache).
	minCacheDuration = time.Second
)

// ComputeCacheTTL returns the effective cache TTL as min(configTTL, timeUntilExpiry),
// together with whether the entry should be cached at all.
// It guards against caching already-expired or imminently-expiring entries:
//   - expiresAt == nil → configTTL, true (no expiry set, cache for the full configured duration)
//   - timeUntilExpiry < minCacheDuration → 0, false (already expired or expiring very soon, do not cache)
//   - otherwise → min(configTTL, timeUntilExpiry), true
func ComputeCacheTTL(configTTL time.Duration, expiresAt *time.Time) (time.Duration, bool) {
	if expiresAt == nil {
		return configTTL, true
	}

	timeUntilExpiry := time.Until(*expiresAt)
	if timeUntilExpiry < minCacheDuration {
		return 0, false
	}

	if timeUntilExpiry < configTTL {
		return timeUntilExpiry, true
	}
	return configTTL, true
}

// reviewed - @aeneasr - 2026-03-25
