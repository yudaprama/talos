// Package cachecontrol provides context-based cache control directives.
package cachecontrol

import (
	"context"
	"strings"
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

// Directives holds the Cache-Control directives the proxy and verifier act on.
// Only these directives are tracked; unknown directives are ignored.
type Directives struct {
	NoStore bool // no-store: must not be stored in any cache.
	NoCache bool // no-cache: a stored response must be revalidated before reuse.
	Private bool // private: shared caches must not store the response.
}

// ParseHeader parses an HTTP Cache-Control header value into the directives we
// act on. Directive names are case-insensitive (RFC 7234 §5.2). Argument forms
// (no-cache="field", max-age=0) are recognized by directive name only; we need
// presence, not the argument value, so quoted arguments are not fully parsed.
//
// Splitting on "," is safe for presence detection even when an argument carries
// a quoted comma (no-cache="a, b"): the part before "=" is still the directive
// name. This deliberately avoids matching substrings like x-no-store-hint that
// a strings.Contains check would wrongly treat as directives.
func ParseHeader(value string) Directives {
	var d Directives
	for part := range strings.SplitSeq(value, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "no-store":
			d.NoStore = true
		case "no-cache":
			d.NoCache = true
		case "private":
			d.Private = true
		}
	}
	return d
}

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
//   - configTTL <= 0 → 0, false (caching disabled by configuration, do not cache)
//   - expiresAt == nil → configTTL, true (no expiry set, cache for the full configured duration)
//   - timeUntilExpiry < minCacheDuration → 0, false (already expired or expiring very soon, do not cache)
//   - otherwise → min(configTTL, timeUntilExpiry), true
func ComputeCacheTTL(configTTL time.Duration, expiresAt *time.Time) (time.Duration, bool) {
	if configTTL <= 0 {
		return 0, false
	}
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
