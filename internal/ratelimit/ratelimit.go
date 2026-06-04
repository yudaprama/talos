// Package ratelimit defines the rate limiter interface and types shared across
// OSS and commercial editions. Implementations live in commercial/ratelimit/.
package ratelimit

import (
	"context"
	"time"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// Result represents the outcome of a rate limit check.
type Result struct {
	// Allowed is true if the request is within quota.
	Allowed bool
	// Remaining is the approximate number of requests available before the limit is reached.
	Remaining int64
	// ResetAt is when the rate limiter returns to full capacity (all quota recovered).
	ResetAt time.Time
}

// Limiter checks and decrements rate limit counters.
type Limiter interface {
	// Allow checks if a request is allowed under the key's rate limit policy.
	// If policy is nil, always returns allowed (no enforcement).
	Allow(ctx context.Context, keyID string, policy *talosv2alpha1.RateLimitPolicy) (*Result, error)
	// Enabled reports whether this limiter enforces quotas (false for the OSS no-op).
	Enabled() bool
	// Close releases any resources held by the limiter.
	Close() error
}

// NoopLimiter is a rate limiter that always allows requests.
// Used in OSS builds where enforcement is not available.
type NoopLimiter struct{}

// Allow always returns allowed with no counting.
func (n *NoopLimiter) Allow(_ context.Context, _ string, _ *talosv2alpha1.RateLimitPolicy) (*Result, error) {
	return &Result{Allowed: true}, nil
}

// Enabled reports false: the no-op limiter performs no enforcement.
func (n *NoopLimiter) Enabled() bool { return false }

// Close is a no-op.
func (n *NoopLimiter) Close() error { return nil }
