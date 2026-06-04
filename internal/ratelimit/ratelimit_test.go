package ratelimit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNoopLimiterEnabled documents that the OSS no-op limiter never reports as
// enforcing. Callers rely on this to avoid emitting cache-control directives in
// OSS builds, which have no enforcement and no edge proxy.
func TestNoopLimiterEnabled(t *testing.T) {
	t.Parallel()

	assert.False(t, (&NoopLimiter{}).Enabled())
}
