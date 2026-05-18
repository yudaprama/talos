package tracing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/testutil"
	"github.com/ory-corp/talos/internal/tracing"
)

// TestInitTracer_Disabled tests tracing when disabled in config
func TestInitTracer_Disabled(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Create provider with test defaults (tracing disabled by default)
	provider := testutil.NewTestProvider(t)

	tp, err := tracing.InitTracer(ctx, provider)
	require.NoError(t, err)
	assert.Nil(t, tp, "Tracer provider should be nil when tracing is disabled")
}

// reviewed - @aeneasr - 2026-03-25
