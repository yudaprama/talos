//go:build !commercial

package tracing_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/testutil"
	"github.com/ory/talos/internal/tracing"
)

// TestInitTracerOSSEnabled verifies that InitTracer builds a real OTLP/gRPC
// TracerProvider when tracing is enabled in OSS builds. The gRPC exporter dials
// lazily, so no live collector is required for construction to succeed.
func TestInitTracerOSSEnabled(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	provider := testutil.NewTestProvider(t)
	require.NoError(t, provider.Set(ctx, config.KeyTracingEnabled, true))
	require.NoError(t, provider.Set(ctx, config.KeyTracingExporter, "otlp"))
	require.NoError(t, provider.Set(ctx, config.KeyTracingEndpoint, "localhost:4317"))

	tp, err := tracing.InitTracer(ctx, provider)
	require.NoError(t, err)
	require.NotNil(t, tp, "OSS InitTracer must return a provider when tracing is enabled")

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tp.Shutdown(shutdownCtx)
	})
}
