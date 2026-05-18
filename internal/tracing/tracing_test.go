package tracing_test

import (
	"context"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/ory-corp/talos/internal/tracing"

	"github.com/ory-corp/talos/internal/contextx"

	"github.com/ory/x/otelx"
)

func TestStart(t *testing.T) {
	t.Parallel()

	t.Run("starts span with NID from context", func(t *testing.T) {
		t.Parallel()

		testNID := uuid.Must(uuid.FromString("12345678-1234-1234-1234-123456789abc"))
		ctx := context.Background()
		ctx = context.WithValue(ctx, contextx.NIDKey{}, testNID)

		var err error
		ctx, span := tracing.Start(ctx, "test.operation")
		require.NotNil(t, span)
		t.Cleanup(func() { otelx.End(span, &err) })

		assert.NotEqual(t, context.Background(), ctx)
	})

	t.Run("handles missing NID gracefully", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		var err error
		ctx, span := tracing.Start(ctx, "test.operation")
		require.NotNil(t, span)
		t.Cleanup(func() { otelx.End(span, &err) })

		assert.NotNil(t, ctx)
	})

	t.Run("accepts additional attributes", func(t *testing.T) {
		t.Parallel()

		testNID := uuid.Must(uuid.FromString("87654321-4321-4321-4321-cba987654321"))
		ctx := context.Background()
		ctx = context.WithValue(ctx, contextx.NIDKey{}, testNID)

		var err error
		_, span := tracing.Start(ctx, "test.operation")
		require.NotNil(t, span)
		t.Cleanup(func() { otelx.End(span, &err) })
	})
}

func TestStartWithoutNID(t *testing.T) {
	t.Parallel()

	t.Run("starts span without NID attribute", func(t *testing.T) {
		t.Parallel()

		testNID := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
		ctx := context.Background()
		ctx = context.WithValue(ctx, contextx.NIDKey{}, testNID)

		var err error
		ctx, span := tracing.StartWithoutNID(ctx, "crypto.operation")
		require.NotNil(t, span)
		t.Cleanup(func() { otelx.End(span, &err) })

		assert.NotNil(t, ctx)
	})

	t.Run("accepts custom attributes", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		var err error
		ctx, span := tracing.StartWithoutNID(ctx, "crypto.hash")
		require.NotNil(t, span)
		t.Cleanup(func() { otelx.End(span, &err) })

		assert.NotNil(t, ctx)
	})
}

func TestStart_NIDAttribute(t *testing.T) {
	// Not parallel: mutates the global OTEL tracer provider.
	recorder := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	t.Run("skips nid attribute when NID is uuid.Nil", func(t *testing.T) {
		_, span := tracing.Start(context.Background(), "test.nil_nid")
		span.End()

		spans := recorder.Ended()
		require.NotEmpty(t, spans)
		last := spans[len(spans)-1]
		for _, attr := range last.Attributes() {
			assert.NotEqual(t, attribute.Key("nid"), attr.Key,
				"nid attribute should be skipped when NID is uuid.Nil (OSS single-tenant)")
		}
	})

	t.Run("includes nid attribute when NID is set", func(t *testing.T) {
		testNID := uuid.Must(uuid.FromString("12345678-1234-1234-1234-123456789abc"))
		ctx := context.WithValue(context.Background(), contextx.NIDKey{}, testNID)

		_, span := tracing.Start(ctx, "test.real_nid")
		span.End()

		spans := recorder.Ended()
		require.NotEmpty(t, spans)
		last := spans[len(spans)-1]
		found := false
		for _, attr := range last.Attributes() {
			if attr.Key == "nid" {
				found = true
				assert.Equal(t, testNID.String(), attr.Value.AsString())
			}
		}
		assert.True(t, found, "nid attribute should be present for real NIDs")
	})
}

// reviewed - @aeneasr - 2026-03-25
