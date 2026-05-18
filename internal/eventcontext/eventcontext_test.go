package eventcontext_test

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
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/x/otelx"
	orysemconv "github.com/ory/x/otelx/semconv"

	"github.com/ory-corp/talos/internal/contextx"
	"github.com/ory-corp/talos/internal/eventcontext"
	"github.com/ory-corp/talos/internal/events"
)

func TestNewFromContext(t *testing.T) {
	t.Parallel()

	nid := uuid.Must(uuid.FromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8"))
	ctx := context.WithValue(context.Background(), contextx.NIDKey{}, nid)

	exporter, tp, ctx, span := setupOTEL(t, ctx)
	emitter := events.NewOTELEmitter()
	eventcontext.NewFromContext(ctx, events.EventAPIKeyCreated).Emit(ctx, emitter)

	otelx.End(span, nil)
	_ = tp.ForceFlush(t.Context())
	spans := exporter.GetSpans()

	require.Len(t, spans, 1)
	require.Len(t, spans[0].Events, 1)
	assert.Equal(t, "APIKeyCreated", spans[0].Events[0].Name)
	assertAttr(t, spans[0].Events[0].Attributes, orysemconv.AttributeKeyNID.String(), nid.String())
}

func TestNewFromContext_NilNetworkID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	exporter, tp, ctx, span := setupOTEL(t, ctx)
	emitter := events.NewOTELEmitter()
	eventcontext.NewFromContext(ctx, events.EventTokenDerived).Emit(ctx, emitter)

	otelx.End(span, nil)
	_ = tp.ForceFlush(t.Context())
	spans := exporter.GetSpans()

	require.Len(t, spans, 1)
	require.Len(t, spans[0].Events, 1)
	assert.Equal(t, "TokenDerived", spans[0].Events[0].Name)
	assertAttr(t, spans[0].Events[0].Attributes, orysemconv.AttributeKeyNID.String(), uuid.Nil.String())
}

func setupOTEL(t *testing.T, ctx context.Context) (*tracetest.InMemoryExporter, *sdktrace.TracerProvider, context.Context, trace.Span) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(nil) })

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(ctx, "test-op")
	return exporter, tp, ctx, span
}

func assertAttr(t *testing.T, attrs []attribute.KeyValue, key, expectedValue string) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, expectedValue, attr.Value.AsString(), "attribute %s", key)
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}

// reviewed - @aeneasr - 2026-03-27
