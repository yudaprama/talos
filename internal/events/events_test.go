package events

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
)

// TestEventBuilder_Fields consolidates single-field builder tests into one
// table-driven test (replaces WithActor, WithReason, WithOperation, WithKeyType).
func TestEventBuilder_Fields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func() *EventBuilder
		check func(t *testing.T, _ *AuditEvent)
	}{
		{
			name: "basic fields",
			build: func() *EventBuilder {
				return New(EventAPIKeyCreated).
					WithNetworkID(uuid.Nil).
					WithKeyID("01H...").
					WithPrefix("talos").
					WithKeyType("issued")
			},
			check: func(t *testing.T, e *AuditEvent) {
				t.Helper()
				assert.Equal(t, EventAPIKeyCreated, e.EventType)
				assert.Equal(t, uuid.Nil, e.NetworkID)
				assert.Equal(t, "01H...", e.KeyID)
				assert.Equal(t, "talos", e.Prefix)
				assert.Equal(t, "issued", e.KeyType)
			},
		},
		{
			name: "WithActor",
			build: func() *EventBuilder {
				return New(EventAPIKeyCreated).WithNetworkID(uuid.Nil).WithActor("user-123")
			},
			check: func(t *testing.T, e *AuditEvent) {
				t.Helper()
				assert.Equal(t, "user-123", e.ActorID)
			},
		},
		{
			name: "WithReason",
			build: func() *EventBuilder {
				return New(EventAPIKeyVerificationFailed).WithNetworkID(uuid.Nil).WithReason("revoked")
			},
			check: func(t *testing.T, e *AuditEvent) {
				t.Helper()
				assert.Equal(t, "revoked", e.Reason)
			},
		},
		{
			name: "WithOperation",
			build: func() *EventBuilder {
				return New(EventAPIKeyUpdated).WithNetworkID(uuid.Nil).WithOperation("update_metadata")
			},
			check: func(t *testing.T, e *AuditEvent) {
				t.Helper()
				assert.Equal(t, "update_metadata", e.Operation)
			},
		},
		{
			name: "WithKeyType/issued",
			build: func() *EventBuilder {
				return New(EventAPIKeyCreated).WithNetworkID(uuid.Nil).WithKeyType("issued")
			},
			check: func(t *testing.T, e *AuditEvent) {
				t.Helper()
				assert.Equal(t, "issued", e.KeyType)
			},
		},
		{
			name: "WithKeyType/imported",
			build: func() *EventBuilder {
				return New(EventAPIKeyCreated).WithNetworkID(uuid.Nil).WithKeyType("imported")
			},
			check: func(t *testing.T, e *AuditEvent) {
				t.Helper()
				assert.Equal(t, "imported", e.KeyType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.check(t, tt.build().event)
		})
	}
}

func TestEventBuilder_WithMetadata(t *testing.T) {
	t.Parallel()

	event := New(EventTokenDerived).
		WithNetworkID(uuid.Nil).
		WithMetadata("algorithm", "jwt").
		WithMetadata("ttl", "3600").
		event

	assert.Len(t, event.Metadata, 2)
	assert.Equal(t, "jwt", event.Metadata["algorithm"])
	assert.Equal(t, "3600", event.Metadata["ttl"])
}

func TestOTELEmitter_Emit(t *testing.T) {
	t.Parallel()

	env, ctx, span := setupOTELTest(t)

	emitter := NewOTELEmitter()
	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,
		KeyID:     "01HQZX9VYQKJB8XQZQXQZQXQXQ",
		Prefix:    "talos",
		ActorID:   "user-123",
		KeyType:   "issued",
		Metadata:  map[string]string{},
	}

	emitter.Emit(ctx, event)

	spans := env.flushAndGetEvents(t, span)
	require.Len(t, spans, 1)
	require.Len(t, spans[0].Events, 1)

	spanEvent := spans[0].Events[0]
	assert.Equal(t, "APIKeyCreated", spanEvent.Name)

	attrs := spanEvent.Attributes
	assertAttribute(t, attrs, AttrNetworkID.String(), uuid.Nil.String())
	assertAttribute(t, attrs, AttrKeyID.String(), "01HQZX9VYQKJB8XQZQXQZQXQXQ")
	assertAttribute(t, attrs, AttrAPIKeyPrefix.String(), "talos")
	assertAttribute(t, attrs, AttrActorID.String(), "user-123")
	assertAttribute(t, attrs, AttrKeyType.String(), "issued")
}

func TestOTELEmitter_EmitWithSpan(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)

	tracer := tp.Tracer("test")
	_, span := tracer.Start(t.Context(), "test-operation")

	emitter := NewOTELEmitter()
	event := &AuditEvent{
		EventType: EventAPIKeyRevoked,
		NetworkID: uuid.Nil,
		KeyID:     "01H...",
		Reason:    "user_requested",
		Metadata:  map[string]string{},
	}

	emitter.EmitWithSpan(span, event)

	otelx.End(span, nil)
	_ = tp.ForceFlush(t.Context())

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	require.Len(t, spans[0].Events, 1)

	spanEvent := spans[0].Events[0]
	assert.Equal(t, "APIKeyRevoked", spanEvent.Name)

	attrs := spanEvent.Attributes
	assertAttribute(t, attrs, AttrNetworkID.String(), uuid.Nil.String())
	assertAttribute(t, attrs, AttrKeyID.String(), "01H...")
	assertAttribute(t, attrs, AttrReason.String(), "user_requested")
}

// TestOTELEmitter_EdgeCases consolidates nil-event and non-recording-span
// safety tests (replaces separate EmitNilEvent and EmitNonRecordingSpan tests).
func TestOTELEmitter_EdgeCases(t *testing.T) {
	t.Parallel()

	emitter := NewOTELEmitter()

	t.Run("nil event does not panic", func(t *testing.T) {
		t.Parallel()
		assert.NotPanics(t, func() {
			emitter.Emit(t.Context(), nil)
		})
	})

	t.Run("non-recording span does not panic", func(t *testing.T) {
		t.Parallel()
		event := &AuditEvent{
			EventType: EventAPIKeyCreated,
			NetworkID: uuid.Nil,
			Metadata:  map[string]string{},
		}
		assert.NotPanics(t, func() {
			emitter.Emit(t.Context(), event)
		})
	})

	t.Run("Enabled returns true", func(t *testing.T) {
		t.Parallel()
		assert.True(t, emitter.Enabled())
	})
}

func TestOTELEmitter_EmitWithMetadata(t *testing.T) {
	t.Parallel()

	env, ctx, span := setupOTELTest(t)

	emitter := NewOTELEmitter()
	event := &AuditEvent{
		EventType: EventTokenDerived,
		NetworkID: uuid.Nil,
		KeyID:     "01H...",
		Metadata:  map[string]string{"algorithm": "jwt", "ttl": "3600"},
	}

	emitter.Emit(ctx, event)

	spans := env.flushAndGetEvents(t, span)
	require.Len(t, spans, 1)
	require.Len(t, spans[0].Events, 1)

	spanEvent := spans[0].Events[0]
	assert.Equal(t, "TokenDerived", spanEvent.Name)

	attrs := spanEvent.Attributes
	assertAttribute(t, attrs, "metadata.algorithm", "jwt")
	assertAttribute(t, attrs, "metadata.ttl", "3600")
}

// TestNoopEmitter consolidates Noop emitter tests (replaces separate Emit,
// EmitWithSpan, and Enabled tests).
func TestNoopEmitter(t *testing.T) {
	t.Parallel()

	emitter := NewNoopEmitter()
	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,
		Metadata:  map[string]string{},
	}

	assert.NotPanics(t, func() {
		emitter.Emit(t.Context(), event)
	})
	assert.NotPanics(t, func() {
		emitter.EmitWithSpan(nil, event)
	})
	assert.False(t, emitter.Enabled())
}

// TestEventBuilder_EmitVariants consolidates builder Emit tests (replaces
// separate Emit and EmitWithDisabledEmitter tests).
func TestEventBuilder_EmitVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		emitter Emitter
		setup   func(t *testing.T) (context.Context, func(_ *testing.T))
	}{
		{
			name:    "OTEL emitter records span event",
			emitter: NewOTELEmitter(),
			setup: func(t *testing.T) (context.Context, func(_ *testing.T)) {
				t.Helper()
				env, ctx, span := setupOTELTest(t)
				return ctx, func(t *testing.T) {
					t.Helper()
					spans := env.flushAndGetEvents(t, span)
					require.Len(t, spans, 1)
					require.Len(t, spans[0].Events, 1)
					assert.Equal(t, "APIKeyCreated", spans[0].Events[0].Name)
				}
			},
		},
		{
			name:    "disabled emitter does not panic",
			emitter: NewNoopEmitter(),
			setup: func(t *testing.T) (context.Context, func(_ *testing.T)) {
				t.Helper()
				return t.Context(), func(*testing.T) {}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, verify := tt.setup(t)
			assert.NotPanics(t, func() {
				New(EventAPIKeyCreated).
					WithNetworkID(uuid.Nil).
					WithKeyID("01H...").
					Emit(ctx, tt.emitter)
			})
			verify(t)
		})
	}
}

func TestEventBuilder_EmitWithNilEmitter(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		New(EventAPIKeyCreated).
			WithNetworkID(uuid.Nil).
			Emit(t.Context(), nil)
	})
}

func TestEventBuilder_FailureScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		eventType EventType
		reason    string
	}{
		{"verification failed - revoked", EventAPIKeyVerificationFailed, "revoked"},
		{"verification failed - expired", EventAPIKeyVerificationFailed, "expired"},
		{"import failed - invalid_checksum", EventAPIKeyImportFailed, "invalid_checksum"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event := New(tt.eventType).
				WithNetworkID(uuid.Nil).
				WithReason(tt.reason).
				event

			assert.Equal(t, tt.eventType, event.EventType)
			assert.Equal(t, tt.reason, event.Reason)
		})
	}
}

// otelTestEnv holds the OTEL test infrastructure for event emission tests.
type otelTestEnv struct {
	exporter *tracetest.InMemoryExporter
	tp       *sdktrace.TracerProvider
}

func setupOTELTest(t *testing.T) (*otelTestEnv, context.Context, trace.Span) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(nil) })

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(t.Context(), "test-operation")
	t.Cleanup(func() { otelx.End(span, nil) })

	return &otelTestEnv{exporter: exporter, tp: tp}, ctx, span
}

func (e *otelTestEnv) flushAndGetEvents(t *testing.T, span trace.Span) []tracetest.SpanStub {
	t.Helper()
	otelx.End(span, nil)
	_ = e.tp.ForceFlush(t.Context())
	return e.exporter.GetSpans()
}

func assertAttribute(t *testing.T, attrs []attribute.KeyValue, key, expectedValue string) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, expectedValue, attr.Value.AsString(), "attribute %s", key)
			return
		}
	}
	t.Errorf("attribute %s not found", key)
}

// Benchmark tests
func BenchmarkEventBuilder(b *testing.B) {
	emitter := NewNoopEmitter()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		New(EventAPIKeyCreated).
			WithNetworkID(uuid.Nil).
			WithKeyID("01HQZX9VYQKJB8XQZQXQZQXQXQ").
			WithPrefix("talos").
			WithActor("user-123").
			WithKeyType("issued").
			Emit(b.Context(), emitter)
	}
}

func BenchmarkOTELEmitter_Emit(b *testing.B) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(nil)

	tracer := tp.Tracer("benchmark")
	ctx, span := tracer.Start(b.Context(), "benchmark-operation")
	b.Cleanup(func() { otelx.End(span, nil) })

	emitter := NewOTELEmitter()
	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,
		KeyID:     "01H...",
		Metadata:  map[string]string{},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		emitter.Emit(ctx, event)
	}
}

func BenchmarkNoopEmitter_Emit(b *testing.B) {
	emitter := NewNoopEmitter()
	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,
		KeyID:     "01H...",
		Metadata:  map[string]string{},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		emitter.Emit(b.Context(), event)
	}
}

// TestEventLifecycle_AllEventTypes verifies every defined EventType can be
// built, emitted, and recorded as an OTEL span event with the correct name.
func TestEventLifecycle_AllEventTypes(t *testing.T) {
	t.Parallel()

	eventTypes := []struct {
		eventType    EventType
		expectedName string
	}{
		{EventAPIKeyCreated, "APIKeyCreated"},
		{EventAPIKeyUpdated, "APIKeyUpdated"},
		{EventAPIKeyRevoked, "APIKeyRevoked"},
		{EventAPIKeyRotated, "APIKeyRotated"},
		{EventAPIKeyVerified, "APIKeyVerified"},
		{EventAPIKeyVerificationFailed, "APIKeyVerificationFailed"},
		{EventAPIKeyImportFailed, "APIKeyImportFailed"},
		{EventAPIKeyDeleted, "APIKeyDeleted"},
		{EventImportedAPIKeyDeleted, "ImportedAPIKeyDeleted"},
		{EventTokenDerived, "TokenDerived"},
	}

	for _, tt := range eventTypes {
		t.Run(tt.expectedName, func(t *testing.T) {
			t.Parallel()

			env, ctx, span := setupOTELTest(t)
			emitter := NewOTELEmitter()

			New(tt.eventType).
				WithNetworkID(uuid.Nil).
				WithKeyID("lifecycle-key").
				WithKeyType("issued").
				Emit(ctx, emitter)

			spans := env.flushAndGetEvents(t, span)
			require.Len(t, spans, 1)
			require.Len(t, spans[0].Events, 1, "expected exactly one OTEL event for %s", tt.expectedName)
			assert.Equal(t, tt.expectedName, spans[0].Events[0].Name)
			assertAttribute(t, spans[0].Events[0].Attributes, AttrKeyID.String(), "lifecycle-key")
		})
	}
}

// reviewed - @aeneasr - 2026-03-27
