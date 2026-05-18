// Package tracing provides OpenTelemetry tracing utilities for Talos.
package tracing

import (
	"context"
	"sync/atomic"

	"github.com/gofrs/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory-corp/talos/internal/contextx"
)

// TracerName is the name of the Talos OTEL tracer.
// Exported so startup code can obtain the same tracer instance by name.
const TracerName = "ory-talos"

// tracerValue wraps trace.Tracer for use with atomic.Pointer.
type tracerValue struct {
	tracer trace.Tracer
}

// activeTracer is set once at startup by SetTracer.
// Uses atomic.Pointer to avoid a data race between SetTracer (startup) and
// getTracer (request handling). Nil stored value means fall back to the global
// OTEL provider.
var activeTracer atomic.Pointer[tracerValue]

// SetTracer overrides the tracer used by Start and StartWithoutNID.
// Call once at process start, before any requests are served.
// Commercial builds use this to inject an analytics-wrapped tracer.
func SetTracer(t trace.Tracer) {
	activeTracer.Store(&tracerValue{tracer: t})
}

func getTracer() trace.Tracer {
	if v := activeTracer.Load(); v != nil {
		return v.tracer
	}
	return otel.Tracer(TracerName)
}

// Start creates a new span with the given operation name and optional attributes.
// NID from context is added as the first attribute when set. It is omitted when
// NID is uuid.Nil (OSS single-tenant mode) to keep traces free of useless noise.
func Start(ctx context.Context, operationName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	nid := contextx.NetworkIDFromContext(ctx)
	var allAttrs []attribute.KeyValue
	if nid == uuid.Nil {
		allAttrs = append(make([]attribute.KeyValue, 0, len(attrs)), attrs...)
	} else {
		allAttrs = make([]attribute.KeyValue, 0, len(attrs)+1)
		allAttrs = append(allAttrs, attribute.String("nid", nid.String()))
		allAttrs = append(allAttrs, attrs...)
	}

	ctx, span := getTracer().Start(ctx, operationName, trace.WithAttributes(allAttrs...))
	return ctx, span
}

// StartWithoutNID creates a new span without adding the NID attribute.
// Use for operations where NID is not applicable (e.g., crypto utilities).
func StartWithoutNID(ctx context.Context, operationName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, span := getTracer().Start(ctx, operationName, trace.WithAttributes(attrs...))
	return ctx, span
}

// reviewed - @aeneasr - 2026-03-25
