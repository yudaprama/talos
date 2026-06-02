// Package events provides audit event emission for OpenTelemetry pipelines.
//
// This package implements structured audit events for all significant lifecycle
// operations in Talos. Events are emitted to downstream OTEL pipelines and
// never persisted locally.
//
// Example usage:
//
//	emitter := events.NewOTELEmitter()
//	events.New(events.EventIssuedAPIKeyCreated).
//	    WithNetworkID(networkID). // uuid.UUID
//	    WithKeyID(keyID).
//	    WithPrefix("talos").
//	    WithActor(actorID).
//	    Emit(ctx, emitter)
package events

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
	"go.opentelemetry.io/otel/trace"

	orysemconv "github.com/ory/x/otelx/semconv"

	"github.com/ory/talos/pkg/semconv"
)

// EventType is an alias for orysemconv.Event to maintain backward compatibility
// within the internal package.
type EventType = orysemconv.Event

// Audit event types emitted by Talos. These alias the shared semantic
// convention constants so call sites can reference them via this package.
const (
	EventIssuedAPIKeyCreated      = semconv.EventIssuedAPIKeyCreated
	EventImportedAPIKeyCreated    = semconv.EventImportedAPIKeyCreated
	EventIssuedAPIKeyUpdated      = semconv.EventIssuedAPIKeyUpdated
	EventImportedAPIKeyUpdated    = semconv.EventImportedAPIKeyUpdated
	EventIssuedAPIKeyRevoked      = semconv.EventIssuedAPIKeyRevoked
	EventImportedAPIKeyRevoked    = semconv.EventImportedAPIKeyRevoked
	EventIssuedAPIKeyRotated      = semconv.EventIssuedAPIKeyRotated
	EventAPIKeyVerified           = semconv.EventAPIKeyVerified
	EventAPIKeyVerificationFailed = semconv.EventAPIKeyVerificationFailed
	EventAPIKeyImportFailed       = semconv.EventAPIKeyImportFailed
	EventAPIKeyDerivedToken       = semconv.EventAPIKeyDerivedToken
	EventImportedAPIKeyDeleted    = semconv.EventImportedAPIKeyDeleted
)

// AuditEvent is the base structure for all audit events.
// Events are emitted to OTEL as span events with structured attributes.
type AuditEvent struct {
	// Core fields (always present)
	EventType EventType `json:"event_type"`
	NetworkID uuid.UUID `json:"network_id"`

	// Key identification (present for key-related events)
	KeyID  string `json:"key_id,omitempty"`
	Prefix string `json:"prefix,omitempty"`

	// Key origin (present for created/rotated events)
	KeyType string `json:"key_type,omitempty"` // "issued" or "imported"

	// Operation context
	Operation string `json:"operation,omitempty"` // Human-readable operation name
	Reason    string `json:"reason,omitempty"`    // Failure reason or additional context

	// Actor information (who performed the operation)
	ActorID string `json:"actor_id,omitempty"`

	// Key properties (present for create/rotate/update events)
	Expiry     *time.Time `json:"expiry,omitempty"`
	Visibility string     `json:"visibility,omitempty"` // "public" or "secret"

	// Additional context (varies by event type)
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Emitter emits audit events to OpenTelemetry
type Emitter interface {
	// Emit emits an audit event to the current span in the context
	Emit(ctx context.Context, event *AuditEvent)

	// EmitWithSpan emits an audit event to a specific span
	EmitWithSpan(span trace.Span, event *AuditEvent)

	// Enabled returns true if the emitter is enabled
	Enabled() bool
}

// OTELEmitter implements Emitter using OpenTelemetry span events
type OTELEmitter struct {
	enabled bool
}

// NewOTELEmitter creates a new OTEL emitter
func NewOTELEmitter() *OTELEmitter {
	return &OTELEmitter{enabled: true}
}

// Emit emits an audit event to the current span in the context
func (e *OTELEmitter) Emit(ctx context.Context, event *AuditEvent) {
	if !e.enabled || event == nil {
		return
	}

	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	e.EmitWithSpan(span, event)
}

// EmitWithSpan emits an audit event to a specific span
func (e *OTELEmitter) EmitWithSpan(span trace.Span, event *AuditEvent) {
	if !e.enabled || event == nil || span == nil {
		return
	}

	if !span.IsRecording() {
		return
	}

	// Convert event to OTEL attributes
	attrs := eventToAttributes(event)

	// Emit as span event using event type as name
	span.AddEvent(string(event.EventType), trace.WithAttributes(attrs...))
}

// Enabled returns true if the emitter is enabled
func (e *OTELEmitter) Enabled() bool {
	return e.enabled
}

// NoopEmitter is a no-op implementation for testing or disabled audit
type NoopEmitter struct{}

// NewNoopEmitter creates a new noop emitter
func NewNoopEmitter() *NoopEmitter {
	return &NoopEmitter{}
}

// Emit does nothing
func (e *NoopEmitter) Emit(_ context.Context, _ *AuditEvent) {
	// No-op
}

// EmitWithSpan does nothing
func (e *NoopEmitter) EmitWithSpan(_ trace.Span, _ *AuditEvent) {
	// No-op
}

// Enabled returns false
func (e *NoopEmitter) Enabled() bool {
	return false
}

// EventBuilder provides a fluent API for constructing audit events
type EventBuilder struct {
	event *AuditEvent
}

// New creates a new event builder with the specified event type
func New(eventType EventType) *EventBuilder {
	return &EventBuilder{
		event: &AuditEvent{
			EventType: eventType,
			Metadata:  make(map[string]string),
		},
	}
}

// WithNetworkID sets the network ID
func (b *EventBuilder) WithNetworkID(networkID uuid.UUID) *EventBuilder {
	b.event.NetworkID = networkID

	return b
}

// WithKeyID sets the key ID
func (b *EventBuilder) WithKeyID(keyID string) *EventBuilder {
	b.event.KeyID = keyID

	return b
}

// WithPrefix sets the key prefix
func (b *EventBuilder) WithPrefix(prefix string) *EventBuilder {
	b.event.Prefix = prefix

	return b
}

// WithKeyType sets the key origin type ("issued" or "imported").
// Used with EventAPIKeyImportFailed to record the origin of a failed import.
func (b *EventBuilder) WithKeyType(keyType string) *EventBuilder {
	b.event.KeyType = keyType

	return b
}

// WithOperation sets the operation name
func (b *EventBuilder) WithOperation(operation string) *EventBuilder {
	b.event.Operation = operation

	return b
}

// WithReason sets the reason (typically for failures)
func (b *EventBuilder) WithReason(reason string) *EventBuilder {
	b.event.Reason = reason

	return b
}

// WithActor sets the actor ID
func (b *EventBuilder) WithActor(actorID string) *EventBuilder {
	b.event.ActorID = actorID

	return b
}

// WithExpiry sets the key expiration timestamp.
func (b *EventBuilder) WithExpiry(expiry *time.Time) *EventBuilder {
	b.event.Expiry = expiry
	return b
}

// WithVisibility sets the key visibility ("public" or "secret").
func (b *EventBuilder) WithVisibility(visibility string) *EventBuilder {
	b.event.Visibility = visibility
	return b
}

// WithMetadata adds a metadata key-value pair
func (b *EventBuilder) WithMetadata(key, value string) *EventBuilder {
	if b.event.Metadata == nil {
		b.event.Metadata = make(map[string]string)
	}
	b.event.Metadata[key] = value

	return b
}

// Emit emits the event using the provided emitter
func (b *EventBuilder) Emit(ctx context.Context, emitter Emitter) {
	if emitter.Enabled() {
		emitter.Emit(ctx, b.event)
	}
}

// reviewed - @aeneasr - 2026-03-27
