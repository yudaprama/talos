package events

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/trace"
)

// SpyEmitter is a thread-safe test emitter that records all emitted events.
// It is not a mock — it captures real AuditEvent values for assertion in tests.
type SpyEmitter struct {
	mu     sync.Mutex
	Events []*AuditEvent
}

// Emit records the event in the Events slice.
func (s *SpyEmitter) Emit(_ context.Context, event *AuditEvent) {
	if event == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, event)
}

// EmitWithSpan records the event, ignoring the span.
func (s *SpyEmitter) EmitWithSpan(_ trace.Span, event *AuditEvent) {
	if event == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, event)
}

// Enabled always returns true so the EventBuilder calls Emit.
func (s *SpyEmitter) Enabled() bool {
	return true
}

// Reset clears all recorded events.
func (s *SpyEmitter) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = s.Events[:0]
}

// All returns a copy of all recorded events.
func (s *SpyEmitter) All() []*AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*AuditEvent, len(s.Events))
	copy(out, s.Events)
	return out
}
