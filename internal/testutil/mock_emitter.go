package testutil

import (
	"context"
	"maps"
	"slices"
	"sync"

	"go.opentelemetry.io/otel/trace"

	"github.com/ory-corp/talos/internal/events"
)

// MockEmitter is a mock implementation of events.Emitter for testing.
// It captures all emitted events in a thread-safe slice for inspection.
type MockEmitter struct {
	mu     sync.RWMutex
	events []*events.AuditEvent
}

// NewMockEmitter creates a new MockEmitter
func NewMockEmitter() *MockEmitter {
	return &MockEmitter{
		events: make([]*events.AuditEvent, 0),
	}
}

// emit is the internal implementation that captures an event
func (m *MockEmitter) emit(event *events.AuditEvent) {
	if event == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Deep copy the event to avoid mutations after emission
	eventCopy := *event
	if event.Metadata != nil {
		eventCopy.Metadata = maps.Clone(event.Metadata)
	}

	m.events = append(m.events, &eventCopy)
}

// Emit captures an audit event from the current span context
func (m *MockEmitter) Emit(_ context.Context, event *events.AuditEvent) {
	m.emit(event)
}

// EmitWithSpan captures an audit event to a specific span
func (m *MockEmitter) EmitWithSpan(_ trace.Span, event *events.AuditEvent) {
	m.emit(event)
}

// Enabled returns true (mock emitter is always enabled)
func (m *MockEmitter) Enabled() bool {
	return true
}

// Events returns a copy of all captured events
func (m *MockEmitter) Events() []*events.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*events.AuditEvent, len(m.events))
	copy(result, m.events)

	return result
}

// EventsOfType returns all captured events of a specific type
func (m *MockEmitter) EventsOfType(eventType events.EventType) []*events.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*events.AuditEvent, 0)
	for _, event := range m.events {
		if event.EventType == eventType {
			result = append(result, event)
		}
	}

	return result
}

// EventCount returns the total number of captured events
func (m *MockEmitter) EventCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.events)
}

// EventCountOfType returns the number of captured events of a specific type
func (m *MockEmitter) EventCountOfType(eventType events.EventType) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, event := range m.events {
		if event.EventType == eventType {
			count++
		}
	}

	return count
}

// LastEvent returns the most recently emitted event, or nil if none
func (m *MockEmitter) LastEvent() *events.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.events) == 0 {
		return nil
	}

	return m.events[len(m.events)-1]
}

// LastEventOfType returns the most recently emitted event of a specific type, or nil if none
func (m *MockEmitter) LastEventOfType(eventType events.EventType) *events.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].EventType == eventType {
			return m.events[i]
		}
	}

	return nil
}

// Reset clears all captured events
func (m *MockEmitter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = make([]*events.AuditEvent, 0)
}

// HasEvent returns true if an event matching the predicate was emitted
func (m *MockEmitter) HasEvent(predicate func(*events.AuditEvent) bool) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return slices.ContainsFunc(m.events, predicate)
}

// FindEvent returns the first event matching the predicate, or nil if none
func (m *MockEmitter) FindEvent(predicate func(*events.AuditEvent) bool) *events.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, event := range m.events {
		if predicate(event) {
			return event
		}
	}

	return nil
}

// reviewed - @aeneasr - 2026-03-27
