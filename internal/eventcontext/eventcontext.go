// Package eventcontext provides context helpers for audit events.
package eventcontext

import (
	"context"

	"github.com/ory-corp/talos/internal/contextx"

	"github.com/ory-corp/talos/internal/events"
)

// NewFromContext creates an event builder with network ID extracted from context.
func NewFromContext(ctx context.Context, eventType events.EventType) *events.EventBuilder {
	return events.New(eventType).
		WithNetworkID(contextx.NetworkIDFromContext(ctx))
}

// reviewed - @aeneasr - 2026-03-25
