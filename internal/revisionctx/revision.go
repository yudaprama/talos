// Package revisionctx stores and retrieves the project revision ID from context.
// The revision ID is populated by the cloud bridge middleware and consumed by
// the /revisions/talos endpoint, which lets e2e tests wait until Talos has
// loaded a given project revision before issuing API calls.
package revisionctx

import "context"

type contextKey struct{}

// WithRevisionID returns a new context with the given revision ID.
func WithRevisionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// RevisionIDFromContext returns the revision ID stored in the context,
// or empty string if not set (e.g. OSS build or new project with no config).
func RevisionIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(contextKey{}).(string)
	return id
}

// reviewed - @aeneasr - 2026-03-25
