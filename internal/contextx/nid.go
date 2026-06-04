// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package contextx

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
)

var (
	// ErrMissingNetworkID indicates that no network ID value is present in context.
	ErrMissingNetworkID = errors.New("network id missing from context")
	// ErrInvalidNetworkIDType indicates that the network ID value has an unexpected type.
	ErrInvalidNetworkIDType = errors.New("network id in context has invalid type")
)

// NetworkIDFromContext returns the network ID from context, falling back to
// uuid.Nil when it is absent or invalid. It reads the raw context value in both
// editions, so best-effort paths (tracing, audit context, cache keys, and
// verification, which is backstopped by the strict commercial persister) reflect
// whatever NID is set. Pagination tokens, rate-limit keying, and storage paths
// must instead use RequiredNetworkIDFromContext so a missing NID fails loud in
// commercial; note that in OSS the strict accessor always resolves to uuid.Nil
// regardless of context, while this best-effort accessor does not.
func NetworkIDFromContext(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(NIDKey{}).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

// reviewed - @aeneasr - 2026-03-25
