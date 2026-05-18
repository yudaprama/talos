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

// NetworkIDFromContext returns the network ID from the context,
// or uuid.Nil if none is set.
func NetworkIDFromContext(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(NIDKey{}).(uuid.UUID); ok {
		return id
	}
	return uuid.Nil
}

// RequiredNetworkIDFromContext returns the network ID from the context.
// It fails when the value is missing or has the wrong type.
func RequiredNetworkIDFromContext(ctx context.Context) (uuid.UUID, error) {
	raw := ctx.Value(NIDKey{})
	if raw == nil {
		return uuid.Nil, errors.WithStack(ErrMissingNetworkID)
	}
	nid, ok := raw.(uuid.UUID)
	if !ok {
		return uuid.Nil, errors.WithStack(ErrInvalidNetworkIDType)
	}
	return nid, nil
}

// reviewed - @aeneasr - 2026-03-25
