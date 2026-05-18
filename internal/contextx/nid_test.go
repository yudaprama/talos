// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package contextx

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkIDFromContext_Default(t *testing.T) {
	t.Parallel()

	nid := NetworkIDFromContext(t.Context())
	assert.Equal(t, uuid.Nil, nid)
}

func TestNetworkIDFromContext_Custom(t *testing.T) {
	t.Parallel()

	customNID := uuid.Must(uuid.FromString("12345678-1234-1234-1234-123456789012"))
	ctx := context.WithValue(t.Context(), NIDKey{}, customNID)

	assert.Equal(t, customNID, NetworkIDFromContext(ctx))
}

func TestNetworkIDFromContext_NilUUID(t *testing.T) {
	t.Parallel()

	// Storing uuid.Nil explicitly must round-trip correctly.
	ctx := context.WithValue(t.Context(), NIDKey{}, uuid.Nil)
	assert.Equal(t, uuid.Nil, NetworkIDFromContext(ctx))
}

func TestNetworkIDFromContext_Overwrite(t *testing.T) {
	t.Parallel()

	nid1 := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	nid2 := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))

	ctx := context.WithValue(t.Context(), NIDKey{}, nid1)
	ctx = context.WithValue(ctx, NIDKey{}, nid2)

	// The most-recently set value must win.
	assert.Equal(t, nid2, NetworkIDFromContext(ctx))
}

func TestNetworkIDFromContext_WrongType(t *testing.T) {
	t.Parallel()

	// A value of the wrong type stored under NIDKey must not be returned;
	// the function falls back to uuid.Nil.
	ctx := context.WithValue(t.Context(), NIDKey{}, "not-a-uuid")
	assert.Equal(t, uuid.Nil, NetworkIDFromContext(ctx))
}

func TestRequiredNetworkIDFromContext_Success(t *testing.T) {
	t.Parallel()

	customNID := uuid.Must(uuid.FromString("12345678-1234-1234-1234-123456789012"))
	ctx := context.WithValue(t.Context(), NIDKey{}, customNID)

	nid, err := RequiredNetworkIDFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, customNID, nid)
}

func TestRequiredNetworkIDFromContext_ExplicitNilAllowed(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), NIDKey{}, uuid.Nil)
	nid, err := RequiredNetworkIDFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, uuid.Nil, nid)
}

func TestRequiredNetworkIDFromContext_Missing(t *testing.T) {
	t.Parallel()

	_, err := RequiredNetworkIDFromContext(t.Context())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingNetworkID))
}

func TestRequiredNetworkIDFromContext_WrongType(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), NIDKey{}, "not-a-uuid")
	_, err := RequiredNetworkIDFromContext(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidNetworkIDType))
}
