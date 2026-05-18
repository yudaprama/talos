package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ory-corp/talos/internal/errdef"
)

// TestHerodotErrorGRPCPassthrough verifies that herodot errors returned by the
// service layer carry correct gRPC status codes and reason fields when inspected
// via status.FromError — the contract the adapter now relies on.
func TestHerodotErrorGRPCPassthrough(t *testing.T) {
	t.Parallel()

	t.Run("BadRequest with reason preserves code and reason", func(t *testing.T) {
		t.Parallel()
		err := errdef.BadRequest("status filter requires actor_id to be provided")

		st, ok := status.FromError(err)
		require.True(t, ok, "herodot error should satisfy status.FromError")
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Equal(t, "status filter requires actor_id to be provided", err.ReasonField)
	})

	t.Run("NotFound with reason preserves code and reason", func(t *testing.T) {
		t.Parallel()
		err := errdef.NotFound("api_key")

		st, ok := status.FromError(err)
		require.True(t, ok, "herodot error should satisfy status.FromError")
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Contains(t, err.ReasonField, "api_key not found")
	})

	t.Run("FailedPrecondition preserves code and reason", func(t *testing.T) {
		t.Parallel()
		err := errdef.FailedPrecondition("cannot derive token from expired parent key")

		st, ok := status.FromError(err)
		require.True(t, ok, "herodot error should satisfy status.FromError")
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "cannot derive token from expired parent key", err.ReasonField)
	})

	t.Run("nil error returns OK status", func(t *testing.T) {
		t.Parallel()
		st, ok := status.FromError(nil)
		require.True(t, ok)
		assert.Equal(t, codes.OK, st.Code())
	})
}

// reviewed - @aeneasr - 2026-03-26
