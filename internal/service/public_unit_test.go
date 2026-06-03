package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/ratelimit"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// controlledLimiter is a test-local ratelimit.Limiter whose behaviour is
// set at construction time. It covers the three applyRateLimiting paths:
// allowed, denied, and error.
type controlledLimiter struct {
	result *ratelimit.Result
	err    error
}

func (c *controlledLimiter) Allow(_ context.Context, _ string, _ *talosv2alpha1.RateLimitPolicy) (*ratelimit.Result, error) {
	return c.result, c.err
}
func (c *controlledLimiter) Close() error { return nil }

// newPV creates a protovalidate.Validator for use in tests.
func newPV(t *testing.T) protovalidate.Validator {
	t.Helper()
	pv, err := protovalidate.New()
	require.NoError(t, err)
	return pv
}

// newPublicWithLimiter constructs a Public with the given
// limiter and a nil verifier. Only use it in tests that do NOT reach the
// verifier code path.
func newPublicWithLimiter(t *testing.T, rl ratelimit.Limiter) *Public {
	t.Helper()
	return NewPublic(nil, newPV(t), rl)
}

// TestMapErrorToVerificationCode verifies all eight switch branches in
// mapErrorToVerificationCode.
func TestMapErrorToVerificationCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want talosv2alpha1.VerificationErrorCode
	}{
		{
			name: "expired key",
			err:  errdef.ErrAPIKeyExpired(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_EXPIRED,
		},
		{
			name: "revoked key",
			err:  errdef.ErrAPIKeyRevoked(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_REVOKED,
		},
		{
			name: "key not found",
			err:  errdef.ErrAPIKeyNotFound(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_NOT_FOUND,
		},
		{
			name: "parent key invalid maps to not found",
			err:  errdef.ErrParentKeyInvalid(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_NOT_FOUND,
		},
		{
			name: "signature invalid",
			err:  errdef.ErrSignatureInvalid(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_SIGNATURE_INVALID,
		},
		{
			name: "credential required maps to invalid format",
			err:  errdef.ErrCredentialRequired(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT,
		},
		{
			name: "invalid api key format",
			err:  errdef.ErrInvalidAPIKeyFormat(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT,
		},
		{
			name: "unknown credential maps to invalid format",
			err:  errdef.ErrUnknownCredential(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT,
		},
		{
			name: "invalid token type maps to invalid format",
			err:  errdef.ErrInvalidTokenType(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT,
		},
		{
			name: "ip not allowed",
			err:  errdef.ErrIPNotAllowed(),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_IP_NOT_ALLOWED,
		},
		{
			name: "unrecognised internal error",
			err:  errors.New("some unexpected database error"),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INTERNAL,
		},
		{
			name: "wrapped known error still resolves correctly",
			err:  errors.Join(errors.New("wrapper"), errdef.ErrAPIKeyExpired()),
			want: talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_EXPIRED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mapErrorToVerificationCode(tc.err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestApplyRateLimiting verifies the three distinct behaviours of applyRateLimiting:
// no-op when no policy is set, denial when the limiter denies, and fail-open when
// the limiter returns an error.
func TestApplyRateLimiting(t *testing.T) {
	t.Parallel()

	policy := &talosv2alpha1.RateLimitPolicy{Quota: 100}

	t.Run("nil policy is a no-op", func(t *testing.T) {
		t.Parallel()

		// The limiter must never be called when there is no policy; use a
		// limiter that would panic on invocation to confirm.
		srv := newPublicWithLimiter(t, &controlledLimiter{
			err: errors.New("limiter must not be called"),
		})

		resp := &talosv2alpha1.VerifyApiKeyResponse{IsValid: true}
		srv.applyRateLimiting(t.Context(), "key-1", resp, trace.SpanFromContext(t.Context()))

		assert.True(t, resp.IsValid, "response must stay active when no policy is present")
		assert.Nil(t, resp.ErrorCode)
		assert.Nil(t, resp.ErrorMessage)
	})

	t.Run("denied request marks response inactive", func(t *testing.T) {
		t.Parallel()

		resetAt := time.Now().Add(time.Minute)
		srv := newPublicWithLimiter(t, &controlledLimiter{
			result: &ratelimit.Result{
				Allowed:   false,
				Remaining: 0,
				ResetAt:   resetAt,
			},
		})

		resp := &talosv2alpha1.VerifyApiKeyResponse{IsValid: true, RateLimitPolicy: policy}
		srv.applyRateLimiting(t.Context(), "key-2", resp, trace.SpanFromContext(t.Context()))

		assert.False(t, resp.IsValid)
		require.NotNil(t, resp.ErrorCode)
		assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_RATE_LIMITED, resp.GetErrorCode())
		require.NotNil(t, resp.ErrorMessage)
		assert.Equal(t, "rate limit exceeded", resp.GetErrorMessage())
		assert.Equal(t, int64(0), resp.GetRateLimitRemaining())
		require.NotNil(t, resp.RateLimitResetTime)
	})

	t.Run("limiter error fails open - IsValid stays true", func(t *testing.T) {
		t.Parallel()

		srv := newPublicWithLimiter(t, &controlledLimiter{
			err: errors.New("redis connection refused"),
		})

		resp := &talosv2alpha1.VerifyApiKeyResponse{IsValid: true, RateLimitPolicy: policy}
		srv.applyRateLimiting(t.Context(), "key-3", resp, trace.SpanFromContext(t.Context()))

		assert.True(t, resp.IsValid, "fail-open: response must remain active on limiter error")
		assert.Nil(t, resp.ErrorCode)
		assert.Nil(t, resp.RateLimitResetTime)
	})

	t.Run("allowed request preserves IsValid and sets remaining fields", func(t *testing.T) {
		t.Parallel()

		resetAt := time.Now().Add(30 * time.Second)
		srv := newPublicWithLimiter(t, &controlledLimiter{
			result: &ratelimit.Result{
				Allowed:   true,
				Remaining: 42,
				ResetAt:   resetAt,
			},
		})

		resp := &talosv2alpha1.VerifyApiKeyResponse{IsValid: true, RateLimitPolicy: policy}
		srv.applyRateLimiting(t.Context(), "key-4", resp, trace.SpanFromContext(t.Context()))

		assert.True(t, resp.IsValid)
		assert.Nil(t, resp.ErrorCode)
		assert.Equal(t, int64(42), resp.GetRateLimitRemaining())
		require.NotNil(t, resp.RateLimitResetTime)
	})
}

// TestBatchVerifyAPIKeys_Validation covers the proto validation boundary for
// BatchVerifyAPIKeys. The proto rules enforce min_items: 1 on the requests
// field and min_len: 1 on each credential, so invalid inputs are rejected
// before any handler logic runs.
//
// Note: the nil-item and empty-credential guards inside BatchVerifyAPIKeys are
// defensive dead code — the proto validator blocks those inputs first. These
// tests document that boundary.
func TestBatchVerifyAPIKeys_Validation(t *testing.T) {
	t.Parallel()

	srv := newPublicWithLimiter(t, &ratelimit.NoopLimiter{})

	t.Run("empty request list is rejected by proto validation", func(t *testing.T) {
		t.Parallel()

		req := &talosv2alpha1.BatchVerifyApiKeysRequest{
			Requests: []*talosv2alpha1.VerifyApiKeyRequest{},
		}

		_, err := srv.BatchVerifyAPIKeys(t.Context(), req)

		require.Error(t, err, "empty requests must be rejected before handler logic")
	})

	t.Run("item with empty credential is rejected by proto validation", func(t *testing.T) {
		t.Parallel()

		req := &talosv2alpha1.BatchVerifyApiKeysRequest{
			Requests: []*talosv2alpha1.VerifyApiKeyRequest{
				{Credential: ""},
			},
		}

		_, err := srv.BatchVerifyAPIKeys(t.Context(), req)

		require.Error(t, err, "empty credential must be rejected before handler logic")
	})
}

// TestVerificationErrorToResponse verifies that verificationErrorToResponse
// uses the herodot ReasonField when present and falls back to a generic
// message for non-herodot errors.
func TestVerificationErrorToResponse(t *testing.T) {
	t.Parallel()

	t.Run("herodot error with ReasonField uses reason as message", func(t *testing.T) {
		t.Parallel()

		resp := verificationErrorToResponse(errdef.ErrAPIKeyNotFound())

		require.NotNil(t, resp)
		assert.False(t, resp.IsValid)
		assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_NOT_FOUND, resp.GetErrorCode())
		// ErrAPIKeyNotFound has ReasonField set to "API key not found"
		assert.Equal(t, "API key not found", resp.GetErrorMessage())
	})

	t.Run("herodot error without ReasonField uses ErrorField", func(t *testing.T) {
		t.Parallel()

		resp := verificationErrorToResponse(errdef.ErrSignatureInvalid())

		require.NotNil(t, resp)
		assert.False(t, resp.IsValid)
		assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_SIGNATURE_INVALID, resp.GetErrorCode())
		assert.Equal(t, "Signature verification failed.", resp.GetErrorMessage())
	})

	t.Run("non-herodot error returns generic internal message", func(t *testing.T) {
		t.Parallel()

		resp := verificationErrorToResponse(errors.New("sql: connection reset by peer"))

		require.NotNil(t, resp)
		assert.False(t, resp.IsValid)
		assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INTERNAL, resp.GetErrorCode())
		assert.Equal(t, "An internal server error occurred.", resp.GetErrorMessage())
	})

	t.Run("response has no rate limit or metadata fields", func(t *testing.T) {
		t.Parallel()

		resp := verificationErrorToResponse(errdef.ErrAPIKeyExpired())

		assert.Nil(t, resp.RateLimitPolicy)
		assert.Nil(t, resp.Metadata)
	})
}

// reviewed - @aeneasr - 2026-03-25
