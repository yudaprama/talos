package errdef

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"

	"github.com/ory/herodot"
)

// TestErrorDefinitions validates all error types have required fields.
func TestErrorDefinitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          func() *herodot.DefaultError
		wantHTTPCode int
		wantGRPCCode codes.Code
		wantID       string
	}{
		{"payment required", ErrPaymentRequired, 403, codes.PermissionDenied, "payment_required"},
		{"invalid api key format", ErrInvalidAPIKeyFormat, 400, codes.InvalidArgument, "invalid_api_key_format"},
		{"credential required", ErrCredentialRequired, 400, codes.InvalidArgument, "credential_required"},
		{"unknown credential", ErrUnknownCredential, 400, codes.InvalidArgument, "unknown_credential"},
		{"derived token not revocable", ErrDerivedTokenNotRevocable, 400, codes.InvalidArgument, "derived_token_not_revocable"},
		{"api key expired", ErrAPIKeyExpired, 401, codes.Unauthenticated, "api_key_expired"},
		{"api key revoked", ErrAPIKeyRevoked, 401, codes.Unauthenticated, "api_key_revoked"},
		{"api key not found", ErrAPIKeyNotFound, 404, codes.NotFound, "api_key_not_found"},
		{"signature invalid", ErrSignatureInvalid, 401, codes.Unauthenticated, "signature_invalid"},
		{"invalid token type", ErrInvalidTokenType, 400, codes.InvalidArgument, "invalid_token_type"},
		{"parent key invalid", ErrParentKeyInvalid, 401, codes.Unauthenticated, "parent_key_invalid"},
		{"api key exists", ErrAPIKeyExists, 409, codes.AlreadyExists, "api_key_exists"},
		{"service unavailable", ErrServiceUnavailable, 503, codes.Unavailable, "service_unavailable"},
		{"gateway timeout", ErrGatewayTimeout, 504, codes.DeadlineExceeded, "gateway_timeout"},
		{"too many requests", ErrTooManyRequests, 429, codes.ResourceExhausted, "too_many_requests"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.err()
			assert.Equal(t, tt.wantHTTPCode, err.CodeField, "HTTP code mismatch")
			assert.Equal(t, tt.wantGRPCCode, err.GRPCCodeField, "gRPC code mismatch")
			assert.Equal(t, tt.wantID, err.IDField, "error ID mismatch")
			assert.NotEmpty(t, err.StatusField, "status field is empty")
			assert.NotEmpty(t, err.ErrorField, "error field is empty")
		})
	}
}

// TestAllErrorsHaveRequiredFields ensures all custom errors have necessary fields.
func TestAllErrorsHaveRequiredFields(t *testing.T) {
	t.Parallel()

	constructors := []func() *herodot.DefaultError{
		ErrPaymentRequired,
		ErrInvalidAPIKeyFormat,
		ErrCredentialRequired,
		ErrUnknownCredential,
		ErrDerivedTokenNotRevocable,
		ErrAPIKeyExpired,
		ErrAPIKeyRevoked,
		ErrAPIKeyNotFound,
		ErrSignatureInvalid,
		ErrInvalidTokenType,
		ErrParentKeyInvalid,
		ErrAPIKeyExists,
		ErrServiceUnavailable,
		ErrGatewayTimeout,
		ErrTooManyRequests,
	}

	for _, ctor := range constructors {
		err := ctor()
		t.Run(err.IDField, func(t *testing.T) {
			t.Parallel()

			assert.NotEmpty(t, err.IDField, "error missing ID")
			assert.NotZero(t, err.CodeField, "error missing HTTP code")
			assert.NotEmpty(t, err.StatusField, "error missing status")
			assert.NotEmpty(t, err.ErrorField, "error missing message")
			assert.NotEqual(t, codes.Unknown, err.GRPCCodeField, "error missing gRPC code")
		})
	}
}

// TestStandardErrorsAreUsable validates that base errors have IDField for AIP-193 compliance.
func TestStandardErrorsAreUsable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  func() *herodot.DefaultError
		code int
		id   string
		grpc codes.Code
	}{
		{"bad request", ErrBadRequest, 400, "bad_request", codes.InvalidArgument},
		{"unauthorized", ErrUnauthorized, 401, "unauthorized", codes.Unauthenticated},
		{"forbidden", ErrForbidden, 403, "forbidden", codes.PermissionDenied},
		{"not found", ErrNotFound, 404, "not_found", codes.NotFound},
		{"conflict", ErrConflict, 409, "conflict", codes.AlreadyExists},
		{"internal server error", ErrInternalServerError, 500, "internal_server_error", codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.err()
			assert.Equal(t, tt.code, err.CodeField)
			assert.Equal(t, tt.id, err.IDField, "IDField required for AIP-193 reason")
			assert.Equal(t, tt.grpc, err.GRPCCodeField)
			assert.NotEmpty(t, err.ErrorField)
			assert.NotEmpty(t, err.StatusField)
		})
	}
}

// TestHelperFunctions validates error helper functions.
func TestHelperFunctions(t *testing.T) {
	t.Parallel()

	t.Run("NotFound", func(t *testing.T) {
		err := NotFound("API key")
		assert.Equal(t, 404, err.CodeField)
		assert.Contains(t, err.ReasonField, "API key not found")
	})

	t.Run("BadRequest", func(t *testing.T) {
		err := BadRequest("invalid id")
		assert.Equal(t, 400, err.CodeField)
		assert.Contains(t, err.ReasonField, "invalid id")
	})

	t.Run("InternalError", func(t *testing.T) {
		err := InternalError("database failed")
		assert.Equal(t, 500, err.CodeField)
		assert.Contains(t, err.ReasonField, "database failed")
	})

	t.Run("Conflict", func(t *testing.T) {
		err := Conflict("key already exists")
		assert.Equal(t, 409, err.CodeField)
		assert.Contains(t, err.ReasonField, "key already exists")
	})
}

// TestErrorWithReason validates WithReason preserves error type.
func TestErrorWithReason(t *testing.T) {
	t.Parallel()

	err := ErrAPIKeyNotFound().WithReason("custom reason")
	assert.Equal(t, "api_key_not_found", err.IDField)
	assert.Equal(t, 404, err.CodeField)
	assert.Equal(t, "custom reason", err.ReasonField)
}

// TestErrorWithReasonf validates WithReasonf preserves error type.
func TestErrorWithReasonf(t *testing.T) {
	t.Parallel()

	err := ErrAPIKeyNotFound().WithReasonf("API key %s not found", "abc123")
	assert.Equal(t, "api_key_not_found", err.IDField)
	assert.Equal(t, 404, err.CodeField)
	assert.Contains(t, err.ReasonField, "abc123")
}

// reviewed - @aeneasr - 2026-03-25
