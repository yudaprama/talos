// Package errdef provides common error definitions used across the application.
package errdef

import (
	"net/http"

	"google.golang.org/grpc/codes"

	"github.com/ory/herodot"
)

// Each error is defined as an instantiator function that returns a fresh
// *herodot.DefaultError pointer. Callers can mutate the returned value
// (WithReason, WithWrap, etc.) without affecting shared state.

// ErrBadRequest represents a 400 Bad Request error.
func ErrBadRequest() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "bad_request",
		CodeField:     http.StatusBadRequest,
		StatusField:   http.StatusText(http.StatusBadRequest),
		ErrorField:    "The request was malformed or contained invalid parameters",
		GRPCCodeField: codes.InvalidArgument,
	}
}

// ErrUnauthorized represents a 401 Unauthorized error.
func ErrUnauthorized() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "unauthorized",
		CodeField:     http.StatusUnauthorized,
		StatusField:   http.StatusText(http.StatusUnauthorized),
		ErrorField:    "The request could not be authorized",
		GRPCCodeField: codes.Unauthenticated,
	}
}

// ErrForbidden represents a 403 Forbidden error.
func ErrForbidden() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "forbidden",
		CodeField:     http.StatusForbidden,
		StatusField:   http.StatusText(http.StatusForbidden),
		ErrorField:    "The requested action was forbidden",
		GRPCCodeField: codes.PermissionDenied,
	}
}

// ErrNotFound represents a 404 Not Found error.
func ErrNotFound() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "not_found",
		CodeField:     http.StatusNotFound,
		StatusField:   http.StatusText(http.StatusNotFound),
		ErrorField:    "The requested resource could not be found",
		GRPCCodeField: codes.NotFound,
	}
}

// ErrConflict represents a 409 Conflict error.
func ErrConflict() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "conflict",
		CodeField:     http.StatusConflict,
		StatusField:   http.StatusText(http.StatusConflict),
		ErrorField:    "The resource could not be created due to a conflict",
		GRPCCodeField: codes.AlreadyExists,
	}
}

// ErrInternalServerError represents a 500 Internal Server Error.
func ErrInternalServerError() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "internal_server_error",
		CodeField:     http.StatusInternalServerError,
		StatusField:   http.StatusText(http.StatusInternalServerError),
		ErrorField:    "An internal server error occurred, please contact the system administrator",
		GRPCCodeField: codes.Internal,
	}
}

// ErrPaymentRequired is returned when a feature requires a paid license.
// Uses HTTP 403 + PERMISSION_DENIED because HTTP 402 has no canonical gRPC mapping.
// The reason "payment_required" (from IDField) conveys the specific cause via ErrorInfo.
func ErrPaymentRequired() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "payment_required",
		CodeField:     http.StatusForbidden,
		StatusField:   http.StatusText(http.StatusForbidden),
		ErrorField:    "The feature is not available and requires payment.",
		GRPCCodeField: codes.PermissionDenied,
	}
}

// ErrInvalidAPIKeyFormat represents an invalid API key format (400 Bad Request).
func ErrInvalidAPIKeyFormat() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "invalid_api_key_format",
		CodeField:     http.StatusBadRequest,
		StatusField:   http.StatusText(http.StatusBadRequest),
		ErrorField:    "The API key format is invalid.",
		GRPCCodeField: codes.InvalidArgument,
	}
}

// ErrCredentialRequired represents a missing credential (400 Bad Request).
func ErrCredentialRequired() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "credential_required",
		CodeField:     http.StatusBadRequest,
		StatusField:   http.StatusText(http.StatusBadRequest),
		ErrorField:    "A credential is required.",
		GRPCCodeField: codes.InvalidArgument,
	}
}

// ErrUnknownCredential represents an unsupported credential type (400 Bad Request).
func ErrUnknownCredential() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "unknown_credential",
		CodeField:     http.StatusBadRequest,
		StatusField:   http.StatusText(http.StatusBadRequest),
		ErrorField:    "The credential type is not recognized.",
		GRPCCodeField: codes.InvalidArgument,
	}
}

// ErrDerivedTokenNotRevocable represents self-revocation attempts for derived tokens (400 Bad Request).
func ErrDerivedTokenNotRevocable() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "derived_token_not_revocable",
		CodeField:     http.StatusBadRequest,
		StatusField:   http.StatusText(http.StatusBadRequest),
		ErrorField:    "Derived tokens cannot be revoked.",
		GRPCCodeField: codes.InvalidArgument,
	}
}

// ErrAPIKeyExpired represents an expired API key (401 Unauthorized).
func ErrAPIKeyExpired() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "api_key_expired",
		CodeField:     http.StatusUnauthorized,
		StatusField:   http.StatusText(http.StatusUnauthorized),
		ErrorField:    "The API key has expired.",
		GRPCCodeField: codes.Unauthenticated,
	}
}

// ErrAPIKeyRevoked represents a revoked API key (401 Unauthorized).
func ErrAPIKeyRevoked() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "api_key_revoked",
		CodeField:     http.StatusUnauthorized,
		StatusField:   http.StatusText(http.StatusUnauthorized),
		ErrorField:    "The API key has been revoked.",
		GRPCCodeField: codes.Unauthenticated,
	}
}

// ErrAPIKeyNotFound represents an API key not found (404 Not Found).
func ErrAPIKeyNotFound() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "api_key_not_found",
		CodeField:     http.StatusNotFound,
		StatusField:   http.StatusText(http.StatusNotFound),
		ErrorField:    "The API key was not found.",
		ReasonField:   "API key not found",
		GRPCCodeField: codes.NotFound,
	}
}

// ErrSignatureInvalid represents failed signature verification (401 Unauthorized).
func ErrSignatureInvalid() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "signature_invalid",
		CodeField:     http.StatusUnauthorized,
		StatusField:   http.StatusText(http.StatusUnauthorized),
		ErrorField:    "Signature verification failed.",
		GRPCCodeField: codes.Unauthenticated,
	}
}

// ErrInvalidTokenType represents an unexpected token type (400 Bad Request).
func ErrInvalidTokenType() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "invalid_token_type",
		CodeField:     http.StatusBadRequest,
		StatusField:   http.StatusText(http.StatusBadRequest),
		ErrorField:    "The token type is invalid.",
		GRPCCodeField: codes.InvalidArgument,
	}
}

// ErrParentKeyInvalid represents parent key validation failures (401 Unauthorized).
func ErrParentKeyInvalid() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "parent_key_invalid",
		CodeField:     http.StatusUnauthorized,
		StatusField:   http.StatusText(http.StatusUnauthorized),
		ErrorField:    "Parent key validation failed.",
		GRPCCodeField: codes.Unauthenticated,
	}
}

// ErrAPIKeyExists represents an API key that already exists (409 Conflict).
func ErrAPIKeyExists() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "api_key_exists",
		CodeField:     http.StatusConflict,
		StatusField:   http.StatusText(http.StatusConflict),
		ErrorField:    "An API key with this identifier already exists.",
		GRPCCodeField: codes.AlreadyExists,
	}
}

// ErrServiceUnavailable represents a service unavailable error (503 Service Unavailable).
func ErrServiceUnavailable() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "service_unavailable",
		CodeField:     http.StatusServiceUnavailable,
		StatusField:   http.StatusText(http.StatusServiceUnavailable),
		ErrorField:    "The service is temporarily unavailable.",
		GRPCCodeField: codes.Unavailable,
	}
}

// ErrIPNotAllowed is returned when the client IP is not in the key's allowed CIDR list (403 Forbidden).
func ErrIPNotAllowed() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "ip_not_allowed",
		CodeField:     http.StatusForbidden,
		StatusField:   http.StatusText(http.StatusForbidden),
		ErrorField:    "The request IP is not allowed for this API key.",
		GRPCCodeField: codes.PermissionDenied,
	}
}

// ErrGatewayTimeout represents a gateway timeout error (504 Gateway Timeout).
func ErrGatewayTimeout() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "gateway_timeout",
		CodeField:     http.StatusGatewayTimeout,
		StatusField:   http.StatusText(http.StatusGatewayTimeout),
		ErrorField:    "The operation timed out.",
		GRPCCodeField: codes.DeadlineExceeded,
	}
}

// ErrFailedPrecondition represents a failed precondition error (409 Conflict).
func ErrFailedPrecondition() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "failed_precondition",
		CodeField:     http.StatusConflict,
		StatusField:   http.StatusText(http.StatusConflict),
		ErrorField:    "The operation cannot be completed due to a failed precondition.",
		GRPCCodeField: codes.FailedPrecondition,
	}
}

// ErrTooManyRequests represents a rate/exhaustion error (429 Too Many Requests).
func ErrTooManyRequests() *herodot.DefaultError {
	return &herodot.DefaultError{
		IDField:       "too_many_requests",
		CodeField:     http.StatusTooManyRequests,
		StatusField:   http.StatusText(http.StatusTooManyRequests),
		ErrorField:    "The request was throttled due to resource exhaustion.",
		GRPCCodeField: codes.ResourceExhausted,
	}
}

// Helper functions for creating contextual errors.

// NotFound creates a 404 error with a resource-specific reason.
func NotFound(resource string) *herodot.DefaultError {
	return ErrNotFound().WithReasonf("%s not found", resource)
}

// BadRequest creates a 400 error with a specific reason.
func BadRequest(reason string) *herodot.DefaultError {
	return ErrBadRequest().WithReason(reason)
}

// InternalError creates a 500 error with a specific reason.
func InternalError(reason string) *herodot.DefaultError {
	return ErrInternalServerError().WithReason(reason)
}

// Conflict creates a 409 error with a specific reason.
func Conflict(reason string) *herodot.DefaultError {
	return ErrConflict().WithReason(reason)
}

// FailedPrecondition creates a 409 error with a specific reason for state-based rejections.
func FailedPrecondition(reason string) *herodot.DefaultError {
	return ErrFailedPrecondition().WithReason(reason)
}

// reviewed - @aeneasr - 2026-03-25
