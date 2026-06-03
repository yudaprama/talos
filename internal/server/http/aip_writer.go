package http

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"

	stderr "errors"

	"github.com/cockroachdb/errors"
	codepb "google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/codes"

	"github.com/ory/talos/internal/errdef"

	"github.com/ory/herodot"
)

// AIPWriter wraps herodot.JSONWriter to produce Google AIP-193 compliant error responses.
// Success responses (Write, WriteCode, WriteCreated) are delegated to the embedded JSONWriter.
// Error responses (WriteError, WriteErrorCode) are serialized in AIP-193 format.
type AIPWriter struct {
	*herodot.JSONWriter

	domain string
}

var _ herodot.Writer = (*AIPWriter)(nil)

// NewAIPWriter creates a new AIP-193 compliant writer.
// The domain parameter identifies the service (e.g., "talos.ory.com").
func NewAIPWriter(reporter herodot.ErrorReporter, domain string) *AIPWriter {
	return &AIPWriter{
		JSONWriter: herodot.NewJSONWriter(reporter),
		domain:     domain,
	}
}

// WriteError extracts the status code from the error and delegates to WriteErrorCode.
func (w *AIPWriter) WriteError(rw http.ResponseWriter, r *http.Request, err error, opts ...herodot.Option) {
	if c := herodot.StatusCodeCarrier(nil); stderr.As(err, &c) {
		w.WriteErrorCode(rw, r, c.StatusCode(), err, opts...)
	} else {
		w.WriteErrorCode(rw, r, http.StatusInternalServerError, err, opts...)
	}
}

// WriteErrorCode writes an AIP-193 compliant error response.
func (w *AIPWriter) WriteErrorCode(rw http.ResponseWriter, r *http.Request, code int, err error, _ ...herodot.Option) {
	if code == 0 {
		code = http.StatusInternalServerError
	}

	if errors.Is(r.Context().Err(), context.Canceled) {
		code = 499 // Client Closed Request
	}

	// Log via the embedded reporter
	w.Reporter.ReportError(r, code, err, "An error occurred while handling a request")

	// Extract herodot error fields
	herodotErr, ok := stderr.AsType[*herodot.DefaultError](err)
	if !ok {
		herodotErr = errdef.ErrInternalServerError().WithReason("an internal error occurred").WithTrace(err)
	}

	// Build AIP-193 response
	resp := w.buildAIPResponse(herodotErr, code)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)

	if encErr := json.NewEncoder(rw).Encode(resp); encErr != nil {
		w.Reporter.ReportError(r, code, errors.WithStack(encErr), "Could not write error response")
	}
}

// buildAIPResponse converts a herodot error to AIP-193 format.
func (w *AIPWriter) buildAIPResponse(err *herodot.DefaultError, httpCode int) aipErrorResponse {
	// Prefer ReasonField as message (more contextual), fall back to ErrorField,
	// then to standard HTTP status text to ensure message is never empty (W3).
	message := err.ReasonField
	if message == "" {
		message = err.ErrorField
	}
	if message == "" {
		message = http.StatusText(httpCode)
	}

	// Derive the canonical status from the error's gRPC code, which is the
	// authoritative AIP-193 status. The HTTP code is overloaded — 409 maps to
	// both FAILED_PRECONDITION and ALREADY_EXISTS, and 402 has no canonical gRPC
	// status — so deriving the status from it loses information. Fall back to the
	// HTTP-code mapping only when no gRPC code is set (zero value == codes.OK).
	statusName := httpToGRPCStatus(httpCode)
	if err.GRPCCodeField != codes.OK {
		statusName = grpcCodeToAIPStatus(err.GRPCCodeField)
	}

	// Build ErrorInfo reason from IDField, sanitized to AIP-193 pattern (W2).
	// Falls back to UNSPECIFIED_ERROR when IDField is empty to avoid restating the status (F2).
	reason := "UNSPECIFIED_ERROR"
	if err.IDField != "" {
		reason = sanitizeReason(err.IDField)
	}

	// Convert details map to string-keyed metadata
	metadata := make(map[string]string, len(err.DetailsField))
	for k, v := range err.DetailsField {
		if s, ok := v.(string); ok {
			metadata[k] = s
		}
	}

	detail := aipErrorInfo{
		Type:   "type.googleapis.com/google.rpc.ErrorInfo",
		Reason: reason,
		Domain: w.domain,
	}
	if len(metadata) > 0 {
		detail.Metadata = metadata
	}

	return aipErrorResponse{
		Error: aipError{
			Code:    httpCode,
			Message: message,
			Status:  statusName,
			Details: []any{detail},
		},
	}
}

// AIP-193 error response types

type aipErrorResponse struct {
	Error aipError `json:"error"`
}

type aipError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Details []any  `json:"details"`
}

type aipErrorInfo struct {
	Type     string            `json:"@type"`
	Reason   string            `json:"reason"`
	Domain   string            `json:"domain"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// OpenAPIErrorResponse is the published error response schema in OpenAPI docs.
// It mirrors the runtime AIP envelope exactly.
type OpenAPIErrorResponse = aipErrorResponse

// grpcCodeToAIPStatus returns the canonical AIP-193 status name for a gRPC code
// (e.g. codes.FailedPrecondition -> "FAILED_PRECONDITION"). grpc's codes.Code
// values are numerically identical to google.rpc.Code, so we reuse the generated
// enum names instead of maintaining a parallel mapping table.
func grpcCodeToAIPStatus(c codes.Code) string {
	if c > math.MaxInt32 {
		return codepb.Code_UNKNOWN.String()
	}
	return codepb.Code(c).String()
}

// httpToGRPCStatus maps HTTP status codes to canonical AIP-193 status names.
// Based on https://cloud.google.com/apis/design/errors#handling_errors
func httpToGRPCStatus(httpCode int) string {
	switch httpCode {
	case 200:
		return "OK"
	case 400:
		return "INVALID_ARGUMENT"
	case 401:
		return "UNAUTHENTICATED"
	case 403:
		return "PERMISSION_DENIED"
	case 404:
		return "NOT_FOUND"
	case 409:
		return "ALREADY_EXISTS"
	case 429:
		return "RESOURCE_EXHAUSTED"
	case 499:
		// Client Closed Request — canonical per Google's gRPC mapping, though not IANA-registered.
		return "CANCELLED"
	case 500:
		return "INTERNAL"
	case 501:
		return "UNIMPLEMENTED"
	case 503:
		return "UNAVAILABLE"
	case 504:
		return "DEADLINE_EXCEEDED"
	default:
		return "UNKNOWN"
	}
}

// sanitizeReason converts an error ID to a valid AIP-193 reason string.
// The spec requires reasons to match [A-Z][A-Z0-9_]+[A-Z0-9].
func sanitizeReason(id string) string {
	upper := strings.ToUpper(id)
	var b strings.Builder
	b.Grow(len(upper))
	for _, r := range upper {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	result := b.String()
	result = strings.TrimLeft(result, "_0123456789")
	result = strings.TrimRight(result, "_")
	if result == "" {
		return "UNSPECIFIED_ERROR"
	}
	return result
}

// reviewed - @aeneasr - 2026-03-26
