package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	"github.com/ory-corp/talos/internal/errdef"
)

type noopReporter struct{}

func (noopReporter) ReportError(_ *http.Request, _ int, _ error, _ ...any) {}

func newTestWriter() *AIPWriter {
	return NewAIPWriter(noopReporter{}, "talos.ory.com")
}

func writeAndParse(t *testing.T, writer *AIPWriter, err error) (int, aipErrorResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	writer.WriteError(rec, req, err)

	var resp aipErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return rec.Code, resp
}

func TestAIPWriter_CustomErrors(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	tests := []struct {
		name           string
		err            error
		wantCode       int
		wantStatus     string
		wantReason     string
		wantMessage    string
		wantHasDetails bool
	}{
		{
			name:        "api_key_not_found",
			err:         errdef.ErrAPIKeyNotFound().WithReasonf("key %s not found", "abc123"),
			wantCode:    404,
			wantStatus:  "NOT_FOUND",
			wantReason:  "API_KEY_NOT_FOUND",
			wantMessage: "key abc123 not found",
		},
		{
			name:        "bad_request",
			err:         errdef.BadRequest("invalid page token"),
			wantCode:    400,
			wantStatus:  "INVALID_ARGUMENT",
			wantReason:  "BAD_REQUEST",
			wantMessage: "invalid page token",
		},
		{
			name:        "api_key_expired",
			err:         errdef.ErrAPIKeyExpired(),
			wantCode:    401,
			wantStatus:  "UNAUTHENTICATED",
			wantReason:  "API_KEY_EXPIRED",
			wantMessage: "The API key has expired.",
		},
		{
			name:        "api_key_revoked",
			err:         errdef.ErrAPIKeyRevoked(),
			wantCode:    401,
			wantStatus:  "UNAUTHENTICATED",
			wantReason:  "API_KEY_REVOKED",
			wantMessage: "The API key has been revoked.",
		},
		{
			name:        "conflict_already_exists",
			err:         errdef.ErrAPIKeyExists().WithReasonf("key abc already imported"),
			wantCode:    409,
			wantStatus:  "ALREADY_EXISTS",
			wantReason:  "API_KEY_EXISTS",
			wantMessage: "key abc already imported",
		},
		{
			name:        "service_unavailable",
			err:         errdef.ErrServiceUnavailable().WithReasonf("redis down"),
			wantCode:    503,
			wantStatus:  "UNAVAILABLE",
			wantReason:  "SERVICE_UNAVAILABLE",
			wantMessage: "redis down",
		},
		{
			name:        "internal_error",
			err:         errdef.InternalError("sign JWT token"),
			wantCode:    500,
			wantStatus:  "INTERNAL",
			wantReason:  "INTERNAL_SERVER_ERROR",
			wantMessage: "sign JWT token",
		},
		{
			name:        "forbidden_ip",
			err:         errdef.ErrIPNotAllowed().WithReasonf("1.2.3.4 not in allowed CIDRs"),
			wantCode:    403,
			wantStatus:  "PERMISSION_DENIED",
			wantReason:  "IP_NOT_ALLOWED",
			wantMessage: "1.2.3.4 not in allowed CIDRs",
		},
		{
			name:        "gateway_timeout",
			err:         errdef.ErrGatewayTimeout().WithReasonf("database operation timed out"),
			wantCode:    504,
			wantStatus:  "DEADLINE_EXCEEDED",
			wantReason:  "GATEWAY_TIMEOUT",
			wantMessage: "database operation timed out",
		},
		{
			name:        "payment_required",
			err:         errdef.ErrPaymentRequired(),
			wantCode:    403,
			wantStatus:  "PERMISSION_DENIED",
			wantReason:  "PAYMENT_REQUIRED",
			wantMessage: "The feature is not available and requires payment.",
		},
		{
			name:        "invalid_api_key_format",
			err:         errdef.ErrInvalidAPIKeyFormat(),
			wantCode:    400,
			wantStatus:  "INVALID_ARGUMENT",
			wantReason:  "INVALID_API_KEY_FORMAT",
			wantMessage: "The API key format is invalid.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, resp := writeAndParse(t, writer, tt.err)

			assert.Equal(t, tt.wantCode, code, "HTTP status code")
			assert.Equal(t, tt.wantCode, resp.Error.Code, "JSON code field")
			assert.Equal(t, tt.wantStatus, resp.Error.Status, "JSON status field")
			assert.Equal(t, tt.wantMessage, resp.Error.Message, "JSON message field")

			require.Len(t, resp.Error.Details, 1, "should have exactly one detail")

			detailJSON, err := json.Marshal(resp.Error.Details[0])
			require.NoError(t, err)

			var detail aipErrorInfo
			require.NoError(t, json.Unmarshal(detailJSON, &detail))

			assert.Equal(t, "type.googleapis.com/google.rpc.ErrorInfo", detail.Type)
			assert.Equal(t, tt.wantReason, detail.Reason)
			assert.Equal(t, "talos.ory.com", detail.Domain)
		})
	}
}

func TestAIPWriter_NonHerodotError(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	code, resp := writeAndParse(t, writer, errors.New("something unexpected"))

	assert.Equal(t, 500, code)
	assert.Equal(t, 500, resp.Error.Code)
	assert.Equal(t, "INTERNAL", resp.Error.Status)
	assert.Equal(t, "an internal error occurred", resp.Error.Message)

	// Non-herodot errors go through the fallback path in WriteErrorCode,
	// which wraps them in ErrInternalServerError (which has IDField).
	detailJSON, err := json.Marshal(resp.Error.Details[0])
	require.NoError(t, err)
	var detail aipErrorInfo
	require.NoError(t, json.Unmarshal(detailJSON, &detail))
	assert.Equal(t, "INTERNAL_SERVER_ERROR", detail.Reason, "reason should come from IDField, not status")
}

func TestAIPWriter_ContentType(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	writer.WriteError(rec, req, errdef.ErrNotFound())

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestAIPWriter_WriteErrorCode(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	writer.WriteErrorCode(rec, req, 503, errdef.ErrServiceUnavailable())

	assert.Equal(t, 503, rec.Code)

	var resp aipErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 503, resp.Error.Code)
	assert.Equal(t, "UNAVAILABLE", resp.Error.Status)
}

func TestAIPWriter_SuccessResponseUnchanged(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	type payload struct {
		Name string `json:"name"`
	}
	writer.Write(rec, req, &payload{Name: "test"})

	assert.Equal(t, 200, rec.Code)

	var resp payload
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "test", resp.Name)
}

func TestAIPWriter_ErrorWithDetails(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	err := errdef.ErrAPIKeyNotFound().WithReasonf("key not found").WithDetail("key_id", "abc123")
	code, resp := writeAndParse(t, writer, err)

	assert.Equal(t, 404, code)

	detailJSON, marshalErr := json.Marshal(resp.Error.Details[0])
	require.NoError(t, marshalErr)
	var detail aipErrorInfo
	require.NoError(t, json.Unmarshal(detailJSON, &detail))

	assert.Equal(t, "abc123", detail.Metadata["key_id"])
}

// TestAIPWriter_ResponseSnapshots locks down the full JSON wire format of AIP-193 error responses.
// Each snapshot captures the exact bytes a consumer would receive, ensuring we follow Google AIP-193
// and don't accidentally break the error contract.
func TestAIPWriter_ResponseSnapshots(t *testing.T) {
	t.Parallel()

	snapshotter := cupaloy.New(cupaloy.SnapshotSubdirectory(".snapshots"))
	writer := newTestWriter()

	tests := []struct {
		name string
		err  error
	}{
		// Domain-specific error with contextual reason and metadata
		{"not_found_with_reason_and_metadata", errdef.ErrAPIKeyNotFound().WithReasonf("key %s not found", "abc123").WithDetail("key_id", "abc123")},
		// Bare sentinel — no reason, no metadata (message falls back to ErrorField)
		{"expired_bare_sentinel", errdef.ErrAPIKeyExpired()},
		// Generic helper — inherits herodot base (no IDField)
		{"bad_request_generic", errdef.BadRequest("page_token is malformed")},
		// Non-herodot error — should produce a safe internal error
		{"non_herodot_plain_error", errors.New("unexpected nil pointer")},
		// Permission denied with contextual reason
		{"forbidden_ip_restriction", errdef.ErrIPNotAllowed().WithReasonf("192.168.1.1 is not in the allowed CIDR list")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v2alpha1/admin/issuedApiKeys/abc123", nil)
			writer.WriteError(rec, req, tt.err)

			// Pretty-print for readable snapshots
			var raw json.RawMessage
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
			pretty, err := json.MarshalIndent(raw, "", "  ")
			require.NoError(t, err)

			snapshotter.SnapshotT(t, string(pretty))
		})
	}
}

func TestAIPWriter_MessageFallback(t *testing.T) {
	t.Parallel()
	writer := newTestWriter()

	// Error without ReasonField — should use ErrorField as message
	code, resp := writeAndParse(t, writer, errdef.ErrAPIKeyExpired())
	assert.Equal(t, 401, code)
	assert.Equal(t, "The API key has expired.", resp.Error.Message)

	// Error with ReasonField — should use ReasonField
	code2, resp2 := writeAndParse(t, writer, errdef.ErrAPIKeyExpired().WithReasonf("expired 2h ago"))
	assert.Equal(t, 401, code2)
	assert.Equal(t, "expired 2h ago", resp2.Error.Message)

	// Error with neither ReasonField nor ErrorField — should use HTTP status text (W3)
	emptyErr := &herodot.DefaultError{
		CodeField:     500,
		GRPCCodeField: 0,
	}
	code3, resp3 := writeAndParse(t, writer, emptyErr)
	assert.Equal(t, 500, code3)
	assert.Equal(t, "Internal Server Error", resp3.Error.Message)
}

func TestSanitizeReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"bad_request", "BAD_REQUEST"},
		{"api-key-expired", "API_KEY_EXPIRED"},
		{"normal_id", "NORMAL_ID"},
		{"123_leading_digits", "LEADING_DIGITS"},
		{"__leading_underscores", "LEADING_UNDERSCORES"},
		{"trailing___", "TRAILING"},
		{"", "UNSPECIFIED_ERROR"},
		{"123", "UNSPECIFIED_ERROR"},
		{"a", "A"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, sanitizeReason(tt.input))
		})
	}
}

func TestHTTPToGRPCStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		httpCode int
		want     string
	}{
		{200, "OK"},
		{400, "INVALID_ARGUMENT"},
		{401, "UNAUTHENTICATED"},
		{403, "PERMISSION_DENIED"},
		{404, "NOT_FOUND"},
		{409, "ALREADY_EXISTS"},
		{429, "RESOURCE_EXHAUSTED"},
		{499, "CANCELLED"},
		{500, "INTERNAL"},
		{501, "UNIMPLEMENTED"},
		{503, "UNAVAILABLE"},
		{504, "DEADLINE_EXCEEDED"},
		{418, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, httpToGRPCStatus(tt.httpCode))
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
