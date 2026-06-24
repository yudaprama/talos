// Package http provides gRPC-Gateway HTTP/REST server functionality.
package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// GatewayVerifyPath is the edge/gateway-friendly verify route.
//
// Unlike the standard POST /v2alpha1/admin/apiKeys:verify (which always returns
// HTTP 200 and reports validity in the body), this endpoint returns HTTP 401 when
// the credential is invalid. That is the status-code contract an external auth
// decision point needs: an Ory Oathkeeper `remote_json` authenticator treats any
// 2xx as authenticated, so the gateway cannot use the 200-on-invalid admin
// endpoint directly.
//
// The credential is read from the JSON request body {"credential": "..."} or,
// failing that, the Authorization: Bearer header. A "Bearer " / "bearer " prefix
// is stripped from either source. A valid key yields 200 with the full
// VerifyApiKeyResponse serialized as camelCase JSON (protojson), e.g.
// {"isValid": true, "actorId": "..."} — so Oathkeeper can resolve the subject via
// `subject_from: "{{ .actorId }}"`.
const GatewayVerifyPath = "/gateway/verify"

var errGatewayCredentialMissing = errors.New("credential is required (body {\"credential\": \"...\"} or Authorization: Bearer)")

// handleGatewayVerify verifies a credential and returns 401 on failure, 200 on
// success. It delegates to the existing AdminVerifyApiKey service method; the
// only difference from the standard endpoint is the HTTP status code mapping.
func (s *GatewayServer) handleGatewayVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeGatewayVerifyError(w, http.StatusMethodNotAllowed, "VERIFICATION_ERROR_INVALID_FORMAT", "method not allowed")
		return
	}

	credential, err := extractGatewayCredential(r)
	if err != nil {
		writeGatewayVerifyError(w, http.StatusBadRequest, "VERIFICATION_ERROR_INVALID_FORMAT", err.Error())
		return
	}

	resp, verifyErr := s.adminAdapter.AdminVerifyApiKey(r.Context(), &talosv2alpha1.VerifyApiKeyRequest{
		Credential: credential,
	})
	// VerifyAPIKey maps every key-level failure to a 200 + IsValid:false body, so a
	// returned error here is an internal/server problem, not an invalid key.
	if verifyErr != nil {
		slog.WarnContext(r.Context(), "gateway verify call failed", slog.Any("error", verifyErr))
		writeGatewayVerifyError(w, http.StatusInternalServerError, "VERIFICATION_ERROR_INTERNAL", "verification failed")
		return
	}

	if resp == nil || !resp.GetIsValid() {
		code := "VERIFICATION_ERROR_INVALID"
		if c := resp.GetErrorCode(); c != 0 {
			code = c.String()
		}
		msg := "invalid credential"
		if m := resp.GetErrorMessage(); m != "" {
			msg = m
		}
		writeGatewayVerifyError(w, http.StatusUnauthorized, code, msg)
		return
	}

	body, mErr := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(resp)
	if mErr != nil {
		writeGatewayVerifyError(w, http.StatusInternalServerError, "VERIFICATION_ERROR_INTERNAL", "marshal response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// extractGatewayCredential resolves the credential from the request body
// {"credential": "..."} or, failing that, the Authorization: Bearer header. A
// "Bearer " / "bearer " prefix is stripped from either source.
func extractGatewayCredential(r *http.Request) (string, error) {
	if r.Body != nil && r.ContentLength != 0 {
		var payload struct {
			Credential string `json:"credential"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil && strings.TrimSpace(payload.Credential) != "" {
			return stripBearer(strings.TrimSpace(payload.Credential)), nil
		}
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		return stripBearer(auth), nil
	}
	return "", errGatewayCredentialMissing
}

func stripBearer(v string) string {
	if c, ok := strings.CutPrefix(v, "Bearer "); ok {
		return strings.TrimSpace(c)
	}
	if c, ok := strings.CutPrefix(v, "bearer "); ok {
		return strings.TrimSpace(c)
	}
	return strings.TrimSpace(v)
}

func writeGatewayVerifyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"isValid":      false,
		"errorCode":    code,
		"errorMessage": message,
	})
}
