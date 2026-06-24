package http

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// fakeVerifyServer is a minimal ApiKeysServer that only implements
// AdminVerifyApiKey, returning a canned response/error. All other methods come
// from the embedded UnimplementedApiKeysServer.
type fakeVerifyServer struct {
	talosv2alpha1.UnimplementedApiKeysServer
	resp *talosv2alpha1.VerifyApiKeyResponse
	err  error
}

func (f *fakeVerifyServer) AdminVerifyApiKey(_ context.Context, _ *talosv2alpha1.VerifyApiKeyRequest) (*talosv2alpha1.VerifyApiKeyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func TestHandleGatewayVerify(t *testing.T) {
	invalidFmt := talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT
	validResp := &talosv2alpha1.VerifyApiKeyResponse{IsValid: true, ActorId: "actor-1"}
	invalidResp := &talosv2alpha1.VerifyApiKeyResponse{
		IsValid:      false,
		ErrorCode:    &invalidFmt,
		ErrorMessage: proto.String("nope"),
	}

	cases := []struct {
		name             string
		method           string
		body             string
		auth             string
		fakeResp         *talosv2alpha1.VerifyApiKeyResponse
		fakeErr          error
		wantStatus       int
		wantBodyContains string
	}{
		{
			name: "valid via body credential", method: http.MethodPost,
			body: `{"credential":"sk-xyz"}`, fakeResp: validResp,
			wantStatus: http.StatusOK, wantBodyContains: `"actorId":"actor-1"`,
		},
		{
			name: "valid via Authorization Bearer (prefix stripped)", method: http.MethodPost,
			auth: "Bearer sk-xyz", fakeResp: validResp,
			wantStatus: http.StatusOK, wantBodyContains: `"isValid":true`,
		},
		{
			name: "invalid credential maps to 401", method: http.MethodPost,
			body: `{"credential":"bad"}`, fakeResp: invalidResp,
			wantStatus: http.StatusUnauthorized, wantBodyContains: `"isValid":false`,
		},
		{
			name: "missing credential maps to 400", method: http.MethodPost,
			body: `{}`, wantStatus: http.StatusBadRequest,
		},
		{
			name: "service error maps to 500", method: http.MethodPost,
			body: `{"credential":"x"}`, fakeErr: errors.New("boom"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "GET with Bearer also works", method: http.MethodGet,
			auth: "Bearer sk-xyz", fakeResp: validResp,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &GatewayServer{adminAdapter: &fakeVerifyServer{resp: tc.fakeResp, err: tc.fakeErr}}

			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, GatewayVerifyPath, body)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()

			s.handleGatewayVerify(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code, "status for %q; body=%s", tc.name, rec.Body.String())
			if tc.wantBodyContains != "" {
				assert.Contains(t, rec.Body.String(), tc.wantBodyContains)
			}
		})
	}
}

func TestStripBearer(t *testing.T) {
	assert.Equal(t, "sk-x", stripBearer("Bearer sk-x"))
	assert.Equal(t, "sk-x", stripBearer("bearer sk-x"))
	assert.Equal(t, "sk-x", stripBearer("sk-x"))
}
