// Package api_test provides SDK-based HTTP test helpers
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	client "github.com/ory-corp/talos/internal/client/generated"
)

// SDK Client Helpers
//
// These helpers use the generated OpenAPI SDK client for type-safe API calls.
// They replace the manual HTTP helpers in setup_test.go for better type safety,
// automatic error handling, and cleaner test code.
//
// Generated SDK location:
//   import client "github.com/ory-corp/talos/internal/client/generated"

// closeBody schedules the HTTP response body for cleanup if non-nil.
func (s *APIKeyE2ETestSuite) closeBody(httpResp *http.Response) {
	s.T().Helper()
	if httpResp != nil && httpResp.Body != nil {
		s.T().Cleanup(func() { _ = httpResp.Body.Close() })
	}
}

// newImportReq creates a ImportAPIKeyRequest with required fields for batch import tests.
func newImportReq(rawKey, name, actorID string) client.ImportAPIKeyRequest {
	req := client.NewImportAPIKeyRequest()
	req.SetRawKey(rawKey)
	req.SetName(name)
	req.SetActorId(actorID)
	return *req
}

// setupSDKClient creates a configured SDK client for the test server
func (s *APIKeyE2ETestSuite) setupSDKClient() *client.APIClient {
	s.T().Helper()

	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{{URL: s.testServer.HTTPURL}}
	return client.NewAPIClient(cfg)
}

// sdkIssueAPIKey creates an API key using the SDK
func (s *APIKeyE2ETestSuite) sdkIssueAPIKey(ctx context.Context, req *client.IssueAPIKeyRequest) *client.IssueAPIKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminIssueAPIKey(ctx).
		IssueAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "create API key")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkVerify verifies a credential using the SDK
func (s *APIKeyE2ETestSuite) sdkVerify(ctx context.Context, credential string) *client.VerifyAPIKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	req := client.NewVerifyAPIKeyRequest()
	req.SetCredential(credential)

	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminVerifyAPIKey(ctx).
		VerifyAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "verify credential")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

// sdkVerifyNoCache verifies a credential with cache bypass (Cache-Control: no-cache).
// Use this after revocation to ensure fresh DB lookup instead of cached results.
func (s *APIKeyE2ETestSuite) sdkVerifyNoCache(ctx context.Context, credential string) *client.VerifyAPIKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	apiClient.GetConfig().AddDefaultHeader("Cache-Control", "no-cache")

	req := client.NewVerifyAPIKeyRequest()
	req.SetCredential(credential)

	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminVerifyAPIKey(ctx).
		VerifyAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "verify credential")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkBatchVerify performs batch verification using the SDK
func (s *APIKeyE2ETestSuite) sdkBatchVerify(ctx context.Context, credentials []string) *client.BatchVerifyAPIKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()

	// Build array of verify requests
	requests := make([]client.VerifyAPIKeyRequest, len(credentials))
	for i, cred := range credentials {
		req := client.NewVerifyAPIKeyRequest()
		req.SetCredential(cred)
		requests[i] = *req
	}

	batchReq := client.NewBatchVerifyAPIKeysRequest()
	batchReq.Requests = requests

	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminBatchVerifyAPIKeys(ctx).
		BatchVerifyAPIKeysRequest(*batchReq).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "batch verify credentials")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkGetIssuedAPIKey retrieves an API key by ID using the SDK
func (s *APIKeyE2ETestSuite) sdkGetIssuedAPIKey(ctx context.Context, keyID string) *client.IssuedAPIKey {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminGetIssuedAPIKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "get API key")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// buildIssuedKeysFilter constructs an AIP-160 filter string from optional actorID and status parameters.
func buildIssuedKeysFilter(actorID *string, status *string) string {
	var filterParts []string
	if actorID != nil {
		filterParts = append(filterParts, fmt.Sprintf("actor_id=%q", *actorID))
	}
	if status != nil && *status != "" {
		filterParts = append(filterParts, "status="+*status)
	}
	return strings.Join(filterParts, " AND ")
}

// sdkListIssuedAPIKeys lists API keys using the SDK
func (s *APIKeyE2ETestSuite) sdkListIssuedAPIKeys(ctx context.Context, pageSize *int32, pageToken *string, actorID *string, status *string) *client.ListIssuedAPIKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	req := apiClient.APIKeysAPI.AdminListIssuedAPIKeys(ctx)

	if pageSize != nil {
		req = req.PageSize(*pageSize)
	}
	if pageToken != nil {
		req = req.PageToken(*pageToken)
	}
	if filter := buildIssuedKeysFilter(actorID, status); filter != "" {
		req = req.Filter(filter)
	}

	resp, httpResp, err := req.Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "list API keys")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

// sdkRotateIssuedAPIKey rotates an API key using the SDK
func (s *APIKeyE2ETestSuite) sdkRotateIssuedAPIKey(ctx context.Context, keyID string, name *string, scopes []string, metadata map[string]any) *client.RotateIssuedAPIKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()

	body := client.NewAdminRotateIssuedAPIKeyBody()
	if name != nil {
		body.SetName(*name)
	}
	if scopes != nil {
		body.SetScopes(scopes)
	}
	if metadata != nil {
		body.SetMetadata(metadata)
	}

	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminRotateIssuedAPIKey(ctx, keyID).
		AdminRotateIssuedAPIKeyBody(*body).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "rotate API key")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkDeriveToken derives a token from an API key using the SDK
func (s *APIKeyE2ETestSuite) sdkDeriveToken(ctx context.Context, req *client.DeriveTokenRequest) *client.DeriveTokenResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminDeriveToken(ctx).
		DeriveTokenRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "derive token")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkImportAPIKey imports an external API key using the SDK
func (s *APIKeyE2ETestSuite) sdkImportAPIKey(ctx context.Context, req *client.ImportAPIKeyRequest) *client.ImportedAPIKey {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminImportAPIKey(ctx).
		ImportAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "import API key")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

func (s *APIKeyE2ETestSuite) sdkBatchImportAPIKeys(ctx context.Context, req *client.BatchImportAPIKeysRequest) *client.BatchImportAPIKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminBatchImportAPIKeys(ctx).
		BatchImportAPIKeysRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "batch import API keys")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

// sdkGetImportedAPIKey retrieves an imported API key by ID using the SDK
func (s *APIKeyE2ETestSuite) sdkGetImportedAPIKey(ctx context.Context, keyID string) *client.ImportedAPIKey {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminGetImportedAPIKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "get imported API key")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkListImportedAPIKeys lists imported API keys using the SDK
func (s *APIKeyE2ETestSuite) sdkListImportedAPIKeys(ctx context.Context, pageSize *int32, pageToken *string, actorID *string, statusFilter ...string) *client.ListImportedAPIKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	req := apiClient.APIKeysAPI.AdminListImportedAPIKeys(ctx)

	if pageSize != nil {
		req = req.PageSize(*pageSize)
	}
	if pageToken != nil {
		req = req.PageToken(*pageToken)
	}
	// Build AIP-160 filter expression from individual parameters
	var filterParts []string
	if actorID != nil {
		filterParts = append(filterParts, "actor_id=\""+*actorID+"\"")
	}
	if len(statusFilter) > 0 && statusFilter[0] != "" {
		filterParts = append(filterParts, "status="+statusFilter[0])
	}
	if len(filterParts) > 0 {
		req = req.Filter(strings.Join(filterParts, " AND "))
	}

	resp, httpResp, err := req.Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "list imported API keys")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkDeleteImportedAPIKey deletes an imported API key using the SDK
func (s *APIKeyE2ETestSuite) sdkDeleteImportedAPIKey(ctx context.Context, keyID string) {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminDeleteImportedAPIKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "delete imported API key")
}

// sdkGetJWKS retrieves the JWKS using the SDK
func (s *APIKeyE2ETestSuite) sdkGetJWKS(ctx context.Context) *client.GetJWKSResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		GetJWKS(ctx).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "get JWKS")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

func (s *APIKeyE2ETestSuite) sdkSelfRevoke(ctx context.Context, credential string, reason client.RevocationReason) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	req := client.NewSelfRevokeAPIKeyRequest()
	req.SetCredential(credential)
	req.SetReason(reason)
	_, httpResp, err := apiClient.APIKeysAPI.
		RevokeAPIKey(ctx).
		SelfRevokeAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "self-revoke API key")
}

func (s *APIKeyE2ETestSuite) sdkIssueAPIKeyExpectError(ctx context.Context, req *client.IssueAPIKeyRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminIssueAPIKey(ctx).
		IssueAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkRevokeAPIKeyExpectError(ctx context.Context, keyID string, body client.AdminRevokeAPIKeyBody) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminRevokeAPIKey(ctx, keyID).
		AdminRevokeAPIKeyBody(body).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkSelfRevokeExpectError(ctx context.Context, req *client.SelfRevokeAPIKeyRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		RevokeAPIKey(ctx).
		SelfRevokeAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkVerifyExpectError(ctx context.Context, credential string) (*client.VerifyAPIKeyResponse, *http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	req := client.NewVerifyAPIKeyRequest()
	req.SetCredential(credential)
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminVerifyAPIKey(ctx).
		VerifyAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return resp, httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkGetIssuedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminGetIssuedAPIKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkRotateIssuedAPIKeyExpectError(ctx context.Context, keyID string, body client.AdminRotateIssuedAPIKeyBody) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminRotateIssuedAPIKey(ctx, keyID).
		AdminRotateIssuedAPIKeyBody(body).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkListIssuedAPIKeysExpectError(ctx context.Context, pageSize *int32, pageToken *string, actorID *string, statusFilter *string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	req := apiClient.APIKeysAPI.AdminListIssuedAPIKeys(ctx)
	if pageSize != nil {
		req = req.PageSize(*pageSize)
	}
	if pageToken != nil {
		req = req.PageToken(*pageToken)
	}
	if filter := buildIssuedKeysFilter(actorID, statusFilter); filter != "" {
		req = req.Filter(filter)
	}
	_, httpResp, err := req.Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkImportAPIKeyExpectError(ctx context.Context, req *client.ImportAPIKeyRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminImportAPIKey(ctx).
		ImportAPIKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkBatchImportAPIKeysExpectError(ctx context.Context, req *client.BatchImportAPIKeysRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminBatchImportAPIKeys(ctx).
		BatchImportAPIKeysRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkGetImportedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminGetImportedAPIKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkRevokeImportedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminRevokeAPIKey(ctx, keyID).
		AdminRevokeAPIKeyBody(client.AdminRevokeAPIKeyBody{}).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkDeleteImportedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminDeleteImportedAPIKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkDeriveTokenExpectError(ctx context.Context, req *client.DeriveTokenRequest) error {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminDeriveToken(ctx).
		DeriveTokenRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return err
}

func (s *APIKeyE2ETestSuite) requireHTTPError(err error, httpResp *http.Response, expectedStatus int) {
	s.T().Helper()
	s.Require().Error(err, "expected HTTP error")
	s.Require().NotNil(httpResp, "HTTP response should not be nil")
	s.closeBody(httpResp)
	s.Equal(expectedStatus, httpResp.StatusCode, "unexpected HTTP status code")
}

func (s *APIKeyE2ETestSuite) requireHTTPErrorContains(err error, httpResp *http.Response, reasonSubstring string) {
	s.T().Helper()
	s.Require().Error(err, "expected HTTP error")
	s.Require().NotNil(httpResp, "HTTP response should not be nil")
	s.Equal(http.StatusBadRequest, httpResp.StatusCode, "unexpected HTTP status code")
	body, readErr := io.ReadAll(httpResp.Body)
	s.T().Cleanup(func() { _ = httpResp.Body.Close() })
	s.Require().NoError(readErr, "read error response body")
	var errorBody struct {
		Error struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"error"`
	}
	s.Require().NoError(json.Unmarshal(body, &errorBody), "parse error body: %s", string(body))
	s.Contains(errorBody.Error.Reason, reasonSubstring, "error reason should contain %q, got %q", reasonSubstring, errorBody.Error.Reason)
}

// sdkRevokeAPIKeyWithReason revokes any API key (issued or imported) with a reason.
// An optional reasonText can be provided (only valid with PRIVILEGE_WITHDRAWN).
func (s *APIKeyE2ETestSuite) sdkRevokeAPIKeyWithReason(ctx context.Context, keyID string, reason client.RevocationReason, reasonText ...string) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	body := client.NewAdminRevokeAPIKeyBody()
	body.SetReason(reason)
	if len(reasonText) > 0 {
		body.SetDescription(reasonText[0])
	}
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminRevokeAPIKey(ctx, keyID).
		AdminRevokeAPIKeyBody(*body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "revoke API key")
}

func (s *APIKeyE2ETestSuite) sdkRevokeAPIKeyWithReasonAndTextExpectError(ctx context.Context, keyID string, reason client.RevocationReason, reasonText string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	body := client.NewAdminRevokeAPIKeyBody()
	body.SetReason(reason)
	body.SetDescription(reasonText)
	_, httpResp, err := apiClient.APIKeysAPI.
		AdminRevokeAPIKey(ctx, keyID).
		AdminRevokeAPIKeyBody(*body).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

// sdkVerifyRaw sends a raw HTTP verify request and returns the *http.Response,
// allowing callers to inspect HTTP headers (e.g., rate limit headers) that the SDK discards.
func (s *APIKeyE2ETestSuite) sdkVerifyRaw(ctx context.Context, credential string) *http.Response {
	s.T().Helper()

	body := fmt.Sprintf(`{"credential":%q}`, credential)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.testServer.HTTPURL+"/v2alpha1/admin/apiKeys:verify",
		strings.NewReader(body))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (s *APIKeyE2ETestSuite) sdkUpdateIssuedAPIKey(ctx context.Context, keyID string, body client.AdminUpdateIssuedAPIKeyRequest) *client.IssuedAPIKey {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminUpdateIssuedAPIKey(ctx, keyID).
		AdminUpdateIssuedAPIKeyRequest(body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "update issued API key")
	s.Require().NotNil(resp)
	return resp
}

func (s *APIKeyE2ETestSuite) sdkUpdateImportedAPIKey(ctx context.Context, keyID string, body client.AdminUpdateImportedAPIKeyRequest) *client.ImportedAPIKey {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.APIKeysAPI.
		AdminUpdateImportedAPIKey(ctx, keyID).
		AdminUpdateImportedAPIKeyRequest(body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "update imported API key")
	s.Require().NotNil(resp)
	return resp
}

// reviewed - @aeneasr - 2026-03-27
