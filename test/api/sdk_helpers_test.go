// Package api_test provides SDK-based HTTP test helpers
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	client "github.com/ory/talos/internal/client/generated"
)

// SDK Client Helpers
//
// These helpers use the generated OpenAPI SDK client for type-safe API calls.
// They replace the manual HTTP helpers in setup_test.go for better type safety,
// automatic error handling, and cleaner test code.
//
// Generated SDK location:
//   import client "github.com/ory/talos/internal/client/generated"

// closeBody schedules the HTTP response body for cleanup if non-nil.
func (s *APIKeyE2ETestSuite) closeBody(httpResp *http.Response) {
	s.T().Helper()
	if httpResp != nil && httpResp.Body != nil {
		s.T().Cleanup(func() { _ = httpResp.Body.Close() })
	}
}

// newImportReq creates a ImportApiKeyRequest with required fields for batch import tests.
func newImportReq(rawKey, name, actorID string) client.ImportApiKeyRequest {
	req := client.NewImportApiKeyRequest()
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
func (s *APIKeyE2ETestSuite) sdkIssueAPIKey(ctx context.Context, req *client.IssueApiKeyRequest) *client.IssueApiKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminIssueApiKey(ctx).
		IssueApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "create API key")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkVerify verifies a credential using the SDK
func (s *APIKeyE2ETestSuite) sdkVerify(ctx context.Context, credential string) *client.VerifyApiKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	req := client.NewVerifyApiKeyRequest()
	req.SetCredential(credential)

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminVerifyApiKey(ctx).
		VerifyApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "verify credential")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

// sdkVerifyNoCache verifies a credential with cache bypass (Cache-Control: no-cache).
// Use this after revocation to ensure fresh DB lookup instead of cached results.
func (s *APIKeyE2ETestSuite) sdkVerifyNoCache(ctx context.Context, credential string) *client.VerifyApiKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	apiClient.GetConfig().AddDefaultHeader("Cache-Control", "no-cache")

	req := client.NewVerifyApiKeyRequest()
	req.SetCredential(credential)

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminVerifyApiKey(ctx).
		VerifyApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "verify credential")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkBatchVerify performs batch verification using the SDK
func (s *APIKeyE2ETestSuite) sdkBatchVerify(ctx context.Context, credentials []string) *client.BatchVerifyApiKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()

	// Build array of verify requests
	requests := make([]client.VerifyApiKeyRequest, len(credentials))
	for i, cred := range credentials {
		req := client.NewVerifyApiKeyRequest()
		req.SetCredential(cred)
		requests[i] = *req
	}

	batchReq := client.NewBatchVerifyApiKeysRequest()
	batchReq.Requests = requests

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminBatchVerifyApiKeys(ctx).
		BatchVerifyApiKeysRequest(*batchReq).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "batch verify credentials")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkGetIssuedAPIKey retrieves an API key by ID using the SDK
func (s *APIKeyE2ETestSuite) sdkGetIssuedAPIKey(ctx context.Context, keyID string) *client.IssuedApiKey {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminGetIssuedApiKey(ctx, keyID).
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
func (s *APIKeyE2ETestSuite) sdkListIssuedAPIKeys(ctx context.Context, pageSize *int32, pageToken *string, actorID *string, status *string) *client.ListIssuedApiKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	req := apiClient.ApiKeysAPI.AdminListIssuedApiKeys(ctx)

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
func (s *APIKeyE2ETestSuite) sdkRotateIssuedAPIKey(ctx context.Context, keyID string, name *string, scopes []string, metadata map[string]any) *client.RotateIssuedApiKeyResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()

	body := client.NewAdminRotateIssuedApiKeyBody()
	if name != nil {
		body.SetName(*name)
	}
	if scopes != nil {
		body.SetScopes(scopes)
	}
	if metadata != nil {
		body.SetMetadata(metadata)
	}

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminRotateIssuedApiKey(ctx, keyID).
		AdminRotateIssuedApiKeyBody(*body).
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
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminDeriveToken(ctx).
		DeriveTokenRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "derive token")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkImportAPIKey imports an external API key using the SDK
func (s *APIKeyE2ETestSuite) sdkImportAPIKey(ctx context.Context, req *client.ImportApiKeyRequest) *client.ImportedApiKey {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminImportApiKey(ctx).
		ImportApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "import API key")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

func (s *APIKeyE2ETestSuite) sdkBatchImportAPIKeys(ctx context.Context, req *client.BatchCreateImportedApiKeysRequest) *client.BatchCreateImportedApiKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminBatchCreateImportedApiKeys(ctx).
		BatchCreateImportedApiKeysRequest(*req).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "batch import API keys")
	s.Require().NotNil(resp, "response should not be nil")

	return resp
}

// sdkGetImportedAPIKey retrieves an imported API key by ID using the SDK
func (s *APIKeyE2ETestSuite) sdkGetImportedAPIKey(ctx context.Context, keyID string) *client.ImportedApiKey {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminGetImportedApiKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "get imported API key")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

// sdkListImportedAPIKeys lists imported API keys using the SDK
func (s *APIKeyE2ETestSuite) sdkListImportedAPIKeys(ctx context.Context, pageSize *int32, pageToken *string, actorID *string, statusFilter ...string) *client.ListImportedApiKeysResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	req := apiClient.ApiKeysAPI.AdminListImportedApiKeys(ctx)

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
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminDeleteImportedApiKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "delete imported API key")
}

// sdkGetJWKS retrieves the JWKS using the SDK
func (s *APIKeyE2ETestSuite) sdkGetJWKS(ctx context.Context) *client.GetJWKSResponse {
	s.T().Helper()

	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		GetJwks(ctx).
		Execute()
	s.closeBody(httpResp)

	s.Require().NoError(err, "get JWKS")
	s.Require().NotNil(resp, "response should not be nil")
	return resp
}

func (s *APIKeyE2ETestSuite) sdkSelfRevoke(ctx context.Context, credential string, reason client.RevocationReason) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	req := client.NewSelfRevokeApiKeyRequest()
	req.SetCredential(credential)
	req.SetReason(reason)
	_, httpResp, err := apiClient.ApiKeysAPI.
		RevokeApiKey(ctx).
		SelfRevokeApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "self-revoke API key")
}

func (s *APIKeyE2ETestSuite) sdkIssueAPIKeyExpectError(ctx context.Context, req *client.IssueApiKeyRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminIssueApiKey(ctx).
		IssueApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkRevokeIssuedAPIKeyExpectError(ctx context.Context, keyID string, body client.AdminRevokeIssuedApiKeyBody) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRevokeIssuedApiKey(ctx, keyID).
		AdminRevokeIssuedApiKeyBody(body).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkSelfRevokeExpectError(ctx context.Context, req *client.SelfRevokeApiKeyRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		RevokeApiKey(ctx).
		SelfRevokeApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkVerifyExpectError(ctx context.Context, credential string) (*client.VerifyApiKeyResponse, *http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	req := client.NewVerifyApiKeyRequest()
	req.SetCredential(credential)
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminVerifyApiKey(ctx).
		VerifyApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return resp, httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkGetIssuedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminGetIssuedApiKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkRotateIssuedAPIKeyExpectError(ctx context.Context, keyID string, body client.AdminRotateIssuedApiKeyBody) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRotateIssuedApiKey(ctx, keyID).
		AdminRotateIssuedApiKeyBody(body).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkListIssuedAPIKeysExpectError(ctx context.Context, pageSize *int32, pageToken *string, actorID *string, statusFilter *string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	req := apiClient.ApiKeysAPI.AdminListIssuedApiKeys(ctx)
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

func (s *APIKeyE2ETestSuite) sdkImportAPIKeyExpectError(ctx context.Context, req *client.ImportApiKeyRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminImportApiKey(ctx).
		ImportApiKeyRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkBatchImportAPIKeysExpectError(ctx context.Context, req *client.BatchCreateImportedApiKeysRequest) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminBatchCreateImportedApiKeys(ctx).
		BatchCreateImportedApiKeysRequest(*req).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkGetImportedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminGetImportedApiKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkRevokeImportedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRevokeImportedApiKey(ctx, keyID).
		AdminRevokeImportedApiKeyBody(client.AdminRevokeImportedApiKeyBody{}).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkDeleteImportedAPIKeyExpectError(ctx context.Context, keyID string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminDeleteImportedApiKey(ctx, keyID).
		Execute()
	s.closeBody(httpResp)
	return httpResp, err
}

func (s *APIKeyE2ETestSuite) sdkDeriveTokenExpectError(ctx context.Context, req *client.DeriveTokenRequest) error {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	_, httpResp, err := apiClient.ApiKeysAPI.
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

// sdkRevokeIssuedAPIKeyWithReason revokes an issued API key with a reason.
// An optional reasonText can be provided (only valid with PRIVILEGE_WITHDRAWN).
func (s *APIKeyE2ETestSuite) sdkRevokeIssuedAPIKeyWithReason(ctx context.Context, keyID string, reason client.RevocationReason, reasonText ...string) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	body := client.NewAdminRevokeIssuedApiKeyBody()
	body.SetReason(reason)
	if len(reasonText) > 0 {
		body.SetDescription(reasonText[0])
	}
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRevokeIssuedApiKey(ctx, keyID).
		AdminRevokeIssuedApiKeyBody(*body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "revoke issued API key")
}

// sdkRevokeImportedAPIKeyWithReason revokes an imported API key with a reason.
// An optional reasonText can be provided (only valid with PRIVILEGE_WITHDRAWN).
func (s *APIKeyE2ETestSuite) sdkRevokeImportedAPIKeyWithReason(ctx context.Context, keyID string, reason client.RevocationReason, reasonText ...string) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	body := client.NewAdminRevokeImportedApiKeyBody()
	body.SetReason(reason)
	if len(reasonText) > 0 {
		body.SetDescription(reasonText[0])
	}
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRevokeImportedApiKey(ctx, keyID).
		AdminRevokeImportedApiKeyBody(*body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "revoke imported API key")
}

func (s *APIKeyE2ETestSuite) sdkRevokeIssuedAPIKeyWithReasonAndTextExpectError(ctx context.Context, keyID string, reason client.RevocationReason, reasonText string) (*http.Response, error) {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	body := client.NewAdminRevokeIssuedApiKeyBody()
	body.SetReason(reason)
	body.SetDescription(reasonText)
	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRevokeIssuedApiKey(ctx, keyID).
		AdminRevokeIssuedApiKeyBody(*body).
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

func (s *APIKeyE2ETestSuite) sdkUpdateIssuedAPIKey(ctx context.Context, keyID string, body client.AdminUpdateIssuedApiKeyRequest) *client.IssuedApiKey {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminUpdateIssuedApiKey(ctx, keyID).
		AdminUpdateIssuedApiKeyRequest(body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "update issued API key")
	s.Require().NotNil(resp)
	return resp
}

func (s *APIKeyE2ETestSuite) sdkUpdateImportedAPIKey(ctx context.Context, keyID string, body client.AdminUpdateImportedApiKeyRequest) *client.ImportedApiKey {
	s.T().Helper()
	apiClient := s.setupSDKClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminUpdateImportedApiKey(ctx, keyID).
		AdminUpdateImportedApiKeyRequest(body).
		Execute()
	s.closeBody(httpResp)
	s.Require().NoError(err, "update imported API key")
	s.Require().NotNil(resp)
	return resp
}

// reviewed - @aeneasr - 2026-03-27
