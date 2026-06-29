// Package testserver provides test server utilities that require the testing package.
// Separated to prevent testing package from polluting production binaries.
package testserver

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	commercialregistry "github.com/ory/talos/commercial/registry"
	"github.com/ory/talos/internal/boot"
	client "github.com/ory/talos/internal/client/generated"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/metrics"
	"github.com/ory/talos/internal/ratelimit"
	"github.com/ory/talos/internal/registry"
	httpserver "github.com/ory/talos/internal/server/http"
	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/testutil"
	"github.com/ory/talos/internal/verifier"
)

// TestServer represents a test Ory Talos server with file-based database and HTTP gateway.
// All interactions go through the HTTP SDK client, matching production behavior.
type TestServer struct {
	t        *testing.T
	Emitter  *testutil.MockEmitter
	Metrics  *metrics.Metrics
	HTTPURL  string
	Gatherer prometheus.Gatherer
	verifier *verifier.Verifier
	Provider *config.Provider
}

// serverConfig holds pre-construction configuration for the test server.
type serverConfig struct {
	limiter         ratelimit.Limiter
	configOverrides map[string]any
}

// Option allows customizing test server setup
type Option func(*serverConfig)

// WithRateLimiter sets the rate limiter used by the public server.
// Defaults to &ratelimit.NoopLimiter{} when not provided.
func WithRateLimiter(l ratelimit.Limiter) Option {
	return func(cfg *serverConfig) {
		cfg.limiter = l
	}
}

// WithConfigOverrides sets additional config values applied on top of the test
// server defaults. Keys are dotted config paths (e.g.
// "credentials.derived_tokens.jwt.signing_key_id"). Values override any
// matching default in createMockProviderForTestServer.
func WithConfigOverrides(values map[string]any) Option {
	return func(cfg *serverConfig) {
		cfg.configOverrides = values
	}
}

// createMockProviderForTestServer creates a properly configured config provider
// with all required test defaults for the test server. Additional configx options
// can be passed to override defaults (e.g., setting cache type for commercial builds).
func createMockProviderForTestServer(t *testing.T, extraOpts ...configx.OptionModifier) *config.Provider {
	t.Helper()

	// Generate signing keys and encode as base64:// literal (required by the config schema).
	keyURL := testutil.TestSigningKeyJWKSURL(t)

	opts := append([]configx.OptionModifier{configx.WithValues(map[string]any{
		config.KeySecretsHMACCurrent.String():                            "test-hmac-secret-for-api-key-checksum-validation-32chars",
		config.KeyCredentialsAPIKeysDefaultTTL.String():                  "24h",
		config.KeyCredentialsAPIKeysMaxTTL.String():                      "8760h", // 365*24*time.Hour
		config.KeyCacheEnabled.String():                                  true,
		config.KeyCacheTTL.String():                                      "5m",
		config.KeyCredentialsAPIKeysPrefixCurrent.String():               "talos",
		config.KeyCredentialsDerivedTokensDefaultTTL.String():            "1h",
		config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent.String(): "mc",
		config.KeyCacheMemoryMaxSize.String():                            100 * 1024 * 1024,
		config.KeyCacheMemoryNumCounters.String():                        10000,
		config.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String():    []string{keyURL},
	})}, extraOpts...)
	return testutil.NewTestProvider(t, opts...)
}

// NewTestServer creates a new test server with file-based SQLite database.
// Uses registry.ServiceFactory for service construction, matching production.
func NewTestServer(t *testing.T, opts ...Option) *TestServer {
	t.Helper()
	ctx := t.Context()

	// Apply options to serverConfig before constructing the server.
	cfg := &serverConfig{
		limiter: &ratelimit.NoopLimiter{},
	}
	for _, opt := range opts {
		opt(cfg)
	}
	// Initialize file-based SQLite database.
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err, "initialize test database")

	// Create MockEmitter for capturing audit events
	mockEmitter := testutil.NewMockEmitter()

	// Create JSON writer for HTTP error responses.
	writer := herodot.NewJSONWriter(nil)

	// User-supplied config overrides are applied after defaults so they win.
	var extraOverrides []configx.OptionModifier
	if len(cfg.configOverrides) > 0 {
		extraOverrides = append(extraOverrides, configx.WithValues(cfg.configOverrides))
	}

	// Initialize feature options (commercial builds provide cache factories and multi-tenant middleware).
	// First pass uses a minimal provider — Options() doesn't depend on cache config.
	initialProvider := createMockProviderForTestServer(t, extraOverrides...)
	propOpts, err := commercialregistry.Options(ctx, initialProvider, nil, writer)
	require.NoError(t, err, "initialize feature options")

	// Select cache type based on available factories: "memory" when commercial
	// cache factories are registered, schema default ("noop") for OSS.
	providerOpts := append([]configx.OptionModifier{}, extraOverrides...)
	if len(propOpts.CacheFactories) > 0 {
		providerOpts = append(providerOpts, configx.WithValues(map[string]any{
			config.KeyCacheType.String(): "memory",
		}))
	}
	mockProvider := createMockProviderForTestServer(t, providerOpts...)

	// Create ServiceFactory (same as production)
	promRegistry := prometheus.NewRegistry()
	factory, err := registry.NewServiceFactory(ctx, driver, mockProvider, mockEmitter, httpx.NewResilientClient(), propOpts.CacheFactories, nil, promRegistry)
	require.NoError(t, err, "create service factory")
	t.Cleanup(func() { _ = factory.Close() })

	// Create services through factory (same as production)
	admin, err := factory.CreateAdmin(ctx)
	require.NoError(t, err, "create admin")

	verifier, err := factory.CreateVerifier(ctx)
	require.NoError(t, err, "create verifier")

	// Build adapters with the (potentially custom) rate limiter.
	publicSvc := service.NewPublic(verifier, factory.ProtoValidator(), cfg.limiter, nil, admin)
	adminAdapter := httpserver.NewAllInOneAdapter(admin, publicSvc)

	// Create health checker
	healthChecker := health.NewChecker(writer)

	// Use boot.HTTPHandlerFromDependencies with pre-built adapters to match production
	// gateway + middleware wiring while supporting the custom rate limiter option.
	deps := &boot.ServerDependencies{
		Writer:        writer,
		Factory:       factory,
		Provider:      mockProvider,
		HealthChecker: healthChecker,
		PropOpts:      propOpts,
		Mode:          boot.ModeAllInOne,
		PreBuiltAdmin: adminAdapter,
	}
	handler, err := boot.HTTPHandlerFromDependencies(ctx, deps, &boot.HandlerOptions{
		SkipOTEL:           true,
		SkipRequestID:      true,
		SkipRequestLogging: true,
	})
	require.NoError(t, err, "create HTTP handler")

	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)

	return &TestServer{
		t:        t,
		Emitter:  mockEmitter,
		Metrics:  factory.Metrics(),
		HTTPURL:  httpServer.URL,
		Gatherer: promRegistry,
		verifier: verifier,
		Provider: mockProvider,
	}
}

// ResetFailureEventLimiter clears the per-NID rate-limit buckets on the
// verifier so that subtests checking failure-event emission are not
// affected by limits consumed by earlier tests.
func (ts *TestServer) ResetFailureEventLimiter() {
	ts.verifier.ResetFailureEventLimiter()
}

// Close is a no-op. Cleanup is handled by t.Cleanup callbacks registered in NewTestServer.
func (ts *TestServer) Close() {
	// All cleanup handled by t.Cleanup in NewTestServer
}

// sdkClient creates a configured SDK client for the test server
func (ts *TestServer) sdkClient() *client.APIClient {
	ts.t.Helper()
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{{URL: ts.HTTPURL}}
	return client.NewAPIClient(cfg)
}

// CreateTestAPIKey creates an API key for testing via HTTP SDK
func (ts *TestServer) CreateTestAPIKey(t *testing.T, name string) (*client.IssuedApiKey, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	req := client.NewIssueApiKeyRequest()
	req.SetName(name)
	req.SetActorId("test-user")
	req.SetScopes([]string{"read", "write"})

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminIssueApiKey(ctx).
		IssueApiKeyRequest(*req).
		Execute()
	require.NoError(t, err, "create test API key")
	require.NotNil(t, resp.IssuedApiKey)
	require.NotEmpty(t, resp.GetSecret(), "secret should not be empty")
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}

	return resp.IssuedApiKey, resp.GetSecret()
}

// CreateTestAPIKeyWithOptions creates an API key with custom options via HTTP SDK.
// Accepts the protobuf request type for backward compatibility with existing test setup code,
// but sends the request through HTTP.
func (ts *TestServer) CreateTestAPIKeyWithOptions(t *testing.T, name, actorID string, scopes []string, ttl *string, metadata map[string]any) (*client.IssuedApiKey, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	req := client.NewIssueApiKeyRequest()
	req.SetName(name)
	req.SetActorId(actorID)
	if scopes != nil {
		req.SetScopes(scopes)
	}
	if ttl != nil {
		req.SetTtl(*ttl)
	}
	if metadata != nil {
		req.SetMetadata(metadata)
	}

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminIssueApiKey(ctx).
		IssueApiKeyRequest(*req).
		Execute()
	require.NoError(t, err, "create test API key")
	require.NotNil(t, resp.IssuedApiKey)
	require.NotEmpty(t, resp.GetSecret())
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}

	return resp.IssuedApiKey, resp.GetSecret()
}

// VerifyTestToken verifies a credential via HTTP SDK
func (ts *TestServer) VerifyTestToken(t *testing.T, credential string) *client.VerifyApiKeyResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	req := client.NewVerifyApiKeyRequest()
	req.SetCredential(credential)

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminVerifyApiKey(ctx).
		VerifyApiKeyRequest(*req).
		Execute()
	require.NoError(t, err, "verify test credential")
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}

	return resp
}

// DeriveTestToken derives a session token from an API key token via HTTP SDK
func (ts *TestServer) DeriveTestToken(t *testing.T, apiKeyToken string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	req := client.NewDeriveTokenRequest()
	req.SetCredential(apiKeyToken)

	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminDeriveToken(ctx).
		DeriveTokenRequest(*req).
		Execute()
	require.NoError(t, err, "derive test token")
	require.NotNil(t, resp.Token)
	require.NotEmpty(t, resp.Token.GetToken())
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}

	return resp.Token.GetToken()
}

// RevokeTestAPIKey revokes an issued API key via HTTP SDK
func (ts *TestServer) RevokeTestAPIKey(t *testing.T, keyID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	body := client.NewAdminRevokeIssuedApiKeyBody()
	body.SetReason(client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

	_, httpResp, err := apiClient.ApiKeysAPI.
		AdminRevokeIssuedApiKey(ctx, keyID).
		AdminRevokeIssuedApiKeyBody(*body).
		Execute()
	require.NoError(t, err, "revoke test API key")
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}
}

// AssertAPIKeyExists checks that an API key exists and is active via HTTP SDK
func (ts *TestServer) AssertAPIKeyExists(t *testing.T, keyID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminGetIssuedApiKey(ctx, keyID).
		Execute()
	require.NoError(t, err, "API key %s should exist", keyID)
	require.NotNil(t, resp)
	require.Equal(t, keyID, resp.GetKeyId())
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}
}

// AssertAPIKeyRevoked checks that an API key has been revoked via HTTP SDK
func (ts *TestServer) AssertAPIKeyRevoked(t *testing.T, keyID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	apiClient := ts.sdkClient()
	resp, httpResp, err := apiClient.ApiKeysAPI.
		AdminGetIssuedApiKey(ctx, keyID).
		Execute()
	require.NoError(t, err, "API key %s should exist", keyID)
	require.NotNil(t, resp)
	require.Equal(t, string(client.KEYSTATUS_KEY_STATUS_REVOKED), string(resp.GetStatus()), "API key should be revoked")
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}
}

// reviewed - @aeneasr - 2026-03-27
