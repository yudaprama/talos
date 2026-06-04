package service_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"buf.build/go/protovalidate"

	"github.com/ory/x/httpx"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/metrics"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/ratelimit"
	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/testutil"
	"github.com/ory/talos/internal/verifier"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// newPublicForTest builds a *service.Public that shares the supplied verifier.
// JWKS reads signing keys via the verifier, so the resulting Public sees the
// same key set as the Admin from setupTestService.
func newPublicForTest(t *testing.T, v *verifier.Verifier) *service.Public {
	t.Helper()
	pv, err := protovalidate.New()
	require.NoError(t, err)
	return service.NewPublic(v, pv, &ratelimit.NoopLimiter{})
}

// TestGetJWKS tests the GetJwks service method with various signing key configurations
func TestGetJWKS(t *testing.T) {
	t.Parallel()

	t.Run("success - active signing key present", func(t *testing.T) {
		_, v, ctx := setupTestService(t)
		pub := newPublicForTest(t, v)

		resp, err := pub.GetJwks(ctx, &talosv2alpha1.GetJWKSRequest{})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Jwks)

		// Convert protobuf struct to map for inspection
		jwksMap := resp.Jwks.AsMap()
		require.Contains(t, jwksMap, "keys")

		keys, ok := jwksMap["keys"].([]any)
		require.True(t, ok, "keys should be an array")
		require.NotEmpty(t, keys, "should have at least one key")

		// Validate first key structure (RFC 7517 compliance)
		firstKey, ok := keys[0].(map[string]any)
		require.True(t, ok, "key should be a map")

		// Required JWK fields (RFC 7517)
		assert.Contains(t, firstKey, "kty", "key type (kty) is required")
		assert.Contains(t, firstKey, "use", "public key use (use) should be present")
		assert.Contains(t, firstKey, "kid", "key ID (kid) should be present")

		// Verify key type
		kty, ok := firstKey["kty"].(string)
		require.True(t, ok, "kty should be a string")
		assert.NotEmpty(t, kty, "key type should not be empty")

		// Verify use field (should be "sig" for signing keys)
		use, ok := firstKey["use"].(string)
		require.True(t, ok, "use should be a string")
		assert.Equal(t, "sig", use, "use should be 'sig' for signing keys")

		// Verify kid is present
		kid, ok := firstKey["kid"].(string)
		require.True(t, ok, "kid should be a string")
		assert.NotEmpty(t, kid, "key ID should not be empty")

		// Verify algorithm field if present
		if alg, exists := firstKey["alg"]; exists {
			algStr, ok := alg.(string)
			require.True(t, ok, "alg should be a string")
			assert.NotEmpty(t, algStr, "algorithm should not be empty")
		}
	})

	t.Run("success - EdDSA key format", func(t *testing.T) {
		_, v, ctx := setupTestService(t)
		pub := newPublicForTest(t, v)

		resp, err := pub.GetJwks(ctx, &talosv2alpha1.GetJWKSRequest{})
		require.NoError(t, err)

		jwksMap := resp.Jwks.AsMap()
		keys, ok := jwksMap["keys"].([]any)
		require.True(t, ok, "keys should be an array")
		firstKey, ok := keys[0].(map[string]any)
		require.True(t, ok, "key should be a map")

		// For Ed25519 keys, expect OKP key type
		kty, ok := firstKey["kty"].(string)
		require.True(t, ok, "kty should be a string")
		assert.Equal(t, "OKP", kty, "Ed25519 keys should have OKP key type")

		// Should have crv (curve) field for OKP keys
		if kty == "OKP" {
			assert.Contains(t, firstKey, "crv", "OKP keys should have curve (crv)")
			assert.Contains(t, firstKey, "x", "OKP keys should have x coordinate")

			// Verify curve is Ed25519
			crv, ok := firstKey["crv"].(string)
			require.True(t, ok)
			assert.Equal(t, "Ed25519", crv, "curve should be Ed25519")
		}

		// Should NOT contain private key material
		assert.NotContains(t, firstKey, "d", "should not expose private key material (d parameter)")
	})

	t.Run("success - no private key material leaked", func(t *testing.T) {
		_, v, ctx := setupTestService(t)
		pub := newPublicForTest(t, v)

		resp, err := pub.GetJwks(ctx, &talosv2alpha1.GetJWKSRequest{})
		require.NoError(t, err)

		jwksMap := resp.Jwks.AsMap()
		keys, ok := jwksMap["keys"].([]any)
		require.True(t, ok, "keys should be an array")

		for i, keyInterface := range keys {
			key, ok := keyInterface.(map[string]any)
			require.True(t, ok, "key %d should be a map", i)

			// RFC 7517: private key material should NEVER appear in public JWKS
			assert.NotContains(t, key, "d", "key %d should not contain private exponent (d)", i)
			assert.NotContains(t, key, "p", "key %d should not contain prime factor p", i)
			assert.NotContains(t, key, "q", "key %d should not contain prime factor q", i)
			assert.NotContains(t, key, "dp", "key %d should not contain dp", i)
			assert.NotContains(t, key, "dq", "key %d should not contain dq", i)
			assert.NotContains(t, key, "qi", "key %d should not contain qi", i)
		}
	})

	t.Run("success - JWKS is valid JSON", func(t *testing.T) {
		_, v, ctx := setupTestService(t)
		pub := newPublicForTest(t, v)

		resp, err := pub.GetJwks(ctx, &talosv2alpha1.GetJWKSRequest{})
		require.NoError(t, err)

		// Convert to JSON and verify it's valid
		jwksMap := resp.Jwks.AsMap()
		jsonBytes, err := json.Marshal(jwksMap)
		require.NoError(t, err, "JWKS should serialize to valid JSON")

		// Verify it deserializes back
		var decoded map[string]any
		err = json.Unmarshal(jsonBytes, &decoded)
		require.NoError(t, err, "JWKS JSON should deserialize")

		// Verify structure
		keys, ok := decoded["keys"].([]any)
		require.True(t, ok)
		require.NotEmpty(t, keys)
	})

	t.Run("error - JWKS format stability", func(t *testing.T) {
		// This test documents the expected JWKS structure
		_, v, ctx := setupTestService(t)
		pub := newPublicForTest(t, v)

		resp, err := pub.GetJwks(ctx, &talosv2alpha1.GetJWKSRequest{})
		require.NoError(t, err)

		jwksMap := resp.Jwks.AsMap()

		// Document expected top-level structure
		assert.Len(t, jwksMap, 1, "JWKS should have exactly one top-level field")
		assert.Contains(t, jwksMap, "keys", "JWKS must contain 'keys' array")

		keys, ok := jwksMap["keys"].([]any)
		require.True(t, ok, "keys should be an array")
		firstKey, ok := keys[0].(map[string]any)
		require.True(t, ok, "key should be a map")

		// Document expected key fields for EdDSA
		expectedFields := []string{"kty", "use", "kid", "crv", "x"}
		for _, field := range expectedFields {
			assert.Contains(t, firstKey, field, "EdDSA key should contain field: %s", field)
		}

		// Forbidden fields
		forbiddenFields := []string{"d", "p", "q", "dp", "dq", "qi"}
		for _, field := range forbiddenFields {
			assert.NotContains(t, firstKey, field, "EdDSA key must not contain private field: %s", field)
		}
	})
}

// TestGetJWKS_NoSigningKeys verifies that GetJwks returns an error when no
// signing keys are configured for the service.
func TestGetJWKS_NoSigningKeys(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)

	// Build a service with no signing key URLs in the provider.
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	// NewTestProvider has no signing_keys.urls configured.
	provider := testutil.NewTestProvider(t)
	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)

	pv, err := protovalidate.New()
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	svc := service.NewAdminFromProvider(
		driver, provider, events.NewNoopEmitter(),
		keyService, cache.NewNoopCache[db.IssuedApiKey](), pv, metrics.New(prometheus.NewRegistry()), tracker,
	)

	pub := service.NewPublic(svc.Verifier(), pv, &ratelimit.NoopLimiter{})
	resp, err := pub.GetJwks(ctx, &talosv2alpha1.GetJWKSRequest{})
	require.Error(t, err, "GetJwks should return an error when no signing keys are configured")
	assert.Nil(t, resp)
}

// reviewed - @aeneasr - 2026-03-26
