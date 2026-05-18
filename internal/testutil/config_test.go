package testutil_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/config"
	"github.com/ory-corp/talos/internal/testutil"

	"github.com/ory/x/configx"
)

func TestNewTestProvider(t *testing.T) {
	t.Parallel()

	provider := testutil.NewTestProvider(t)
	require.NotNil(t, provider)

	ctx := t.Context()

	// Verify all default values are set correctly
	assert.Equal(t, "test-hmac-secret-for-config-provider-32chars", provider.String(ctx, config.KeySecretsDefaultCurrent))
	assert.Equal(t, "test-hmac-secret-for-config-provider-32chars", provider.String(ctx, config.KeySecretsHMACCurrent))
	assert.Equal(t, "test-hmac-secret-for-config-provider-32chars", provider.String(ctx, config.KeySecretsPagination))
	assert.Equal(t, "talos", provider.String(ctx, config.KeyCredentialsAPIKeysPrefixCurrent))
	assert.Equal(t, "mc", provider.String(ctx, config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent))
	assert.Equal(t, "talos-test", provider.String(ctx, config.KeyCredentialsIssuer))
	assert.Equal(t, "noop", provider.String(ctx, config.KeyCacheType))
	assert.Equal(t, 5*time.Minute, provider.Duration(ctx, config.KeyCacheTTL))
	assert.Equal(t, 365*24*time.Hour, provider.Duration(ctx, config.KeyCredentialsAPIKeysMaxTTL))
}

func TestNewTestProvider_WithCustomValues(t *testing.T) {
	t.Parallel()

	provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		config.KeyCacheType.String(): "redis",
		config.KeyCacheTTL.String():  "10m",
	}))
	require.NotNil(t, provider)

	ctx := t.Context()

	// Custom values should override defaults
	assert.Equal(t, "redis", provider.String(ctx, config.KeyCacheType))
	assert.Equal(t, 10*time.Minute, provider.Duration(ctx, config.KeyCacheTTL))

	// Other defaults should still be set
	assert.Equal(t, "talos-test", provider.String(ctx, config.KeyCredentialsIssuer))
	assert.Equal(t, "test-hmac-secret-for-config-provider-32chars", provider.String(ctx, config.KeySecretsDefaultCurrent))
}

func TestNewTestProvider_ReturnsRealProvider(t *testing.T) {
	t.Parallel()

	provider := testutil.NewTestProvider(t)
	require.NotNil(t, provider)

	// Verify it's the real provider type
	assert.IsType(t, &config.Provider{}, provider)

	// Verify it has access to underlying configx provider
	ctx := t.Context()
	underlying := provider.UnderlyingProvider(ctx)
	require.NotNil(t, underlying)
}

// reviewed - @aeneasr - 2026-03-27
