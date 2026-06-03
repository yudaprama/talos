package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestProvider creates a provider with minimal test config including required secrets and issuer
func createTestProvider(t *testing.T) (*Provider, error) {
	t.Helper()
	ctx := t.Context()

	// Create minimal config file with required secrets and credentials issuer
	configContent := `
secrets:
  hmac:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired: []
credentials:
  issuer: "https://test.talos.local"
`
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	return NewProvider(ctx, configFile)
}

func setupProviderWithConfig(t *testing.T, configContent string) (*Provider, context.Context) {
	t.Helper()
	ctx := t.Context()

	// Add required secrets to config content if not present
	if configContent != "" && !strings.Contains(configContent, "secrets:") {
		configContent = `secrets:
  hmac:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired: []
` + configContent
	}

	// Add required credentials.issuer if not present
	// Check if there's already an issuer field, or if there's no credentials section at all
	if configContent != "" && !strings.Contains(configContent, "issuer:") {
		if strings.Contains(configContent, "credentials:") {
			// Credentials section exists but no issuer - add issuer to the credentials section
			// Find the credentials section and append issuer after it
			configContent = strings.Replace(configContent, "credentials:", "credentials:\n  issuer: \"https://test.talos.local\"", 1)
		} else {
			// No credentials section at all - add complete credentials section
			configContent += `
credentials:
  issuer: "https://test.talos.local"
`
		}
	}

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0o600)
	require.NoError(t, err)

	provider, err := NewProvider(ctx, configFile)
	require.NoError(t, err)

	return provider, ctx
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("creates provider with no config files", func(t *testing.T) {
		t.Parallel()

		provider, err := createTestProvider(t)
		require.NoError(t, err)
		require.NotNil(t, provider)
		assert.Equal(t, "0.0.0.0", provider.String(ctx, KeyServeHTTPHost))
		assert.Equal(t, 4420, provider.Int(ctx, KeyServeHTTPPort))
	})

	t.Run("creates provider with config file", func(t *testing.T) {
		t.Parallel()

		provider, cfgCtx := setupProviderWithConfig(t, `
serve:
  http:
    host: "127.0.0.1"
    port: 9999
    cors:
      max_age: 3600
log:
  level: "debug"
tracing:
  enabled: false
  sample_rate: 0.75
credentials:
  derived_tokens:
    default_ttl: "2h"
`)

		assert.Equal(t, "127.0.0.1", provider.String(cfgCtx, KeyServeHTTPHost))
		assert.Equal(t, 9999, provider.Int(cfgCtx, KeyServeHTTPPort))
		assert.Equal(t, "debug", provider.String(cfgCtx, KeyLogLevel))
		assert.False(t, provider.Bool(cfgCtx, KeyTracingEnabled))
		assert.Equal(t, 3600, provider.Int(cfgCtx, KeyServeHTTPCORSMaxAge))
		assert.Equal(t, 2*time.Hour, provider.Duration(cfgCtx, KeyCredentialsDerivedTokensDefaultTTL))
		assert.InDelta(t, 0.75, provider.Float64(cfgCtx, KeyTracingSampleRate), 0.0001)
	})
}

// TestImmutableKeysAreRealConfigKeys guards against the phantom-key regression:
// the hot-reload immutability guard previously watched "tls.key" (no such key)
// and "redis.password" (the real key is "cache.redis.password"), so rotating the
// Redis password at runtime was silently accepted while the live connection kept
// the old value. The immutables are now the typed key constants; this test
// asserts they resolve to the real, addressable schema paths.
func TestImmutableKeysAreRealConfigKeys(t *testing.T) {
	t.Parallel()

	// Lock the immutable set's key paths so a rename can't reintroduce a phantom.
	assert.Equal(t, "db.dsn", KeyDBDSN.String())
	assert.Equal(t, "cache.redis.password", KeyCacheRedisPassword.String())

	// Prove cache.redis.password is a real, readable key (not phantom) by setting
	// it via config and reading it back through the typed constant.
	provider, ctx := setupProviderWithConfig(t, `
cache:
  redis:
    password: "s3cret-rotation-value"
`)
	assert.Equal(t, "s3cret-rotation-value", provider.String(ctx, KeyCacheRedisPassword))
}

func TestProvider_String(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyServeHTTPHost, "localhost"))
	require.NoError(t, provider.Set(ctx, KeyLogLevel, "debug"))

	assert.Equal(t, "localhost", provider.String(ctx, KeyServeHTTPHost))
	assert.Equal(t, "debug", provider.String(ctx, KeyLogLevel))
}

func TestProvider_Bool(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyTracingEnabled, false))

	assert.False(t, provider.Bool(ctx, KeyTracingEnabled))
}

func TestProvider_Int(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyServeHTTPCORSMaxAge, 3600))

	assert.Equal(t, 3600, provider.Int(ctx, KeyServeHTTPCORSMaxAge))
}

func TestProvider_Duration(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyCredentialsDerivedTokensDefaultTTL, "2h"))

	assert.Equal(t, 2*time.Hour, provider.Duration(ctx, KeyCredentialsDerivedTokensDefaultTTL))
}

func TestProvider_Float64(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider, err := createTestProvider(t)
	require.NoError(t, err)
	require.NoError(t, provider.Set(ctx, KeyTracingSampleRate, 0.5))

	assert.InDelta(t, 0.5, provider.Float64(ctx, KeyTracingSampleRate), 0.0001)
}

func TestNewProvider_RequiresSecretsAtSchemaLevel(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	tests := []struct {
		name   string
		config string
	}{
		{
			name: "missing secrets",
			config: `
credentials:
  issuer: "https://test.talos.local"
`,
		},
		{
			name: "empty secrets.hmac.current",
			config: `
secrets:
  hmac:
    current: ""
credentials:
  issuer: "https://test.talos.local"
`,
		},
		{
			name: "missing secrets.hmac.current",
			config: `
secrets:
  hmac:
    retired: []
credentials:
  issuer: "https://test.talos.local"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			configFile := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(configFile, []byte(tt.config), 0o600))

			_, err := NewProvider(ctx, configFile)
			require.Error(t, err, "schema must reject config without required secrets")
		})
	}
}

// reviewed - @aeneasr - 2026-03-25
