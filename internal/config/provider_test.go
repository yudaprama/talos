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
  default:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired: []
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
  default:
    current: "test-hmac-secret-for-config-provider-32chars"
    retired: []
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

// reviewed - @aeneasr - 2026-03-25
