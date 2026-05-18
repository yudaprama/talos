package testutil_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/config"
)

func TestConfigRequiresIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Config without issuer should fail validation
	configYAML := `
secrets:
  default:
    current: "test-secret-minimum-32-characters-long"
    retired: []
`

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte(configYAML), 0o600)
	require.NoError(t, err)

	_, err = config.NewProvider(ctx, configFile)
	require.Error(t, err, "config without credentials.issuer should fail validation")
	// Error should mention either missing "credentials" object or missing "issuer" field
	errMsg := err.Error()
	require.True(t,
		strings.Contains(errMsg, "credentials") || strings.Contains(errMsg, "issuer"),
		"error should mention missing credentials or issuer: %v", err)
}

func TestConfigWithIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Config with issuer should succeed
	configYAML := `
secrets:
  default:
    current: "test-secret-minimum-32-characters-long"
    retired: []
  hmac:
    current: "test-hmac-secret-minimum-32-characters-long"
    retired: []
credentials:
  issuer: "https://test.talos.local"
`

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte(configYAML), 0o600)
	require.NoError(t, err)

	provider, err := config.NewProvider(ctx, configFile)
	require.NoError(t, err)

	issuer := provider.String(ctx, config.KeyCredentialsIssuer)
	require.Equal(t, "https://test.talos.local", issuer)
}

// reviewed - @aeneasr - 2026-03-27
