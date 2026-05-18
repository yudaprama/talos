package crypto_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/config"
	"github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/testutil"

	"github.com/ory/x/configx"
)

func TestHMACSecretsForVerification(t *testing.T) {
	t.Parallel()

	t.Run("HMAC-specific secret configured with retired", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			"secrets": map[string]any{
				"default": map[string]any{
					"current": "default-secret-32chars-min-1234567890",
					"retired": []string{},
				},
				"hmac": map[string]any{
					"current": "hmac-secret-32chars-minimum-12345678901234",
					"retired": []string{"old-hmac-secret-32chars-1234567890123456"},
				},
			},
		}))
		ctx := context.Background()

		secrets, err := crypto.HMACSecretsForVerification(ctx, provider)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"hmac-secret-32chars-minimum-12345678901234",
			"old-hmac-secret-32chars-1234567890123456",
		}, secrets)
	})

	t.Run("HMAC configured with empty retired", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			"secrets": map[string]any{
				"default": map[string]any{
					"current": "default-secret-32chars-min-1234567890",
					"retired": []string{},
				},
				"hmac": map[string]any{
					"current": "hmac-secret-32chars-minimum-12345678901234",
					"retired": []string{},
				},
			},
		}))
		ctx := context.Background()

		secrets, err := crypto.HMACSecretsForVerification(ctx, provider)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"hmac-secret-32chars-minimum-12345678901234",
		}, secrets)
	})

	t.Run("returns error when HMAC not configured", func(t *testing.T) {
		t.Parallel()

		// Create provider directly without testkit base defaults, so that the
		// HMAC section is truly absent.
		ctx := context.Background()
		provider, err := config.NewProviderWithOptions(ctx, configx.WithValues(map[string]any{
			"credentials": map[string]any{
				"issuer": "talos-test",
			},
			"secrets": map[string]any{
				"default": map[string]any{
					"current": "default-secret-32chars-min-1234567890",
					"retired": []string{"old-default-secret-32chars-1234567890"},
				},
			},
		}))
		require.NoError(t, err)

		_, err = crypto.HMACSecretsForVerification(ctx, provider)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project has no HMAC key configured")
	})
}

func TestHMACSecretForSigning(t *testing.T) {
	t.Parallel()

	t.Run("HMAC-specific secret configured", func(t *testing.T) {
		t.Parallel()

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			"secrets": map[string]any{
				"default": map[string]any{
					"current": "default-secret-32chars-min-1234567890",
				},
				"hmac": map[string]any{
					"current": "hmac-secret-32chars-minimum-12345678901234",
				},
			},
		}))
		ctx := context.Background()

		secret, err := crypto.HMACSecretForSigning(ctx, provider)
		require.NoError(t, err)
		assert.Equal(t, "hmac-secret-32chars-minimum-12345678901234", secret)
	})

	t.Run("returns error when HMAC not configured", func(t *testing.T) {
		t.Parallel()

		// Create provider directly without testkit base defaults, so that the
		// HMAC section is truly absent.
		ctx := context.Background()
		provider, err := config.NewProviderWithOptions(ctx, configx.WithValues(map[string]any{
			"credentials": map[string]any{
				"issuer": "talos-test",
			},
			"secrets": map[string]any{
				"default": map[string]any{
					"current": "default-secret-32chars-min-1234567890",
				},
			},
		}))
		require.NoError(t, err)

		_, err = crypto.HMACSecretForSigning(ctx, provider)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project has no HMAC key configured")
	})
}

func TestDefaultSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   map[string]any
		expected []string
	}{
		{
			name: "default secret with retired",
			config: map[string]any{
				"secrets": map[string]any{
					"default": map[string]any{
						"current": "default-secret-32chars-min-1234567890",
						"retired": []string{
							"old-default-secret-32chars-1234567890",
							"very-old-default-secret-32chars-123456",
						},
					},
				},
			},
			expected: []string{
				"default-secret-32chars-min-1234567890",
				"old-default-secret-32chars-1234567890",
				"very-old-default-secret-32chars-123456",
			},
		},
		{
			name: "default secret without retired",
			config: map[string]any{
				"secrets": map[string]any{
					"default": map[string]any{
						"current": "default-secret-32chars-min-1234567890",
						"retired": []string{},
					},
				},
			},
			expected: []string{
				"default-secret-32chars-min-1234567890",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := testutil.NewTestProvider(t, configx.WithValues(tt.config))
			ctx := context.Background()

			secrets := crypto.DefaultSecrets(ctx, provider)
			assert.Equal(t, tt.expected, secrets)
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
