package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/config"

	"github.com/ory/x/configx"
)

// NewTestProvider creates a real config provider with test defaults.
// Additional options can be passed to customize config values.
//
// Example:
//
//	provider := testkit.NewTestProvider(t)
//	provider := testkit.NewTestProvider(t, configx.WithValues(map[string]any{
//	  "cache.type": "redis",
//	}))
func NewTestProvider(tb testing.TB, opts ...configx.OptionModifier) *config.Provider {
	tb.Helper()

	// Create a context - use context.Background() for benchmarks/tests
	var ctx context.Context
	if t, ok := tb.(contextGetter); ok {
		ctx = t.Context()
	} else {
		ctx = context.Background()
	}

	// Base test defaults - deterministic values for reproducible tests
	baseOpts := []configx.OptionModifier{
		configx.WithValues(map[string]any{
			"secrets": map[string]any{
				"default": map[string]any{
					"current": "test-hmac-secret-for-config-provider-32chars",
					"retired": []string{},
				},
				"hmac": map[string]any{
					"current": "test-hmac-secret-for-config-provider-32chars",
					"retired": []string{},
				},
				"pagination": map[string]any{
					"current": "test-hmac-secret-for-config-provider-32chars",
					"retired": []string{},
				},
			},
			"credentials": map[string]any{
				"issuer": "talos-test",
				"api_keys": map[string]any{
					"default_ttl": "2160h",
					"max_ttl":     "8760h",
					"prefix": map[string]any{
						"current": "talos",
						"retired": []any{},
					},
				},
				"derived_tokens": map[string]any{
					"default_ttl": "1h",
					"macaroon": map[string]any{
						"prefix": map[string]any{
							"current": "mc",
							"retired": []any{},
						},
					},
				},
			},
			"cache": map[string]any{
				"type": "noop",
				"ttl":  "5m",
			},
		}),
	}

	// User options override defaults
	allOpts := append([]configx.OptionModifier{}, baseOpts...)
	allOpts = append(allOpts, opts...)

	provider, err := config.NewProviderWithOptions(ctx, allOpts...)
	require.NoError(tb, err)
	return provider
}

// NewTestProviderWithSigningKeys creates a test config provider that includes
// base64://-embedded Ed25519 signing keys. Use this when tests need JWT/macaroon
// token derivation or verification. Additional options can override any defaults.
func NewTestProviderWithSigningKeys(tb testing.TB, opts ...configx.OptionModifier) *config.Provider {
	tb.Helper()

	signingKeyOpt := configx.WithValues(map[string]any{
		config.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String(): []string{TestSigningKeyJWKSURL(tb)},
	})

	allOpts := append([]configx.OptionModifier{signingKeyOpt}, opts...)
	return NewTestProvider(tb, allOpts...)
}

// reviewed - @aeneasr - 2026-03-25
