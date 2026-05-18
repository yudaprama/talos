package service_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/ory-corp/talos/internal/cache"
	"github.com/ory-corp/talos/internal/config"
	"github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/events"
	"github.com/ory-corp/talos/internal/lastused"
	"github.com/ory-corp/talos/internal/metrics"
	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	"github.com/ory-corp/talos/internal/service"
	"github.com/ory-corp/talos/internal/testutil"

	talosv2 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// TestDeriveToken_KIDHintRoutesToConfiguredKey verifies the full service-layer
// path: a JWKS with multiple keys combined with
// credentials.derived_tokens.jwt.signing_key_id causes DeriveToken to emit a JWT
// whose protected header `kid` matches the configured hint. This covers the
// wiring from KeyService.GetActiveSigningKey through SignDerivedTokenParams.KID
// into JWTSigner.Sign — none of which is asserted by existing header-agnostic
// verification tests.
func TestDeriveToken_KIDHintRoutesToConfiguredKey(t *testing.T) {
	t.Parallel()

	// Build a single JWKS with two Ed25519 keys (kid-A, kid-B) and mark kid-B
	// as use="sig" so that default selection would pick kid-B. This makes the
	// override meaningful: selecting kid-A proves the hint beats default
	// preferences, not just the first-key fallback.
	jwksURL := testutil.TestTwoKeyJWKSURL(t, "kid-A", "kid-B", true)

	tests := []struct {
		name    string
		hintKID string
	}{
		{name: "hint selects kid-A", hintKID: "kid-A"},
		{name: "hint selects kid-B", hintKID: "kid-B"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			driver, err := testutil.InitDriver(t, "")
			require.NoError(t, err)
			t.Cleanup(func() { _ = driver.Close() })

			provider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(map[string]any{
				config.KeySecretsHMACCurrent.String():                            "test-hmac-secret-for-api-key-hashing-minimum-32-chars",
				config.KeySecretsDefaultCurrent.String():                         "test-hmac-secret-for-api-key-hashing-minimum-32-chars",
				config.KeySecretsPagination.String():                             "test-secret-for-pagination-encryption-must-be-at-least-32-chars",
				config.KeyCredentialsAPIKeysDefaultTTL.String():                  "2160h",
				config.KeyCredentialsAPIKeysMaxTTL.String():                      "8760h",
				config.KeyCredentialsDerivedTokensDefaultTTL.String():            "1h",
				config.KeyCredentialsAPIKeysPrefixCurrent.String():               "talos",
				config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent.String(): "mc",
				config.KeyCacheTTL.String():                                      "5m",
				config.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String():    []string{jwksURL},
				config.KeyCredentialsDerivedTokensJWTSigningKeyID.String():       tt.hintKID,
			}))

			keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
			require.NoError(t, err)

			pv, err := protovalidate.New()
			require.NoError(t, err)

			tracker := lastused.New(ctx, driver, lastused.Config{
				QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
			})
			t.Cleanup(tracker.Close)

			svc := service.NewAdminFromProvider(
				driver, provider, events.NewNoopEmitter(), keyService,
				cache.NewNoopCache[db.IssuedApiKey](), pv,
				metrics.New(prometheus.NewRegistry()), tracker,
			)

			issued, err := svc.IssueAPIKey(ctx, &talosv2.IssueAPIKeyRequest{
				Name:    "Parent Key",
				ActorId: "actor-kid-hint",
				Scopes:  []string{"read"},
				Ttl:     durationpb.New(24 * time.Hour),
			})
			require.NoError(t, err)

			derived, err := svc.DeriveToken(ctx, &talosv2.DeriveTokenRequest{
				Credential: issued.Secret,
				Algorithm:  talosv2.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
				Ttl:        durationpb.New(time.Hour),
			})
			require.NoError(t, err)
			require.NotNil(t, derived.Token)

			parts := strings.Split(derived.Token.Token, ".")
			require.Len(t, parts, 3)

			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			require.NoError(t, err)

			var header map[string]any
			require.NoError(t, json.Unmarshal(headerBytes, &header))

			assert.Equal(t, tt.hintKID, header["kid"],
				"JWT header kid must equal signing_key_id hint=%q", tt.hintKID)
		})
	}
}
