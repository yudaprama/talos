package service_test

import (
	"context"
	"maps"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/gofrs/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/contextx"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/metrics"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/testutil"
	"github.com/ory/talos/internal/verifier"
)

// testCtx returns a context carrying an explicit nil network ID so the strict
// NID accessors on storage and pagination paths resolve identically in OSS and
// commercial builds. In production the contextualizer middleware sets the NID.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	return context.WithValue(t.Context(), contextx.NIDKey{}, uuid.Nil)
}

// baseTestConfig returns the config values shared by all service test setups.
func baseTestConfig() map[string]any {
	return map[string]any{
		config.KeySecretsHMACCurrent.String():                            "test-hmac-secret-for-api-key-hashing-minimum-32-chars",
		config.KeyCredentialsAPIKeysDefaultTTL.String():                  "2160h",
		config.KeyCredentialsAPIKeysMaxTTL.String():                      "8760h",
		config.KeyCredentialsDerivedTokensDefaultTTL.String():            "1h",
		config.KeyCredentialsAPIKeysPrefixCurrent.String():               "talos",
		config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent.String(): "mc",
		config.KeyCacheEnabled.String():                                  true,
		config.KeyCacheTTL.String():                                      "5m",
	}
}

// setupTestService creates a test Admin and Verifier backed by file-based SQLite.
// The Admin and verifier share the same signing keys so tokens issued by one
// can be verified by the other.
func setupTestService(t *testing.T) (*service.Admin, *verifier.Verifier, context.Context) {
	t.Helper()
	ctx := testCtx(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := driver.Close(); err != nil {
			t.Logf("warning: error closing driver: %v", err)
		}
	})

	provider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(baseTestConfig()))

	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)
	pv, err := protovalidate.New()
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	svc := service.NewAdminFromProvider(driver, provider, events.NewNoopEmitter(), keyService, cache.NewNoopCache[db.IssuedApiKey](), pv, metrics.New(prometheus.NewRegistry()), tracker)

	return svc, svc.Verifier(), ctx
}

// setupTestServiceWithConfig creates a test Admin with extra config overrides
// merged on top of baseTestConfig. Used by tests that need quota or other
// non-default settings.
func setupTestServiceWithConfig(t *testing.T, overrides map[string]any) (*service.Admin, context.Context) {
	t.Helper()
	ctx := testCtx(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := driver.Close(); err != nil {
			t.Logf("warning: error closing driver: %v", err)
		}
	})

	cfg := baseTestConfig()
	maps.Copy(cfg, overrides)

	provider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(cfg))

	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)
	pv, err := protovalidate.New()
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	svc := service.NewAdminFromProvider(driver, provider, events.NewNoopEmitter(), keyService, cache.NewNoopCache[db.IssuedApiKey](), pv, metrics.New(prometheus.NewRegistry()), tracker)
	return svc, ctx
}

// setupTestAdminWithPublicPrefix creates a test Admin with a public key prefix configured.
func setupTestAdminWithPublicPrefix(t *testing.T, publicPrefix string) (*service.Admin, context.Context) {
	t.Helper()
	ctx := testCtx(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := driver.Close(); err != nil {
			t.Logf("warning: error closing driver: %v", err)
		}
	})

	cfg := baseTestConfig()
	cfg[config.KeyCredentialsAPIKeysPrefixPublicCurrent.String()] = publicPrefix

	provider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(cfg))

	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)
	pv, err := protovalidate.New()
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	svc := service.NewAdminFromProvider(driver, provider, events.NewNoopEmitter(), keyService, cache.NewNoopCache[db.IssuedApiKey](), pv, metrics.New(prometheus.NewRegistry()), tracker)

	return svc, ctx
}
