package registry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus"

	commercialregistry "github.com/ory/talos/commercial/registry"
	"github.com/ory/talos/internal/testutil"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"

	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"
)

// newTestFactory creates a ServiceFactory with standard test dependencies.
// It registers cleanup for the driver automatically.
func newTestFactory(t *testing.T, backendFactories map[string]commercialregistry.CacheFactory) (*ServiceFactory, *testutil.MockEmitter) {
	t.Helper()

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	provider := testutil.NewTestProvider(t)
	emitter := testutil.NewMockEmitter()

	factory, err := NewServiceFactory(t.Context(), driver, provider, emitter, httpx.NewResilientClient(), backendFactories, nil, prometheus.NewRegistry())
	require.NoError(t, err)

	return factory, emitter
}

// TestNewServiceFactory tests the service factory constructor
func TestNewServiceFactory(t *testing.T) {
	t.Parallel()

	t.Run("creates factory with all dependencies", func(t *testing.T) {
		t.Parallel()
		backendFactories := make(map[string]commercialregistry.CacheFactory)
		factory, _ := newTestFactory(t, backendFactories)

		require.NotNil(t, factory)
		assert.NotNil(t, factory.driver)
		assert.NotNil(t, factory.provider)
		assert.NotNil(t, factory.emitter)
		assert.NotNil(t, factory.cacheFactories)
	})

	t.Run("stores all dependencies correctly", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, make(map[string]commercialregistry.CacheFactory))

		// Verify we can access stored dependencies
		assert.NotNil(t, factory.Driver())
		assert.NotNil(t, factory.Provider())
	})

	t.Run("handles nil backend factories map", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)
		require.NotNil(t, factory)
	})
}

// TestCreateAdmin tests admin service creation
func TestCreateAdmin(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("creates valid admin service", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		admin, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)
		require.NotNil(t, admin)
	})

	t.Run("multiple calls create separate instances", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		cp1, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)
		require.NotNil(t, cp1)

		cp2, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)
		require.NotNil(t, cp2)

		// Different instances (pointer comparison)
		assert.NotSame(t, cp1, cp2)
	})

	t.Run("admin has correct dependencies", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		admin, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)
		require.NotNil(t, admin)

		// Admin service should be functional - test by creating an API key
		resp, err := admin.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Test Key",
			ActorId: "test-user",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.IssuedApiKey.KeyId)
		assert.NotEmpty(t, resp.Secret)
	})
}

// TestCreateVerifier tests verifier creation
func TestCreateVerifier(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("creates valid verifier", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		verifier, err := factory.CreateVerifier(ctx)
		require.NoError(t, err)
		require.NotNil(t, verifier)
	})

	t.Run("multiple calls create separate instances", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		v1, err := factory.CreateVerifier(ctx)
		require.NoError(t, err)
		require.NotNil(t, v1)

		v2, err := factory.CreateVerifier(ctx)
		require.NoError(t, err)
		require.NotNil(t, v2)

		// Different instances (pointer comparison)
		assert.NotSame(t, v1, v2)
	})

	t.Run("verifier uses cache config from provider", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		verifier, err := factory.CreateVerifier(ctx)
		require.NoError(t, err)
		require.NotNil(t, verifier)

		// Verifier should be functional - we can't easily test internals
		// but we can verify it was created without error
	})
}

// TestBuildCacheConfig tests cache configuration building
func TestBuildCacheConfig(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("reads all cache config from provider", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		config := factory.buildCacheConfig(ctx)
		require.NotNil(t, config)

		// Check that config has expected default values from provider
		assert.NotEmpty(t, config.Type)
		assert.Greater(t, config.TTL, time.Duration(0))
	})

	t.Run("config values read dynamically on each call", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		// First call
		config1 := factory.buildCacheConfig(ctx)
		require.NotNil(t, config1)

		// Second call should read fresh from provider
		config2 := factory.buildCacheConfig(ctx)
		require.NotNil(t, config2)

		// Values should be the same (reading from same provider state)
		assert.Equal(t, config1.Type, config2.Type)
		assert.Equal(t, config1.TTL, config2.TTL)
	})

	t.Run("reads redis connection pool and TLS fields", func(t *testing.T) {
		t.Parallel()

		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
			"cache.redis.min_idle_conns":     10,
			"cache.redis.conn_max_idle_time": "2m",
			"cache.redis.conn_max_lifetime":  "15m",
			"cache.redis.tls.enabled":        true,
		}))

		factory, err := NewServiceFactory(ctx, driver, provider, testutil.NewMockEmitter(), httpx.NewResilientClient(), nil, nil, prometheus.NewRegistry())
		require.NoError(t, err)

		cfg := factory.buildCacheConfig(ctx)

		assert.Equal(t, 10, cfg.RedisMinIdleConns)
		assert.Equal(t, 2*time.Minute, cfg.RedisConnMaxIdleTime)
		assert.Equal(t, 15*time.Minute, cfg.RedisConnMaxLifetime)
		assert.True(t, cfg.RedisTLSEnabled)
	})

	t.Run("redis connection pool fields return schema defaults when unset", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		cfg := factory.buildCacheConfig(ctx)

		// Provider returns schema defaults when no explicit value is configured.
		// These match the cmp.Or fallbacks in NewRedisCache.
		assert.Equal(t, 2, cfg.RedisMinIdleConns)
		assert.Equal(t, 5*time.Minute, cfg.RedisConnMaxIdleTime)
		assert.Equal(t, 30*time.Minute, cfg.RedisConnMaxLifetime)
		assert.False(t, cfg.RedisTLSEnabled)
	})
}

// TestProviderAccessor tests the Provider() accessor
func TestProviderAccessor(t *testing.T) {
	t.Parallel()

	t.Run("returns correct provider instance", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		// Provider() should return a valid instance
		assert.NotNil(t, factory.Provider())
	})
}

// TestDriverAccessor tests the Driver() accessor
func TestDriverAccessor(t *testing.T) {
	t.Parallel()

	t.Run("returns correct driver instance", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)

		// Driver() should return a valid instance
		assert.NotNil(t, factory.Driver())
	})
}

// TestClose tests factory cleanup
func TestClose(t *testing.T) {
	t.Parallel()

	t.Run("closes driver successfully", func(t *testing.T) {
		t.Parallel()
		driver, err := testutil.InitDriver(t, "")
		require.NoError(t, err)

		provider := testutil.NewTestProvider(t)
		emitter := testutil.NewMockEmitter()

		factory, err := NewServiceFactory(t.Context(), driver, provider, emitter, httpx.NewResilientClient(), nil, nil, prometheus.NewRegistry())
		require.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)

		// Driver should be closed (subsequent operations should fail)
		// We can't easily test this without making assumptions about driver internals
	})

	t.Run("handles nil driver gracefully", func(t *testing.T) {
		t.Parallel()
		provider := testutil.NewTestProvider(t)
		emitter := testutil.NewMockEmitter()

		factory, err := NewServiceFactory(t.Context(), nil, provider, emitter, httpx.NewResilientClient(), nil, nil, prometheus.NewRegistry())
		require.NoError(t, err)

		// Should not panic with nil driver
		err = factory.Close()
		assert.NoError(t, err)
	})
}

// TestFactoryIntegration tests full workflow with factory
func TestFactoryIntegration(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("create admin and use it", func(t *testing.T) {
		t.Parallel()
		factory, emitter := newTestFactory(t, nil)
		t.Cleanup(func() { _ = factory.Close() })

		// Create admin
		admin, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)

		// Use admin to create a key
		resp, err := admin.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Integration Test Key",
			ActorId: "test-user-123",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.IssuedApiKey.KeyId)
		assert.NotEmpty(t, resp.Secret)

		// Verify emitter captured the event
		assert.Positive(t, emitter.EventCount())
	})

	t.Run("create verifier and use it", func(t *testing.T) {
		t.Parallel()
		factory, _ := newTestFactory(t, nil)
		t.Cleanup(func() { _ = factory.Close() })

		// Create admin to make a key first
		admin, err := factory.CreateAdmin(ctx)
		require.NoError(t, err)

		resp, err := admin.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Verifier Test Key",
			ActorId: "verify-user",
		})
		require.NoError(t, err)

		// Create verifier
		verifier, err := factory.CreateVerifier(ctx)
		require.NoError(t, err)

		// Use verifier to verify the key
		result, _, err := verifier.VerifyAPIKey(ctx, resp.Secret)
		require.NoError(t, err)
		assert.Equal(t, resp.IssuedApiKey.KeyId, result.KeyID)
	})
}

// reviewed - @aeneasr - 2026-03-26
