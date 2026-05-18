package verifier_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ory-corp/talos/internal/cache"
	"github.com/ory-corp/talos/internal/config"
	"github.com/ory-corp/talos/internal/lastused"
	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	"github.com/ory-corp/talos/internal/testutil"

	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/crypto/token"
	"github.com/ory-corp/talos/internal/events"
	"github.com/ory-corp/talos/internal/metrics"
	"github.com/ory-corp/talos/internal/service"
	"github.com/ory-corp/talos/internal/verifier"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// benchCache is a simple sync.Map-based cache for benchmarks.
// Unlike NoopCache, it actually stores and retrieves values so that
// "cache hit" benchmarks measure the real hot path.
type benchCache[T any] struct {
	mu      sync.RWMutex
	entries map[string]T
}

func newBenchCache[T any]() *benchCache[T] {
	return &benchCache[T]{entries: make(map[string]T)}
}

func (c *benchCache[T]) Get(_ context.Context, key string) (T, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[key]
	return v, ok, nil
}

func (c *benchCache[T]) Set(_ context.Context, key string, value T, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = value
	return nil
}

func (c *benchCache[T]) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	return nil
}

func (c *benchCache[T]) Close() error { return nil }
func (c *benchCache[T]) Metrics() cache.Metrics {
	return cache.NewNoopCache[T]().Metrics()
}
func (c *benchCache[T]) Wait() {}

var (
	testAPIKey   string
	testToken    string
	testVerifier *verifier.Verifier
	testNid      string
	benchSetup   sync.Once
)

func setupBenchmark(b *testing.B) {
	b.Helper()

	benchSetup.Do(func() {
		// Use file-based SQLite for benchmarks
		ctx := b.Context()

		driver, err := testutil.InitDriver(b, "")
		require.NoError(b, err, "benchmark infrastructure: cannot initialize database")

		// Create config provider with test values and signing keys for token derivation
		testSecret := "benchmark-hmac-secret-for-api-key-hashing-32-chars"
		mockProvider := testutil.NewTestProviderWithSigningKeys(b, configx.WithValues(map[string]any{
			config.KeySecretsDefaultCurrent.String():                         testSecret,
			config.KeySecretsHMACCurrent.String():                            testSecret,
			config.KeySecretsPagination.String():                             testSecret,
			config.KeyCredentialsAPIKeysPrefixCurrent.String():               "talos",
			config.KeyCredentialsDerivedTokensMacaroonPrefixCurrent.String(): "mc",
			config.KeyCacheTTL.String():                                      "5m",
			config.KeyCredentialsAPIKeysDefaultTTL.String():                  "2160h", // 90*24*time.Hour
			config.KeyCredentialsAPIKeysMaxTTL.String():                      "8760h", // 365*24*time.Hour
			config.KeyCredentialsDerivedTokensDefaultTTL.String():            "1h",
		}))

		keyService, err := crypto.NewKeyService(b.Context(), mockProvider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
		require.NoError(b, err, "benchmark infrastructure: cannot create key service")

		// Use a real in-memory cache so "cache hit" benchmarks exercise the hot path,
		// not the database on every call (NoopCache always misses).
		noopEmitter := events.NewNoopEmitter()
		apiKeyCache := newBenchCache[db.IssuedApiKey]()

		m := metrics.New(prometheus.NewRegistry())

		tracker := lastused.New(b.Context(), driver, lastused.Config{
			QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
		})
		b.Cleanup(tracker.Close)

		testVerifier = verifier.NewFromProvider(driver, mockProvider, apiKeyCache, noopEmitter, keyService, m, tracker)

		// Create test data with explicit noop emitter
		pv, err := protovalidate.New()
		require.NoError(b, err, "benchmark infrastructure: cannot create protovalidate validator")

		admin := service.NewAdminFromProvider(driver, mockProvider, noopEmitter, keyService, apiKeyCache, pv, m, tracker)

		// Note: Network is created automatically by driver.Initialize()
		// Using uuid.Nil for single-network OSS model
		testNid = "00000000-0000-0000-0000-000000000000"

		// Create API key
		resp, err := admin.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    "Benchmark Key",
			ActorId: "bench-1",
			Scopes:  []string{"read", "write"},
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(b, err, "benchmark setup: IssueAPIKey failed")
		testAPIKey = resp.Secret

		// Derive token from API key
		tokenResp, err := admin.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential:   testAPIKey,
			Algorithm:    talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:          durationpb.New(time.Hour),
			CustomClaims: nil,
		})
		require.NoError(b, err, "benchmark setup: DeriveToken failed")
		testToken = tokenResp.Token.Token

		// Pre-warm cache
		_, _, _ = testVerifier.VerifyAPIKey(ctx, testAPIKey)
	})
}

// Benchmarks use shared state (testVerifier, testAPIKey, testToken) initialized once
// via sync.Once in setupBenchmark.
// Run with: go test -bench=. -benchtime=5s ./internal/verifier/...

func BenchmarkVerifyAPIKey_CacheHit(b *testing.B) {
	setupBenchmark(b)
	require.NotEmpty(b, testAPIKey, "benchmark setup produced empty API key")

	ctx := b.Context()

	b.ResetTimer()
	for b.Loop() {
		result, _, err := testVerifier.VerifyAPIKey(ctx, testAPIKey)
		if err != nil || result == nil {
			b.Errorf("Verification failed: %v", err)
		}
	}
}

func BenchmarkVerifyAPIKey_CacheMiss(b *testing.B) {
	setupBenchmark(b)
	require.NotEmpty(b, testNid, "benchmark setup produced empty network ID")

	ctx := b.Context()
	hmacSecret := []byte("benchmark-hmac-secret-for-testing-only-32-chars")

	// Pre-generate keys outside the timer to isolate verification cost.
	const poolSize = 1000
	keys := make([]string, poolSize)
	for i := range poolSize {
		prefix := fmt.Sprintf("bench%d", i%100)
		key, _, err := crypto.GenerateAPIKey(ctx, prefix, hmacSecret)
		require.NoError(b, err)
		keys[i] = key
	}

	b.ResetTimer()
	for i := range b.N {
		// Each key misses the cache and fails verification (not in DB).
		_, _, err := testVerifier.VerifyAPIKey(ctx, keys[i%poolSize])
		if err == nil {
			b.Error("Expected error for non-existent key")
		}
	}
}

func BenchmarkVerifyDerivedToken(b *testing.B) {
	setupBenchmark(b)
	require.NotEmpty(b, testToken, "benchmark setup produced empty token")

	ctx := b.Context()

	b.ResetTimer()
	for b.Loop() {
		result, _, err := testVerifier.VerifyAPIKey(ctx, testToken)
		if err != nil || result == nil {
			b.Errorf("Token verification failed: %v", err)
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	ctx := b.Context()
	hmacSecret := []byte("benchmark-hmac-secret-for-testing-only-32-chars")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			prefix := fmt.Sprintf("bench%d", time.Now().UnixNano()%1000)

			key, keyID, err := crypto.GenerateAPIKey(ctx, prefix, hmacSecret)
			if err != nil {
				b.Errorf("Key generation failed: %v", err)
			}
			if len(keyID) != 36 {
				b.Errorf("Invalid key ID length: expected 36 (UUID), got %d", len(keyID))
			}
			if len(key) < 32 {
				b.Errorf("Key too short: %d", len(key))
			}
		}
	})
}

func BenchmarkTokenGeneration(b *testing.B) {
	// TODO is this really needed?
	// Setup JWT signer
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(b, err)

	kid := crypto.GenerateKeyID()
	signer, err := token.NewJWTSigner(privKey, kid)
	require.NoError(b, err)

	// Create reusable claims
	now := time.Now()
	claims := token.NewClaims()
	claims.SetTokenID(crypto.GenerateKeyID())
	claims.SetSubject("key-456")
	claims.SetIssuer("talos-service")
	claims.SetTokenType(token.TokenTypeIssued)
	claims.SetKeyID("key-456")
	claims.SetActorID("user-789")
	claims.SetScopes([]string{"read", "write"})
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(time.Hour))
	claims.SetNotBefore(now)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tokenString, err := signer.Sign(b.Context(), claims)
			if err != nil {
				b.Errorf("Token generation failed: %v", err)
			}
			if len(tokenString) < 100 {
				b.Errorf("Token too short: %d", len(tokenString))
			}
		}
	})
}

// Memory allocation benchmarks
func BenchmarkVerifyAPIKey_Memory(b *testing.B) {
	if testVerifier == nil {
		setupBenchmark(b)
	}
	require.NotEmpty(b, testAPIKey, "benchmark setup produced empty API key")

	ctx := b.Context()

	// Warm up cache; discard the result, audit log, and error intentionally.
	warmResult, _, warmErr := testVerifier.VerifyAPIKey(ctx, testAPIKey)
	_, _ = warmResult, warmErr

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		result, _, _ := testVerifier.VerifyAPIKey(ctx, testAPIKey)
		_ = result
	}
}

// reviewed - @aeneasr - 2026-03-27
