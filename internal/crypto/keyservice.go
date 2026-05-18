package crypto

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/dgraph-io/ristretto/v2"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory-corp/talos/internal/errdef"
	"github.com/ory-corp/talos/internal/tracing"

	"github.com/ory/x/fetcher"
	"github.com/ory/x/otelx"

	talosconfig "github.com/ory-corp/talos/internal/config"
)

const keyServiceCacheTTL = 15 * time.Minute

// KeyServiceMetrics is a metrics observer for KeyService.
// Implement and pass to NewKeyService to instrument key loading operations.
// Use NoopKeyServiceMetrics() when metrics are not needed (e.g., tests).
type KeyServiceMetrics interface {
	// RecordKeyLoad records a key load attempt with its result and duration.
	RecordKeyLoad(result string, _ float64)
	// SetKeysLoaded sets the gauge for the number of loaded signing keys.
	SetKeysLoaded(_ float64)
}

type noopKeyServiceMetrics struct{}

func (noopKeyServiceMetrics) RecordKeyLoad(string, float64) {}
func (noopKeyServiceMetrics) SetKeysLoaded(float64)         {}

// NoopKeyServiceMetrics returns a no-op metrics implementation for tests.
func NoopKeyServiceMetrics() KeyServiceMetrics { return noopKeyServiceMetrics{} }

// Investigation: fetcher dedup with x/jwksx.FetcherNext
//
// The fetch+cache logic in KeyService overlaps significantly with
// x/jwksx.FetcherNext (x/jwksx/fetcher_v2.go). Both use lestrrat-go/jwx/v3,
// ristretto caching with SHA-256 keys, and x/fetcher for URL fetching.
//
// Key differences that prevent direct reuse today:
//   - KeyService fetches URLs sequentially; FetcherNext uses errgroup (parallel).
//   - KeyService always returns jwk.Set; FetcherNext returns jwk.Key or jwk.Set.
//   - KeyService adds signing key selection (algorithm preference, "use":"sig")
//     and RefreshKeys() for cache invalidation, which FetcherNext lacks.
//
// Recommended path: extract the common fetch+cache+parse loop into a shared
// helper in x/jwksx, then have both KeyService and FetcherNext call it.
// The signing key selection and refresh logic remain Talos-specific.

// KeyService manages signing keys loaded from configuration URLs.
// It supports loading keys from file://, https://, and base64:// URLs.
// HTTP responses are cached by the fetcher's built-in ristretto cache keyed by sha256(url).
type KeyService struct {
	provider  talosconfig.ProviderInterface
	fetcher   *fetcher.Fetcher
	httpCache *ristretto.Cache[[]byte, []byte]
	metrics   KeyServiceMetrics
}

// NewKeyService creates a new key service that loads keys from config URLs.
// Keys are loaded lazily on first use to allow initialization without configured keys.
// This allows API key verification to work without signing keys (JWT verification needs them).
func NewKeyService(_ context.Context, provider talosconfig.ProviderInterface, httpClient *retryablehttp.Client, metrics KeyServiceMetrics) (*KeyService, error) {
	cache, err := ristretto.NewCache[[]byte, []byte](&ristretto.Config[[]byte, []byte]{
		NumCounters: 1000,
		MaxCost:     10 * 1024 * 1024, // 10 MB
		BufferItems: 64,
	})
	if err != nil {
		return nil, errors.Wrap(err, "create signing key cache")
	}

	f := fetcher.NewFetcher(
		fetcher.WithClient(httpClient),
		fetcher.WithCache(cache, keyServiceCacheTTL),
	)

	return &KeyService{
		provider:  provider,
		fetcher:   f,
		httpCache: cache,
		metrics:   metrics,
	}, nil
}

// LoadSigningKeys loads all signing keys from configured URLs.
// Returns a jwk.Set containing all loaded keys.
// HTTP responses are cached by the fetcher's built-in ristretto cache keyed by sha256(url).
func (ks *KeyService) LoadSigningKeys(ctx context.Context) (result jwk.Set, err error) {
	ctx, span := tracing.Start(ctx, "keyservice.LoadSigningKeys")
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		if result != nil {
			keyCount := result.Len()
			span.SetAttributes(
				attribute.Int("key_count", keyCount),
			)
			ks.metrics.RecordKeyLoad("success", duration)
			ks.metrics.SetKeysLoaded(float64(keyCount))
		} else {
			ks.metrics.RecordKeyLoad("error", duration)
		}
		otelx.End(span, &err)
	}()

	keyURLs := ks.provider.Strings(ctx, talosconfig.KeyCredentialsDerivedTokensJWTSigningKeysURLs)
	if len(keyURLs) == 0 {
		return nil, errors.New("no signing key URLs configured (credentials.derived_tokens.jwt.signing_keys.urls)")
	}

	keySet := jwk.NewSet()

	for _, keyURL := range keyURLs {
		keyData, err := ks.fetcher.FetchContext(ctx, keyURL)
		if err != nil {
			return nil, errors.Wrapf(err, "fetch signing key from %s", keyURL)
		}

		fetchedSet, err := jwk.Parse(keyData.Bytes())
		if err != nil {
			return nil, errors.Wrapf(err, "parse signing key from %s", keyURL)
		}

		for i := range fetchedSet.Len() {
			key, ok := fetchedSet.Key(i)
			if !ok {
				return nil, errors.New("get key from fetched set")
			}
			if err := keySet.AddKey(key); err != nil {
				return nil, errors.Wrap(err, "add key to set")
			}
		}
	}

	if keySet.Len() == 0 {
		return nil, errors.New("no valid signing keys loaded from configuration")
	}

	return keySet, nil
}

// ListActiveSigningKeys returns all active signing keys for verification.
// This is the main method used by verifiers to get public keys.
func (ks *KeyService) ListActiveSigningKeys(ctx context.Context) (jwk.Set, error) {
	return ks.LoadSigningKeys(ctx)
}

// GetActiveSigningKey returns the active signing key for token signing.
// This is used by the admin when creating new tokens.
//
// Selection order:
//  1. If credentials.derived_tokens.jwt.signing_key_id is set, return the key
//     whose JWK "kid" matches. If no such key exists, signing fails.
//  2. Otherwise, return the first key marked with use="sig".
//  3. Fallback to the first key in the set.
func (ks *KeyService) GetActiveSigningKey(ctx context.Context) (_ jwk.Key, err error) {
	ctx, span := tracing.Start(ctx, "keyservice.GetActiveSigningKey")
	defer otelx.End(span, &err)

	keySet, err := ks.LoadSigningKeys(ctx)
	if err != nil {
		return nil, err
	}

	// If a signing key id hint is configured, select that exact key or fail.
	if kidHint := ks.provider.String(ctx, talosconfig.KeyCredentialsDerivedTokensJWTSigningKeyID); kidHint != "" {
		span.SetAttributes(attribute.String("signing_key_id_hint", kidHint))
		key, ok := keySet.LookupKeyID(kidHint)
		if !ok {
			return nil, errdef.InternalError("signing key with id not found in configured JWKS").
				WithDetail("signing_key_id", kidHint)
		}
		span.SetAttributes(attribute.String("selected_kid", kidHint))
		return key, nil
	}

	// Find first key with "use": "sig" or return first key.
	for i := range keySet.Len() {
		key, ok := keySet.Key(i)
		if !ok {
			continue
		}

		// Prefer keys marked for signing.
		if use, hasUse := key.KeyUsage(); hasUse && use == "sig" {
			if kid, hasKID := key.KeyID(); hasKID {
				span.SetAttributes(attribute.String("selected_kid", kid))
			}
			return key, nil
		}
	}

	// Fallback: return first key.
	key, ok := keySet.Key(0)
	if !ok {
		return nil, errors.New("get signing key from set")
	}
	if kid, hasKID := key.KeyID(); hasKID {
		span.SetAttributes(attribute.String("selected_kid", kid))
	}

	return key, nil
}
