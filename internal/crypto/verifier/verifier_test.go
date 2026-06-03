package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	stderrors "errors"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	talosconfig "github.com/ory/talos/internal/config"
	internalcrypto "github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/testutil"
)

// rsaKeyToJWKSURL serializes an RSA private key into a base64:// JWKS URL.
func rsaKeyToJWKSURL(t *testing.T, key jwk.Key) string {
	t.Helper()

	keySet := jwk.NewSet()
	err := keySet.AddKey(key)
	require.NoError(t, err)

	data, err := json.Marshal(keySet)
	require.NoError(t, err)

	return "base64://" + base64.StdEncoding.EncodeToString(data)
}

func newKeyServiceFromURL(t *testing.T, jwksURL string) *internalcrypto.KeyService {
	t.Helper()

	provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		talosconfig.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String(): []string{jwksURL},
	}))

	ks, err := internalcrypto.NewKeyService(t.Context(), provider, httpx.NewResilientClient(), internalcrypto.NoopKeyServiceMetrics())
	require.NoError(t, err)
	return ks
}

func TestVerifyJWT(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Generate RSA key
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key, err := jwk.Import(rawKey)
	require.NoError(t, err)

	err = key.Set(jwk.KeyIDKey, "test-key-1")
	require.NoError(t, err)
	err = key.Set(jwk.AlgorithmKey, jwa.RS256())
	require.NoError(t, err)

	// Setup KeyService via base64:// URL
	jwksURL := rsaKeyToJWKSURL(t, key)
	keyService := newKeyServiceFromURL(t, jwksURL)
	v := NewVerifier(keyService)

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()

		// Create a signed token
		tok, err := jwt.NewBuilder().
			Issuer("talos").
			Subject("user123").
			Audience([]string{"api"}).
			Expiration(time.Now().Add(time.Hour)).
			Build()
		require.NoError(t, err)

		// Sign it
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err)

		// Verify
		claims, err := v.VerifyJWT(ctx, string(signed), []string{"talos"}, 0)
		require.NoError(t, err)
		sub, _ := claims.Subject()
		require.Equal(t, "user123", sub)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()

		tok, err := jwt.NewBuilder().
			Issuer("talos").
			Subject("user123").
			Expiration(time.Now().Add(-time.Hour)).
			Build()
		require.NoError(t, err)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
		require.NoError(t, err)

		_, err = v.VerifyJWT(ctx, string(signed), []string{"talos"}, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), `"exp" not satisfied`)
	})

	t.Run("no keys available", func(t *testing.T) {
		t.Parallel()

		// Empty JWKS — no keys
		emptyJWKS := `{"keys":[]}`
		emptyURL := "base64://" + base64.StdEncoding.EncodeToString([]byte(emptyJWKS))
		emptyService := newKeyServiceFromURL(t, emptyURL)
		emptyVerifier := NewVerifier(emptyService)

		_, err := emptyVerifier.VerifyJWT(ctx, "some.token.here", []string{"talos"}, 0)
		require.Error(t, err)
		herodotErr, ok := stderrors.AsType[*herodot.DefaultError](err)
		require.True(t, ok)
		require.Equal(t, 503, herodotErr.StatusCode())
		require.Contains(t, herodotErr.Reason(), "get signing keys")
	})
}

func TestVerifyMacaroon(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Macaroon verification never consults KeyService — a nil key service is
	// enough to prove the invariant that JWT key material is off the macaroon
	// verify path.
	v := NewVerifier(nil)

	t.Run("no HMAC secrets configured", func(t *testing.T) {
		t.Parallel()

		_, err := v.VerifyMacaroon(ctx, "token", nil, []string{"issuer"}, []string{"mc"}, 5*time.Minute)
		require.Error(t, err)
		herodotErr, ok := stderrors.AsType[*herodot.DefaultError](err)
		require.True(t, ok)
		require.Equal(t, 503, herodotErr.StatusCode())
		require.Contains(t, herodotErr.Reason(), "HMAC secrets")
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()

		// Just ensure it reaches the verification step and fails on invalid token.
		_, err := v.VerifyMacaroon(ctx, "invalid-token-string", [][]byte{[]byte("some-hmac-secret-32-bytes-longxxx")}, []string{"https://issuer.com"}, []string{"mc"}, 5*time.Minute)
		require.Error(t, err)
	})
}

// reviewed - @aeneasr - 2026-03-26
