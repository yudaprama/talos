package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// TestSigningKeyJWKSURL generates an Ed25519 signing key pair and returns a
// base64:// URL containing the serialized JWK set. The URL can be used directly
// as a signing_keys.urls config value, exercising the same fetcher path as production.
func TestSigningKeyJWKSURL(tb testing.TB) string {
	tb.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)

	return ed25519PrivateKeyToJWKSURL(tb, priv, "test-signing-key-1")
}

// TestSigningKeyJWKSURLWithKey generates a base64:// JWKS URL from the given
// Ed25519 private key and key ID. Use this when the test needs access to the
// private key (e.g. to manually sign JWTs for verification testing).
func TestSigningKeyJWKSURLWithKey(tb testing.TB, priv ed25519.PrivateKey, keyID string) string {
	tb.Helper()
	return ed25519PrivateKeyToJWKSURL(tb, priv, keyID)
}

// TestSigningKeyJWKSURLWithHMAC generates a base64:// JWKS URL containing both
// an Ed25519 key and an HMAC (oct) key. Use this to test that symmetric keys
// are properly filtered from the public JWKS endpoint.
func TestSigningKeyJWKSURLWithHMAC(tb testing.TB) string {
	tb.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)

	edKey := newEd25519JWK(tb, priv, "test-ed25519-key")

	hmacSecret := make([]byte, 32)
	_, err = rand.Read(hmacSecret)
	require.NoError(tb, err)

	hmacKey, err := jwk.Import(hmacSecret)
	require.NoError(tb, err)
	require.NoError(tb, hmacKey.Set(jwk.KeyIDKey, "test-hmac-key"))
	require.NoError(tb, hmacKey.Set(jwk.AlgorithmKey, jwa.HS256()))
	require.NoError(tb, hmacKey.Set(jwk.KeyUsageKey, "sig"))

	keySet := jwk.NewSet()
	require.NoError(tb, keySet.AddKey(edKey))
	require.NoError(tb, keySet.AddKey(hmacKey))

	return jwksToBase64URL(tb, keySet)
}

func ed25519PrivateKeyToJWKSURL(tb testing.TB, priv ed25519.PrivateKey, keyID string) string {
	tb.Helper()

	keySet := jwk.NewSet()
	require.NoError(tb, keySet.AddKey(newEd25519JWK(tb, priv, keyID)))

	return jwksToBase64URL(tb, keySet)
}

// TestTwoKeyJWKSURL builds a base64:// JWKS URL containing two Ed25519 keys with
// the provided key IDs. If useSigOnSecond is true, the second key is marked
// use="sig" so KeyService default selection prefers it. Use this helper when a
// test needs to prove that `signing_key_id` overrides the default-selection
// heuristics (use:sig preference, first-key fallback).
func TestTwoKeyJWKSURL(tb testing.TB, kid1, kid2 string, useSigOnSecond bool) string {
	tb.Helper()

	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)
	key1, err := jwk.Import(priv1)
	require.NoError(tb, err)
	require.NoError(tb, key1.Set(jwk.KeyIDKey, kid1))

	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)
	key2, err := jwk.Import(priv2)
	require.NoError(tb, err)
	require.NoError(tb, key2.Set(jwk.KeyIDKey, kid2))
	if useSigOnSecond {
		require.NoError(tb, key2.Set(jwk.KeyUsageKey, "sig"))
	}

	keySet := jwk.NewSet()
	require.NoError(tb, keySet.AddKey(key1))
	require.NoError(tb, keySet.AddKey(key2))

	return jwksToBase64URL(tb, keySet)
}

func newEd25519JWK(tb testing.TB, priv ed25519.PrivateKey, keyID string) jwk.Key {
	tb.Helper()

	key, err := jwk.Import(priv)
	require.NoError(tb, err)
	require.NoError(tb, key.Set(jwk.KeyIDKey, keyID))
	require.NoError(tb, key.Set(jwk.AlgorithmKey, "EdDSA"))
	require.NoError(tb, key.Set(jwk.KeyUsageKey, "sig"))

	return key
}

func jwksToBase64URL(tb testing.TB, keySet jwk.Set) string {
	tb.Helper()

	data, err := json.Marshal(keySet)
	require.NoError(tb, err)

	return "base64://" + base64.StdEncoding.EncodeToString(data)
}

// reviewed - @aeneasr - 2026-03-26
