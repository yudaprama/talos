package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SignerTestCase defines a test case for a specific signer implementation
type SignerTestCase struct {
	Name         string
	Issuer       string // Issuer to use in claims (must match macaroon location for macaroon signers)
	CreateSigner func(*testing.T) Signer
	// Verify uses the standalone verification function appropriate for the algorithm.
	Verify func(ctx context.Context, _ *testing.T, tokenString string) (*Claims, error)
}

// buildJWTVerifyFunc returns a verify function for a JWTSigner using standalone verification.
func buildJWTVerifyFunc(t *testing.T, signer *JWTSigner) func(ctx context.Context, _ *testing.T, tokenString string) (*Claims, error) {
	t.Helper()
	pub, err := signer.PublicKey()
	require.NoError(t, err)
	k, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, signer.KeyID()))
	switch signer.algorithm {
	case JWTAlgorithmEdDSA:
		require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	case JWTAlgorithmRS256:
		require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.RS256()))
	}
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(k))
	return func(ctx context.Context, _ *testing.T, tokenString string) (*Claims, error) {
		return verifyJWTWithKeySet(ctx, tokenString, keySet, 0)
	}
}

// buildMacaroonVerifyFunc returns a verify function for a MacaroonSigner using standalone verification.
func buildMacaroonVerifyFunc(t *testing.T, hmacSecret []byte, prefix string) func(ctx context.Context, _ *testing.T, tokenString string) (*Claims, error) {
	t.Helper()
	return func(ctx context.Context, _ *testing.T, tokenString string) (*Claims, error) {
		return VerifyMacaroonWithSecrets(ctx, tokenString, [][]byte{hmacSecret}, []string{testIssuer}, []string{prefix}, testClockSkew)
	}
}

// getFullSignerTestCases returns test cases with proper verify functions.
func getFullSignerTestCases(t *testing.T) []SignerTestCase {
	t.Helper()
	edKey := func() ed25519.PrivateKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		return priv
	}
	rsaKey := func() *rsa.PrivateKey {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		return priv
	}

	edPriv := edKey()
	rsaPriv := rsaKey()
	macSecret := []byte("signer-test-hmac-secret-must-be-32-bytes!!")

	edSigner, err := NewJWTSigner(edPriv, "test-key-ed25519")
	require.NoError(t, err)
	rsaSigner, err := NewJWTSigner(rsaPriv, "test-key-rsa")
	require.NoError(t, err)
	macSigner, err := NewMacaroonSigner(macSecret, "https://test.example.com", "mc")
	require.NoError(t, err)

	return []SignerTestCase{
		{
			Name:         "JWT_EdDSA",
			Issuer:       "test-issuer",
			CreateSigner: func(_ *testing.T) Signer { return edSigner },
			Verify:       buildJWTVerifyFunc(t, edSigner),
		},
		{
			Name:         "JWT_RS256",
			Issuer:       "test-issuer",
			CreateSigner: func(_ *testing.T) Signer { return rsaSigner },
			Verify:       buildJWTVerifyFunc(t, rsaSigner),
		},
		{
			Name:         "Macaroon_v2",
			Issuer:       "https://test.example.com", // Must match the signer location
			CreateSigner: func(_ *testing.T) Signer { return macSigner },
			Verify:       buildMacaroonVerifyFunc(t, macSecret, "mc"),
		},
	}
}

func TestSigner_SignAndVerify(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			// Create test claims
			now := time.Now()
			claims := &Claims{
				tokenID:   "test-token-id-123",
				subject:   "key-abc",
				issuer:    tc.Issuer,
				audience:  []string{"test-audience"},
				tokenType: TokenTypeIssued,
				keyID:     "key-abc",
				actorID:   "owner-xyz",
				scopes:    []string{"read", "write"},
				metadata:  map[string]any{"env": "test"},
				issuedAt:  now,
				expiresAt: now.Add(1 * time.Hour),
				notBefore: now,
			}

			// Sign
			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)
			assert.NotEmpty(t, tokenString)

			// Verify using standalone function
			verifiedClaims, err := tc.Verify(ctx, t, tokenString)
			require.NoError(t, err)
			require.NotNil(t, verifiedClaims)

			// Verify all claims match
			assert.Equal(t, claims.tokenID, verifiedClaims.tokenID)
			assert.Equal(t, claims.subject, verifiedClaims.subject)
			assert.Equal(t, claims.issuer, verifiedClaims.issuer)
			assert.Equal(t, claims.audience, verifiedClaims.audience)
			assert.Equal(t, claims.GetKeyID(), verifiedClaims.GetKeyID())
			assert.Equal(t, claims.actorID, verifiedClaims.actorID)
			assert.Equal(t, claims.scopes, verifiedClaims.scopes)
			assert.Equal(t, claims.metadata, verifiedClaims.metadata)

			// Times should be close (within 1 second due to JWT precision)
			assert.WithinDuration(t, claims.issuedAt, verifiedClaims.issuedAt, time.Second)
			assert.WithinDuration(t, claims.expiresAt, verifiedClaims.expiresAt, time.Second)
			assert.WithinDuration(t, claims.notBefore, verifiedClaims.notBefore, time.Second)
		})
	}
}

func TestSigner_ExpiredToken(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			// Create expired token
			past := time.Now().Add(-2 * time.Hour)
			claims := &Claims{
				tokenID:   "expired-token",
				subject:   "user-456",
				issuer:    tc.Issuer,
				tokenType: TokenTypeIssued,
				issuedAt:  past,
				expiresAt: past.Add(1 * time.Hour), // Expired 1 hour ago
				notBefore: past,
			}

			// Sign
			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			// Verify should fail
			_, err = tc.Verify(ctx, t, tokenString)
			require.Error(t, err)
		})
	}
}

func TestSigner_NotYetValid(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			// Create token that's not yet valid
			future := time.Now().Add(2 * time.Hour)
			claims := &Claims{
				tokenID:   "future-token",
				subject:   "user-456",
				issuer:    tc.Issuer,
				tokenType: TokenTypeIssued,
				issuedAt:  time.Now(),
				expiresAt: future.Add(1 * time.Hour),
				notBefore: future, // Not valid until 2 hours from now
			}

			// Sign
			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			// Verify should fail
			_, err = tc.Verify(ctx, t, tokenString)
			require.Error(t, err)
		})
	}
}

func TestSigner_InvalidToken(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	invalidTokens := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"random_string", "this-is-not-a-valid-token"},
		{"malformed", "a.b"},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			for _, invalidToken := range invalidTokens {
				t.Run(invalidToken.name, func(t *testing.T) {
					_, err := tc.Verify(ctx, t, invalidToken.token)
					assert.Error(t, err)
				})
			}
		})
	}
}

func TestSigner_TamperedToken(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			// Create valid token
			now := time.Now()
			claims := &Claims{
				tokenID:   "tamper-test",
				subject:   "user-456",
				issuer:    tc.Issuer,
				tokenType: TokenTypeIssued,
				issuedAt:  now,
				expiresAt: now.Add(1 * time.Hour),
				notBefore: now,
			}

			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			// Tamper with the token
			if len(tokenString) > 10 {
				tamperedToken := tokenString[:len(tokenString)-10] + "tampered00"

				// Verify should fail
				_, err = tc.Verify(ctx, t, tamperedToken)
				assert.Error(t, err)
			}
		})
	}
}

func TestSigner_MinimalClaims(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			// Minimal required claims
			now := time.Now()
			claims := &Claims{
				tokenID:   "minimal-token",
				subject:   "user-456",
				issuer:    tc.Issuer,
				tokenType: TokenTypeIssued,
				issuedAt:  now,
				expiresAt: now.Add(1 * time.Hour),
				notBefore: now,
			}

			// Sign
			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			// Verify
			verifiedClaims, err := tc.Verify(ctx, t, tokenString)
			require.NoError(t, err)
			assert.Equal(t, claims.tokenID, verifiedClaims.tokenID)
		})
	}
}

func TestSigner_SessionToken(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			// Session token with parent
			now := time.Now()
			claims := &Claims{
				tokenID:   "session-token-123",
				subject:   "key-xyz",
				issuer:    tc.Issuer,
				tokenType: TokenTypeDerived,
				parentID:  "key-xyz",
				keyID:     "key-xyz",
				issuedAt:  now,
				expiresAt: now.Add(15 * time.Minute), // Shorter lived
				notBefore: now,
			}

			// Sign
			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			// Verify (parentID falls back to subject)
			verifiedClaims, err := tc.Verify(ctx, t, tokenString)
			require.NoError(t, err)
			assert.Equal(t, "key-xyz", verifiedClaims.GetParentID())
		})
	}
}

func TestSigner_EmptyOptionalFields(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)
			ctx := t.Context()

			now := time.Now()
			claims := &Claims{
				tokenID:   "empty-fields-test",
				subject:   "user-456",
				issuer:    tc.Issuer,
				tokenType: TokenTypeIssued,
				issuedAt:  now,
				expiresAt: now.Add(1 * time.Hour),
				notBefore: now,
				// Empty/nil optional fields
				scopes:   []string{},
				metadata: map[string]any{},
				audience: []string{},
			}

			// Sign
			tokenString, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			// Verify
			verifiedClaims, err := tc.Verify(ctx, t, tokenString)
			require.NoError(t, err)
			assert.Equal(t, claims.tokenID, verifiedClaims.tokenID)
		})
	}
}

func TestSigner_PublicKeyAndKeyID(t *testing.T) {
	t.Parallel()

	testCases := getFullSignerTestCases(t)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			signer := tc.CreateSigner(t)

			// Get algorithm
			alg := signer.Algorithm()
			assert.NotEmpty(t, string(alg))

			// Get public key (skip for HMAC-based algorithms like macaroons)
			if alg != AlgorithmMacaroon {
				pubKey, err := signer.PublicKey()
				require.NoError(t, err)
				assert.NotNil(t, pubKey)
			} else {
				// Macaroons use HMAC (symmetric), so no public key
				_, err := signer.PublicKey()
				require.Error(t, err, "macaroons should return error for PublicKey()")
			}

			// JWT signers expose a per-key identifier; macaroons do not.
			kid := signer.KeyID()
			if alg == AlgorithmMacaroon {
				assert.Empty(t, kid, "macaroon KeyID must be empty (single shared secret)")
			} else {
				assert.NotEmpty(t, kid)
				assert.Contains(t, kid, "test-key")
			}
		})
	}
}

// Benchmark all signers
func BenchmarkSigner_Sign(b *testing.B) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edSigner, _ := NewJWTSigner(edPriv, "bench-ed25519")

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaSigner, _ := NewJWTSigner(rsaPriv, "bench-rsa")

	macSecret := []byte("bench-signer-hmac-secret-must-be-32-bytes!!")
	macSigner, _ := NewMacaroonSigner(macSecret, "https://bench.example.com", "mc")

	signers := []struct {
		name   string
		signer Signer
	}{
		{"JWT_EdDSA", edSigner},
		{"JWT_RS256", rsaSigner},
		{"Macaroon_v2", macSigner},
	}

	for _, s := range signers {
		b.Run(s.name, func(b *testing.B) {
			ctx := b.Context()
			now := time.Now()
			claims := &Claims{
				tokenID:   "bench-token",
				subject:   "user-456",
				issuer:    "bench-issuer",
				tokenType: TokenTypeIssued,
				issuedAt:  now,
				expiresAt: now.Add(1 * time.Hour),
				notBefore: now,
			}

			b.ResetTimer()
			for range b.N {
				_, err := s.signer.Sign(ctx, claims)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSigner_Verify(b *testing.B) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edSigner, _ := NewJWTSigner(edPriv, "bench-ed25519")
	edPub, _ := edSigner.PublicKey()
	edJWK, _ := jwk.Import(edPub)
	_ = edJWK.Set(jwk.KeyIDKey, edSigner.KeyID())
	_ = edJWK.Set(jwk.AlgorithmKey, jwa.EdDSA())
	edKeySet := jwk.NewSet()
	_ = edKeySet.AddKey(edJWK)

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaSigner, _ := NewJWTSigner(rsaPriv, "bench-rsa")
	rsaPub, _ := rsaSigner.PublicKey()
	rsaJWK, _ := jwk.Import(rsaPub)
	_ = rsaJWK.Set(jwk.KeyIDKey, rsaSigner.KeyID())
	_ = rsaJWK.Set(jwk.AlgorithmKey, jwa.RS256())
	rsaKeySet := jwk.NewSet()
	_ = rsaKeySet.AddKey(rsaJWK)

	macSecret := []byte("bench-signer-hmac-secret-must-be-32-bytes!!")
	macSigner, _ := NewMacaroonSigner(macSecret, "https://bench.example.com", "mc")
	macSecrets := [][]byte{macSecret}

	type benchCase struct {
		name   string
		signer Signer
		verify func(_ context.Context, token string) (*Claims, error)
	}

	cases := []benchCase{
		{"JWT_EdDSA", edSigner, func(ctx context.Context, token string) (*Claims, error) {
			return verifyJWTWithKeySet(ctx, token, edKeySet, 0)
		}},
		{"JWT_RS256", rsaSigner, func(ctx context.Context, token string) (*Claims, error) {
			return verifyJWTWithKeySet(ctx, token, rsaKeySet, 0)
		}},
		{"Macaroon_v2", macSigner, func(ctx context.Context, token string) (*Claims, error) {
			return VerifyMacaroonWithSecrets(ctx, token, macSecrets, []string{"https://bench.example.com"}, []string{"mc"}, testClockSkew)
		}},
	}

	for _, bc := range cases {
		b.Run(bc.name, func(b *testing.B) {
			ctx := b.Context()
			now := time.Now()
			claims := &Claims{
				tokenID:   "bench-token",
				subject:   "user-456",
				issuer:    "bench-issuer",
				tokenType: TokenTypeIssued,
				issuedAt:  now,
				expiresAt: now.Add(1 * time.Hour),
				notBefore: now,
			}

			tokenString, _ := bc.signer.Sign(ctx, claims)

			b.ResetTimer()
			for range b.N {
				_, err := bc.verify(ctx, tokenString)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
