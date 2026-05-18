package token

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/crypto"
)

// Benchmark JWT vs Macaroon token operations

// benchMacaroonSecret is a fixed HMAC secret used for macaroon benchmarks.
var benchMacaroonSecret = []byte("bench-hmac-secret-must-be-at-least-32-bytes!")

func setupBenchClaims(_ *testing.B) *Claims {
	now := time.Now()
	return &Claims{
		tokenID:   crypto.GenerateKeyID(),
		subject:   "user-bench",
		issuer:    "https://bench.example.com",
		tokenType: TokenTypeDerived,
		keyID:     "key-bench",
		parentID:  "parent-bench",
		actorID:   "user-123",
		scopes:    []string{"read", "write", "admin"},
		metadata: map[string]any{
			"app": "benchmark",
			"env": "test",
		},
		issuedAt:  now,
		expiresAt: now.Add(1 * time.Hour),
		notBefore: now,
	}
}

// JWT Signing Benchmarks

func BenchmarkJWT_Sign_EdDSA(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(b, err)

	signer, err := NewJWTSigner(privateKey, "test-key")
	require.NoError(b, err)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := signer.Sign(ctx, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWT_Verify_EdDSA(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(b, err)

	signer, err := NewJWTSigner(privateKey, "test-key")
	require.NoError(b, err)

	// Build key set for standalone verification
	pub, _ := signer.PublicKey()
	k, _ := jwk.Import(pub)
	_ = k.Set(jwk.KeyIDKey, signer.KeyID())
	_ = k.Set(jwk.AlgorithmKey, jwa.EdDSA())
	keySet := jwk.NewSet()
	_ = keySet.AddKey(k)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	// Create token
	token, err := signer.Sign(ctx, claims)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := verifyJWTWithKeySet(ctx, token, keySet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Macaroon Signing Benchmarks

func BenchmarkMacaroon_Sign(b *testing.B) {
	signer, err := NewMacaroonSigner(benchMacaroonSecret, "https://bench.example.com", "mc")
	require.NoError(b, err)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := signer.Sign(ctx, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMacaroon_Verify(b *testing.B) {
	signer, err := NewMacaroonSigner(benchMacaroonSecret, "https://bench.example.com", "mc")
	require.NoError(b, err)

	secrets := [][]byte{benchMacaroonSecret}

	claims := setupBenchClaims(b)
	ctx := b.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := VerifyMacaroonWithSecrets(ctx, token, secrets, []string{"https://bench.example.com"}, []string{"mc"}, testClockSkew)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Parallel benchmarks for realistic workloads

func BenchmarkJWT_Sign_EdDSA_Parallel(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(b, err)

	signer, err := NewJWTSigner(privateKey, "test-key")
	require.NoError(b, err)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := signer.Sign(ctx, claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJWT_Verify_EdDSA_Parallel(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(b, err)

	signer, err := NewJWTSigner(privateKey, "test-key")
	require.NoError(b, err)

	// Build key set for standalone verification
	pub, _ := signer.PublicKey()
	k, _ := jwk.Import(pub)
	_ = k.Set(jwk.KeyIDKey, signer.KeyID())
	_ = k.Set(jwk.AlgorithmKey, jwa.EdDSA())
	keySet := jwk.NewSet()
	_ = keySet.AddKey(k)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	// Create token
	token, err := signer.Sign(ctx, claims)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := verifyJWTWithKeySet(ctx, token, keySet)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkMacaroon_Sign_Parallel(b *testing.B) {
	signer, err := NewMacaroonSigner(benchMacaroonSecret, "https://bench.example.com", "mc")
	require.NoError(b, err)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := signer.Sign(ctx, claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkMacaroon_Verify_Parallel(b *testing.B) {
	signer, err := NewMacaroonSigner(benchMacaroonSecret, "https://bench.example.com", "mc")
	require.NoError(b, err)

	secrets := [][]byte{benchMacaroonSecret}

	claims := setupBenchClaims(b)
	ctx := b.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := VerifyMacaroonWithSecrets(ctx, token, secrets, []string{"https://bench.example.com"}, []string{"mc"}, testClockSkew)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Token size benchmarks

func BenchmarkTokenSize_JWT(b *testing.B) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(b, err)

	signer, err := NewJWTSigner(privateKey, "test-key")
	require.NoError(b, err)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(b, err)

	b.ReportMetric(float64(len(token)), "bytes/token")
}

func BenchmarkTokenSize_Macaroon(b *testing.B) {
	signer, err := NewMacaroonSigner(benchMacaroonSecret, "https://bench.example.com", "mc")
	require.NoError(b, err)

	claims := setupBenchClaims(b)
	ctx := b.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(b, err)

	b.ReportMetric(float64(len(token)), "bytes/token")
}
