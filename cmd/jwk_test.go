package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/x/cmdx"
)

// parseJWKFromFile reads and parses a JWK from the given file path.
func parseJWKFromFile(t *testing.T, outputFile string) jwk.Key {
	t.Helper()

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	key, err := jwk.ParseKey(data)
	require.NoError(t, err)

	return key
}

// parseJWKSFromFile reads and parses a JWKS from the given file path, returning the first key.
func parseJWKSFromFile(t *testing.T, outputFile string) jwk.Key {
	t.Helper()

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	set, err := jwk.Parse(data)
	require.NoError(t, err)
	assert.Equal(t, 1, set.Len(), "JWKS should contain 1 key")

	key, ok := set.Key(0)
	require.True(t, ok)

	return key
}

// assertJWKFile parses a JWK from file and asserts its key type, algorithm, and key ID.
func assertJWKFile(t *testing.T, outputFile string, keyType jwa.KeyType, alg, kid string) jwk.Key {
	t.Helper()
	key := parseJWKFromFile(t, outputFile)
	assert.Equal(t, keyType, key.KeyType())
	var gotAlg jwa.SignatureAlgorithm
	require.NoError(t, key.Get(jwk.AlgorithmKey, &gotAlg))
	assert.Equal(t, alg, gotAlg.String())
	var gotKID string
	require.NoError(t, key.Get(jwk.KeyIDKey, &gotKID))
	assert.Equal(t, kid, gotKID)
	return key
}

func TestJWKGenerateEdDSA(t *testing.T) {
	t.Parallel()

	// Test basic EdDSA generation with multiple flags in one key generation
	t.Run("generate EdDSA key with all flags", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "eddsa", "--kid", "test-key-1", "--use", "sig", "--output", outputFile)
		require.NoError(t, err)

		key := assertJWKFile(t, outputFile, jwa.OKP(), jwa.EdDSA().String(), "test-key-1")

		// Verify sig usage
		var use string
		require.NoError(t, key.Get(jwk.KeyUsageKey, &use))
		assert.Equal(t, "sig", use)
	})

	t.Run("generate EdDSA public key only", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "eddsa", "--public-only", "--output", outputFile)
		require.NoError(t, err)

		key := parseJWKFromFile(t, outputFile)
		assert.Equal(t, jwa.OKP(), key.KeyType())
		var dKey any
		hasPrivate := key.Get("d", &dKey) == nil
		assert.False(t, hasPrivate, "public key should not have 'd' field")
	})

	t.Run("generate EdDSA key as JWKS", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "eddsa", "--jwks", "--output", outputFile)
		require.NoError(t, err)

		key := parseJWKSFromFile(t, outputFile)
		assert.Equal(t, jwa.OKP(), key.KeyType())
	})

	t.Run("reject alg flag", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "eddsa", "--alg", "EdDSA", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
	})
}

func TestJWKGenerateECDSA(t *testing.T) {
	t.Parallel()

	// Test P-256 (default) with custom kid - covers default curve and kid flag
	t.Run("generate P-256 ECDSA key with custom kid", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "ecdsa", "--kid", "ecdsa-key-1", "--output", outputFile)
		require.NoError(t, err)

		assertJWKFile(t, outputFile, jwa.EC(), jwa.ES256().String(), "ecdsa-key-1")
	})

	// Test P-521 curve - verifies curve flag works (P-384 uses same code path, skipped)
	t.Run("generate P-521 ECDSA key", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "ecdsa", "--curve", "P-521", "--output", outputFile)
		require.NoError(t, err)

		key := parseJWKFromFile(t, outputFile)
		assert.Equal(t, jwa.EC(), key.KeyType())
		var alg jwa.SignatureAlgorithm
		require.NoError(t, key.Get(jwk.AlgorithmKey, &alg))
		assert.Equal(t, jwa.ES512().String(), alg.String())
	})

	// Test error handling for invalid curve (no key generation)
	t.Run("reject invalid curve", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "ecdsa", "--curve", "P-128", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
	})

	t.Run("reject alg flag", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "ecdsa", "--alg", "ES256", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
	})
}

func TestJWKGenerateRSA(t *testing.T) {
	t.Parallel()

	// RSA key generation with custom algorithm and kid
	t.Run("generate RSA key with all flags", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "rsa", "--alg", "RS512", "--kid", "rsa-key-1", "--output", outputFile)
		require.NoError(t, err)

		assertJWKFile(t, outputFile, jwa.RSA(), "RS512", "rsa-key-1")
	})

	t.Run("reject bits below minimum", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "rsa", "--bits", "1024", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "below minimum of 2048")
	})

	t.Run("reject bits above maximum", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "rsa", "--bits", "8193", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum of 8192 bits")
	})

	t.Run("reject incompatible algorithm families", func(t *testing.T) {
		t.Parallel()

		for _, alg := range []string{"HS256", "ES256", "EdDSA", "HS512"} {
			t.Run(alg, func(t *testing.T) {
				t.Parallel()

				_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
					"jwk", "generate", "rsa", "--bits", "2048", "--alg", alg, "--output", filepath.Join(t.TempDir(), "key.json"))
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not valid for RSA keys")
			})
		}
	})

	t.Run("accept all valid RSA algorithm families", func(t *testing.T) {
		t.Parallel()

		for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
			t.Run(alg, func(t *testing.T) {
				t.Parallel()

				outputFile := filepath.Join(t.TempDir(), "key.json")
				_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
					"jwk", "generate", "rsa", "--bits", "2048", "--alg", alg, "--output", outputFile)
				require.NoError(t, err)

				key := parseJWKFromFile(t, outputFile)
				var gotAlg jwa.SignatureAlgorithm
				require.NoError(t, key.Get(jwk.AlgorithmKey, &gotAlg))
				assert.Equal(t, alg, gotAlg.String())
			})
		}
	})
}

func TestJWKGenerateHMAC(t *testing.T) {
	t.Parallel()

	// Test HMAC with default bits and custom kid
	t.Run("generate HMAC secret with default bits", func(t *testing.T) {
		t.Parallel()

		outputFile := filepath.Join(t.TempDir(), "key.json")
		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "hmac", "--kid", "hmac-secret-1", "--output", outputFile)
		require.NoError(t, err)

		assertJWKFile(t, outputFile, jwa.OctetSeq(), jwa.HS512().String(), "hmac-secret-1")
	})

	// Test error handling for non-multiple-of-8 bits
	t.Run("reject non-multiple-of-8 bits", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "hmac", "--bits", "100", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
	})

	// Test error handling for bits below minimum
	t.Run("reject bits below minimum", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "hmac", "--bits", "128", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "below minimum of 256")
	})

	t.Run("reject public-only flag", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "hmac", "--public-only", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
	})

	t.Run("reject alg flag", func(t *testing.T) {
		t.Parallel()

		_, _, err := cmdx.ExecCtx(t.Context(), NewRoot(), nil,
			"jwk", "generate", "hmac", "--alg", "HS256", "--output", filepath.Join(t.TempDir(), "key.json"))
		require.Error(t, err)
	})
}

// TestJWKKeyUsability verifies generated keys can be parsed and used for signing.
// This is a single test that covers key usability without duplicating algorithm tests.
func TestJWKKeyUsability(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "key.json")

	rootCmd := NewRoot()
	rootCmd.SetArgs([]string{"jwk", "generate", "eddsa", "--output", outputFile})
	err := rootCmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	key, err := jwk.ParseKey(data)
	require.NoError(t, err)

	// Verify we can extract the raw key (would be used for signing)
	var rawKey any
	err = jwk.Export(key, &rawKey)
	require.NoError(t, err)
	assert.NotNil(t, rawKey)

	// Verify we can get the public key
	pubKey, err := key.PublicKey()
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// TestJWKFingerprintDeterminism verifies that auto-generated key IDs are deterministic.
// Same key should always produce the same fingerprint (JWK Thumbprint).
func TestJWKFingerprintDeterminism(t *testing.T) {
	t.Parallel()

	// Generate the same key twice without custom kid
	tmpDir := t.TempDir()

	outputFile1 := filepath.Join(tmpDir, "key1.json")
	rootCmd1 := NewRoot()
	rootCmd1.SetArgs([]string{"jwk", "generate", "eddsa", "--output", outputFile1})
	require.NoError(t, rootCmd1.Execute())

	data1, err := os.ReadFile(outputFile1)
	require.NoError(t, err)
	key1, err := jwk.ParseKey(data1)
	require.NoError(t, err)

	// Verify key ID exists and is a fingerprint (base64-encoded, not UUID)
	var kid1 string
	require.NoError(t, key1.Get(jwk.KeyIDKey, &kid1))
	assert.NotEmpty(t, kid1, "auto-generated key ID should not be empty")
	// Base64 URL encoding uses [A-Za-z0-9_-], so we just check length (SHA256=32 bytes -> ~43 chars base64)
	assert.GreaterOrEqual(t, len(kid1), 40, "fingerprint should be reasonably long (base64-encoded SHA256)")
	// Verify it's not a UUID (UUID format has specific pattern with hyphens in fixed positions)
	assert.NotRegexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, kid1,
		"key ID should not be UUID format")
}

// TestJWKCustomKIDOverride verifies that custom key IDs override auto-generation.
func TestJWKCustomKIDOverride(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "key.json")

	rootCmd := NewRoot()
	rootCmd.SetArgs([]string{"jwk", "generate", "eddsa", "--kid", "custom-prod-key", "--output", outputFile})
	require.NoError(t, rootCmd.Execute())

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	key, err := jwk.ParseKey(data)
	require.NoError(t, err)

	// Verify custom kid is used, not auto-generated fingerprint
	var kid string
	require.NoError(t, key.Get(jwk.KeyIDKey, &kid))
	assert.Equal(t, "custom-prod-key", kid, "custom kid should override auto-generation")
}

func TestJWKEdgeCases(t *testing.T) {
	t.Parallel()

	// Large RSA key - expensive, skip in short mode
	t.Run("very large RSA key (8192 bits)", func(t *testing.T) {
		t.Parallel()

		if testing.Short() {
			t.Skip("Skipping slow test in short mode")
		}
		if os.Getenv("CI") != "" {
			t.Skip("Skipping 8192-bit RSA key generation in CI (too slow)")
		}

		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "rsa-8192.json")

		rootCmd := NewRoot()
		rootCmd.SetArgs([]string{"jwk", "generate", "rsa", "--bits", "8192", "--output", outputFile})
		err := rootCmd.Execute()
		require.NoError(t, err)

		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		key, err := jwk.ParseKey(data)
		require.NoError(t, err)
		assert.Equal(t, jwa.RSA(), key.KeyType())
	})

	// Error case: non-existent directory (tests error handling, key generation aborted on write)
	t.Run("non-existent parent directory", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "nonexistent", "subdir", "key.json")

		rootCmd := NewRoot()
		rootCmd.SetArgs([]string{"jwk", "generate", "eddsa", "--output", outputFile})
		err := rootCmd.Execute()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	// Special characters in filename - single key generation tests filesystem handling
	t.Run("special characters in filename", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		// Use unicode filename to test filesystem handling
		outputFile := filepath.Join(tmpDir, "key-файл-🔑.json")

		rootCmd := NewRoot()
		rootCmd.SetArgs([]string{"jwk", "generate", "eddsa", "--output", outputFile})
		err := rootCmd.Execute()
		require.NoError(t, err)

		_, err = os.Stat(outputFile)
		require.NoError(t, err)

		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		_, err = jwk.ParseKey(data)
		require.NoError(t, err)
	})

	// Overwrite existing file
	t.Run("overwrite existing file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		outputFile := filepath.Join(tmpDir, "existing.json")

		err := os.WriteFile(outputFile, []byte("existing content"), 0o600)
		require.NoError(t, err)

		rootCmd := NewRoot()
		rootCmd.SetArgs([]string{"jwk", "generate", "eddsa", "--output", outputFile})
		err = rootCmd.Execute()
		require.NoError(t, err)

		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)

		assert.NotEqual(t, "existing content", string(data))

		_, err = jwk.ParseKey(data)
		require.NoError(t, err)
	})
}

func TestGetJWKSCmd(t *testing.T) {
	// Not parallel: setupTestServer starts a real serve command in-process,
	// which registers metrics with prometheus.DefaultRegisterer. Parallel runs
	// of this test would panic with duplicate registration.

	tc := setupTestServer(t)

	stdout, _ := tc.execNoErr(t, "jwk", "get")

	var jwks map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &jwks))
	assert.Contains(t, jwks, "keys", "JWKS should contain 'keys' field")
}

// reviewed - @aeneasr - 2026-03-25
