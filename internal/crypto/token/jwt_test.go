package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyJWTWithSigner is a test helper that builds a key set from the signer's public key
// and verifies a JWT token using the standalone verifyJWTWithKeySet function.
func verifyJWTWithSigner(t *testing.T, ctx context.Context, signer *JWTSigner, tokenString string) (*Claims, error) {
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
	return verifyJWTWithKeySet(ctx, tokenString, keySet)
}

func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return priv
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return priv
}

func TestNewJWTSigner_EdDSA(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	kid := "test-key-1"

	signer, err := NewJWTSigner(priv, kid)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, AlgorithmJWT, signer.Algorithm())
	assert.Equal(t, kid, signer.KeyID())
}

func TestNewJWTSigner_RS256(t *testing.T) {
	t.Parallel()

	priv := generateRSAKey(t)
	kid := "test-key-2"

	signer, err := NewJWTSigner(priv, kid)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, AlgorithmJWT, signer.Algorithm())
	assert.Equal(t, kid, signer.KeyID())
}

func TestNewJWTSigner_InvalidKeyType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     any
		wantErr string
	}{
		{
			name:    "HMAC-style byte slice rejected",
			key:     []byte("secret"),
			wantErr: "unsupported private key type",
		},
		{
			name:    "unsupported struct type rejected",
			key:     struct{}{},
			wantErr: "unsupported private key type",
		},
		{
			name:    "nil key rejected",
			key:     nil,
			wantErr: "unsupported private key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewJWTSigner(tt.key, "test-kid")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestJWTSigner_SignAndVerify_EdDSA(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	kid := "test-key-1"

	signer, err := NewJWTSigner(priv, kid)
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "tok_12345",
		subject:   "user_123",
		issuer:    "talos-service",
		audience:  []string{"api.example.com"},
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
		actorID:   "user_123",
		scopes:    []string{"read", "write"},
		metadata:  map[string]any{"env": "test"},
	}

	ctx := t.Context()

	// Sign the token
	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify the token
	verifiedClaims, err := verifyJWTWithSigner(t, ctx, signer, token)
	require.NoError(t, err)
	assert.Equal(t, claims.tokenID, verifiedClaims.tokenID)
	assert.Equal(t, claims.subject, verifiedClaims.subject)
	assert.Equal(t, claims.issuer, verifiedClaims.issuer)
	assert.Equal(t, claims.audience, verifiedClaims.audience)
	assert.Equal(t, claims.actorID, verifiedClaims.actorID)
	assert.Equal(t, claims.scopes, verifiedClaims.scopes)
	assert.Equal(t, claims.metadata, verifiedClaims.metadata)
}

func TestJWTSigner_SignAndVerify_RS256(t *testing.T) {
	t.Parallel()

	priv := generateRSAKey(t)
	kid := "test-key-2"

	signer, err := NewJWTSigner(priv, kid)
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "tok_67890",
		subject:   "service_456",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(2 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeDerived,
		keyID:     "service_456",
		parentID:  "service_456",
		scopes:    []string{"read"},
	}

	ctx := t.Context()

	// Sign the token
	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify the token
	// tokenType, keyID, and parentID are not serialized to JWT;
	// GetKeyID/GetParentID fall back to subject.
	verifiedClaims, err := verifyJWTWithSigner(t, ctx, signer, token)
	require.NoError(t, err)
	assert.Equal(t, claims.tokenID, verifiedClaims.tokenID)
	assert.Equal(t, claims.subject, verifiedClaims.GetKeyID())
	assert.Equal(t, claims.subject, verifiedClaims.GetParentID())
}

func TestJWTSigner_VerifyInvalidToken(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "test-kid")
	require.NoError(t, err)

	ctx := t.Context()

	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{
			name:    "Malformed token",
			token:   "not.a.valid.token",
			wantErr: "parse",
		},
		{
			name:    "Empty token",
			token:   "",
			wantErr: "parse",
		},
		{
			name:    "Random string",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
			wantErr: "parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifyJWTWithSigner(t, ctx, signer, tt.token)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestJWTSigner_VerifyExpiredToken(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "test-kid")
	require.NoError(t, err)

	// Create an already expired token
	claims := &Claims{
		tokenID:   "tok_expired",
		subject:   "user_123",
		issuer:    "talos-service",
		issuedAt:  time.Now().Add(-2 * time.Hour),
		expiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		notBefore: time.Now().Add(-2 * time.Hour),
		tokenType: TokenTypeIssued,
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Verification should fail due to expiration
	_, err = verifyJWTWithSigner(t, ctx, signer, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "\"exp\" not satisfied")
}

// Key rotation correctness is tested via TestVerifyJWT_MultipleKeys (multiple keys in key set)
// and the E2E rotation tests in internal/service/api_keys_rotate_test.go.

func TestJWTSigner_VerifyNotYetValidToken(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "test-kid")
	require.NoError(t, err)

	// Create a token that's not yet valid
	claims := &Claims{
		tokenID:   "tok_future",
		subject:   "user_123",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(2 * time.Hour),
		notBefore: time.Now().Add(1 * time.Hour), // Not valid for another hour
		tokenType: TokenTypeIssued,
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Verification should fail due to NotBefore
	_, err = verifyJWTWithSigner(t, ctx, signer, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "\"nbf\" not satisfied")
}

func TestVerifyJWTWithKeySet_MultiKey(t *testing.T) {
	t.Parallel()

	// Create two different signers
	priv1 := generateEd25519Key(t)
	signer1, err := NewJWTSigner(priv1, "key-1")
	require.NoError(t, err)

	priv2 := generateEd25519Key(t)
	signer2, err := NewJWTSigner(priv2, "key-2")
	require.NoError(t, err)

	// Build a jwk.Set from both signers' public keys
	keySet := jwk.NewSet()
	for _, s := range []*JWTSigner{signer1, signer2} {
		pub, err := s.PublicKey()
		require.NoError(t, err)
		k, err := jwk.Import(pub)
		require.NoError(t, err)
		require.NoError(t, k.Set(jwk.KeyIDKey, s.KeyID()))
		require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.EdDSA()))
		require.NoError(t, keySet.AddKey(k))
	}

	ctx := t.Context()

	// Sign tokens with different keys
	claims1 := &Claims{
		tokenID:   "tok_1",
		subject:   "user_1",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
	}
	token1, err := signer1.Sign(ctx, claims1)
	require.NoError(t, err)

	claims2 := &Claims{
		tokenID:   "tok_2",
		subject:   "user_2",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
	}
	token2, err := signer2.Sign(ctx, claims2)
	require.NoError(t, err)

	// Verifies that a key set containing multiple signing keys correctly validates
	// tokens signed by any of the keys in the set (key rotation scenario).
	// Verify both tokens with the key set
	verified1, err := verifyJWTWithKeySet(ctx, token1, keySet)
	require.NoError(t, err)
	assert.Equal(t, claims1.tokenID, verified1.tokenID)
	assert.Equal(t, claims1.subject, verified1.subject)

	verified2, err := verifyJWTWithKeySet(ctx, token2, keySet)
	require.NoError(t, err)
	assert.Equal(t, claims2.tokenID, verified2.tokenID)
	assert.Equal(t, claims2.subject, verified2.subject)
}

func TestVerifyJWTWithKeySet_UnknownKey(t *testing.T) {
	t.Parallel()

	// Create a signer
	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "unknown-key")
	require.NoError(t, err)

	ctx := t.Context()

	claims := &Claims{
		tokenID:   "tok_1",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
	}

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Verify with an empty key set - should fail
	emptyKeySet := jwk.NewSet()
	_, err = verifyJWTWithKeySet(ctx, token, emptyKeySet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "find key")
}

func TestJWTSigner_PublicKey(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "test-kid")
	require.NoError(t, err)

	pubKey, err := signer.PublicKey()
	require.NoError(t, err)
	assert.NotNil(t, pubKey)

	// Verify it's an Ed25519 public key
	_, ok := pubKey.(ed25519.PublicKey)
	assert.True(t, ok, "Public key should be Ed25519PublicKey")
}

func TestJWTSigner_SessionToken(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "test-kid")
	require.NoError(t, err)

	// Tests that a derived token (TokenTypeDerived) with parent reference can be signed
	// and verified. The verifier-level tests in verifier_test.go cover the full
	// verification path for all credential types including derived tokens.
	// Create a session token with parent reference
	claims := &Claims{
		tokenID:   "tok_session_123",
		subject:   "tok_root_456",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeDerived,
		parentID:  "tok_root_456",
		scopes:    []string{"read"}, // Attenuated scopes
	}

	ctx := t.Context()

	token, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// tokenType and parentID are not serialized; parentID falls back to subject
	verified, err := verifyJWTWithSigner(t, ctx, signer, token)
	require.NoError(t, err)
	assert.Equal(t, "tok_root_456", verified.GetParentID())
	assert.Equal(t, []string{"read"}, verified.scopes)
}

func TestJWTVerify_ValidatesIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Create signer with EdDSA
	privateKey := generateEd25519Key(t)
	signer, err := NewJWTSigner(privateKey, "test-key-id")
	require.NoError(t, err)

	// Create claims with specific issuer
	claims := NewClaims()
	claims.SetTokenID("test-token-id")
	claims.SetIssuer("https://trusted.issuer.com")
	claims.SetSubject("test-subject")
	claims.SetIssuedAt(time.Now().UTC())
	claims.SetExpiration(time.Now().UTC().Add(1 * time.Hour))

	// Sign token
	tokenString, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Build key set for standalone verification
	pub, err := signer.PublicKey()
	require.NoError(t, err)
	k, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, signer.KeyID()))
	require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(k))

	// Verify with correct expected issuer - should succeed
	verifiedClaims, err := VerifyJWTWithKeySetAndIssuer(ctx, tokenString, keySet, []string{"https://trusted.issuer.com"})
	require.NoError(t, err)
	require.NotNil(t, verifiedClaims)

	issuer, ok := verifiedClaims.Issuer()
	require.True(t, ok)
	require.Equal(t, "https://trusted.issuer.com", issuer)

	// Verify with wrong expected issuer - should fail
	_, err = VerifyJWTWithKeySetAndIssuer(ctx, tokenString, keySet, []string{"https://wrong.issuer.com"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "issuer")

	// Verify with retired issuer in allowed list - should succeed
	verifiedClaims2, err := VerifyJWTWithKeySetAndIssuer(ctx, tokenString, keySet, []string{"https://new.issuer.com", "https://trusted.issuer.com"})
	require.NoError(t, err)
	issuer2, ok := verifiedClaims2.Issuer()
	require.True(t, ok)
	require.Equal(t, "https://trusted.issuer.com", issuer2)
}

func TestJWTVerify_RejectsTokenWithoutIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Create signer
	privateKey := generateEd25519Key(t)
	signer, err := NewJWTSigner(privateKey, "test-key-id")
	require.NoError(t, err)

	// Build key set for standalone verification
	pub, err := signer.PublicKey()
	require.NoError(t, err)
	k, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, signer.KeyID()))
	require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(k))

	// Create claims WITHOUT issuer
	claims := NewClaims()
	claims.SetTokenID("test-token-id")
	claims.SetSubject("test-subject")
	claims.SetIssuedAt(time.Now().UTC())
	claims.SetExpiration(time.Now().UTC().Add(1 * time.Hour))
	// Deliberately NOT setting issuer

	// Sign token
	tokenString, err := signer.Sign(ctx, claims)
	require.NoError(t, err)

	// Verify should fail due to missing issuer
	_, err = VerifyJWTWithKeySetAndIssuer(ctx, tokenString, keySet, []string{"https://any.issuer.com"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "issuer")
}

func TestJWTSigner_AdversarialInputs(t *testing.T) {
	t.Parallel()

	priv := generateEd25519Key(t)
	signer, err := NewJWTSigner(priv, "test-kid")
	require.NoError(t, err)

	ctx := t.Context()

	// Sign a valid token so we can construct tampered variants.
	validClaims := &Claims{
		tokenID:   "tok_valid",
		subject:   "user_123",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
	}
	validToken, err := signer.Sign(ctx, validClaims)
	require.NoError(t, err)

	// Split valid token into parts for constructing adversarial variants.
	parts := splitJWT(validToken)
	require.Len(t, parts, 3, "valid JWT must have 3 parts")

	tests := []struct {
		name  string
		token string
	}{
		// Segment boundary truncation
		{name: "header only", token: parts[0]},
		{name: "header and payload only", token: parts[0] + "." + parts[1]},

		// Extra segments
		{name: "four segments", token: validToken + ".extra"},
		{name: "five segments", token: "a.b.c.d.e"},

		// Empty segments
		{name: "two dots only", token: ".."},
		{name: "empty header", token: "." + parts[1] + "." + parts[2]},
		{name: "empty payload", token: parts[0] + ".." + parts[2]},
		{name: "empty signature", token: parts[0] + "." + parts[1] + "."},

		// Garbage content
		{name: "valid base64url header garbage payload", token: parts[0] + ".AAAA.AAAA"},
		// Note: JWX library tolerates standard base64 padding in payload (strips padding before decoding).
		// This is acceptable behavior since the signature still covers the original unpadded payload.

		// Tampered signatures
		{name: "flipped last signature byte", token: flipLastByte(validToken)},
		{name: "all-zero signature", token: parts[0] + "." + parts[1] + "." + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "truncated signature to 1 byte", token: parts[0] + "." + parts[1] + "." + "QQ"},

		// Null bytes and special characters
		{name: "null byte between segments", token: parts[0] + ".\x00." + parts[2]},
		{name: "null byte in header", token: "\x00" + parts[0] + "." + parts[1] + "." + parts[2]},
		{name: "unicode BOM prefix", token: "\xef\xbb\xbf" + validToken},
		{name: "RTL override in token", token: parts[0] + ".\u202e" + parts[1] + "." + parts[2]},
		{name: "unicode replacement char", token: parts[0] + ".\ufffd." + parts[2]},

		// Large tokens
		{name: "64KB random string", token: string(make([]byte, 65536))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := verifyJWTWithSigner(t, ctx, signer, tt.token)
			assert.Error(t, err, "adversarial token %q must be rejected", tt.name)
		})
	}
}

func TestJWTSigner_CrossKeyVerification(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Sign with key A, verify with key B — must fail.
	privA := generateEd25519Key(t)
	signerA, err := NewJWTSigner(privA, "key-a")
	require.NoError(t, err)

	privB := generateEd25519Key(t)
	signerB, err := NewJWTSigner(privB, "key-b")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "tok_cross",
		subject:   "user_123",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
	}

	tokenA, err := signerA.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = verifyJWTWithSigner(t, ctx, signerB, tokenA)
	require.Error(t, err, "token signed by key-a must not verify with key-b")
}

// splitJWT splits a JWT string by "." into parts.
func splitJWT(token string) []string {
	return strings.Split(token, ".")
}

// TestJWTSigner_EmitsKIDInHeader asserts that Sign writes the signer's kid and
// algorithm into the JWS protected header. This is the direct contract between
// key selection (KeyService.GetActiveSigningKey) and what downstream verifiers
// read from the header — if the wiring in Sign ever drops the kid, every other
// test in this package would still pass because jwx tries all keys in a set
// when verifying.
func TestJWTSigner_EmitsKIDInHeader(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	claims := &Claims{
		tokenID:   "tok_kid_header",
		subject:   "user_kid_header",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
	}

	tests := []struct {
		name    string
		newKey  func(t *testing.T) any
		wantAlg string
	}{
		{
			name: "EdDSA",
			newKey: func(t *testing.T) any {
				t.Helper()
				return generateEd25519Key(t)
			},
			wantAlg: string(JWTAlgorithmEdDSA),
		},
		{
			name: "RS256",
			newKey: func(t *testing.T) any {
				t.Helper()
				return generateRSAKey(t)
			},
			wantAlg: string(JWTAlgorithmRS256),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			const wantKID = "expected-kid-xyz"
			signer, err := NewJWTSigner(tt.newKey(t), wantKID)
			require.NoError(t, err)

			signed, err := signer.Sign(ctx, claims)
			require.NoError(t, err)

			parts := splitJWT(signed)
			require.Len(t, parts, 3, "JWT must have three parts")

			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			require.NoError(t, err, "decode JWS header")

			var header map[string]any
			require.NoError(t, json.Unmarshal(headerBytes, &header))

			assert.Equal(t, wantKID, header["kid"], "kid from signer must be written into the JWS header")
			assert.Equal(t, tt.wantAlg, header["alg"], "alg from signer must match the JWS header")
		})
	}
}

// flipLastByte returns a token with the last byte of the signature flipped.
func flipLastByte(token string) string {
	if len(token) == 0 {
		return token
	}
	b := []byte(token)
	b[len(b)-1] ^= 0xFF
	return string(b)
}

// TestVerifyJWTWithKeySet_RetiredKeyNotInSet verifies that a token signed by a
// retired key (removed from the active key set) is correctly rejected. This
// exercises the "key rotation gap" scenario where an old signing key is rotated
// out before all tokens it signed have expired.
func TestVerifyJWTWithKeySet_RetiredKeyNotInSet(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// old key signs a token
	privOld := generateEd25519Key(t)
	signerOld, err := NewJWTSigner(privOld, "key-old")
	require.NoError(t, err)

	claims := &Claims{
		tokenID:   "tok_retired",
		subject:   "user_legacy",
		issuer:    "talos-service",
		issuedAt:  time.Now(),
		expiresAt: time.Now().Add(1 * time.Hour),
		notBefore: time.Now(),
		tokenType: TokenTypeIssued,
	}
	tokenOld, err := signerOld.Sign(ctx, claims)
	require.NoError(t, err)

	// Build key set with only the new key (old key has been retired)
	privNew := generateEd25519Key(t)
	signerNew, err := NewJWTSigner(privNew, "key-new")
	require.NoError(t, err)

	pubNew, err := signerNew.PublicKey()
	require.NoError(t, err)
	k, err := jwk.Import(pubNew)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, signerNew.KeyID()))
	require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.EdDSA()))

	newOnlySet := jwk.NewSet()
	require.NoError(t, newOnlySet.AddKey(k))

	_, err = verifyJWTWithKeySet(ctx, tokenOld, newOnlySet)
	require.Error(t, err, "token signed by retired key must not verify against new-only key set")
}

// reviewed - @aeneasr - 2026-03-25
