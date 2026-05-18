package pagination

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testNID    = "11111111-1111-1111-1111-111111111111"
	testSecret = "test-secret-for-pagination-encryption-must-be-at-least-32-chars"
)

func TestEncodeDecodeCursor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		id        string
		wantEmpty bool
		wantErr   bool
	}{
		{
			name:    "valid cursor",
			id:      "01HQZX9VYQKJB8XQZQXQZQXQXQ",
			wantErr: false,
		},
		{
			name:      "empty id returns empty token",
			id:        "",
			wantEmpty: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Encode
			token, err := EncodeCursor(testSecret, tt.id, testNID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.wantEmpty {
				assert.Empty(t, token)
				return
			}

			assert.NotEmpty(t, token)

			// Decode
			cursor, err := DecodeCursor([]string{testSecret}, token)
			require.NoError(t, err)
			require.NotNil(t, cursor)

			assert.Equal(t, tt.id, cursor.ID)
			assert.Equal(t, testNID, cursor.NID)
		})
	}
}

func TestDecodeCursor_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		wantNil   bool
		wantError bool
	}{
		{
			name:    "empty token",
			token:   "",
			wantNil: true,
		},
		{
			name:      "invalid token",
			token:     "not-a-valid-cursor",
			wantError: true,
		},
		{
			name:      "random bytes",
			token:     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw",
			wantError: true,
		},
		{
			name:      "truncated base64 token",
			token:     "dGhpcyBpcyB0cnVuY2F0ZQ==",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cursor, err := DecodeCursor([]string{testSecret}, tt.token)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, cursor)
			}
		})
	}
}

func TestValidatePageSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pageSize int32
		want     int32
	}{
		{
			name:     "zero returns default",
			pageSize: 0,
			want:     50,
		},
		{
			name:     "negative returns default",
			pageSize: -10,
			want:     50,
		},
		{
			name:     "valid page size",
			pageSize: 100,
			want:     100,
		},
		{
			name:     "exceeds max returns max",
			pageSize: 2000,
			want:     1000,
		},
		{
			name:     "at max boundary",
			pageSize: 1000,
			want:     1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ValidatePageSize(tt.pageSize)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()

	id := "01HQZX9VYQKJB8XQZQXQZQXQXQ"

	// Encode
	token, err := EncodeCursor(testSecret, id, testNID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Decode
	cursor, err := DecodeCursor([]string{testSecret}, token)
	require.NoError(t, err)
	require.NotNil(t, cursor)

	// Verify round trip
	assert.Equal(t, id, cursor.ID)
	assert.Equal(t, testNID, cursor.NID)
}

func TestTokensAreOpaque(t *testing.T) {
	t.Parallel()

	// Generate two tokens with the same data
	id := "01HQZX9VYQKJB8XQZQXQZQXQXQ"

	token1, err := EncodeCursor(testSecret, id, testNID)
	require.NoError(t, err)

	token2, err := EncodeCursor(testSecret, id, testNID)
	require.NoError(t, err)

	// Tokens should be different due to random nonce in keysetpagination
	assert.NotEqual(t, token1, token2, "tokens with same data should be different due to random nonce")

	// But both should decode to the same values
	cursor1, err := DecodeCursor([]string{testSecret}, token1)
	require.NoError(t, err)

	cursor2, err := DecodeCursor([]string{testSecret}, token2)
	require.NoError(t, err)

	assert.Equal(t, cursor1.ID, cursor2.ID)
	assert.Equal(t, cursor1.NID, cursor2.NID)
}

func TestDifferentSecrets(t *testing.T) {
	t.Parallel()

	secret1 := "test-secret-must-be-at-least-32-characters-long"
	secret2 := "another-test-secret-must-be-at-least-32-characters"
	id := "test-id"

	// Encode with secret1
	token, err := EncodeCursor(secret1, id, testNID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Decode with secret1 works
	cursor, err := DecodeCursor([]string{secret1}, token)
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, id, cursor.ID)

	// Encode with secret2 produces a decodable token
	token2, err := EncodeCursor(secret2, id, testNID)
	require.NoError(t, err)

	cursor2, err := DecodeCursor([]string{secret2}, token2)
	require.NoError(t, err)
	assert.Equal(t, id, cursor2.ID)

	// Decoding secret1's token with secret2 fails
	_, err = DecodeCursor([]string{secret2}, token)
	assert.Error(t, err, "token from secret1 should not decode with secret2")
}

func TestEncodeCursor_SecretTooShort(t *testing.T) {
	t.Parallel()

	_, err := EncodeCursor("short", "test-id", testNID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 characters")
}

func TestEncodeCursor_EmptySecret(t *testing.T) {
	t.Parallel()

	_, err := EncodeCursor("", "test-id", testNID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 characters")
}

func TestEncodingWithoutNetworkID(t *testing.T) {
	t.Parallel()

	_, err := EncodeCursor(testSecret, "test-id", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network ID not configured")
}

func TestDecodingWithoutSecrets(t *testing.T) {
	t.Parallel()

	// First encode with a secret
	id := "test-id"
	token, err := EncodeCursor(testSecret, id, testNID)
	require.NoError(t, err)

	// Try to decode without any secrets
	_, err = DecodeCursor([]string{}, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption secrets not configured")
}

func TestEncodeDecodeCursor_NilUUID(t *testing.T) {
	t.Parallel()

	// OSS mode uses uuid.Nil which serializes to this string.
	// EncodeCursor rejects empty string NID, but nil UUID is a valid
	// non-empty string and must work for OSS pagination.
	const ossNID = "00000000-0000-0000-0000-000000000000"

	token, err := EncodeCursor(testSecret, "item-1", ossNID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	cursor, err := DecodeCursor([]string{testSecret}, token)
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, "item-1", cursor.ID)
	assert.Equal(t, ossNID, cursor.NID)
}

func TestDecodeCursorWithRetry_KeyRotation(t *testing.T) {
	t.Parallel()

	// Secret rotation scenario:
	// - oldSecret was used to create existing tokens
	// - newSecret is the current secret
	// - During grace period, both secrets should work
	oldSecret := "old-pagination-secret-at-least-32-characters-long"
	newSecret := "new-pagination-secret-at-least-32-characters-long"

	// Create token with OLD secret (simulates token created before rotation)
	tokenFromOldSecret, err := EncodeCursor(oldSecret, "item-123", testNID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenFromOldSecret)

	// Create token with NEW secret (simulates token created after rotation)
	tokenFromNewSecret, err := EncodeCursor(newSecret, "item-456", testNID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenFromNewSecret)

	t.Run("decode with only new secret fails for old tokens", func(t *testing.T) {
		cursor, err := DecodeCursor([]string{newSecret}, tokenFromOldSecret)
		require.Error(t, err)
		assert.Nil(t, cursor)
	})

	t.Run("decode with secret rotation succeeds for old tokens", func(t *testing.T) {
		// With secret rotation (new secret first, then old secret), old tokens work
		secrets := []string{newSecret, oldSecret}
		cursor, err := DecodeCursor(secrets, tokenFromOldSecret)
		require.NoError(t, err)
		require.NotNil(t, cursor)
		assert.Equal(t, "item-123", cursor.ID)
	})

	t.Run("decode with secret rotation succeeds for new tokens", func(t *testing.T) {
		// New tokens are decoded with the first (current) secret
		secrets := []string{newSecret, oldSecret}
		cursor, err := DecodeCursor(secrets, tokenFromNewSecret)
		require.NoError(t, err)
		require.NotNil(t, cursor)
		assert.Equal(t, "item-456", cursor.ID)
	})

	t.Run("encode always uses first secret", func(t *testing.T) {
		// Encoding should always use the first (current) secret
		secrets := []string{newSecret, oldSecret}
		token, err := EncodeCursor(secrets[0], "item-789", testNID)
		require.NoError(t, err)

		// Verify it was encoded with the new secret
		cursor, err := DecodeCursor([]string{newSecret}, token)
		require.NoError(t, err)
		assert.Equal(t, "item-789", cursor.ID)
	})

	t.Run("empty token returns nil cursor", func(t *testing.T) {
		secrets := []string{newSecret, oldSecret}
		cursor, err := DecodeCursor(secrets, "")
		require.NoError(t, err)
		assert.Nil(t, cursor)
	})

	t.Run("invalid token fails with all secrets", func(t *testing.T) {
		secrets := []string{newSecret, oldSecret}
		cursor, err := DecodeCursor(secrets, "invalid-token-data")
		require.Error(t, err)
		assert.Nil(t, cursor)
	})
}

func TestDecodeCursorWithRetry_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("no secrets provided", func(t *testing.T) {
		cursor, err := DecodeCursor([]string{}, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
		assert.Nil(t, cursor)
	})

	t.Run("invalid secrets in slice are skipped", func(t *testing.T) {
		token, err := EncodeCursor(testSecret, "test-id", testNID)
		require.NoError(t, err)

		// Mix of invalid (too short) and valid secrets
		secrets := []string{"short", testSecret, "x"}
		cursor, err := DecodeCursor(secrets, token)
		require.NoError(t, err)
		require.NotNil(t, cursor)
		assert.Equal(t, "test-id", cursor.ID)
	})
}

func TestDecodeCursor_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed base64",
			token: "!!!not-base64-at-all$$$",
		},
		{
			name:  "valid base64 but garbage content",
			token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		{
			name:  "empty string",
			token: "",
		},
		{
			name:  "extremely long cursor",
			token: strings.Repeat("A", 1<<16), // 64 KiB of base64 chars
		},
		{
			name:  "null bytes in cursor",
			token: "AAAA\x00\x00\x00\x00BBBB",
		},
		{
			name:  "base64 of SQL injection in id field",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"id":"'; DROP TABLE api_keys; --","nid":"` + testNID + `"}`)),
		},
		{
			name:  "base64 of SQL injection in nid field",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"id":"item-1","nid":"' OR 1=1; --"}`)),
		},
		{
			name:  "base64 of empty JSON object",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		},
		{
			name:  "base64 of JSON array instead of object",
			token: base64.RawURLEncoding.EncodeToString([]byte(`["id","nid"]`)),
		},
		{
			name:  "base64 of nested JSON",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"id":{"$ne":""},"nid":"` + testNID + `"}`)),
		},
		{
			name:  "single byte",
			token: "X",
		},
		{
			name: "unicode in cursor",
			//nolint:gosmopolitan // testing unicode handling in cursor decoding
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"id":"日本語","nid":"` + testNID + `"}`)),
		},
		{
			name:  "valid base64 of tampered cursor with extra fields",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"id":"item-1","nid":"` + testNID + `","admin":true}`)),
		},
		{
			name:  "cursor with only whitespace",
			token: "   \t\n  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cursor, err := DecodeCursor([]string{testSecret}, tt.token)
			// Empty token is valid (returns nil cursor, no error).
			// All other adversarial inputs must either error or return nil.
			if tt.token == "" {
				require.NoError(t, err)
				assert.Nil(t, cursor)
			} else {
				// The encrypted token format rejects anything that is not
				// a properly encrypted token, so all of these must fail.
				assert.Error(t, err, "adversarial token %q should be rejected", tt.name)
			}
		})
	}
}

// TestDecodeCursor_WrongSecretCannotForge verifies that a cursor encoded with
// one secret cannot be decoded with a different secret, preventing cursor
// forgery by external parties who do not know the server secret.
func TestDecodeCursor_WrongSecretCannotForge(t *testing.T) {
	t.Parallel()

	attackerSecret := "attacker-controlled-secret-at-least-32-chars-long"
	forgedToken, err := EncodeCursor(attackerSecret, "'; DROP TABLE keys; --", testNID)
	require.NoError(t, err)

	cursor, err := DecodeCursor([]string{testSecret}, forgedToken)
	require.Error(t, err, "forged token must be rejected")
	assert.Nil(t, cursor)
}

// FuzzDecodeCursor exercises the decode path with arbitrary byte strings.
// It must never panic, and must always return either a valid cursor or an error.
func FuzzDecodeCursor(f *testing.F) {
	// Seed with a valid token so the fuzzer has realistic structure to mutate.
	validToken, err := EncodeCursor(testSecret, "seed-id", testNID)
	require.NoError(f, err)

	f.Add(validToken)
	f.Add("")
	f.Add("not-a-token")
	f.Add(strings.Repeat("A", 1<<16))
	f.Add("AAAA\x00\x00\x00\x00BBBB")

	f.Fuzz(func(t *testing.T, token string) {
		cursor, err := DecodeCursor([]string{testSecret}, token)
		if err != nil {
			// Error path — cursor must be nil.
			assert.Nil(t, cursor, "on error, cursor must be nil")
			return
		}
		// Success path — only the empty-token case returns (nil, nil).
		if token == "" {
			assert.Nil(t, cursor)
		} else {
			require.NotNil(t, cursor)
			assert.NotEmpty(t, cursor.ID)
			assert.NotEmpty(t, cursor.NID)
		}
	})
}

// FuzzCursorRoundTrip verifies that Encode→Decode is an identity for arbitrary
// ID and NID values. The fuzz engine generates random ID/NID pairs; every
// successful encode must decode back to the original values.
func FuzzCursorRoundTrip(f *testing.F) {
	f.Add("seed-id", testNID)
	f.Add("01HQZX9VYQKJB8XQZQXQZQXQXQ", "22222222-2222-2222-2222-222222222222")
	f.Add("", testNID) // empty ID is a special case: EncodeCursor returns ""
	//nolint:gosmopolitan // testing unicode handling in cursor round-trip
	f.Add("日本語", "33333333-3333-3333-3333-333333333333")
	f.Add(strings.Repeat("x", 4096), testNID) // very long ID

	f.Fuzz(func(t *testing.T, id, nid string) {
		// EncodeCursor rejects empty NID.
		// Skip non-UTF-8 inputs: JSON marshaling (used by keysetpagination) replaces
		// invalid UTF-8 with U+FFFD, which breaks the round-trip equality check.
		// Real cursor IDs are always valid UTF-8 (UUIDs, base62-encoded IDs).
		if nid == "" || !utf8.ValidString(id) || !utf8.ValidString(nid) {
			return
		}

		token, err := EncodeCursor(testSecret, id, nid)
		require.NoError(t, err)

		if id == "" {
			assert.Empty(t, token, "empty ID must produce empty token")
			return
		}

		require.NotEmpty(t, token)

		cursor, err := DecodeCursor([]string{testSecret}, token)
		require.NoError(t, err)
		require.NotNil(t, cursor)
		assert.Equal(t, id, cursor.ID, "round-trip ID mismatch")
		assert.Equal(t, nid, cursor.NID, "round-trip NID mismatch")
	})
}

// reviewed - @aeneasr - 2026-03-26
