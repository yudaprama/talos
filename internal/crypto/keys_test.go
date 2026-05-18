package crypto

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uuidRegex matches UUID v4 format (36 chars with hyphens)
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// encodeIdentifier is a test helper that encodes a timestamp+UUID pair to base58.
func encodeIdentifier(timestamp int64, uuidStr string) string {
	return base58.Encode(fmt.Appendf(nil, "%v:%s", timestamp, uuidStr))
}

func TestGenerateKeyID(t *testing.T) {
	t.Parallel()

	t.Run("generates valid UUID v4 key ID", func(t *testing.T) {
		t.Parallel()

		id := GenerateKeyID()
		assert.NotEmpty(t, id)
		assert.Len(t, id, 36, "UUID key ID should be 36 characters")

		// Verify it's valid UUID v4 format
		assert.True(t, uuidRegex.MatchString(id), "should be valid UUID v4 format")
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		t.Parallel()

		id1 := GenerateKeyID()
		id2 := GenerateKeyID()
		id3 := GenerateKeyID()

		assert.NotEqual(t, id1, id2, "IDs should be unique")
		assert.NotEqual(t, id2, id3, "IDs should be unique")
		assert.NotEqual(t, id1, id3, "IDs should be unique")
	})
}

func FuzzParseAPIKey(f *testing.F) {
	// Seed corpus with valid and invalid examples (timestamp+UUID format)
	f.Add("")
	f.Add("_")
	f.Add("___")
	f.Add("invalid")
	f.Add("sk_live_abc123xyz789")                                                    // Imported key format
	f.Add("prod_v2_5Z7Hn9K3mPqRtVwXyBcDeFgHiJkLmNoPqRsTuVwXyZ_AbC3XyZ789")           // Wrong version
	f.Add("verylongprefix_v1_5Z7Hn9K3mPqRtVwXyBcDeFgHiJkLmNoPqRsTuVwXyZ_AbC3XyZ789") // Prefix too long

	f.Fuzz(func(t *testing.T, key string) {
		// parseAPIKey should never panic, regardless of input
		components, err := parseAPIKey(key)

		if err == nil {
			// If parsing succeeds, verify the components are valid
			// Note: Use rune count (not byte length) for validation since regex counts runes
			prefixRuneCount := utf8.RuneCountInString(components.TokenPrefix)
			assert.NotEmpty(t, components.TokenPrefix, "prefix should not be empty")
			assert.GreaterOrEqual(t, prefixRuneCount, 1, "prefix should be at least 1 char")
			assert.LessOrEqual(t, prefixRuneCount, 8, "prefix should be at most 8 chars")

			assert.Equal(t, "v1", components.Version, "version should be v1")

			// KeyID should be UUID format (36 chars with hyphens)
			keyIDRuneCount := utf8.RuneCountInString(components.KeyID)
			assert.Equal(t, 36, keyIDRuneCount, "UUID key ID should be 36 chars")

			checksumRuneCount := utf8.RuneCountInString(components.Checksum)
			assert.GreaterOrEqual(t, checksumRuneCount, 10, "checksum should be at least 10 chars")
			assert.LessOrEqual(t, checksumRuneCount, 11, "checksum should be at most 11 chars")

			// Verify timestamp is present and valid
			assert.NotZero(t, components.Timestamp, "timestamp should be non-zero")

			// Parse again to ensure idempotency
			components2, err2 := parseAPIKey(key)
			require.NoError(t, err2, "second parse should also succeed")
			assert.Equal(t, components, components2, "parsing should be deterministic")
		}
	})
}

func TestDecodeIdentifier(t *testing.T) {
	t.Parallel()

	t.Run("decodes identifier to timestamp and UUID", func(t *testing.T) {
		t.Parallel()

		expectedTimestamp := int64(1707600000)
		expectedUUID := "550e8400-e29b-41d4-a716-446655440001"

		identifier := encodeIdentifier(expectedTimestamp, expectedUUID)

		timestamp, uuidStr, err := DecodeIdentifier(identifier)
		require.NoError(t, err)

		assert.Equal(t, expectedTimestamp, timestamp)
		assert.Equal(t, expectedUUID, uuidStr)
	})

	t.Run("round-trip encoding preserves data", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			timestamp int64
			uuid      string
		}{
			{
				name:      "recent timestamp",
				timestamp: 1707600000,
				uuid:      "550e8400-e29b-41d4-a716-446655440002",
			},
			{
				name:      "min timestamp (1970)",
				timestamp: 1,
				uuid:      "660f9511-f3ac-52e5-b827-557766551111",
			},
			{
				name:      "current timestamp",
				timestamp: 1739288400, // 2025-02-11 12:00:00 UTC (approximate current time)
				uuid:      "770fa622-04bd-63f6-c938-668877662222",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				identifier := encodeIdentifier(tt.timestamp, tt.uuid)

				decodedTimestamp, decodedUUID, err := DecodeIdentifier(identifier)
				require.NoError(t, err)

				assert.Equal(t, tt.timestamp, decodedTimestamp)
				assert.Equal(t, tt.uuid, decodedUUID)
			})
		}
	})

	t.Run("rejects invalid base58", func(t *testing.T) {
		t.Parallel()

		// Base58 doesn't include 0, O, I, l
		_, _, err := DecodeIdentifier("0OIl")
		require.Error(t, err)
	})

	t.Run("rejects empty identifier", func(t *testing.T) {
		t.Parallel()

		_, _, err := DecodeIdentifier("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "identifier length 0 outside valid range")
	})

	t.Run("rejects oversized identifier", func(t *testing.T) {
		t.Parallel()

		// 129-char string exceeds the 128-char max
		oversized := strings.Repeat("A", 129)
		_, _, err := DecodeIdentifier(oversized)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "outside valid range")
	})

	t.Run("rejects identifier missing colon separator", func(t *testing.T) {
		t.Parallel()

		// Encode something that doesn't contain a colon when decoded
		_, _, err := DecodeIdentifier("2NEpo7TZRRrLZSi2U")
		require.Error(t, err)
	})

	t.Run("rejects identifier with multiple colons", func(t *testing.T) {
		t.Parallel()

		// Manually encode "123:456:789" in base58
		// SplitN(_, 2) yields ["123", "456:789"], which fails uuid.FromString
		data := []byte("123:456:789")
		encoded := base58.Encode(data)
		_, _, err := DecodeIdentifier(encoded)
		require.Error(t, err)
	})

	t.Run("adversarial inputs", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			raw       string // raw content to base58-encode (if non-empty)
			literal   string // literal identifier string (if raw is empty)
			errSubstr string
		}{
			{
				name:      "negative timestamp",
				raw:       "-1:550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "", // ParseInt accepts negative values; verify it doesn't panic
			},
			{
				name:      "zero timestamp",
				raw:       "0:550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "",
			},
			{
				name:      "non-numeric timestamp",
				raw:       "notanumber:550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "parse timestamp",
			},
			{
				name:      "float timestamp",
				raw:       "123.456:550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "parse timestamp",
			},
			{
				name:      "timestamp overflow (exceeds int64)",
				raw:       "99999999999999999999:550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "parse timestamp",
			},
			{
				name:      "colon in UUID position",
				raw:       "1707600000:550e8400:e29b:41d4:a716:446655440000",
				errSubstr: "decode UUID",
			},
			{
				name:      "malformed UUID (too short)",
				raw:       "1707600000:not-a-uuid",
				errSubstr: "decode UUID",
			},
			{
				name:      "malformed UUID (nil UUID format)",
				raw:       "1707600000:00000000-0000-0000-0000-000000000000",
				errSubstr: "", // nil UUID is valid; just verify no panic
			},
			{
				name:      "empty after colon",
				raw:       "1707600000:",
				errSubstr: "outside valid range", // decoded length < 20 bytes
			},
			{
				name:      "empty before colon",
				raw:       ":550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "parse timestamp",
			},
			{
				name:      "just a colon",
				raw:       ":",
				errSubstr: "", // decoded length will be too short
			},
			{
				name:      "boundary: exactly 128-char identifier",
				literal:   strings.Repeat("A", 128),
				errSubstr: "", // may or may not decode validly, but must not panic
			},
			{
				name:      "boundary: exactly 129-char identifier (rejected)",
				literal:   strings.Repeat("A", 129),
				errSubstr: "outside valid range",
			},
			{
				name:      "single byte identifier",
				literal:   "A",
				errSubstr: "", // decoded length too short
			},
			{
				name:      "null bytes in raw content",
				raw:       "1707600000:\x00\x00\x00\x00-\x00\x00\x00\x00-\x00\x00\x00\x00-\x00\x00\x00\x00-\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
				errSubstr: "", // must not panic
			},
			{
				name:      "whitespace in timestamp",
				raw:       " 1707600000 :550e8400-e29b-41d4-a716-446655440000",
				errSubstr: "parse timestamp",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				var identifier string
				if tt.literal != "" {
					identifier = tt.literal
				} else {
					identifier = base58.Encode([]byte(tt.raw))
				}

				timestamp, uuidStr, err := DecodeIdentifier(identifier)
				if tt.errSubstr != "" {
					require.Error(t, err, "expected error for input %q", tt.name)
					assert.Contains(t, err.Error(), tt.errSubstr)
				} else if err == nil {
					// For cases where we don't assert a specific error,
					// just verify no panic. If it succeeds, check invariants.
					assert.NotEmpty(t, uuidStr, "UUID should be non-empty on success")
					_ = timestamp // timestamp may legitimately be 0 or negative
				}
			})
		}
	})
}

func TestParseAPIKey_WithTimestamp(t *testing.T) {
	t.Parallel()

	t.Run("valid API key with timestamp-embedded identifier", func(t *testing.T) {
		t.Parallel()

		// Build a valid key manually
		timestamp := int64(1707600000)
		uuidStr := "550e8400-e29b-41d4-a716-446655440003"

		identifier := encodeIdentifier(timestamp, uuidStr)

		// Construct key with placeholder checksum
		key := fmt.Sprintf("prod_v1_%s_AbC3XyZ789", identifier)

		components, err := parseAPIKey(key)
		require.NoError(t, err)

		assert.Equal(t, "prod", components.TokenPrefix)
		assert.Equal(t, "v1", components.Version)
		assert.Equal(t, uuidStr, components.KeyID)
		assert.Equal(t, timestamp, components.Timestamp)
		assert.Equal(t, "AbC3XyZ789", components.Checksum)
	})

	t.Run("invalid API keys", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			key       string
			errSubstr string
		}{
			{
				name:      "identifier too short",
				key:       "prod_v1_abc_AbC3XyZ789",
				errSubstr: "invalid API key format",
			},
			{
				name:      "invalid base58 in identifier (contains 0)",
				key:       "prod_v1_0OIl1234567890123456789012_AbC3XyZ789",
				errSubstr: "invalid API key format",
			},
			{
				name:      "missing checksum",
				key:       "prod_v1_5Z7Hn9K3mPqRtVwXyBcDeFgHiJkLmNo",
				errSubstr: "invalid API key format",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				_, err := parseAPIKey(tt.key)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			})
		}
	})
}

func TestParseAPIKey_Integration(t *testing.T) {
	t.Parallel()

	t.Run("parses complete valid key", func(t *testing.T) {
		t.Parallel()

		timestamp := int64(1739288400) // Fixed timestamp for deterministic test
		uuidStr := "550e8400-e29b-41d4-a716-446655440000"

		identifier := encodeIdentifier(timestamp, uuidStr)

		// Use realistic checksum
		key := fmt.Sprintf("test_v1_%s_AbC3XyZ789e", identifier)

		components, err := parseAPIKey(key)
		require.NoError(t, err)

		assert.Equal(t, "test", components.TokenPrefix)
		assert.Equal(t, "v1", components.Version)
		assert.Equal(t, uuidStr, components.KeyID)
		assert.Equal(t, timestamp, components.Timestamp)
		assert.Equal(t, "AbC3XyZ789e", components.Checksum)
	})

	t.Run("parsing is idempotent", func(t *testing.T) {
		t.Parallel()

		timestamp := int64(1707600000)
		uuidStr := "550e8400-e29b-41d4-a716-446655440007"
		identifier := encodeIdentifier(timestamp, uuidStr)
		key := fmt.Sprintf("dev_v1_%s_DEF456ghi7", identifier)

		components1, err := parseAPIKey(key)
		require.NoError(t, err)

		components2, err := parseAPIKey(key)
		require.NoError(t, err)

		assert.Equal(t, components1, components2)
	})
}

func TestGenerateAPIKey_WithTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hmacSecret := []byte("test-secret-key-32-bytes-long!!")

	t.Run("generates key with current timestamp", func(t *testing.T) {
		t.Parallel()

		beforeGen := time.Now().UTC().Unix()
		fullKey, keyID, err := GenerateAPIKey(ctx, "prod", hmacSecret)
		afterGen := time.Now().UTC().Unix()

		t.Log(fullKey, keyID)
		require.NoError(t, err)
		assert.NotEmpty(t, fullKey)
		assert.NotEmpty(t, keyID)

		// Parse the generated key
		components, err := parseAPIKey(fullKey)
		require.NoError(t, err)

		assert.Equal(t, "v1", components.Version)
		assert.Equal(t, "prod", components.TokenPrefix)
		assert.Equal(t, keyID, components.KeyID)

		// Timestamp should be within generation window
		assert.GreaterOrEqual(t, components.Timestamp, beforeGen)
		assert.LessOrEqual(t, components.Timestamp, afterGen)

		// Verify checksum
		_, checksumErr := VerifyAPIKeyChecksum(fullKey, [][]byte{hmacSecret})
		assert.NoError(t, checksumErr)
	})

	t.Run("generates unique keys", func(t *testing.T) {
		t.Parallel()

		key1, id1, _ := GenerateAPIKey(ctx, "test", hmacSecret)
		time.Sleep(1 * time.Second)
		key2, id2, _ := GenerateAPIKey(ctx, "test", hmacSecret)

		assert.NotEqual(t, key1, key2, "keys should be unique")
		assert.NotEqual(t, id1, id2, "key IDs should be unique")

		// Different timestamps
		comp1, _ := parseAPIKey(key1)
		comp2, _ := parseAPIKey(key2)
		assert.Less(t, comp1.Timestamp, comp2.Timestamp)
	})

	t.Run("checksum includes timestamp in HMAC", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "dev", hmacSecret)
		require.NoError(t, err)

		components, err := parseAPIKey(fullKey)
		require.NoError(t, err)

		// Tamper with timestamp by reconstructing identifier
		tamperedTimestamp := components.Timestamp + 3600 // +1 hour
		tamperedIdentifier := encodeIdentifier(tamperedTimestamp, components.KeyID)
		tamperedKey := fmt.Sprintf(
			"%s_v1_%s_%s",
			components.TokenPrefix,
			tamperedIdentifier,
			components.Checksum,
		)

		// Verification should fail (checksum won't match)
		_, tamperedErr := VerifyAPIKeyChecksum(tamperedKey, [][]byte{hmacSecret})
		assert.Error(t, tamperedErr, "tampered timestamp should fail checksum verification")
	})

	t.Run("rejects invalid prefix length", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name   string
			prefix string
		}{
			{"empty prefix", ""},
			{"too long prefix (17 chars)", "verylongprefixval"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				_, _, err := GenerateAPIKey(ctx, tt.prefix, hmacSecret)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "prefix must be 1-16 characters")
			})
		}
	})
}

func TestVerifyAPIKeyChecksum_WithTimestamp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hmacSecret := []byte("test-secret-key-32-bytes-long!!")

	t.Run("valid checksum verification succeeds", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "prod", hmacSecret)
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{hmacSecret})
		assert.NoError(t, err, "checksum should be valid for freshly generated key")
	})

	t.Run("checksum verification fails with wrong secret", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "prod", hmacSecret)
		require.NoError(t, err)

		wrongSecret := []byte("wrong-secret-key-32-bytes-long!!")
		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{wrongSecret})
		assert.Error(t, err, "checksum should fail with wrong HMAC secret")
	})

	t.Run("timestamp tampering detected", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "dev", hmacSecret)
		require.NoError(t, err)

		components, err := parseAPIKey(fullKey)
		require.NoError(t, err)

		// Tamper: change timestamp
		tamperedIdentifier := encodeIdentifier(
			components.Timestamp+3600, // +1 hour
			components.KeyID,
		)
		tamperedKey := fmt.Sprintf(
			"%s_v1_%s_%s",
			components.TokenPrefix,
			tamperedIdentifier,
			components.Checksum,
		)

		_, err = VerifyAPIKeyChecksum(tamperedKey, [][]byte{hmacSecret})
		assert.Error(t, err, "checksum should fail when timestamp is tampered")
	})

	t.Run("UUID tampering detected", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "test", hmacSecret)
		require.NoError(t, err)

		components, err := parseAPIKey(fullKey)
		require.NoError(t, err)

		// Tamper: change UUID
		differentUUID := GenerateKeyID()
		tamperedIdentifier := encodeIdentifier(
			components.Timestamp,
			differentUUID,
		)
		tamperedKey := fmt.Sprintf(
			"%s_v1_%s_%s",
			components.TokenPrefix,
			tamperedIdentifier,
			components.Checksum,
		)

		_, err = VerifyAPIKeyChecksum(tamperedKey, [][]byte{hmacSecret})
		assert.Error(t, err, "checksum should fail when UUID is tampered")
	})

	t.Run("prefix tampering detected", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "prod", hmacSecret)
		require.NoError(t, err)

		components, err := parseAPIKey(fullKey)
		require.NoError(t, err)

		// Reconstruct with different prefix
		identifier := encodeIdentifier(components.Timestamp, components.KeyID)
		tamperedKey := fmt.Sprintf(
			"dev_v1_%s_%s",
			identifier,
			components.Checksum,
		)

		_, err = VerifyAPIKeyChecksum(tamperedKey, [][]byte{hmacSecret})
		assert.Error(t, err, "checksum should fail when prefix is changed")
	})

	t.Run("invalid API key format returns error", func(t *testing.T) {
		t.Parallel()

		tests := []string{
			"invalid",
			"prod_v1",
			"prod_v1_abc",
			"",
		}

		for _, key := range tests {
			_, err := VerifyAPIKeyChecksum(key, [][]byte{hmacSecret})
			assert.Error(t, err, "invalid key format should return error: %s", key)
		}
	})
}

func TestVerifyAPIKeyChecksum_WithRotation(t *testing.T) {
	t.Parallel()

	oldSecret := []byte("old-secret-at-least-32-chars-long-1234567890")
	newSecret := []byte("new-secret-at-least-32-chars-long-1234567890")

	ctx := context.Background()

	t.Run("key created with old secret verifies with old secret only", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "test", oldSecret)
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{oldSecret})
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{newSecret})
		require.Error(t, err)
	})

	t.Run("key created with old secret verifies during rotation", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "test", oldSecret)
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{newSecret, oldSecret})
		assert.NoError(t, err)
	})

	t.Run("key created with new secret verifies after rotation", func(t *testing.T) {
		t.Parallel()

		fullKey, _, err := GenerateAPIKey(ctx, "test", newSecret)
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{newSecret})
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{newSecret, oldSecret})
		require.NoError(t, err)

		_, err = VerifyAPIKeyChecksum(fullKey, [][]byte{oldSecret})
		require.Error(t, err)
	})

	t.Run("multiple retired secrets all valid", func(t *testing.T) {
		t.Parallel()

		veryOldSecret := []byte("very-old-secret-32chars-minimum-1234567890")
		oldSecret := []byte("old-secret-at-least-32-chars-long-123456789")
		currentSecret := []byte("current-secret-32chars-minimum-1234567890")

		veryOldKey, _, err := GenerateAPIKey(ctx, "test", veryOldSecret)
		require.NoError(t, err)

		oldKey, _, err := GenerateAPIKey(ctx, "test", oldSecret)
		require.NoError(t, err)

		currentKey, _, err := GenerateAPIKey(ctx, "test", currentSecret)
		require.NoError(t, err)

		secrets := [][]byte{currentSecret, oldSecret, veryOldSecret}
		_, err = VerifyAPIKeyChecksum(veryOldKey, secrets)
		require.NoError(t, err)
		_, err = VerifyAPIKeyChecksum(oldKey, secrets)
		require.NoError(t, err)
		_, err = VerifyAPIKeyChecksum(currentKey, secrets)
		require.NoError(t, err)
	})
}

// reviewed - @aeneasr - 2026-03-26
