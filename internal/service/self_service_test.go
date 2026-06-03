package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/ory/talos/internal/errdef"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

func dbKeyToVerifyResponseT(t *testing.T, dbKey *db.IssuedApiKey) *talosv2alpha1.VerifyApiKeyResponse {
	t.Helper()
	response, err := dbKeyToVerifyResponse(t.Context(), dbKey)
	require.NoError(t, err)
	return response
}

func TestDbKeyToVerifyResponse_RateLimitPolicy(t *testing.T) {
	t.Parallel()

	t.Run("includes rate limit policy when both quota and window are set", func(t *testing.T) {
		t.Parallel()

		expiresAt := time.Now().Add(24 * time.Hour)

		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_123",
			ActorID:         new("user_456"),
			Scopes:          json.RawMessage(`["read","write"]`),
			ExpiresAt:       &expiresAt,
			Metadata:        json.RawMessage(`{}`),
			RateLimitQuota:  new(int64(1000)),
			RateLimitWindow: new(int64(3600)),
		}

		response := dbKeyToVerifyResponseT(t, dbKey)

		require.NotNil(t, response)
		assert.True(t, response.IsValid)
		assert.Equal(t, "test_key_123", response.KeyId)
		assert.Equal(t, "user_456", response.ActorId)

		// Verify rate limit policy is included
		require.NotNil(t, response.RateLimitPolicy)
		assert.Equal(t, int64(1000), response.RateLimitPolicy.Quota)
		require.NotNil(t, response.RateLimitPolicy.Window)
		assert.Equal(t, int64(3600), int64(response.RateLimitPolicy.Window.AsDuration().Seconds()))
		assert.Equal(t, "requests", response.RateLimitPolicy.Unit)
	})

	t.Run("omits rate limit policy when quota is nil", func(t *testing.T) {
		t.Parallel()

		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_123",
			Scopes:          json.RawMessage(`[]`),
			Metadata:        json.RawMessage(`{}`),
			RateLimitQuota:  nil,
			RateLimitWindow: new(int64(3600)),
		}

		response := dbKeyToVerifyResponseT(t, dbKey)

		require.NotNil(t, response)
		assert.Nil(t, response.RateLimitPolicy)
	})

	t.Run("omits rate limit policy when window is nil", func(t *testing.T) {
		t.Parallel()

		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_123",
			Scopes:          json.RawMessage(`[]`),
			Metadata:        json.RawMessage(`{}`),
			RateLimitQuota:  new(int64(1000)),
			RateLimitWindow: nil,
		}

		response := dbKeyToVerifyResponseT(t, dbKey)

		require.NotNil(t, response)
		assert.Nil(t, response.RateLimitPolicy)
	})

	t.Run("omits rate limit policy when both are nil", func(t *testing.T) {
		t.Parallel()

		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_123",
			Scopes:          json.RawMessage(`[]`),
			Metadata:        json.RawMessage(`{}`),
			RateLimitQuota:  nil,
			RateLimitWindow: nil,
		}

		response := dbKeyToVerifyResponseT(t, dbKey)

		require.NotNil(t, response)
		assert.Nil(t, response.RateLimitPolicy)
	})

	t.Run("handles zero values correctly", func(t *testing.T) {
		t.Parallel()

		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_123",
			Scopes:          json.RawMessage(`[]`),
			Metadata:        json.RawMessage(`{}`),
			RateLimitQuota:  new(int64(0)),
			RateLimitWindow: new(int64(0)),
		}

		response := dbKeyToVerifyResponseT(t, dbKey)

		require.NotNil(t, response)
		// Zero values are still valid policies (unlimited or invalid)
		require.NotNil(t, response.RateLimitPolicy)
		assert.Equal(t, int64(0), response.RateLimitPolicy.Quota)
		require.NotNil(t, response.RateLimitPolicy.Window)
		assert.Equal(t, int64(0), int64(response.RateLimitPolicy.Window.AsDuration().Seconds()))
	})

	t.Run("returns error response for revoked key", func(t *testing.T) {
		t.Parallel()

		response := verificationErrorToResponse(errdef.ErrAPIKeyRevoked())

		require.NotNil(t, response)
		assert.False(t, response.IsValid)
		assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_REVOKED, response.GetErrorCode())
		assert.Equal(t, "The API key has been revoked.", response.GetErrorMessage())
		// Rate limit policy should not be included in error responses
		assert.Nil(t, response.RateLimitPolicy)
	})
}

func TestDbKeyToVerifyResponse_Metadata(t *testing.T) {
	t.Parallel()

	t.Run("includes metadata along with rate limit policy", func(t *testing.T) {
		t.Parallel()

		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_123",
			Scopes:          json.RawMessage(`[]`),
			Metadata:        json.RawMessage(`{"environment":"production","tier":"premium"}`),
			RateLimitQuota:  new(int64(500)),
			RateLimitWindow: new(int64(60)),
		}

		response := dbKeyToVerifyResponseT(t, dbKey)

		require.NotNil(t, response)
		assert.True(t, response.IsValid)

		// Verify both metadata and rate limit policy are included
		require.NotNil(t, response.Metadata)
		require.NotNil(t, response.RateLimitPolicy)
		assert.Equal(t, int64(500), response.RateLimitPolicy.Quota)
		require.NotNil(t, response.RateLimitPolicy.Window)
		assert.Equal(t, int64(60), int64(response.RateLimitPolicy.Window.AsDuration().Seconds()))
	})
}

func TestDbKeyToVerifyResponse_AllFields(t *testing.T) {
	t.Parallel()

	t.Run("key with allowed_cidrs still returns active response", func(t *testing.T) {
		// VerifyApiKeyResponse does not carry IP restriction data.
		// IP enforcement happens in the verifier layer before dbKeyToVerifyResponse is called.
		// This test asserts the mapper does not fail on a key that has AllowedCidrs set.
		t.Parallel()
		cidrs, _ := json.Marshal([]string{"10.0.0.0/8", "192.168.0.0/16"})
		dbKey := &db.IssuedApiKey{
			KeyID:        "test_key_ip",
			ActorID:      new("user_ip"),
			Scopes:       json.RawMessage(`["read"]`),
			Metadata:     json.RawMessage(`{}`),
			AllowedCidrs: cidrs,
		}
		resp := dbKeyToVerifyResponseT(t, dbKey)
		require.NotNil(t, resp)
		assert.True(t, resp.IsValid)
		assert.Equal(t, "test_key_ip", resp.KeyId)
	})

	t.Run("key with rate limits and expiry returns all fields populated", func(t *testing.T) {
		t.Parallel()
		expiresAt := time.Now().Add(time.Hour)
		dbKey := &db.IssuedApiKey{
			KeyID:           "test_key_full",
			ActorID:         new("user_full"),
			Scopes:          json.RawMessage(`["read","write"]`),
			Metadata:        json.RawMessage(`{"env":"prod"}`),
			ExpiresAt:       &expiresAt,
			RateLimitQuota:  new(int64(100)),
			RateLimitWindow: new(int64(60)),
		}
		resp := dbKeyToVerifyResponseT(t, dbKey)
		require.NotNil(t, resp)
		assert.True(t, resp.IsValid)
		assert.Equal(t, "test_key_full", resp.KeyId)
		assert.Equal(t, "user_full", resp.ActorId)
		require.NotNil(t, resp.ExpireTime)
		require.NotNil(t, resp.RateLimitPolicy)
		assert.Equal(t, int64(100), resp.RateLimitPolicy.Quota)
		require.NotNil(t, resp.Metadata)
	})

	t.Run("key with past expiry is still reported as active by dbKeyToVerifyResponse", func(t *testing.T) {
		t.Parallel()
		// dbKeyToVerifyResponse is a pure field mapper — it does NOT check expiry.
		// Expiry enforcement happens in the verifier before this function is called.
		past := time.Now().Add(-time.Hour)
		dbKey := &db.IssuedApiKey{
			KeyID:     "test_key_expired",
			ActorID:   new("user_exp"),
			Scopes:    json.RawMessage(`[]`),
			Metadata:  json.RawMessage(`{}`),
			ExpiresAt: &past,
		}
		resp := dbKeyToVerifyResponseT(t, dbKey)
		require.NotNil(t, resp)
		// The function itself does not enforce expiry — IsValid is always true here.
		assert.True(t, resp.IsValid)
		require.NotNil(t, resp.ExpireTime, "expire_time must be populated even for past expiry")
	})
}

func TestDbKeyToVerifyResponse_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("all fields survive JSON marshal and unmarshal", func(t *testing.T) {
		t.Parallel()

		expiresAt := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		actorID := "user_roundtrip"

		dbKey := &db.IssuedApiKey{
			KeyID:           "key_roundtrip",
			ActorID:         &actorID,
			Scopes:          json.RawMessage(`["read","write","admin"]`),
			Metadata:        json.RawMessage(`{"env":"prod","tier":"premium"}`),
			ExpiresAt:       &expiresAt,
			RateLimitQuota:  new(int64(500)),
			RateLimitWindow: new(int64(60)),
			Visibility:      int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC),
		}

		original := dbKeyToVerifyResponseT(t, dbKey)
		require.NotNil(t, original)

		// Marshal to JSON using protojson (canonical proto serialization)
		data, err := protojson.Marshal(original)
		require.NoError(t, err)

		// Verify all expected fields are present in JSON
		assert.JSONEq(t, `{
			"isValid": true,
			"keyId": "key_roundtrip",
			"actorId": "user_roundtrip",
			"scopes": ["read", "write", "admin"],
			"expireTime": "2026-06-15T12:00:00Z",
			"metadata": {"env": "prod", "tier": "premium"},
			"rateLimitPolicy": {
				"quota": "500",
				"window": "60s",
				"unit": "requests"
			},
			"visibility": "KEY_VISIBILITY_PUBLIC"
		}`, string(data))

		// Unmarshal back and verify fields match
		roundTripped := &talosv2alpha1.VerifyApiKeyResponse{}
		err = protojson.Unmarshal(data, roundTripped)
		require.NoError(t, err)

		assert.Equal(t, original.IsValid, roundTripped.IsValid)
		assert.Equal(t, original.KeyId, roundTripped.KeyId)
		assert.Equal(t, original.ActorId, roundTripped.ActorId)
		assert.Equal(t, original.Scopes, roundTripped.Scopes)
		assert.Equal(t, original.ExpireTime.AsTime(), roundTripped.ExpireTime.AsTime())
		assert.Equal(t, original.Visibility, roundTripped.Visibility)
		assert.Equal(t, original.RateLimitPolicy.Quota, roundTripped.RateLimitPolicy.Quota)
		assert.Equal(t, original.RateLimitPolicy.Window.AsDuration(), roundTripped.RateLimitPolicy.Window.AsDuration())
	})

	t.Run("nil optional fields produce clean JSON", func(t *testing.T) {
		t.Parallel()

		dbKey := &db.IssuedApiKey{
			KeyID:    "key_minimal",
			Scopes:   json.RawMessage(`[]`),
			Metadata: json.RawMessage(`{}`),
		}

		resp := dbKeyToVerifyResponseT(t, dbKey)
		data, err := protojson.Marshal(resp)
		require.NoError(t, err)

		// Verify nil fields are omitted from JSON
		var raw map[string]any
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "keyId")
		assert.NotContains(t, raw, "expireTime", "nil expire_time should be omitted")
		assert.NotContains(t, raw, "rateLimitPolicy", "nil rate_limit_policy should be omitted")
		assert.NotContains(t, raw, "metadata", "empty metadata should be omitted")
	})
}

func TestDbKeyToVerifyResponse_MalformedScopes(t *testing.T) {
	t.Parallel()

	_, err := dbKeyToVerifyResponse(t.Context(), &db.IssuedApiKey{
		KeyID:  "key_bad_scopes",
		Scopes: json.RawMessage(`{"oops"`),
	})
	require.Error(t, err)
}

// reviewed - @aeneasr - 2026-03-26
