// Package persistencetest provides test utilities for persistence package that require the testing package.
// Separated to prevent testing package from polluting production binaries.
package persistencetest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/contextx"

	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/persistence"
	"github.com/ory/talos/internal/persistence/persistmodel"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
	persistencetypes "github.com/ory/talos/internal/persistence/types"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// DriverTestSuite provides comprehensive tests for persistence.Persister interface
// Can be used with any driver implementation (SQLite, Postgres, MySQL, CockroachDB)
type DriverTestSuite struct {
	t      *testing.T
	driver persistence.Persister
	nid    uuid.UUID
}

// RunDriverTestSuite executes all tests in the suite against the provided driver
// This validates that the driver correctly implements the persistence.Persister interface
func RunDriverTestSuite(t *testing.T, driver persistence.Persister, nid uuid.UUID) {
	t.Helper()

	suite := &DriverTestSuite{
		t:      t,
		driver: driver,
		nid:    nid,
	}

	// Test groups organized by functionality
	t.Run("ConnectionLifecycle", suite.TestConnectionLifecycle)
	t.Run("APIKeyOperations", suite.TestAPIKeyOperations)
	t.Run("APIKeyListing", suite.TestAPIKeyListing)
	t.Run("APIKeyExpiration", suite.TestAPIKeyExpiration)
	t.Run("APIKeyRevocation", suite.TestAPIKeyRevocation)
	t.Run("ImportedKeyOperations", suite.TestImportedKeyOperations)
	t.Run("FullLifecycle", suite.TestFullLifecycle)
	t.Run("UTCTimestampEnforcement", suite.TestUTCTimestampEnforcement)
	t.Run("APIKeyIdempotency", suite.TestAPIKeyIdempotency)
	t.Run("BatchImportIdempotency", suite.TestBatchImportIdempotency)
	t.Run("GetImportedAPIKeysBatch", suite.TestGetImportedAPIKeysBatch)
	t.Run("APIKeyRotation", suite.TestAPIKeyRotation)
	t.Run("ImportedAPIKeyRotation", suite.TestImportedAPIKeyRotation)
	t.Run("IssuedKey_FullFieldRoundTrip", suite.TestIssuedKeyFullFieldRoundTrip)
	t.Run("ImportedKey_FullFieldRoundTrip", suite.TestImportedKeyFullFieldRoundTrip)
	t.Run("BatchCreateImported_FullFieldRoundTrip", suite.TestBatchCreateImportedFullFieldRoundTrip)
	t.Run("GetIssuedAPIKeyByRequestID", suite.TestGetIssuedAPIKeyByRequestID)
	t.Run("InitializeIdempotency", suite.TestInitializeIdempotency)
	t.Run("InitializeNetworkIdempotency", suite.TestInitializeNetworkIdempotency)
	t.Run("BatchUpdateLastUsed", suite.TestBatchUpdateLastUsed)
	t.Run("CountActiveAPIKeysUpTo", suite.TestCountActiveAPIKeysUpTo)
}

// ctx returns the test context for test operations with NID already set
func (s *DriverTestSuite) ctx() context.Context {
	return context.WithValue(s.t.Context(), contextx.NIDKey{}, s.nid)
}

func (s *DriverTestSuite) createAPIKey(params persistencetypes.CreateIssuedAPIKeyParams) (db.IssuedApiKey, error) {
	return s.driver.CreateIssuedAPIKey(s.ctx(), params)
}

func (s *DriverTestSuite) createImportedAPIKey(params persistencetypes.CreateImportedKeyParams) (db.ImportedApiKey, error) {
	return s.driver.CreateImportedAPIKey(s.ctx(), params)
}

// revokeAPIKey is a shorthand that revokes an API key with KEY_COMPROMISE reason.
func (s *DriverTestSuite) revokeAPIKey(keyID string) error {
	return s.driver.RevokeIssuedAPIKey(s.ctx(), persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:       keyID,
		Reason:      int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
		Description: "",
	})
}

func (s *DriverTestSuite) revokeImportedAPIKey(keyID string, reason int32, reasonText string, expiresAt *time.Time) (db.ImportedApiKey, error) {
	return s.driver.RevokeImportedAPIKey(s.ctx(), persistencetypes.RevokeImportedKeyParams{
		KeyID:       keyID,
		Reason:      reason,
		Description: reasonText,
		ExpiresAt:   expiresAt,
	})
}

func newCreateParams(keyID, name, actorID string, scopes []string) persistencetypes.CreateIssuedAPIKeyParams {
	// Marshal scopes to JSON for the new validation-normalized interface
	scopesJSON, _ := json.Marshal(scopes) //nolint:errchkjson // test helper, error impossible for string slices
	if len(scopesJSON) == 0 {
		scopesJSON = json.RawMessage(`[]`)
	}
	return persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:       keyID,
		Name:        name,
		TokenPrefix: "pk_test_",
		ActorID:     actorID,
		Scopes:      scopesJSON,
	}
}

// scopesToJSON is a helper that converts []string to json.RawMessage for tests
func scopesToJSON(scopes []string) json.RawMessage {
	if len(scopes) == 0 {
		return json.RawMessage(`[]`)
	}
	scopesJSON, _ := json.Marshal(scopes) //nolint:errchkjson // test helper, error impossible for string slices
	return scopesJSON
}

// hashImportedKeyID delegates to the production crypto.HashImportedAPIKey.
func hashImportedKeyID(rawKey string, nid string) string {
	return crypto.HashImportedAPIKey(rawKey, nid)
}

// TestConnectionLifecycle tests Initialize, Ping, Close, DB methods
func (s *DriverTestSuite) TestConnectionLifecycle(t *testing.T) {
	t.Run("Ping returns no error when connected", func(t *testing.T) {
		err := s.driver.Ping(s.ctx())
		assert.NoError(t, err)
	})

	t.Run("DB returns non-nil database connection", func(t *testing.T) {
		sqlDB := s.driver.DB()
		require.NotNil(t, sqlDB)

		// Verify we can execute a simple query
		var result int
		err := sqlDB.QueryRowContext(s.ctx(), "SELECT 1").Scan(&result)
		require.NoError(t, err)
		assert.Equal(t, 1, result)
	})
}

// TestAPIKeyOperations tests CRUD operations for API keys
func (s *DriverTestSuite) TestAPIKeyOperations(t *testing.T) {
	t.Run("CreateAPIKey with valid parameters", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		name := "Test API Key"
		tokenPrefix := "pk_test_"
		actorID := "test-user-123"
		scopes := []string{"read", "write"}
		metadata := json.RawMessage(`{"env": "test"}`)
		expiresAt := time.Now().Add(24 * time.Hour)

		apiKey, err := s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       keyID,
			Name:        name,
			TokenPrefix: tokenPrefix,
			ActorID:     actorID,
			Scopes:      scopesToJSON(scopes),
			Metadata:    metadata,
			ExpiresAt:   &expiresAt,
		})

		require.NoError(t, err)
		assert.Equal(t, keyID, apiKey.KeyID)
		assert.Equal(t, name, apiKey.Name)
		assert.Equal(t, tokenPrefix, apiKey.TokenPrefix)
		assert.Equal(t, int64(1), apiKey.Version) // Version is hardcoded to 1 in implementation
		require.NotNil(t, apiKey.ActorID)
		assert.Equal(t, actorID, *apiKey.ActorID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), apiKey.Status)
		assert.NotNil(t, apiKey.CreatedAt)
		assert.NotNil(t, apiKey.UpdatedAt)
	})

	t.Run("CreateAPIKey with no expiration", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()

		apiKey, err := s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       keyID,
			Name:        "No Expiry Key",
			TokenPrefix: "pk_test_",
			ActorID:     "test-user",
			Scopes:      scopesToJSON([]string{}),
		})

		require.NoError(t, err)
		assert.Equal(t, keyID, apiKey.KeyID)
		assert.Nil(t, apiKey.ExpiresAt)
	})

	t.Run("GetAPIKey retrieves existing key", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		created, err := s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       keyID,
			Name:        "Get Test",
			TokenPrefix: "pk_test_",
			ActorID:     "owner-1",
			Scopes:      scopesToJSON([]string{"read"}),
		})
		require.NoError(t, err)

		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, created.KeyID, retrieved.KeyID)
		assert.Equal(t, created.Name, retrieved.Name)
	})

	t.Run("GetAPIKey returns error for non-existent key", func(t *testing.T) {
		nonExistentID := uuid.Must(uuid.NewV4()).String()

		_, err := s.driver.GetIssuedAPIKey(s.ctx(), nonExistentID)
		assert.Error(t, err)
	})

	t.Run("GetAPIKey returns ErrNoRows for malformed key ID", func(t *testing.T) {
		// A non-UUID key_id can never identify an issued key. Every backend must
		// surface this as sql.ErrNoRows so the service layer maps it to 404,
		// instead of leaking a driver-specific parse error as a 500.
		_, err := s.driver.GetIssuedAPIKey(s.ctx(), "not-a-valid-uuid")
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("GetActiveAPIKey returns active key", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "Active Key", "owner-2", []string{"read"}))
		require.NoError(t, err)

		apiKey, err := s.driver.GetActiveIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, keyID, apiKey.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), apiKey.Status)
	})

	t.Run("GetActiveAPIKey returns error for revoked key", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "To Revoke", "owner-3", []string{}))
		require.NoError(t, err)

		err = s.revokeAPIKey(keyID)
		require.NoError(t, err)

		_, err = s.driver.GetActiveIssuedAPIKey(s.ctx(), keyID)
		assert.Error(t, err, "GetActiveAPIKey should fail for revoked key")
	})

	t.Run("RevokeApiKey marks key as revoked", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "Revoke Test", "owner-4", []string{}))
		require.NoError(t, err)

		err = s.revokeAPIKey(keyID)
		require.NoError(t, err)

		apiKey, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), apiKey.Status)
	})

	t.Run("RevokeApiKey is idempotent", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "Idempotent Revoke", "owner-5", []string{}))
		require.NoError(t, err)

		err = s.revokeAPIKey(keyID)
		require.NoError(t, err)

		// Revoke again
		err = s.revokeAPIKey(keyID)
		require.NoError(t, err)

		apiKey, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), apiKey.Status)
	})

	t.Run("DeleteAPIKey removes key permanently", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "Delete Test", "owner-6", []string{}))
		require.NoError(t, err)

		err = s.driver.DeleteIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		_, err = s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		assert.Error(t, err, "GetAPIKey should fail after deletion")
	})

	t.Run("DeleteAPIKey is idempotent", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "Idempotent Delete", "owner-7", []string{}))
		require.NoError(t, err)

		err = s.driver.DeleteIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		// Delete again - should not error
		err = s.driver.DeleteIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
	})

	t.Run("UpdateAPIKeyMetadata updates name, scopes, and metadata", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		params := newCreateParams(keyID, "Old Name", "owner-8", []string{"read"})
		params.Metadata = json.RawMessage(`{"old": true}`)
		_, err := s.createAPIKey(params)
		require.NoError(t, err)

		newName := "New Name"
		newScopes := []string{"read", "write", "admin"}
		newMetadata := json.RawMessage(`{"updated": true}`)

		updated, err := s.driver.UpdateIssuedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateIssuedAPIKeyParams{
			KeyID:    keyID,
			Name:     newName,
			Scopes:   newScopes,
			Metadata: newMetadata,
		})
		require.NoError(t, err)
		assert.Equal(t, newName, updated.Name)
		assert.JSONEq(t, string(newMetadata), string(updated.Metadata))

		// Verify persistence
		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, newName, retrieved.Name)
	})

	t.Run("UpdateAPIKeyMetadata returns error for non-existent key", func(t *testing.T) {
		nonExistentID := uuid.Must(uuid.NewV4()).String()

		_, err := s.driver.UpdateIssuedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateIssuedAPIKeyParams{
			KeyID:  nonExistentID,
			Name:   "Name",
			Scopes: []string{},
		})
		assert.Error(t, err)
	})

	t.Run("UpdateAPIKeyLastUsed updates timestamp", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		created, err := s.createAPIKey(newCreateParams(keyID, "Usage Tracking", "owner-9", []string{}))
		require.NoError(t, err)
		originalLastUsed := created.LastUsedAt

		// Wait a moment to ensure timestamp differs
		time.Sleep(10 * time.Millisecond)

		err = s.driver.UpdateIssuedAPIKeyLastUsed(s.ctx(), keyID)
		require.NoError(t, err)

		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		// LastUsedAt should be updated
		if originalLastUsed == nil {
			assert.NotNil(t, retrieved.LastUsedAt)
		} else {
			assert.True(t, retrieved.LastUsedAt.After(*originalLastUsed) || retrieved.LastUsedAt.Equal(*originalLastUsed))
		}
	})

	t.Run("UpdateAPIKeyLastUsed is idempotent for non-existent key", func(t *testing.T) {
		nonExistentID := uuid.Must(uuid.NewV4()).String()

		// Should not error even if key doesn't exist
		err := s.driver.UpdateIssuedAPIKeyLastUsed(s.ctx(), nonExistentID)
		require.NoError(t, err)
	})

	t.Run("CreateAPIKey with rate limit policy", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		quota := new(int64(1000))
		window := new(int64(3600))

		params := newCreateParams(keyID, "Rate Limited Key", "rate-owner", []string{"read"})
		params.RateLimitQuota = quota
		params.RateLimitWindow = window
		apiKey, err := s.createAPIKey(params)
		require.NoError(t, err)
		require.NotNil(t, apiKey.RateLimitQuota)
		require.NotNil(t, apiKey.RateLimitWindow)
		assert.Equal(t, int64(1000), *apiKey.RateLimitQuota)
		assert.Equal(t, int64(3600), *apiKey.RateLimitWindow)
	})

	t.Run("CreateAPIKey without rate limit policy stores nil", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()

		apiKey, err := s.createAPIKey(newCreateParams(keyID, "No Rate Limit Key", "no-rate-owner", []string{"read"}))
		require.NoError(t, err)
		assert.Nil(t, apiKey.RateLimitQuota)
		assert.Nil(t, apiKey.RateLimitWindow)
	})

	t.Run("GetAPIKey preserves rate limit policy", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		quota := new(int64(1000))
		window := new(int64(3600))

		params := newCreateParams(keyID, "Get Rate Limit Key", "get-rate-owner", []string{"read"})
		params.RateLimitQuota = quota
		params.RateLimitWindow = window
		_, err := s.createAPIKey(params)
		require.NoError(t, err)

		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		require.NotNil(t, retrieved.RateLimitQuota)
		require.NotNil(t, retrieved.RateLimitWindow)
		assert.Equal(t, int64(1000), *retrieved.RateLimitQuota)
		assert.Equal(t, int64(3600), *retrieved.RateLimitWindow)
	})

	t.Run("UpdateAPIKeyMetadata with rate limit", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(keyID, "Update Rate Limit Key", "update-rate-owner", []string{"read"}))
		require.NoError(t, err)

		quota := new(int64(1000))
		window := new(int64(3600))

		updated, err := s.driver.UpdateIssuedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateIssuedAPIKeyParams{
			KeyID:           keyID,
			Name:            "Updated Rate Limit Key",
			Scopes:          []string{"read"},
			RateLimitQuota:  quota,
			RateLimitWindow: window,
		})
		require.NoError(t, err)
		require.NotNil(t, updated.RateLimitQuota)
		require.NotNil(t, updated.RateLimitWindow)
		assert.Equal(t, int64(1000), *updated.RateLimitQuota)
		assert.Equal(t, int64(3600), *updated.RateLimitWindow)
	})

	t.Run("UpdateAPIKeyMetadata nil rate limit clears existing policy", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		params := newCreateParams(keyID, "Clear Rate Limit Key", "clear-rate-owner", []string{"read"})
		params.RateLimitQuota = new(int64(500))
		params.RateLimitWindow = new(int64(1800))
		_, err := s.createAPIKey(params)
		require.NoError(t, err)

		// Passing nil clears the rate limit (service always pre-fetches existing value
		// and passes it through; nil only arrives here when the caller explicitly wants to clear)
		updated, err := s.driver.UpdateIssuedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateIssuedAPIKeyParams{
			KeyID:           keyID,
			Name:            "Updated Name",
			Scopes:          []string{"read"},
			RateLimitQuota:  nil,
			RateLimitWindow: nil,
		})
		require.NoError(t, err)
		assert.Nil(t, updated.RateLimitQuota)
		assert.Nil(t, updated.RateLimitWindow)
	})

	t.Run("IssuedKey round-trip with all fields populated", func(t *testing.T) {
		t.Parallel()
		keyID := uuid.Must(uuid.NewV4()).String()
		actorID := "owner-" + uuid.Must(uuid.NewV4()).String()
		name := "Full Fields Issued Key"
		tokenPrefix := "pk_full_"
		scopes := json.RawMessage(`["read","write","admin"]`)
		metadata := json.RawMessage(`{"env":"prod","tier":"enterprise"}`)
		allowedCIDRs := json.RawMessage(`["10.0.0.0/8","192.168.1.0/24"]`)
		requestID := uuid.Must(uuid.NewV4()).String()
		quota := int64(5000)
		window := int64(3600)
		expiresAt := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
		visibility := int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC)

		_, err := s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:           keyID,
			Name:            name,
			TokenPrefix:     tokenPrefix,
			ActorID:         actorID,
			Scopes:          scopes,
			Metadata:        metadata,
			ExpiresAt:       &expiresAt,
			RateLimitQuota:  &quota,
			RateLimitWindow: &window,
			AllowedCIDRs:    allowedCIDRs,
			RequestID:       requestID,
			Visibility:      visibility,
		})
		require.NoError(t, err)

		got, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		assert.Equal(t, keyID, got.KeyID)
		assert.Equal(t, name, got.Name)
		assert.Equal(t, tokenPrefix, got.TokenPrefix)
		assert.Equal(t, int64(1), got.Version)
		require.NotNil(t, got.ActorID)
		assert.Equal(t, actorID, *got.ActorID)
		assert.JSONEq(t, string(scopes), string(got.Scopes))
		assert.JSONEq(t, string(metadata), string(got.Metadata))
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), got.Status)
		require.NotNil(t, got.ExpiresAt)
		assert.WithinDuration(t, expiresAt, *got.ExpiresAt, time.Second)
		require.NotNil(t, got.RateLimitQuota)
		assert.Equal(t, quota, *got.RateLimitQuota)
		require.NotNil(t, got.RateLimitWindow)
		assert.Equal(t, window, *got.RateLimitWindow)
		assert.JSONEq(t, string(allowedCIDRs), string(got.AllowedCidrs))
		require.NotNil(t, got.RequestID)
		assert.Equal(t, requestID, *got.RequestID)
		assert.Equal(t, visibility, got.Visibility)
		assert.False(t, got.CreatedAt.IsZero(), "created_at must be set")
		assert.False(t, got.UpdatedAt.IsZero(), "updated_at must be set")

		// Also verify via RequestID lookup
		byRequestID, err := s.driver.GetIssuedAPIKeyByRequestID(s.ctx(), requestID)
		require.NoError(t, err)
		assert.Equal(t, keyID, byRequestID.KeyID)

		// Cleanup
		t.Cleanup(func() {
			_ = s.driver.DeleteIssuedAPIKey(s.ctx(), keyID)
		})
	})
}

// TestAPIKeyListing tests pagination and filtering of API keys
func (s *DriverTestSuite) TestAPIKeyListing(t *testing.T) {
	t.Run("ListAPIKeysByNetwork with empty results", func(t *testing.T) {
		// Use a unique network ID to ensure empty results
		// Create context with a different NID that has no keys
		emptyNID := uuid.Must(uuid.NewV4())
		emptyCtx := context.WithValue(t.Context(), contextx.NIDKey{}, emptyNID)

		keys, err := s.driver.ListIssuedAPIKeysByNetwork(emptyCtx, "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 10)
		require.NoError(t, err)
		// OSS uses hardcoded nil UUID, so this test may still return keys
		// Commercial uses the context NID, so it should return empty
		assert.NotNil(t, keys)
	})

	t.Run("ListAPIKeysByNetwork returns created keys", func(t *testing.T) {
		// Create multiple keys
		keyIDs := make([]string, 3)
		for i := range 3 {
			keyID := uuid.Must(uuid.NewV4()).String()
			keyIDs[i] = keyID
			_, err := s.createAPIKey(newCreateParams(keyID, fmt.Sprintf("List Key %d", i), "list-owner", []string{}))
			require.NoError(t, err)
		}

		keys, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 100)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 3, "Should return at least the 3 keys we created")

		// Verify our keys are in the results
		foundCount := 0
		for _, key := range keys {
			for _, createdID := range keyIDs {
				if key.KeyID == createdID {
					foundCount++
				}
			}
		}
		assert.Equal(t, 3, foundCount, "All created keys should be in results")
	})

	t.Run("ListAPIKeysByNetwork respects limit", func(t *testing.T) {
		// Create 5 keys
		for i := range 5 {
			keyID := uuid.Must(uuid.NewV4()).String()
			_, err := s.createAPIKey(newCreateParams(keyID, fmt.Sprintf("Limit Key %d", i), "limit-owner", []string{}))
			require.NoError(t, err)
		}

		keys, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(keys), 2, "Should respect limit parameter")
	})

	t.Run("ListAPIKeysByNetwork filters revoked keys by default", func(t *testing.T) {
		// Create active key
		activeID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(activeID, "Active Filter Key", "filter-owner", []string{}))
		require.NoError(t, err)

		// Create and revoke key
		revokedID := uuid.Must(uuid.NewV4()).String()
		_, err = s.createAPIKey(newCreateParams(revokedID, "Revoked Filter Key", "filter-owner", []string{}))
		require.NoError(t, err)
		err = s.revokeAPIKey(revokedID)
		require.NoError(t, err)

		// List active only (includeAllStatuses = false)
		keys, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 100)
		require.NoError(t, err)

		// Verify revoked key is not in results
		for _, key := range keys {
			assert.NotEqual(t, revokedID, key.KeyID, "Revoked key should not be in active-only results")
		}
	})

	t.Run("ListAPIKeysByNetwork includes revoked keys when requested", func(t *testing.T) {
		// Create and revoke a key
		revokedID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(revokedID, "Include Revoked Key", "include-owner", []string{}))
		require.NoError(t, err)
		err = s.revokeAPIKey(revokedID)
		require.NoError(t, err)

		// List all statuses (includeAllStatuses = true)
		keys, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), "", 0, "", 100)
		require.NoError(t, err)

		// Verify revoked key is in results
		found := false
		for _, key := range keys {
			if key.KeyID == revokedID {
				found = true
				assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), key.Status)
			}
		}
		assert.True(t, found, "Revoked key should be in all-statuses results")
	})

	t.Run("ListAPIKeysByOwner filters by owner", func(t *testing.T) {
		actorID := "owner-" + uuid.Must(uuid.NewV4()).String()

		// Create keys for specific owner
		keyIDs := make([]string, 2)
		for i := range 2 {
			keyID := uuid.Must(uuid.NewV4()).String()
			keyIDs[i] = keyID
			_, err := s.createAPIKey(newCreateParams(keyID, fmt.Sprintf("Owner Key %d", i), actorID, []string{}))
			require.NoError(t, err)
		}

		// Create key for different owner
		otherActorID := "other-owner-" + uuid.Must(uuid.NewV4()).String()
		otherKeyID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(newCreateParams(otherKeyID, "Other Owner Key", otherActorID, []string{}))
		require.NoError(t, err)

		// List keys by owner
		keys, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), actorID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 100)
		require.NoError(t, err)

		// Verify only keys for this owner are returned
		for _, key := range keys {
			if key.KeyID == keyIDs[0] || key.KeyID == keyIDs[1] {
				require.NotNil(t, key.ActorID)
				assert.Equal(t, actorID, *key.ActorID)
			}
			if key.KeyID == otherKeyID {
				t.Errorf("Key for other owner should not be in results")
			}
		}
	})

	t.Run("ListAPIKeysByOwner with cursor pagination", func(t *testing.T) {
		actorID := "cursor-owner-" + uuid.Must(uuid.NewV4()).String()

		// Create 5 keys
		for i := range 5 {
			keyID := uuid.Must(uuid.NewV4()).String()
			_, err := s.createAPIKey(newCreateParams(keyID, fmt.Sprintf("Cursor Key %d", i), actorID, []string{}))
			require.NoError(t, err)
		}

		// Get first page
		page1, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), actorID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(page1), 2)

		if len(page1) > 0 {
			// Get second page using cursor
			cursor := page1[len(page1)-1].KeyID
			page2, err := s.driver.ListIssuedAPIKeysByNetwork(s.ctx(), actorID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), cursor, 2)
			require.NoError(t, err)

			// Verify no overlap
			for _, k1 := range page1 {
				for _, k2 := range page2 {
					assert.NotEqual(t, k1.KeyID, k2.KeyID, "Pages should not overlap")
				}
			}
		}
	})
}

// TestAPIKeyExpiration tests expiration-related operations
func (s *DriverTestSuite) TestAPIKeyExpiration(t *testing.T) {
	t.Run("GetExpiredAPIKeys returns only expired keys", func(t *testing.T) {
		// Create expired key
		expiredID := uuid.Must(uuid.NewV4()).String()
		expiredTime := time.Now().Add(-24 * time.Hour)
		expiredParams := newCreateParams(expiredID, "Expired Key", "expired-owner", []string{})
		expiredParams.ExpiresAt = &expiredTime
		_, err := s.createAPIKey(expiredParams)
		require.NoError(t, err)

		// Create active key with future expiration
		activeID := uuid.Must(uuid.NewV4()).String()
		futureTime := time.Now().Add(24 * time.Hour)
		activeParams := newCreateParams(activeID, "Active Key", "active-owner", []string{})
		activeParams.ExpiresAt = &futureTime
		_, err = s.createAPIKey(activeParams)
		require.NoError(t, err)

		// Get expired keys
		expired, err := s.driver.GetExpiredIssuedAPIKeys(s.ctx(), 100)
		require.NoError(t, err)

		// Verify expired key is in results
		foundExpired := false
		for _, key := range expired {
			if key.KeyID == expiredID {
				foundExpired = true
			}
			// Active key should not be in results
			assert.NotEqual(t, activeID, key.KeyID, "Non-expired key should not be in results")
		}
		assert.True(t, foundExpired, "Expired key should be in results")
	})

	t.Run("ExpireAPIKeys marks expired keys", func(t *testing.T) {
		// Create multiple expired keys
		expiredIDs := make([]string, 3)
		pastTime := time.Now().Add(-25 * time.Hour)
		for i := range 3 {
			keyID := uuid.Must(uuid.NewV4()).String()
			expiredIDs[i] = keyID
			params := newCreateParams(keyID, fmt.Sprintf("To Expire %d", i), "expire-owner", []string{})
			params.ExpiresAt = &pastTime
			_, err := s.createAPIKey(params)
			require.NoError(t, err)
		}

		// Expire them (may include expired keys from previous tests)
		count, err := s.driver.ExpireIssuedAPIKeys(s.ctx(), 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(3), "should expire at least our 3 keys")

		// Verify they are marked as expired
		for _, keyID := range expiredIDs {
			key, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
			require.NoError(t, err)
			assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_EXPIRED), key.Status)
		}
	})

	t.Run("ExpireAPIKeys respects limit", func(t *testing.T) {
		// Create 5 expired keys
		pastTime := time.Now().Add(-25 * time.Hour)
		for i := range 5 {
			keyID := uuid.Must(uuid.NewV4()).String()
			params := newCreateParams(keyID, fmt.Sprintf("Limit Expire %d", i), "limit-expire", []string{})
			params.ExpiresAt = &pastTime
			_, err := s.createAPIKey(params)
			require.NoError(t, err)
		}

		// Expire with limit of 2
		count, err := s.driver.ExpireIssuedAPIKeys(s.ctx(), 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, count, int64(2), "Should respect limit")
	})

	t.Run("ExpireAPIKeys is idempotent", func(t *testing.T) {
		// Create expired key
		keyID := uuid.Must(uuid.NewV4()).String()
		pastTime := time.Now().Add(-25 * time.Hour)
		params := newCreateParams(keyID, "Idempotent Expire", "idem-expire", []string{})
		params.ExpiresAt = &pastTime
		_, err := s.createAPIKey(params)
		require.NoError(t, err)

		// Expire once (may include keys from previous tests, so check >= 1)
		count1, err := s.driver.ExpireIssuedAPIKeys(s.ctx(), 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count1, int64(1), "should expire at least our key")

		// Expire again - should return 0 since all expired keys were already processed
		count2, err := s.driver.ExpireIssuedAPIKeys(s.ctx(), 10)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count2, "second call should find no new expired keys")
	})
}

// TestAPIKeyRevocation tests that revoking keys updates expires_at correctly
func (s *DriverTestSuite) TestAPIKeyRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	thirtyDaysFromNow := now.Add(30 * 24 * time.Hour)

	// Test cases covering all scenarios
	testCases := []struct {
		name              string
		originalExpiresAt *time.Time
		expectedExpiresAt time.Time
		allowDelta        time.Duration
		description       string
	}{
		{
			name:              "without expiration",
			originalExpiresAt: nil,
			expectedExpiresAt: thirtyDaysFromNow,
			allowDelta:        5 * time.Second,
			description:       "NULL expires_at should be set to now + 30 days",
		},
		{
			name:              "with future expiration less than 30 days",
			originalExpiresAt: new(now.Add(10 * 24 * time.Hour)),
			expectedExpiresAt: thirtyDaysFromNow,
			allowDelta:        5 * time.Second,
			description:       "expires_at < 30 days should be extended to now + 30 days",
		},
		{
			name:              "with future expiration more than 30 days",
			originalExpiresAt: new(now.Add(60 * 24 * time.Hour)),
			expectedExpiresAt: now.Add(60 * 24 * time.Hour),
			allowDelta:        5 * time.Second,
			description:       "expires_at > 30 days should remain unchanged",
		},
		{
			name:              "already expired",
			originalExpiresAt: new(now.Add(-24 * time.Hour)),
			expectedExpiresAt: thirtyDaysFromNow,
			allowDelta:        5 * time.Second,
			description:       "expired key should be extended to now + 30 days",
		},
	}

	t.Run("RevokeApiKey updates expires_at", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create API key
				keyID := uuid.Must(uuid.NewV4()).String()
				createParams := newCreateParams(keyID, "test-key", "owner-1", []string{"read"})
				createParams.ExpiresAt = tc.originalExpiresAt

				_, err := s.createAPIKey(createParams)
				require.NoError(t, err, "create API key")

				// Calculate new expiration for revocation
				testNow := time.Now().UTC()
				newExpiresAt := sqlutil.CalculateRevocationExpiry(testNow, tc.originalExpiresAt)

				// Revoke API key
				err = s.driver.RevokeIssuedAPIKey(s.ctx(), persistencetypes.RevokeIssuedAPIKeyParams{
					KeyID:       keyID,
					Reason:      int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED),
					Description: "test revocation",
					ExpiresAt:   newExpiresAt,
				})
				require.NoError(t, err, "revoke API key")

				// Verify the key's expires_at was updated correctly
				key, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
				require.NoError(t, err, "get revoked key")

				// Check status
				assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), key.Status, "key should be revoked")

				// Check expires_at
				require.NotNil(t, key.ExpiresAt, "expires_at should not be nil after revocation")
				assert.WithinDuration(t, tc.expectedExpiresAt, *key.ExpiresAt, tc.allowDelta,
					"expires_at should be %v (description: %s)", tc.expectedExpiresAt, tc.description)
			})
		}
	})

	t.Run("RevokeImportedAPIKey updates expires_at", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create imported key
				keyID := hashImportedKeyID("test-key-"+uuid.Must(uuid.NewV4()).String(), s.nid.String())
				_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
					KeyID:     keyID,
					ActorID:   "owner-1",
					Name:      "test-imported-key",
					Scopes:    json.RawMessage(`["read"]`),
					Metadata:  json.RawMessage(`{}`),
					Status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
					ExpiresAt: tc.originalExpiresAt,
				})
				require.NoError(t, err, "create imported key")

				// Calculate new expiration for revocation
				testNow := time.Now().UTC()
				newExpiresAt := sqlutil.CalculateRevocationExpiry(testNow, tc.originalExpiresAt)

				// Revoke imported key
				key, err := s.revokeImportedAPIKey(
					keyID,
					int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
					"test revocation",
					newExpiresAt,
				)
				require.NoError(t, err, "revoke imported key")

				// Check status
				assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), key.Status, "key should be revoked")

				// Check expires_at
				require.NotNil(t, key.ExpiresAt, "expires_at should not be nil after revocation")
				assert.WithinDuration(t, tc.expectedExpiresAt, *key.ExpiresAt, tc.allowDelta,
					"expires_at should be %v (description: %s)", tc.expectedExpiresAt, tc.description)
			})
		}
	})
}

// TestImportedKeyOperations tests imported key CRUD operations
// Uses SHA512/256 hash format for keyID (64-char hex) to match production behavior
func (s *DriverTestSuite) TestImportedKeyOperations(t *testing.T) {
	t.Run("CreateImportedAPIKey with valid parameters", func(t *testing.T) {
		// Use hash format for keyID (matches production crypto.HashImportedAPIKey)
		rawKey := "test_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		name := "Imported GitHub PAT"
		metadata := json.RawMessage(`{"provider": "github"}`)
		expiresAt := time.Now().Add(90 * 24 * time.Hour)

		importedKey, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:     keyID,
			ActorID:   "github",
			Name:      name,
			Scopes:    json.RawMessage("[]"),
			Metadata:  metadata,
			Status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			ExpiresAt: &expiresAt,
		})

		require.NoError(t, err)
		assert.Equal(t, keyID, importedKey.KeyID)
		require.NotNil(t, importedKey.ActorID)
		assert.Equal(t, "github", *importedKey.ActorID)
		assert.Equal(t, name, importedKey.Name)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), importedKey.Status)
		assert.NotNil(t, importedKey.ExpiresAt)
	})

	t.Run("CreateImportedAPIKey without expiration", func(t *testing.T) {
		rawKey := "no_expiry_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())

		importedKey, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "stripe",
			Name:    "No Expiry",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})

		require.NoError(t, err)
		assert.Equal(t, keyID, importedKey.KeyID)
		assert.Nil(t, importedKey.ExpiresAt)
	})

	t.Run("GetImportedAPIKeyByHash retrieves key by hash", func(t *testing.T) {
		rawKey := "hash_test_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "Hash Test",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, keyID, retrieved.KeyID)
	})

	t.Run("GetImportedAPIKeyByHash returns error for non-existent key", func(t *testing.T) {
		// Use hash format for consistency (even for non-existent keys)
		nonExistentID := hashImportedKeyID("nonexistent_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())

		_, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), nonExistentID)
		assert.Error(t, err)
	})

	t.Run("ListImportedAPIKeys returns created keys", func(t *testing.T) {
		// Create multiple imported keys with hash format
		keyIDs := make([]string, 3)
		for i := range 3 {
			rawKey := fmt.Sprintf("list_key_%d_%s", i, uuid.Must(uuid.NewV4()).String())
			keyID := hashImportedKeyID(rawKey, s.nid.String())
			keyIDs[i] = keyID
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   keyID,
				ActorID: "provider",
				Name:    fmt.Sprintf("List Key %d", i),
				Scopes:  json.RawMessage("[]"),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		keys, err := s.driver.ListImportedAPIKeys(s.ctx(), 0, "", "", 100)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 3)

		// Verify our keys are in results
		foundCount := 0
		for _, key := range keys {
			for _, createdID := range keyIDs {
				if key.KeyID == createdID {
					foundCount++
				}
			}
		}
		assert.Equal(t, 3, foundCount, "All created imported keys should be in results")
	})

	t.Run("ListImportedAPIKeys filters by status", func(t *testing.T) {
		// Create active key with hash format
		activeRaw := "active_status_key_" + uuid.Must(uuid.NewV4()).String()
		activeID := hashImportedKeyID(activeRaw, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   activeID,
			ActorID: "provider",
			Name:    "Active",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// Create revoked key with hash format
		revokedRaw := "revoked_status_key_" + uuid.Must(uuid.NewV4()).String()
		revokedID := hashImportedKeyID(revokedRaw, s.nid.String())
		_, err = s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   revokedID,
			ActorID: "provider",
			Name:    "Revoked",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED),
		})
		require.NoError(t, err)

		// List active only
		keys, err := s.driver.ListImportedAPIKeys(s.ctx(), int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", "", 100)
		require.NoError(t, err)

		// Verify only active keys in results
		for _, key := range keys {
			if key.KeyID == revokedID {
				t.Errorf("Revoked key should not be in active-only results")
			}
		}
	})

	t.Run("ListImportedAPIKeys filters by owner", func(t *testing.T) {
		actorID := "provider-" + uuid.Must(uuid.NewV4()).String()

		// Create keys for specific owner with hash format
		rawKey1 := "owner_key_1_" + uuid.Must(uuid.NewV4()).String()
		keyID1 := hashImportedKeyID(rawKey1, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID1,
			ActorID: actorID,
			Name:    "Owner Key 1",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// Create key for different owner with hash format
		otherOwner := "other-" + uuid.Must(uuid.NewV4()).String()
		rawKey2 := "owner_key_2_" + uuid.Must(uuid.NewV4()).String()
		keyID2 := hashImportedKeyID(rawKey2, s.nid.String())
		_, err = s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID2,
			ActorID: otherOwner,
			Name:    "Other Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// List by owner
		keys, err := s.driver.ListImportedAPIKeys(s.ctx(), 0, actorID, "", 100)
		require.NoError(t, err)

		// Verify filtering
		for _, key := range keys {
			if key.KeyID == keyID1 {
				require.NotNil(t, key.ActorID)
				assert.Equal(t, actorID, *key.ActorID)
			}
			if key.KeyID == keyID2 {
				t.Errorf("Key for other owner should not be in results")
			}
		}
	})

	t.Run("RevokeImportedAPIKey changes status to revoked", func(t *testing.T) {
		rawKey := "revoke_test_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "To Revoke",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// Calculate new expiration for revocation (key has no expiration, so use 30 days)
		now := time.Now().UTC()
		newExpiresAt := sqlutil.CalculateRevocationExpiry(now, nil)

		revoked, err := s.revokeImportedAPIKey(keyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE), "", newExpiresAt)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), revoked.Status)

		// Verify persistence
		retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), retrieved.Status)
	})

	t.Run("DeleteImportedAPIKey removes key permanently", func(t *testing.T) {
		rawKey := "delete_test_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "To Delete",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		err = s.driver.DeleteImportedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		// Verify deletion
		_, err = s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		assert.Error(t, err)
	})

	t.Run("DeleteImportedAPIKey is idempotent", func(t *testing.T) {
		rawKey := "idem_delete_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "Idempotent Delete",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		err = s.driver.DeleteImportedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		// Delete again - should not error
		err = s.driver.DeleteImportedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
	})

	t.Run("CreateImportedAPIKey with rate limit policy", func(t *testing.T) {
		rawKey := "rate_limit_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		quota := int64(1000)
		window := int64(3600)

		importedKey, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:           keyID,
			ActorID:         "provider",
			Name:            "Rate Limited Import",
			Scopes:          json.RawMessage("[]"),
			Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			RateLimitQuota:  &quota,
			RateLimitWindow: &window,
		})
		require.NoError(t, err)
		require.NotNil(t, importedKey.RateLimitQuota)
		require.NotNil(t, importedKey.RateLimitWindow)
		assert.Equal(t, int64(1000), *importedKey.RateLimitQuota)
		assert.Equal(t, int64(3600), *importedKey.RateLimitWindow)
	})

	t.Run("CreateImportedAPIKey without rate limit policy", func(t *testing.T) {
		rawKey := "no_rate_limit_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())

		importedKey, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "No Rate Limit Import",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)
		assert.Nil(t, importedKey.RateLimitQuota)
		assert.Nil(t, importedKey.RateLimitWindow)
	})

	t.Run("UpdateImportedAPIKeyMetadata updates name, scopes, and metadata", func(t *testing.T) {
		t.Parallel()
		rawKey := "update_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:    keyID,
			ActorID:  "provider",
			Name:     "Old Name",
			Scopes:   json.RawMessage(`["read"]`),
			Metadata: json.RawMessage(`{"old": true}`),
			Status:   int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		updated, err := s.driver.UpdateImportedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateImportedKeyParams{
			KeyID:    keyID,
			Name:     "New Name",
			Scopes:   []string{"read", "write"},
			Metadata: json.RawMessage(`{"updated": true}`),
		})
		require.NoError(t, err)
		assert.Equal(t, "New Name", updated.Name)
		assert.JSONEq(t, `{"updated": true}`, string(updated.Metadata))

		// Verify persistence
		retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, "New Name", retrieved.Name)
	})

	t.Run("UpdateImportedAPIKeyMetadata returns error for non-existent key", func(t *testing.T) {
		t.Parallel()
		nonExistentID := hashImportedKeyID("nonexistent_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())

		_, err := s.driver.UpdateImportedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateImportedKeyParams{
			KeyID:  nonExistentID,
			Name:   "Name",
			Scopes: []string{},
		})
		assert.Error(t, err)
	})

	t.Run("UpdateImportedAPIKeyMetadata with rate limit", func(t *testing.T) {
		t.Parallel()
		rawKey := "update_rate_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "Rate Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		quota := int64(1000)
		window := int64(3600)

		updated, err := s.driver.UpdateImportedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateImportedKeyParams{
			KeyID:           keyID,
			Name:            "Rate Limited Import",
			Scopes:          []string{"read"},
			RateLimitQuota:  &quota,
			RateLimitWindow: &window,
		})
		require.NoError(t, err)
		require.NotNil(t, updated.RateLimitQuota)
		require.NotNil(t, updated.RateLimitWindow)
		assert.Equal(t, int64(1000), *updated.RateLimitQuota)
		assert.Equal(t, int64(3600), *updated.RateLimitWindow)
	})

	t.Run("UpdateImportedAPIKeyMetadata nil rate limit clears existing policy", func(t *testing.T) {
		t.Parallel()
		rawKey := "clear_rate_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		quota := int64(500)
		window := int64(1800)
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:           keyID,
			ActorID:         "provider",
			Name:            "Clear Rate",
			Scopes:          json.RawMessage("[]"),
			Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			RateLimitQuota:  &quota,
			RateLimitWindow: &window,
		})
		require.NoError(t, err)

		// Passing nil for rate limit fields clears them (service always pre-fetches existing value
		// and passes it through; nil only arrives here when the caller explicitly wants to clear)
		updated, err := s.driver.UpdateImportedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateImportedKeyParams{
			KeyID:           keyID,
			Name:            "Updated Name",
			Scopes:          []string{"read"},
			RateLimitQuota:  nil,
			RateLimitWindow: nil,
		})
		require.NoError(t, err)
		assert.Nil(t, updated.RateLimitQuota)
		assert.Nil(t, updated.RateLimitWindow)
	})

	t.Run("UpdateImportedAPIKeyLastUsed updates timestamp", func(t *testing.T) {
		rawKey := "last_used_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		created, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "Last Used Test",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		err = s.driver.UpdateImportedAPIKeyLastUsed(s.ctx(), keyID)
		require.NoError(t, err)

		retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)

		// A freshly created key has nil LastUsedAt; after update it must be non-nil.
		assert.Nil(t, created.LastUsedAt, "freshly created key should have nil LastUsedAt")
		assert.NotNil(t, retrieved.LastUsedAt, "LastUsedAt should be set after update")
	})

	t.Run("UpdateImportedAPIKeyLastUsed is idempotent for non-existent key", func(t *testing.T) {
		nonExistentID := hashImportedKeyID("nonexistent_last_used_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())

		// Should not error even if key doesn't exist
		err := s.driver.UpdateImportedAPIKeyLastUsed(s.ctx(), nonExistentID)
		require.NoError(t, err)
	})

	t.Run("ListImportedAPIKeys respects limit", func(t *testing.T) {
		// Create 5 keys
		for i := range 5 {
			rawKey := fmt.Sprintf("limit_imported_%d_%s", i, uuid.Must(uuid.NewV4()).String())
			keyID := hashImportedKeyID(rawKey, s.nid.String())
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   keyID,
				ActorID: "limit-provider",
				Name:    fmt.Sprintf("Limit Key %d", i),
				Scopes:  json.RawMessage("[]"),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		keys, err := s.driver.ListImportedAPIKeys(s.ctx(), int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", "", 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(keys), 2, "Should respect limit parameter")
	})

	t.Run("ListImportedAPIKeys with cursor pagination", func(t *testing.T) {
		actorID := "cursor-import-owner-" + uuid.Must(uuid.NewV4()).String()

		// Create 5 keys
		for i := range 5 {
			rawKey := fmt.Sprintf("cursor_imported_%d_%s", i, uuid.Must(uuid.NewV4()).String())
			keyID := hashImportedKeyID(rawKey, s.nid.String())
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   keyID,
				ActorID: actorID,
				Name:    fmt.Sprintf("Cursor Key %d", i),
				Scopes:  json.RawMessage("[]"),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		// Get first page
		page1, err := s.driver.ListImportedAPIKeys(s.ctx(), int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), actorID, "", 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(page1), 2)

		if len(page1) > 0 {
			// Get second page using cursor
			cursor := page1[len(page1)-1].KeyID
			page2, err := s.driver.ListImportedAPIKeys(s.ctx(), int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), actorID, cursor, 2)
			require.NoError(t, err)

			// Verify no overlap
			for _, k1 := range page1 {
				for _, k2 := range page2 {
					assert.NotEqual(t, k1.KeyID, k2.KeyID, "Pages should not overlap")
				}
			}
		}
	})

	t.Run("ListImportedAPIKeys includes revoked keys when status is unfiltered", func(t *testing.T) {
		// Create and revoke a key
		revokedRaw := "revoked_unfiltered_key_" + uuid.Must(uuid.NewV4()).String()
		revokedID := hashImportedKeyID(revokedRaw, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   revokedID,
			ActorID: "provider",
			Name:    "Include Revoked",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		now := time.Now().UTC()
		newExpiresAt := sqlutil.CalculateRevocationExpiry(now, nil)
		_, err = s.revokeImportedAPIKey(revokedID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE), "", newExpiresAt)
		require.NoError(t, err)

		// List all statuses (status = 0 means unfiltered)
		keys, err := s.driver.ListImportedAPIKeys(s.ctx(), 0, "", "", 100)
		require.NoError(t, err)

		// Verify revoked key is in results
		found := false
		for _, key := range keys {
			if key.KeyID == revokedID {
				found = true
				assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), key.Status)
			}
		}
		assert.True(t, found, "Revoked key should be in all-statuses results")
	})

	t.Run("RevokeImportedAPIKey is idempotent", func(t *testing.T) {
		rawKey := "idem_revoke_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   keyID,
			ActorID: "provider",
			Name:    "Idempotent Revoke",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		now := time.Now().UTC()
		newExpiresAt := sqlutil.CalculateRevocationExpiry(now, nil)

		// Revoke once
		_, err = s.revokeImportedAPIKey(keyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE), "", newExpiresAt)
		require.NoError(t, err)

		// Revoke again - should not error
		revoked, err := s.revokeImportedAPIKey(keyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE), "", newExpiresAt)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), revoked.Status)
	})

	t.Run("ListImportedAPIKeys with empty results", func(t *testing.T) {
		// Use a unique NID to ensure empty results
		emptyNID := uuid.Must(uuid.NewV4())
		emptyCtx := context.WithValue(t.Context(), contextx.NIDKey{}, emptyNID)

		keys, err := s.driver.ListImportedAPIKeys(emptyCtx, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", "", 10)
		require.NoError(t, err)
		assert.NotNil(t, keys)
	})

	t.Run("ImportedKey round-trip with all fields populated", func(t *testing.T) {
		t.Parallel()
		rawKey := "roundtrip_all_fields_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		actorID := "owner-" + uuid.Must(uuid.NewV4()).String()
		name := "Full Fields Key"
		scopes := json.RawMessage(`["read","write","admin"]`)
		metadata := json.RawMessage(`{"env":"prod","tier":"enterprise"}`)
		allowedCIDRs := json.RawMessage(`["10.0.0.0/8","192.168.1.0/24"]`)
		requestID := uuid.Must(uuid.NewV4()).String()
		quota := int64(5000)
		window := int64(3600)
		expiresAt := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
		visibility := int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC)

		_, err := s.driver.CreateImportedAPIKey(s.ctx(), persistencetypes.CreateImportedKeyParams{
			KeyID:           keyID,
			ActorID:         actorID,
			Name:            name,
			Scopes:          scopes,
			Metadata:        metadata,
			Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			ExpiresAt:       &expiresAt,
			RateLimitQuota:  &quota,
			RateLimitWindow: &window,
			AllowedCIDRs:    allowedCIDRs,
			RequestID:       requestID,
			Visibility:      visibility,
		})
		require.NoError(t, err)

		got, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)

		assert.Equal(t, keyID, got.KeyID)
		require.NotNil(t, got.ActorID)
		assert.Equal(t, actorID, *got.ActorID)
		assert.Equal(t, name, got.Name)
		assert.JSONEq(t, string(scopes), string(got.Scopes))
		assert.JSONEq(t, string(metadata), string(got.Metadata))
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), got.Status)
		require.NotNil(t, got.ExpiresAt)
		assert.WithinDuration(t, expiresAt, *got.ExpiresAt, time.Second)
		require.NotNil(t, got.RateLimitQuota)
		assert.Equal(t, quota, *got.RateLimitQuota)
		require.NotNil(t, got.RateLimitWindow)
		assert.Equal(t, window, *got.RateLimitWindow)
		assert.JSONEq(t, string(allowedCIDRs), string(got.AllowedCidrs))
		require.NotNil(t, got.RequestID)
		assert.Equal(t, requestID, *got.RequestID)
		assert.Equal(t, visibility, got.Visibility)

		// Also verify via RequestID lookup
		byRequestID, err := s.driver.GetImportedAPIKeyByRequestID(s.ctx(), requestID)
		require.NoError(t, err)
		assert.Equal(t, keyID, byRequestID.KeyID)
	})
}

// TestFullLifecycle tests realistic workflows combining multiple operations
func (s *DriverTestSuite) TestFullLifecycle(t *testing.T) {
	t.Run("API key full lifecycle: create, use, update, revoke, delete", func(t *testing.T) {
		// Create
		keyID := uuid.Must(uuid.NewV4()).String()
		params := newCreateParams(keyID, "Lifecycle Test", "lifecycle-user", []string{"read"})
		params.Metadata = json.RawMessage(`{"env": "test"}`)
		created, err := s.createAPIKey(params)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), created.Status)

		// Get
		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, keyID, retrieved.KeyID)

		// Get active
		active, err := s.driver.GetActiveIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, keyID, active.KeyID)

		// Use (update last used)
		err = s.driver.UpdateIssuedAPIKeyLastUsed(s.ctx(), keyID)
		require.NoError(t, err)

		// Update metadata
		updated, err := s.driver.UpdateIssuedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateIssuedAPIKeyParams{
			KeyID:    keyID,
			Name:     "Updated Name",
			Scopes:   []string{"read", "write"},
			Metadata: json.RawMessage(`{"updated": true}`),
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", updated.Name)

		// Revoke
		err = s.revokeAPIKey(keyID)
		require.NoError(t, err)

		// Get active should fail
		_, err = s.driver.GetActiveIssuedAPIKey(s.ctx(), keyID)
		require.Error(t, err)

		// But Get should still work
		revoked, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), revoked.Status)

		// Delete
		err = s.driver.DeleteIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		// Get should fail
		_, err = s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		assert.Error(t, err)
	})

	t.Run("Imported key lifecycle: create, retrieve, revoke, delete", func(t *testing.T) {
		// Create with hash format (matches production crypto.HashImportedAPIKey)
		rawKey := "lifecycle_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		created, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:    keyID,
			ActorID:  "github",
			Name:     "Imported Lifecycle",
			Scopes:   json.RawMessage("[]"),
			Metadata: json.RawMessage(`{"provider": "github"}`),
			Status:   int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), created.Status)

		// Retrieve by hash
		retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, keyID, retrieved.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), retrieved.Status)

		// Update metadata
		updated, err := s.driver.UpdateImportedAPIKeyMetadata(s.ctx(), persistencetypes.UpdateImportedKeyParams{
			KeyID:    keyID,
			Name:     "Updated Lifecycle",
			Scopes:   []string{"read", "write"},
			Metadata: json.RawMessage(`{"provider": "github", "updated": true}`),
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated Lifecycle", updated.Name)

		// Verify update persisted
		afterUpdate, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Lifecycle", afterUpdate.Name)

		// Revoke
		now := time.Now().UTC()
		newExpiresAt := sqlutil.CalculateRevocationExpiry(now, nil)
		revoked, err := s.revokeImportedAPIKey(keyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE), "", newExpiresAt)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), revoked.Status)

		// Still retrievable after revocation
		stillThere, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), stillThere.Status)

		// Delete
		err = s.driver.DeleteImportedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		// Should not be retrievable after deletion
		_, err = s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		assert.Error(t, err)
	})
}

// assertTimestampsUTC verifies that createdAt, updatedAt, and optionally expiresAt are in UTC.
func assertTimestampsUTC(t *testing.T, createdAt, updatedAt time.Time, expiresAt *time.Time, prefix string) {
	t.Helper()
	assert.Equal(t, time.UTC, createdAt.Location(), "%s created_at must be UTC, got %v", prefix, createdAt.Location())
	assert.Equal(t, time.UTC, updatedAt.Location(), "%s updated_at must be UTC, got %v", prefix, updatedAt.Location())
	if expiresAt != nil {
		assert.Equal(t, time.UTC, expiresAt.Location(), "%s expires_at must be UTC, got %v", prefix, expiresAt.Location())
	}
}

// TestUTCTimestampEnforcement verifies that all timestamps are stored and retrieved in UTC
// This is critical for consistent behavior across timezones and daylight saving time
func (s *DriverTestSuite) TestUTCTimestampEnforcement(t *testing.T) {
	t.Run("API Key timestamps are UTC", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		expiresAt := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

		// Create API key
		params := newCreateParams(keyID, "UTC Test Key", "test-user", []string{"read"})
		params.Metadata = json.RawMessage(`{}`)
		params.ExpiresAt = &expiresAt
		apiKey, err := s.createAPIKey(params)
		require.NoError(t, err)

		assertTimestampsUTC(t, apiKey.CreatedAt, apiKey.UpdatedAt, apiKey.ExpiresAt, "created")

		// Retrieve the key and verify timestamps are still UTC
		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		assertTimestampsUTC(t, retrieved.CreatedAt, retrieved.UpdatedAt, retrieved.ExpiresAt, "retrieved")
	})

	t.Run("Imported Key timestamps are UTC", func(t *testing.T) {
		rawKey := "utc_imported_key_" + uuid.Must(uuid.NewV4()).String()
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		expiresAt := time.Date(2025, 6, 30, 12, 0, 0, 0, time.UTC)

		// Create imported key
		importedKey, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:     keyID,
			ActorID:   "test-service",
			Name:      "UTC Imported Key",
			Scopes:    json.RawMessage(`[]`),
			Metadata:  json.RawMessage(`{}`),
			Status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			ExpiresAt: &expiresAt,
		})
		require.NoError(t, err)

		assertTimestampsUTC(t, importedKey.CreatedAt, importedKey.UpdatedAt, importedKey.ExpiresAt, "created")

		// Retrieve and verify timestamps remain UTC
		retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
		require.NoError(t, err)

		assertTimestampsUTC(t, retrieved.CreatedAt, retrieved.UpdatedAt, retrieved.ExpiresAt, "retrieved")
	})

	t.Run("UpdateAPIKeyLastUsed sets UTC timestamp", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()

		// Create API key
		params := newCreateParams(keyID, "LastUsed UTC Test", "test-user", []string{"read"})
		params.Metadata = json.RawMessage(`{}`)
		_, err := s.createAPIKey(params)
		require.NoError(t, err)

		// Update last_used_at
		err = s.driver.UpdateIssuedAPIKeyLastUsed(s.ctx(), keyID)
		require.NoError(t, err)

		// Retrieve and verify last_used_at is UTC
		retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
		require.NoError(t, err)

		if retrieved.LastUsedAt != nil {
			assert.Equal(t, time.UTC, retrieved.LastUsedAt.Location(), "last_used_at must be UTC, got %v", retrieved.LastUsedAt.Location())
		}
	})
}

// TestAPIKeyIdempotency tests AIP-133 idempotency key support for both issued and imported keys.
func (s *DriverTestSuite) TestAPIKeyIdempotency(t *testing.T) {
	t.Run("CreateAPIKey stores request_id and GetAPIKeyByRequestID retrieves it", func(t *testing.T) {
		keyID := uuid.Must(uuid.NewV4()).String()
		requestID := uuid.Must(uuid.NewV4()).String()

		_, err := s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID:       keyID,
			Name:        "Idempotency Test Key",
			TokenPrefix: "pk_test_",
			ActorID:     "owner-idem",
			Scopes:      scopesToJSON([]string{"read"}),
			RequestID:   requestID,
		})
		require.NoError(t, err)

		retrieved, err := s.driver.GetIssuedAPIKeyByRequestID(s.ctx(), requestID)
		require.NoError(t, err)
		assert.Equal(t, keyID, retrieved.KeyID)
	})

	t.Run("GetAPIKeyByRequestID returns error for unknown request_id", func(t *testing.T) {
		_, err := s.driver.GetIssuedAPIKeyByRequestID(s.ctx(), "nonexistent-request-id-"+uuid.Must(uuid.NewV4()).String())
		assert.Error(t, err)
	})

	t.Run("CreateAPIKey with empty request_id does not enforce idempotency", func(t *testing.T) {
		// Two keys with empty request_id must be distinct (no unique constraint fires).
		key1ID := uuid.Must(uuid.NewV4()).String()
		_, err := s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID: key1ID, Name: "Dup1", TokenPrefix: "pk_test_", ActorID: "owner-dup",
			Scopes: scopesToJSON([]string{}),
		})
		require.NoError(t, err)

		key2ID := uuid.Must(uuid.NewV4()).String()
		_, err = s.createAPIKey(persistencetypes.CreateIssuedAPIKeyParams{
			KeyID: key2ID, Name: "Dup2", TokenPrefix: "pk_test_", ActorID: "owner-dup",
			Scopes: scopesToJSON([]string{}),
		})
		require.NoError(t, err, "two keys without request_id must not conflict")
	})

	t.Run("CreateImportedAPIKey stores request_id and GetImportedAPIKeyByRequestID retrieves it", func(t *testing.T) {
		rawKey := fmt.Sprintf("import_idem_key_%s", uuid.Must(uuid.NewV4()).String())
		keyID := hashImportedKeyID(rawKey, s.nid.String())
		requestID := uuid.Must(uuid.NewV4()).String()

		_, err := s.driver.CreateImportedAPIKey(s.ctx(), persistencetypes.CreateImportedKeyParams{
			KeyID:     keyID,
			ActorID:   "owner-import-idem",
			Name:      "Idempotency Import Test",
			Scopes:    json.RawMessage(`[]`),
			Metadata:  json.RawMessage(`{}`),
			Status:    int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			RequestID: requestID,
		})
		require.NoError(t, err)

		retrieved, err := s.driver.GetImportedAPIKeyByRequestID(s.ctx(), requestID)
		require.NoError(t, err)
		assert.Equal(t, keyID, retrieved.KeyID)
	})

	t.Run("GetImportedAPIKeyByRequestID returns error for unknown request_id", func(t *testing.T) {
		_, err := s.driver.GetImportedAPIKeyByRequestID(s.ctx(), "nonexistent-import-req-"+uuid.Must(uuid.NewV4()).String())
		assert.Error(t, err)
	})
}

// TestAPIKeyRotation tests the RotateAPIKeyAtomic operation across all backends.
func (s *DriverTestSuite) TestAPIKeyRotation(t *testing.T) {
	t.Run("Basic atomic rotation revokes old key and activates new key", func(t *testing.T) {
		t.Parallel()
		oldKeyID := uuid.Must(uuid.NewV4()).String()
		newKeyID := uuid.Must(uuid.NewV4()).String()
		actorID := "rotate-owner-" + uuid.Must(uuid.NewV4()).String()

		_, err := s.createAPIKey(newCreateParams(oldKeyID, "Old Key", actorID, []string{"read"}))
		require.NoError(t, err)

		result, err := s.driver.RotateIssuedAPIKeyAtomic(s.ctx(), oldKeyID, func(_ db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error) {
			return persistencetypes.RotateIssuedAPIKeyParams{
				OldKeyID:    oldKeyID,
				NewKeyID:    newKeyID,
				Name:        "New Key",
				TokenPrefix: "pk_test_",
				ActorID:     actorID,
				Scopes:      []string{"read", "write"},
				Metadata:    json.RawMessage(`{"rotated": true}`),
			}, nil
		})
		require.NoError(t, err)

		// New key must be active.
		assert.Equal(t, newKeyID, result.NewKey.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), result.NewKey.Status)

		// Old key must be revoked.
		assert.Equal(t, oldKeyID, result.OldKey.KeyID)

		revokedKey, err := s.driver.GetIssuedAPIKey(s.ctx(), oldKeyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), revokedKey.Status)

		// New key ID must differ from old key ID.
		assert.NotEqual(t, result.OldKey.KeyID, result.NewKey.KeyID)
	})

	t.Run("Rotation on non-existent old key returns error", func(t *testing.T) {
		t.Parallel()
		nonExistentID := uuid.Must(uuid.NewV4()).String()
		newKeyID := uuid.Must(uuid.NewV4()).String()

		_, err := s.driver.RotateIssuedAPIKeyAtomic(s.ctx(), nonExistentID, func(_ db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error) {
			return persistencetypes.RotateIssuedAPIKeyParams{
				OldKeyID:    nonExistentID,
				NewKeyID:    newKeyID,
				Name:        "New Key",
				TokenPrefix: "pk_test_",
				ActorID:     "owner",
				Scopes:      []string{},
				Metadata:    json.RawMessage(`{}`),
			}, nil
		})
		assert.Error(t, err, "rotating a non-existent key must return an error")
	})

	t.Run("Rotation on already-revoked key returns error", func(t *testing.T) {
		t.Parallel()
		revokedKeyID := uuid.Must(uuid.NewV4()).String()
		newKeyID := uuid.Must(uuid.NewV4()).String()
		actorID := "revoked-rotate-owner-" + uuid.Must(uuid.NewV4()).String()

		_, err := s.createAPIKey(newCreateParams(revokedKeyID, "Already Revoked", actorID, []string{}))
		require.NoError(t, err)

		err = s.revokeAPIKey(revokedKeyID)
		require.NoError(t, err)

		_, err = s.driver.RotateIssuedAPIKeyAtomic(s.ctx(), revokedKeyID, func(_ db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error) {
			return persistencetypes.RotateIssuedAPIKeyParams{
				OldKeyID:    revokedKeyID,
				NewKeyID:    newKeyID,
				Name:        "New Key",
				TokenPrefix: "pk_test_",
				ActorID:     actorID,
				Scopes:      []string{},
				Metadata:    json.RawMessage(`{}`),
			}, nil
		})
		assert.Error(t, err, "rotating an already-revoked key must return an error")
	})

	t.Run("New key ID differs from old key ID after rotation", func(t *testing.T) {
		t.Parallel()
		oldKeyID := uuid.Must(uuid.NewV4()).String()
		newKeyID := uuid.Must(uuid.NewV4()).String()
		actorID := "id-diff-owner-" + uuid.Must(uuid.NewV4()).String()

		_, err := s.createAPIKey(newCreateParams(oldKeyID, "Pre-Rotation Key", actorID, []string{"read"}))
		require.NoError(t, err)

		result, err := s.driver.RotateIssuedAPIKeyAtomic(s.ctx(), oldKeyID, func(_ db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error) {
			return persistencetypes.RotateIssuedAPIKeyParams{
				OldKeyID:    oldKeyID,
				NewKeyID:    newKeyID,
				Name:        "Post-Rotation Key",
				TokenPrefix: "pk_test_",
				ActorID:     actorID,
				Scopes:      []string{"read"},
				Metadata:    json.RawMessage(`{}`),
			}, nil
		})
		require.NoError(t, err)
		assert.NotEqual(t, result.OldKey.KeyID, result.NewKey.KeyID,
			"new key ID must differ from old key ID after rotation")
		assert.Equal(t, oldKeyID, result.OldKey.KeyID)
		assert.Equal(t, newKeyID, result.NewKey.KeyID)
	})
}

// TestImportedAPIKeyRotation tests the two-step imported key rotation workflow:
// RevokeImportedAPIKey (marks old key REVOKED) followed by CreateImportedAPIKey (imports new key).
func (s *DriverTestSuite) TestImportedAPIKeyRotation(t *testing.T) {
	t.Run("Basic rotation revokes old key and imports new key", func(t *testing.T) {
		t.Parallel()
		actorID := "rotate-imported-owner-" + uuid.Must(uuid.NewV4()).String()

		oldRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		oldKeyID := hashImportedKeyID(oldRaw, s.nid.String())

		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   oldKeyID,
			ActorID: actorID,
			Name:    "Old Imported Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// Step 1: revoke old key with SUPERSEDED reason.
		_, err = s.revokeImportedAPIKey(oldKeyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), "rotated: replaced by new key", nil)
		require.NoError(t, err)

		// Step 2: import new key.
		newRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		newKeyID := hashImportedKeyID(newRaw, s.nid.String())

		_, err = s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   newKeyID,
			ActorID: actorID,
			Name:    "New Imported Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// Old key must be revoked with SUPERSEDED reason.
		oldKey, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), oldKeyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), oldKey.Status)
		assert.Equal(t, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), oldKey.RevocationReason)

		// New key must be active.
		newKey, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), newKeyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), newKey.Status)
	})

	t.Run("Revoke on non-existent old key returns error", func(t *testing.T) {
		t.Parallel()
		nonExistentRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		nonExistentID := hashImportedKeyID(nonExistentRaw, s.nid.String())

		_, err := s.revokeImportedAPIKey(nonExistentID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), "rotated", nil)
		assert.Error(t, err, "revoking a non-existent imported key must return an error")
	})

	t.Run("Rotation workflow succeeds even when old key was already revoked", func(t *testing.T) {
		// Unlike issued key rotation (RotateIssuedAPIKeyAtomic), which atomically guards against
		// rotating a non-active key, imported key rotation is two independent operations:
		// RevokeImportedAPIKey (idempotent) + CreateImportedAPIKey. Because revocation is
		// idempotent, the full rotation workflow succeeds even if the old key was already revoked
		// before the caller begins — there is no atomic guard to reject it.
		t.Parallel()
		actorID := "provider-" + uuid.Must(uuid.NewV4()).String()

		oldRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		oldKeyID := hashImportedKeyID(oldRaw, s.nid.String())

		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   oldKeyID,
			ActorID: actorID,
			Name:    "Pre-Revoked Imported Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		// Simulate pre-existing revocation by some other process.
		_, err = s.revokeImportedAPIKey(oldKeyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), "pre-revoked by another process", nil)
		require.NoError(t, err)

		// Rotation workflow: revoke old key again (SUPERSEDED) — idempotent, must succeed.
		_, err = s.revokeImportedAPIKey(oldKeyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), "rotated: replaced by new key", nil)
		require.NoError(t, err, "revoking a pre-revoked imported key must succeed (idempotent)")

		// Import new key — must also succeed.
		newRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		newKeyID := hashImportedKeyID(newRaw, s.nid.String())

		_, err = s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   newKeyID,
			ActorID: actorID,
			Name:    "Replacement Imported Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err, "creating new imported key after pre-revoked old key must succeed")

		// Old key remains REVOKED.
		oldKey, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), oldKeyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), oldKey.Status)

		// New key is ACTIVE.
		newKey, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), newKeyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), newKey.Status)
	})

	t.Run("New key hash differs from old key hash after rotation", func(t *testing.T) {
		t.Parallel()
		actorID := "hash-diff-owner-" + uuid.Must(uuid.NewV4()).String()

		oldRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		oldKeyID := hashImportedKeyID(oldRaw, s.nid.String())

		_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   oldKeyID,
			ActorID: actorID,
			Name:    "Pre-Rotation Imported Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		_, err = s.revokeImportedAPIKey(oldKeyID, int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), "rotated", nil)
		require.NoError(t, err)

		newRaw := "test_key_" + uuid.Must(uuid.NewV4()).String()
		newKeyID := hashImportedKeyID(newRaw, s.nid.String())

		_, err = s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
			KeyID:   newKeyID,
			ActorID: actorID,
			Name:    "Post-Rotation Imported Key",
			Scopes:  json.RawMessage("[]"),
			Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		})
		require.NoError(t, err)

		assert.NotEqual(t, oldKeyID, newKeyID, "new key hash must differ from old key hash after rotation")
	})
}

// TestBatchImportIdempotency verifies that CreateImportedAPIKeysBatch honours per-key request_id
// fields: re-submitting a batch with the same request_ids must not create duplicate rows and must
// return the original keys in the Existing map.
func (s *DriverTestSuite) TestBatchImportIdempotency(t *testing.T) {
	t.Parallel()
	t.Run("second batch with same request_ids returns keys in Existing, not Inserted", func(t *testing.T) {
		t.Parallel()
		reqID1 := uuid.Must(uuid.NewV4()).String()
		reqID2 := uuid.Must(uuid.NewV4()).String()

		keyID1 := hashImportedKeyID("batch_idem_key1_"+reqID1, s.nid.String())
		keyID2 := hashImportedKeyID("batch_idem_key2_"+reqID2, s.nid.String())

		batch := []persistmodel.BatchCreateImportedAPIKeyInput{
			{
				KeyID: keyID1, ActorID: "owner-batch-idem", Name: "Key 1", RequestID: reqID1,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
			{
				KeyID: keyID2, ActorID: "owner-batch-idem", Name: "Key 2", RequestID: reqID2,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
		}

		// First import: both keys are new.
		first, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), batch)
		require.NoError(t, err)
		assert.Len(t, first.Inserted, 2, "first batch must insert both keys")
		assert.Empty(t, first.Existing, "first batch must have no pre-existing keys")

		// Second import: same request_ids, same key_ids. Must be a no-op.
		second, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), batch)
		require.NoError(t, err)
		assert.Empty(t, second.Inserted, "second batch must not insert any new keys")
		assert.Len(t, second.Existing, 2, "second batch must report both keys as pre-existing")

		// Verify the stored request_ids are retrievable.
		got1, err := s.driver.GetImportedAPIKeyByRequestID(s.ctx(), reqID1)
		require.NoError(t, err)
		assert.Equal(t, keyID1, got1.KeyID)

		got2, err := s.driver.GetImportedAPIKeyByRequestID(s.ctx(), reqID2)
		require.NoError(t, err)
		assert.Equal(t, keyID2, got2.KeyID)
	})

	t.Run("batch without request_id skips request_id idempotency check", func(t *testing.T) {
		t.Parallel()
		keyID := hashImportedKeyID("batch_no_reqid_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())

		batch := []persistmodel.BatchCreateImportedAPIKeyInput{
			{
				KeyID: keyID, ActorID: "owner-no-reqid", Name: "No ReqID Key",
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
		}

		first, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), batch)
		require.NoError(t, err)
		assert.Len(t, first.Inserted, 1, "first batch must insert the key")

		// Same key_id again: idempotency via key_id (ON CONFLICT DO NOTHING) must still work.
		second, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), batch)
		require.NoError(t, err)
		assert.Empty(t, second.Inserted, "second batch must not re-insert the key")
		assert.Len(t, second.Existing, 1, "second batch must report key as pre-existing")
	})

	t.Run("partial overlap: new keys inserted, existing keys returned in Existing", func(t *testing.T) {
		t.Parallel()
		reqID1 := uuid.Must(uuid.NewV4()).String()
		reqID2 := uuid.Must(uuid.NewV4()).String()
		reqID3 := uuid.Must(uuid.NewV4()).String()

		keyID1 := hashImportedKeyID("batch_partial_key1_"+reqID1, s.nid.String())
		keyID2 := hashImportedKeyID("batch_partial_key2_"+reqID2, s.nid.String())
		keyID3 := hashImportedKeyID("batch_partial_key3_"+reqID3, s.nid.String())

		firstBatch := []persistmodel.BatchCreateImportedAPIKeyInput{
			{
				KeyID: keyID1, ActorID: "owner-partial", Name: "Key 1", RequestID: reqID1,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
			{
				KeyID: keyID2, ActorID: "owner-partial", Name: "Key 2", RequestID: reqID2,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
		}

		first, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), firstBatch)
		require.NoError(t, err)
		assert.Len(t, first.Inserted, 2, "first batch must insert both keys")

		// Second batch: key1 exists (via request_id), key3 is new.
		secondBatch := []persistmodel.BatchCreateImportedAPIKeyInput{
			{
				KeyID: keyID1, ActorID: "owner-partial", Name: "Key 1", RequestID: reqID1,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
			{
				KeyID: keyID3, ActorID: "owner-partial", Name: "Key 3", RequestID: reqID3,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
		}

		second, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), secondBatch)
		require.NoError(t, err)
		assert.Len(t, second.Inserted, 1, "second batch must insert only the new key")
		assert.Len(t, second.Existing, 1, "second batch must report one pre-existing key")
		_, existsKey1 := second.Existing[keyID1]
		assert.True(t, existsKey1, "existing key must be key1")
		_, insertedKey3 := second.Inserted[keyID3]
		assert.True(t, insertedKey3, "inserted key must be key3")
	})

	t.Run("different request_id but same key_id returns keys in Existing via key_id conflict", func(t *testing.T) {
		t.Parallel()
		reqID1 := uuid.Must(uuid.NewV4()).String()
		reqID2 := uuid.Must(uuid.NewV4()).String()

		keyID := hashImportedKeyID("batch_diff_reqid_"+reqID1, s.nid.String())

		firstBatch := []persistmodel.BatchCreateImportedAPIKeyInput{
			{
				KeyID: keyID, ActorID: "owner-diff-reqid", Name: "Key 1", RequestID: reqID1,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
		}

		first, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), firstBatch)
		require.NoError(t, err)
		assert.Len(t, first.Inserted, 1, "first batch must insert the key")

		// Same key_id but different request_id: key_id conflict means it goes to Existing.
		secondBatch := []persistmodel.BatchCreateImportedAPIKeyInput{
			{
				KeyID: keyID, ActorID: "owner-diff-reqid", Name: "Key 1 Again", RequestID: reqID2,
				Scopes: json.RawMessage(`[]`), Metadata: json.RawMessage(`{}`),
			},
		}

		second, err := s.driver.CreateImportedAPIKeysBatch(s.ctx(), secondBatch)
		require.NoError(t, err)
		assert.Empty(t, second.Inserted, "second batch must not insert duplicate key_id")
		assert.Len(t, second.Existing, 1, "second batch must report key as pre-existing")
		_, ok := second.Existing[keyID]
		require.True(t, ok, "existing key must be the original key_id")
	})
}

// TestGetImportedAPIKeysBatch verifies batch retrieval of imported keys by hash.
func (s *DriverTestSuite) TestGetImportedAPIKeysBatch(t *testing.T) {
	t.Run("returns all matching keys", func(t *testing.T) {
		t.Parallel()
		hashes := make([]string, 3)
		for i := range 3 {
			raw := fmt.Sprintf("batch_get_%d_%s", i, uuid.Must(uuid.NewV4()).String())
			h := hashImportedKeyID(raw, s.nid.String())
			hashes[i] = h
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   h,
				ActorID: "owner",
				Name:    fmt.Sprintf("Batch Key %d", i),
				Scopes:  json.RawMessage(`[]`),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		got, err := s.driver.GetImportedAPIKeysBatch(s.ctx(), hashes)
		require.NoError(t, err)
		assert.Len(t, got, 3)

		gotIDs := make(map[string]bool, len(got))
		for _, k := range got {
			gotIDs[k.KeyID] = true
		}
		for _, h := range hashes {
			assert.True(t, gotIDs[h], "expected key %s in result", h)
		}
	})

	t.Run("returns only existing keys when some hashes are missing", func(t *testing.T) {
		t.Parallel()
		real1 := hashImportedKeyID("batch_partial_1_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())
		real2 := hashImportedKeyID("batch_partial_2_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())
		fake := hashImportedKeyID("batch_partial_fake_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())

		for _, h := range []string{real1, real2} {
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   h,
				ActorID: "owner",
				Name:    "Partial",
				Scopes:  json.RawMessage(`[]`),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		got, err := s.driver.GetImportedAPIKeysBatch(s.ctx(), []string{real1, fake, real2})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})

	t.Run("empty input returns empty result", func(t *testing.T) {
		t.Parallel()
		got, err := s.driver.GetImportedAPIKeysBatch(s.ctx(), []string{})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("all non-existent hashes returns empty result", func(t *testing.T) {
		t.Parallel()
		fake1 := hashImportedKeyID("nonexist_1_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())
		fake2 := hashImportedKeyID("nonexist_2_"+uuid.Must(uuid.NewV4()).String(), s.nid.String())

		got, err := s.driver.GetImportedAPIKeysBatch(s.ctx(), []string{fake1, fake2})
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

// TestGetIssuedAPIKeyByRequestID verifies GetIssuedAPIKeyByRequestID retrieves
// the key created with that request_id (AIP-133 idempotency lookup).
func (s *DriverTestSuite) TestGetIssuedAPIKeyByRequestID(t *testing.T) {
	t.Parallel()

	keyID := uuid.Must(uuid.NewV4()).String()
	requestID := uuid.Must(uuid.NewV4()).String()
	params := newCreateParams(keyID, "ByRequestID", "owner-byrequest", []string{"read"})
	params.RequestID = requestID
	created, err := s.createAPIKey(params)
	require.NoError(t, err)

	got, err := s.driver.GetIssuedAPIKeyByRequestID(s.ctx(), requestID)
	require.NoError(t, err)
	assert.Equal(t, created.KeyID, got.KeyID)
	require.NotNil(t, got.RequestID)
	assert.Equal(t, requestID, *got.RequestID)
}

// TestInitializeIdempotency verifies that calling Initialize twice succeeds
// without error (the default network already exists on the second call).
func (s *DriverTestSuite) TestInitializeIdempotency(t *testing.T) {
	require.NoError(t, s.driver.Initialize(s.ctx()))
	require.NoError(t, s.driver.Initialize(s.ctx()))
}

// TestInitializeNetworkIdempotency verifies that InitializeNetwork is
// idempotent when the same network ID is supplied twice. OSS drivers always
// run with the default uuid.Nil network and are expected to reject any
// non-default network ID — for those, we only check the default-network case.
func (s *DriverTestSuite) TestInitializeNetworkIdempotency(t *testing.T) {
	if s.nid == uuid.Nil {
		// OSS single-tenant driver: InitializeNetwork is only valid for
		// commercial multi-tenant setups. Skip on OSS.
		t.Skip("InitializeNetwork is commercial-only")
	}
	require.NoError(t, s.driver.InitializeNetwork(s.ctx(), s.nid.String()))
	require.NoError(t, s.driver.InitializeNetwork(s.ctx(), s.nid.String()))
}

// TestBatchUpdateLastUsed tests batch last_used_at updates for both issued and imported keys.
func (s *DriverTestSuite) TestBatchUpdateLastUsed(t *testing.T) {
	nid := s.nid.String()

	t.Run("BatchUpdateIssuedAPIKeyLastUsed updates multiple keys", func(t *testing.T) {
		keyIDs := make([]string, 3)
		for i := range keyIDs {
			keyIDs[i] = uuid.Must(uuid.NewV4()).String()
			_, err := s.createAPIKey(newCreateParams(keyIDs[i], fmt.Sprintf("Batch Issued %d", i), "batch-owner", []string{}))
			require.NoError(t, err)
		}

		err := s.driver.BatchUpdateIssuedAPIKeyLastUsed(s.ctx(), keyIDs)
		require.NoError(t, err)

		for _, keyID := range keyIDs {
			retrieved, err := s.driver.GetIssuedAPIKey(s.ctx(), keyID)
			require.NoError(t, err)
			assert.NotNil(t, retrieved.LastUsedAt, "key %s should have LastUsedAt set", keyID)
		}
	})

	t.Run("BatchUpdateIssuedAPIKeyLastUsed with empty slice is no-op", func(t *testing.T) {
		err := s.driver.BatchUpdateIssuedAPIKeyLastUsed(s.ctx(), nil)
		require.NoError(t, err)

		err = s.driver.BatchUpdateIssuedAPIKeyLastUsed(s.ctx(), []string{})
		require.NoError(t, err)
	})

	t.Run("BatchUpdateIssuedAPIKeyLastUsed with non-existent keys is no-op", func(t *testing.T) {
		err := s.driver.BatchUpdateIssuedAPIKeyLastUsed(s.ctx(), []string{uuid.Must(uuid.NewV4()).String()})
		require.NoError(t, err)
	})

	t.Run("BatchUpdateImportedAPIKeyLastUsed updates multiple keys", func(t *testing.T) {
		keyIDs := make([]string, 3)
		for i := range keyIDs {
			rawKey := fmt.Sprintf("batch_imported_%d_%s", i, uuid.Must(uuid.NewV4()).String())
			keyIDs[i] = hashImportedKeyID(rawKey, nid)
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   keyIDs[i],
				ActorID: "batch-owner",
				Name:    fmt.Sprintf("Batch Imported %d", i),
				Scopes:  json.RawMessage("[]"),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		err := s.driver.BatchUpdateImportedAPIKeyLastUsed(s.ctx(), keyIDs)
		require.NoError(t, err)

		for _, keyID := range keyIDs {
			retrieved, err := s.driver.GetImportedAPIKeyByHash(s.ctx(), keyID)
			require.NoError(t, err)
			assert.NotNil(t, retrieved.LastUsedAt, "key %s should have LastUsedAt set", keyID)
		}
	})

	t.Run("BatchUpdateImportedAPIKeyLastUsed with empty slice is no-op", func(t *testing.T) {
		err := s.driver.BatchUpdateImportedAPIKeyLastUsed(s.ctx(), nil)
		require.NoError(t, err)

		err = s.driver.BatchUpdateImportedAPIKeyLastUsed(s.ctx(), []string{})
		require.NoError(t, err)
	})
}

// TestCountActiveAPIKeysUpTo tests the bounded count used for quota enforcement.
// The count combines active issued and imported keys, skips revoked ones, and
// caps the returned value at the supplied limit.
func (s *DriverTestSuite) TestCountActiveAPIKeysUpTo(t *testing.T) {
	nid := s.nid.String()

	t.Run("counts active issued and imported keys, skips revoked", func(t *testing.T) {
		baseline, err := s.driver.CountActiveAPIKeysUpTo(s.ctx(), 1_000)
		require.NoError(t, err)

		for i := range 3 {
			keyID := uuid.Must(uuid.NewV4()).String()
			_, err := s.createAPIKey(newCreateParams(keyID, fmt.Sprintf("Count Issued %d", i), "count-owner", []string{}))
			require.NoError(t, err)
		}

		for i := range 2 {
			rawKey := fmt.Sprintf("count_imported_%d_%s", i, uuid.Must(uuid.NewV4()).String())
			keyID := hashImportedKeyID(rawKey, nid)
			_, err := s.createImportedAPIKey(persistencetypes.CreateImportedKeyParams{
				KeyID:   keyID,
				ActorID: "count-owner",
				Name:    fmt.Sprintf("Count Imported %d", i),
				Scopes:  json.RawMessage("[]"),
				Status:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			})
			require.NoError(t, err)
		}

		revokedID := uuid.Must(uuid.NewV4()).String()
		_, err = s.createAPIKey(newCreateParams(revokedID, "Revoked", "count-owner", []string{}))
		require.NoError(t, err)
		require.NoError(t, s.revokeAPIKey(revokedID))

		count, err := s.driver.CountActiveAPIKeysUpTo(s.ctx(), 1_000)
		require.NoError(t, err)
		assert.Equal(t, baseline+5, count, "should count 3 issued + 2 imported, ignore 1 revoked")
	})

	t.Run("limit caps the result", func(t *testing.T) {
		baseline, err := s.driver.CountActiveAPIKeysUpTo(s.ctx(), 1_000)
		require.NoError(t, err)
		require.Greater(t, baseline, int64(1), "previous subtests must have produced enough keys to test capping")

		capped, err := s.driver.CountActiveAPIKeysUpTo(s.ctx(), 1)
		require.NoError(t, err)
		assert.Equal(t, int64(1), capped, "should cap at limit=1")
	})

	t.Run("zero or negative limit returns zero", func(t *testing.T) {
		count, err := s.driver.CountActiveAPIKeysUpTo(s.ctx(), 0)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)

		count, err = s.driver.CountActiveAPIKeysUpTo(s.ctx(), -5)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

// reviewed - @aeneasr - 2026-03-26
