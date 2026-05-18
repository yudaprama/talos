package persistencetest

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/persistence/persistmodel"
	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// errorf is the subset of *testing.T used by compareJSONSnapshot. Accepting
// an interface lets the proof test in round_trip_test.go capture failures
// without forwarding them to the real testing.T.
type errorf interface {
	Helper()
	Errorf(format string, args ...any)
}

// compareJSONSnapshot marshals want and got to JSON and asserts deep equality
// on the parsed map representation. Keys named in ignoreKeys are removed from
// both sides before comparison; for each ignored key the helper still asserts
// the got side carries a present (non-null, non-empty) value, so a silently
// dropped server-coerced timestamp surfaces as a failure rather than passing
// silently.
//
// Use ignoreKeys only for fields the driver MUST populate but whose value is
// non-deterministic (server-now timestamps). For fields the driver
// intentionally clears on create, patch the seed-side model before calling
// the helper so both sides carry the same null/zero value and the diff
// passes naturally.
//
// The label disambiguates failures when a single test compares more than one
// snapshot.
func compareJSONSnapshot[T any](t errorf, label string, want, got T, ignoreKeys ...string) {
	t.Helper()
	wantMap := jsonRoundTrip(t, want)
	gotMap := jsonRoundTrip(t, got)
	if wantMap == nil || gotMap == nil {
		return
	}
	for _, k := range ignoreKeys {
		if v, ok := gotMap[k]; !ok || isJSONNil(v) {
			t.Errorf("%s: %T.%s is missing/null on got side after round-trip", label, got, k)
		}
		delete(wantMap, k)
		delete(gotMap, k)
	}
	if diff := cmp.Diff(wantMap, gotMap); diff != "" {
		t.Errorf("%s: %T snapshot mismatch (-want +got):\n%s", label, got, diff)
	}
}

// jsonRoundTrip marshals v to JSON and parses it back to map[string]any so
// two snapshots can be diffed by `db:"…"` tag name (sqlc emits identical db
// and json tags).
func jsonRoundTrip[T any](t errorf, v T) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Errorf("jsonRoundTrip marshal: %v", err)
		return nil
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Errorf("jsonRoundTrip unmarshal: %v", err)
		return nil
	}
	return out
}

// isJSONNil reports whether the unmarshaled JSON value represents an explicit
// null/absent value. Used by compareJSONSnapshot to flag ignored fields the
// driver dropped instead of populating.
func isJSONNil(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	default:
		return false
	}
}

// timestampIgnoreKeys are the JSON keys for server-now timestamps that vary
// between fixture and driver but must always be populated.
func timestampIgnoreKeys() []string {
	return []string{"created_at", "updated_at"}
}

// patchSeedAfterCreateIssued patches a seed model to match the driver's
// canonical state immediately after CreateIssuedAPIKey, so a snapshot diff
// against the persisted row passes naturally. The driver enforces ACTIVE
// status and Version=1, and clears the last-used / revocation columns.
func patchSeedAfterCreateIssued(seed *db.IssuedApiKey) {
	seed.Status = int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE)
	seed.Version = 1
	seed.LastUsedAt = nil
	seed.RevocationReason = 0
	seed.RevocationReasonText = nil
}

// patchSeedAfterCreateImported patches a seed model to match the driver's
// canonical state immediately after CreateImportedAPIKey. CreateImportedAPIKey
// honors params.Status, so status is left intact; the driver still clears
// last-used / revocation columns.
func patchSeedAfterCreateImported(seed *db.ImportedApiKey) {
	seed.LastUsedAt = nil
	seed.RevocationReason = 0
	seed.RevocationReasonText = nil
}

// TestIssuedKeyFullFieldRoundTrip exercises CreateIssuedAPIKey →
// GetIssuedAPIKey with every field populated and verifies the result via JSON
// snapshot diff. It also runs UpdateMetadata, LastUsed update, Revoke, and
// the batch/list variants.
//
// This test does NOT call t.Parallel — the faker-driven seed builders depend
// on package-level state that requires deterministic call order. See the
// concurrency note on newSeedIssuedKey.
func (s *DriverTestSuite) TestIssuedKeyFullFieldRoundTrip(t *testing.T) {
	t.Helper()

	ctx := s.ctx()

	keyID := uuid.Must(uuid.NewV4()).String()
	requestID := uuid.Must(uuid.NewV4()).String()

	seedModel, params := newSeedCreateIssuedAPIKeyParams(t, s.nid)
	params.KeyID = keyID
	params.RequestID = requestID
	seedModel.KeyID = keyID
	seedModel.RequestID = &requestID

	created, err := s.driver.CreateIssuedAPIKey(ctx, params)
	require.NoError(t, err)

	got, err := s.driver.GetIssuedAPIKey(ctx, keyID)
	require.NoError(t, err)

	patchSeedAfterCreateIssued(&seedModel)
	seedModel.NID = got.NID
	compareJSONSnapshot(t, "Create→Get", seedModel, got, timestampIgnoreKeys()...)
	compareJSONSnapshot(t, "Create→Get (driver-returned)", created, got, timestampIgnoreKeys()...)

	t.Run("UpdateMetadata", func(t *testing.T) {
		updateParams := newSeedUpdateIssuedAPIKeyParams(t, keyID)
		updated, err := s.driver.UpdateIssuedAPIKeyMetadata(ctx, updateParams)
		require.NoError(t, err)
		assert.Equal(t, updateParams.Name, updated.Name)
		require.NotNil(t, updated.RateLimitQuota)
		assert.Equal(t, *updateParams.RateLimitQuota, *updated.RateLimitQuota)
		require.NotNil(t, updated.RateLimitWindow)
		assert.Equal(t, *updateParams.RateLimitWindow, *updated.RateLimitWindow)
		readBack, err := s.driver.GetIssuedAPIKey(ctx, keyID)
		require.NoError(t, err)
		compareJSONSnapshot(t, "UpdateMetadata→Get", updated, readBack, timestampIgnoreKeys()...)
	})

	t.Run("LastUsedAt", func(t *testing.T) {
		err := s.driver.UpdateIssuedAPIKeyLastUsed(ctx, keyID)
		require.NoError(t, err)
		readBack, err := s.driver.GetIssuedAPIKey(ctx, keyID)
		require.NoError(t, err)
		require.NotNil(t, readBack.LastUsedAt, "UpdateIssuedAPIKeyLastUsed must populate last_used_at")
		assert.False(t, readBack.LastUsedAt.IsZero())
	})

	t.Run("Revoke", func(t *testing.T) {
		revokeParams := newSeedRevokeIssuedAPIKeyParams(t, keyID)
		err := s.driver.RevokeIssuedAPIKey(ctx, revokeParams)
		require.NoError(t, err)
		readBack, err := s.driver.GetIssuedAPIKey(ctx, keyID)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), readBack.Status)
		assert.Equal(t, revokeParams.Reason, readBack.RevocationReason)
		require.NotNil(t, readBack.RevocationReasonText)
		assert.Equal(t, revokeParams.Description, *readBack.RevocationReasonText)
		require.NotNil(t, readBack.ExpiresAt)
	})

	t.Run("GetBatch", func(t *testing.T) {
		batch, err := s.driver.GetIssuedAPIKeysBatch(ctx, []string{keyID})
		require.NoError(t, err)
		require.Len(t, batch, 1)
		readBack, err := s.driver.GetIssuedAPIKey(ctx, keyID)
		require.NoError(t, err)
		compareJSONSnapshot(t, "GetBatch→Get", batch[0], readBack, timestampIgnoreKeys()...)
	})

	t.Run("ListByNetwork", func(t *testing.T) {
		actor := params.ActorID
		results, err := s.driver.ListIssuedAPIKeysByNetwork(ctx, actor, 0, "", 100)
		require.NoError(t, err)
		var found *db.IssuedApiKey
		for i := range results {
			if results[i].KeyID == keyID {
				found = &results[i]
				break
			}
		}
		require.NotNil(t, found, "list result must include the just-created key")
		readBack, err := s.driver.GetIssuedAPIKey(ctx, keyID)
		require.NoError(t, err)
		compareJSONSnapshot(t, "ListByNetwork→Get", *found, readBack, timestampIgnoreKeys()...)
	})
}

// TestImportedKeyFullFieldRoundTrip exercises the imported-key happy path with
// every field populated. Same concurrency contract as
// TestIssuedKeyFullFieldRoundTrip.
func (s *DriverTestSuite) TestImportedKeyFullFieldRoundTrip(t *testing.T) {
	t.Helper()

	ctx := s.ctx()

	rawKey := "roundtrip_full_imported_" + uuid.Must(uuid.NewV4()).String()
	keyID := crypto.HashImportedAPIKey(rawKey, s.nid.String())
	requestID := uuid.Must(uuid.NewV4()).String()

	seedModel, params := newSeedCreateImportedKeyParams(t, s.nid)
	params.KeyID = keyID
	params.RequestID = requestID
	seedModel.KeyID = keyID
	seedModel.RequestID = &requestID

	created, err := s.driver.CreateImportedAPIKey(ctx, params)
	require.NoError(t, err)

	got, err := s.driver.GetImportedAPIKeyByHash(ctx, keyID)
	require.NoError(t, err)

	patchSeedAfterCreateImported(&seedModel)
	seedModel.NID = got.NID
	compareJSONSnapshot(t, "Create→Get", seedModel, got, timestampIgnoreKeys()...)
	compareJSONSnapshot(t, "Create→Get (driver-returned)", created, got, timestampIgnoreKeys()...)

	t.Run("GetByRequestID", func(t *testing.T) {
		readBack, err := s.driver.GetImportedAPIKeyByRequestID(ctx, requestID)
		require.NoError(t, err)
		compareJSONSnapshot(t, "GetByRequestID→Get", got, readBack, timestampIgnoreKeys()...)
	})

	t.Run("GetBatch", func(t *testing.T) {
		batch, err := s.driver.GetImportedAPIKeysBatch(ctx, []string{keyID})
		require.NoError(t, err)
		require.Len(t, batch, 1)
		compareJSONSnapshot(t, "GetBatch→Get", got, batch[0], timestampIgnoreKeys()...)
	})

	t.Run("ListImportedAPIKeys", func(t *testing.T) {
		listed, err := s.driver.ListImportedAPIKeys(ctx, 0, params.ActorID, "", 100)
		require.NoError(t, err)
		var found *db.ImportedApiKey
		for i := range listed {
			if listed[i].KeyID == keyID {
				found = &listed[i]
				break
			}
		}
		require.NotNil(t, found, "list result must include the just-created imported key")
		readBack, err := s.driver.GetImportedAPIKeyByHash(ctx, keyID)
		require.NoError(t, err)
		compareJSONSnapshot(t, "List→Get", *found, readBack, timestampIgnoreKeys()...)
	})

	t.Run("UpdateMetadata", func(t *testing.T) {
		updateParams := newSeedUpdateImportedKeyParams(t, keyID)
		updated, err := s.driver.UpdateImportedAPIKeyMetadata(ctx, updateParams)
		require.NoError(t, err)
		assert.Equal(t, updateParams.Name, updated.Name)
		readBack, err := s.driver.GetImportedAPIKeyByHash(ctx, keyID)
		require.NoError(t, err)
		compareJSONSnapshot(t, "UpdateMetadata→Get", updated, readBack, timestampIgnoreKeys()...)
	})

	t.Run("Revoke", func(t *testing.T) {
		revokeParams := newSeedRevokeImportedKeyParams(t, keyID)
		revoked, err := s.driver.RevokeImportedAPIKey(ctx, revokeParams)
		require.NoError(t, err)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), revoked.Status)
		assert.Equal(t, revokeParams.Reason, revoked.RevocationReason)
		require.NotNil(t, revoked.RevocationReasonText)
		assert.Equal(t, revokeParams.Description, *revoked.RevocationReasonText)
	})
}

// TestBatchCreateImportedFullFieldRoundTrip verifies that the batch import
// path preserves every field across Create → returned-row.
func (s *DriverTestSuite) TestBatchCreateImportedFullFieldRoundTrip(t *testing.T) {
	t.Helper()

	ctx := s.ctx()

	rawKey := "roundtrip_batch_imported_" + uuid.Must(uuid.NewV4()).String()
	keyID := crypto.HashImportedAPIKey(rawKey, s.nid.String())
	requestID := uuid.Must(uuid.NewV4()).String()

	seedModel, createParams := newSeedCreateImportedKeyParams(t, s.nid)
	createParams.KeyID = keyID
	createParams.RequestID = requestID
	seedModel.KeyID = keyID
	seedModel.RequestID = &requestID

	input := persistmodel.BatchCreateImportedAPIKeyInput{
		KeyID:           createParams.KeyID,
		ActorID:         createParams.ActorID,
		Name:            createParams.Name,
		Scopes:          createParams.Scopes,
		Metadata:        createParams.Metadata,
		ExpiresAt:       createParams.ExpiresAt,
		RateLimitQuota:  createParams.RateLimitQuota,
		RateLimitWindow: createParams.RateLimitWindow,
		AllowedCIDRs:    createParams.AllowedCIDRs,
		Visibility:      createParams.Visibility,
		RequestID:       createParams.RequestID,
	}

	result, err := s.driver.CreateImportedAPIKeysBatch(ctx, []persistmodel.BatchCreateImportedAPIKeyInput{input})
	require.NoError(t, err)
	require.Len(t, result.Inserted, 1)
	inserted, ok := result.Inserted[keyID]
	require.True(t, ok, "batch result must include just-inserted key by id")

	patchSeedAfterCreateImported(&seedModel)
	// The batch path enforces ACTIVE status (matching CreateImportedAPIKey).
	seedModel.Status = int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE)
	seedModel.NID = inserted.NID
	compareJSONSnapshot(t, "BatchCreate→inserted", seedModel, inserted, timestampIgnoreKeys()...)

	readBack, err := s.driver.GetImportedAPIKeyByHash(ctx, keyID)
	require.NoError(t, err)
	compareJSONSnapshot(t, "BatchCreate→Get", inserted, readBack, timestampIgnoreKeys()...)
}
