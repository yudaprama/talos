package service_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// TestListIssuedAPIKeys_Pagination covers page size boundaries, malformed page tokens,
// filter combinations, and full-page exhaustion for issued keys.
func TestListIssuedAPIKeys_Pagination(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Create 5 keys: 3 for user-a, 2 for user-b. Revoke one user-a key.
	for i, req := range []*talosv2alpha1.IssueAPIKeyRequest{
		{Name: "a1", ActorId: "user-a"},
		{Name: "a2", ActorId: "user-a"},
		{Name: "a3", ActorId: "user-a"},
		{Name: "b1", ActorId: "user-b"},
		{Name: "b2", ActorId: "user-b"},
	} {
		resp, err := svc.IssueAPIKey(ctx, req)
		require.NoError(t, err)
		// Revoke the first user-a key so we have a mix of statuses.
		if i == 0 {
			_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{KeyId: resp.IssuedApiKey.KeyId})
			require.NoError(t, err)
		}
	}

	t.Run("page_size=0 defaults to 50 and returns all 5 keys", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{PageSize: 0})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(resp.IssuedApiKeys), 5)
		assert.Empty(t, resp.NextPageToken)
	})

	t.Run("page_size=1 paginates one at a time", func(t *testing.T) {
		t.Parallel()
		seen := map[string]bool{}
		token := ""
		pages := 0
		for {
			resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
				PageSize:  1,
				PageToken: token,
			})
			require.NoError(t, err)
			assert.Len(t, resp.IssuedApiKeys, 1)
			pages++
			seen[resp.IssuedApiKeys[0].KeyId] = true
			if resp.NextPageToken == "" {
				break
			}
			token = resp.NextPageToken
		}
		assert.GreaterOrEqual(t, pages, 5, "should paginate through at least 5 keys")
		assert.Len(t, seen, pages, "no duplicate keys across pages")
	})

	t.Run("last page returns empty next_page_token", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{PageSize: 1000})
		require.NoError(t, err)
		assert.Empty(t, resp.NextPageToken)
	})

	t.Run("malformed page token returns error", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageToken: "not-a-valid-token",
		})
		require.Error(t, err)
	})

	t.Run("garbage bytes page token returns error", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageToken: "\x00\x01\x02\x03\xff\xfe",
		})
		require.Error(t, err)
	})

	t.Run("base64-looking but invalid page token returns error", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageToken: "dGhpcyBsb29rcyBsaWtlIGJhc2U2NCBidXQgaXMgbm90IGEgY3Vyc29y",
		})
		require.Error(t, err)
	})

	t.Run("truncated base64 page token returns error", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageToken: "dGhpcyBpcyB0cnVuY2F0ZQ==",
		})
		require.Error(t, err)
	})

	t.Run("wrong-network_id page token returns error", func(t *testing.T) {
		t.Parallel()
		// Encode a cursor for a different NID. The service must reject it.
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageToken: "eyJpZCI6ImZha2UtaWQiLCJuaWQiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEifQ==",
		})
		require.Error(t, err)
	})

	t.Run("filter by actor_id returns only their keys", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			Filter:   `actor_id="user-a"`,
			PageSize: 50,
		})
		require.NoError(t, err)
		assert.Len(t, resp.IssuedApiKeys, 3)
		for _, k := range resp.IssuedApiKeys {
			assert.Equal(t, "user-a", k.ActorId)
		}
	})

	t.Run("status-only filter requires actor_id", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			Filter:   "status=KEY_STATUS_REVOKED",
			PageSize: 50,
		})
		require.Error(t, err, "status filter without actor_id must be rejected")
	})

	t.Run("filter by actor AND revoked status returns only revoked keys", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			Filter:   `actor_id="user-a" AND status=KEY_STATUS_REVOKED`,
			PageSize: 50,
		})
		require.NoError(t, err)
		assert.Len(t, resp.IssuedApiKeys, 1)
		for _, k := range resp.IssuedApiKeys {
			assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, k.Status)
		}
	})

	t.Run("filter by actor AND status combined", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			Filter:   `actor_id="user-a" AND status=KEY_STATUS_ACTIVE`,
			PageSize: 50,
		})
		require.NoError(t, err)
		assert.Len(t, resp.IssuedApiKeys, 2, "user-a has 3 keys, 1 revoked → 2 active")
		for _, k := range resp.IssuedApiKeys {
			assert.Equal(t, "user-a", k.ActorId)
			assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE, k.Status)
		}
	})

	t.Run("filter with no matching actor returns empty list", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			Filter:   `actor_id="nobody"`,
			PageSize: 50,
		})
		require.NoError(t, err)
		assert.Empty(t, resp.IssuedApiKeys)
		assert.Empty(t, resp.NextPageToken)
	})

	t.Run("filter combined with pagination paginates correctly", func(t *testing.T) {
		t.Parallel()
		// user-a has 3 keys. Paginate 1 at a time with filter.
		seen := map[string]bool{}
		token := ""
		for {
			resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
				Filter:    `actor_id="user-a"`,
				PageSize:  1,
				PageToken: token,
			})
			require.NoError(t, err)
			require.Len(t, resp.IssuedApiKeys, 1)
			key := resp.IssuedApiKeys[0]
			assert.Equal(t, "user-a", key.ActorId)
			assert.False(t, seen[key.KeyId], "duplicate key across pages: %s", key.KeyId)
			seen[key.KeyId] = true
			if resp.NextPageToken == "" {
				break
			}
			token = resp.NextPageToken
		}
		assert.Len(t, seen, 3, "should have iterated all 3 user-a keys")
	})

	t.Run("invalid filter expression returns error", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			Filter: "unknown_field=value",
		})
		require.Error(t, err)
	})
}

// TestListImportedAPIKeys_Pagination covers the same pagination/filter surface for imported keys.
func TestListImportedAPIKeys_Pagination(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Import 4 keys: 2 for actor owner-x, 2 for actor owner-y. Revoke one owner-x key.
	type importedInfo struct {
		keyID string
	}
	importRequests := []*talosv2alpha1.ImportAPIKeyRequest{
		{RawKey: "ext-key-x1-unique", Name: "x1", ActorId: "owner-x", Ttl: durationpb.New(24 * time.Hour)},
		{RawKey: "ext-key-x2-unique", Name: "x2", ActorId: "owner-x", Ttl: durationpb.New(24 * time.Hour)},
		{RawKey: "ext-key-y1-unique", Name: "y1", ActorId: "owner-y", Ttl: durationpb.New(24 * time.Hour)},
		{RawKey: "ext-key-y2-unique", Name: "y2", ActorId: "owner-y", Ttl: durationpb.New(24 * time.Hour)},
	}
	importedKeys := make([]importedInfo, 0, len(importRequests))
	for i, req := range importRequests {
		resp, err := svc.ImportAPIKey(ctx, req)
		require.NoError(t, err)
		importedKeys = append(importedKeys, importedInfo{keyID: resp.KeyId})
		if i == 0 {
			_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{KeyId: resp.KeyId})
			require.NoError(t, err)
		}
	}
	_ = importedKeys

	t.Run("page_size=0 defaults and returns all keys", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{PageSize: 0})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(resp.ImportedApiKeys), 4)
		assert.Empty(t, resp.NextPageToken)
	})

	t.Run("malformed page token returns error", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
			PageToken: "tampered-token",
		})
		require.Error(t, err)
	})

	t.Run("filter by actor returns only their keys", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
			Filter:   `actor_id="owner-x"`,
			PageSize: 50,
		})
		require.NoError(t, err)
		assert.Len(t, resp.ImportedApiKeys, 2)
		for _, k := range resp.ImportedApiKeys {
			assert.Equal(t, "owner-x", k.ActorId)
		}
	})

	t.Run("status-only filter requires actor_id", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
			Filter:   "status=KEY_STATUS_REVOKED",
			PageSize: 50,
		})
		require.Error(t, err, "status filter without actor_id must be rejected")
	})

	t.Run("filter by actor AND revoked status", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
			Filter:   `actor_id="owner-x" AND status=KEY_STATUS_REVOKED`,
			PageSize: 50,
		})
		require.NoError(t, err)
		assert.Len(t, resp.ImportedApiKeys, 1)
		for _, k := range resp.ImportedApiKeys {
			assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, k.Status)
		}
	})

	t.Run("page_size=1 iterates all imported keys without overlap", func(t *testing.T) {
		t.Parallel()
		seen := map[string]bool{}
		token := ""
		pages := 0
		for {
			resp, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
				PageSize:  1,
				PageToken: token,
			})
			require.NoError(t, err)
			assert.Len(t, resp.ImportedApiKeys, 1)
			pages++
			seen[resp.ImportedApiKeys[0].KeyId] = true
			if resp.NextPageToken == "" {
				break
			}
			token = resp.NextPageToken
		}
		assert.GreaterOrEqual(t, pages, 4)
		assert.Len(t, seen, pages, "no duplicate keys across pages")
	})
}

// TestListIssuedAPIKeys_RevokedKeyCursorStability verifies that revoking a key whose ID
// is embedded in a page cursor does not break subsequent pagination. Keyset pagination
// uses (created_at, key_id) > (cursor_ts, cursor_id), so the cursor key need not exist.
func TestListIssuedAPIKeys_RevokedKeyCursorStability(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Create 3 keys so we can paginate with page_size=1.
	names := []string{"cursor-a", "cursor-b", "cursor-c"}
	for _, name := range names {
		_, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    name,
			ActorId: "cursor-owner",
		})
		require.NoError(t, err)
	}

	// Fetch the first page (page_size=1) to get a cursor.
	page1, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
		PageSize: 1,
		Filter:   `actor_id="cursor-owner"`,
	})
	require.NoError(t, err)
	require.Len(t, page1.IssuedApiKeys, 1)
	require.NotEmpty(t, page1.NextPageToken, "should have a next page token")

	firstKeyID := page1.IssuedApiKeys[0].KeyId

	// Revoke the key that the cursor references.
	_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{KeyId: firstKeyID})
	require.NoError(t, err)

	// Continue pagination with the same cursor — should still work.
	seen := map[string]bool{firstKeyID: true}
	token := page1.NextPageToken
	for token != "" {
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageSize:  1,
			PageToken: token,
			Filter:    `actor_id="cursor-owner"`,
		})
		require.NoError(t, err)
		require.Len(t, resp.IssuedApiKeys, 1)
		key := resp.IssuedApiKeys[0]
		assert.False(t, seen[key.KeyId], "duplicate key %s across pages after revocation", key.KeyId)
		seen[key.KeyId] = true
		token = resp.NextPageToken
	}

	assert.Len(t, seen, 3, "should have seen all 3 keys despite mid-pagination revocation")
}

// TestListIssuedAPIKeys_SameTimestampTieBreaking verifies that pagination returns all
// keys without duplicates or gaps even when multiple keys share the same created_at
// timestamp. The keyset cursor uses key_id (UUID) for ordering, so timestamp collisions
// do not affect correctness — this test proves it.
func TestListIssuedAPIKeys_SameTimestampTieBreaking(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Issue 5 keys as fast as possible to maximize timestamp collisions.
	// SQLite stores timestamps with microsecond precision, so rapid inserts
	// may share the same created_at value.
	const keyCount = 5
	for i := range keyCount {
		_, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    "ts-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+i)),
			ActorId: "same-ts-owner",
		})
		require.NoError(t, err)
	}

	// Paginate one key at a time and verify no duplicates or gaps.
	seen := make(map[string]bool)
	token := ""
	pages := 0

	for {
		resp, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedAPIKeysRequest{
			PageSize:  1,
			PageToken: token,
			Filter:    `actor_id="same-ts-owner"`,
		})
		require.NoError(t, err)
		require.Len(t, resp.IssuedApiKeys, 1, "page_size=1 must return exactly 1 item")

		keyID := resp.IssuedApiKeys[0].KeyId
		assert.False(t, seen[keyID], "duplicate key %s on page %d", keyID, pages+1)
		seen[keyID] = true
		pages++

		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
	}

	assert.Len(t, seen, keyCount, "must paginate through all %d keys without gaps", keyCount)
	assert.Equal(t, keyCount, pages, "must take exactly %d pages with page_size=1", keyCount)
}
