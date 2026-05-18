package service_test

import (
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ory/herodot"

	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// TestRotateIssuedAPIKey_RejectsRevokedKey verifies that rotating an already-revoked
// key returns a FailedPrecondition error instead of silently succeeding.
func TestRotateIssuedAPIKey_RejectsRevokedKey(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Issue a key, then revoke it.
	issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
		Name:    "Key to Revoke Then Rotate",
		ActorId: "owner-revoke-rotate",
	})
	require.NoError(t, err)
	keyID := issueResp.IssuedApiKey.KeyId

	_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{
		KeyId:  keyID,
		Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	})
	require.NoError(t, err)

	// Attempt to rotate the revoked key — must fail.
	_, err = svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
		KeyId: keyID,
	})
	require.Error(t, err, "rotating a revoked key must fail")

	var herodotErr *herodot.DefaultError
	require.True(t, errors.As(err, &herodotErr))
	assert.Equal(t, 409, herodotErr.CodeField, "expected 409 Conflict / FailedPrecondition")
}

// TestRotateIssuedAPIKey_ConcurrentDoubleRotation verifies that two concurrent
// rotations of the same key do not both succeed. Exactly one must win; the other
// must receive an error indicating the key was already rotated.
func TestRotateIssuedAPIKey_ConcurrentDoubleRotation(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Issue a key to rotate.
	issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
		Name:    "Key for Concurrent Rotation",
		ActorId: "owner-concurrent",
	})
	require.NoError(t, err)
	keyID := issueResp.IssuedApiKey.KeyId

	const goroutines = 5
	type result struct {
		resp *talosv2alpha1.RotateIssuedAPIKeyResponse
		err  error
	}

	results := make([]result, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Fire concurrent rotation requests.
	for i := range goroutines {
		go func() {
			defer wg.Done()
			resp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
				KeyId: keyID,
			})
			results[i] = result{resp: resp, err: err}
		}()
	}
	wg.Wait()

	// Count successes and failures.
	var successes, failures int
	for _, r := range results {
		if r.err == nil {
			successes++
		} else {
			failures++
		}
	}

	assert.Equal(t, 1, successes, "exactly one concurrent rotation must succeed")
	assert.Equal(t, goroutines-1, failures, "all other concurrent rotations must fail")
}

// TestRotateIssuedAPIKey_MultiFieldUpdate verifies that a single rotation can update
// name, scopes, and metadata simultaneously, and that the old key is revoked.
func TestRotateIssuedAPIKey_MultiFieldUpdate(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	initialMeta, err := structpb.NewStruct(map[string]any{"env": "staging"})
	require.NoError(t, err)

	issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
		Name:     "Original Name",
		ActorId:  "owner-multifield",
		Scopes:   []string{"read"},
		Metadata: initialMeta,
	})
	require.NoError(t, err)
	oldKeyID := issueResp.IssuedApiKey.KeyId

	newMeta, err := structpb.NewStruct(map[string]any{"env": "production", "version": "2"})
	require.NoError(t, err)

	rotateResp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
		KeyId:    oldKeyID,
		Name:     new("Updated Name"),
		Scopes:   []string{"read", "write", "admin"},
		Metadata: newMeta,
	})
	require.NoError(t, err)
	require.NotNil(t, rotateResp.IssuedApiKey)

	// All overridden fields must appear on the new key.
	newKey := rotateResp.IssuedApiKey
	assert.Equal(t, "Updated Name", newKey.Name)
	assert.Equal(t, []string{"read", "write", "admin"}, newKey.Scopes)
	require.NotNil(t, newKey.Metadata)
	assert.Equal(t, "production", newKey.Metadata.AsMap()["env"])
	assert.Equal(t, "2", newKey.Metadata.AsMap()["version"])

	// The new key must have a different ID and a non-empty secret.
	assert.NotEqual(t, oldKeyID, newKey.KeyId)
	assert.NotEmpty(t, rotateResp.Secret)

	// The old key must be revoked.
	require.NotNil(t, rotateResp.OldIssuedApiKey)
	assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, rotateResp.OldIssuedApiKey.Status)
}

// TestRotateIssuedAPIKey_PreservesUntouchedFields verifies that fields not included
// in the rotation request are copied unchanged from the original key.
func TestRotateIssuedAPIKey_PreservesUntouchedFields(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	initialMeta, err := structpb.NewStruct(map[string]any{"service": "billing", "tier": "premium"})
	require.NoError(t, err)

	issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
		Name:     "Preserve Fields Key",
		ActorId:  "owner-preserve",
		Scopes:   []string{"invoices:read", "payments:read"},
		Metadata: initialMeta,
	})
	require.NoError(t, err)
	oldKey := issueResp.IssuedApiKey

	// Rotate with only a name override — all other fields must be inherited.
	rotateResp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
		KeyId: oldKey.KeyId,
		Name:  new("Renamed Key"),
	})
	require.NoError(t, err)
	require.NotNil(t, rotateResp.IssuedApiKey)

	newKey := rotateResp.IssuedApiKey

	// Name must have changed.
	assert.Equal(t, "Renamed Key", newKey.Name)

	// actor_id, scopes, and metadata must be preserved from the original key.
	assert.Equal(t, oldKey.ActorId, newKey.ActorId)
	assert.Equal(t, oldKey.Scopes, newKey.Scopes)
	require.NotNil(t, newKey.Metadata)
	assert.Equal(t, oldKey.Metadata.AsMap(), newKey.Metadata.AsMap())
}

// TestRotateIssuedAPIKey_NameAndScopesOverride verifies that rotation with only
// name and scopes overrides updates both fields and preserves everything else.
func TestRotateIssuedAPIKey_NameAndScopesOverride(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	initialMeta, err := structpb.NewStruct(map[string]any{"region": "us-east-1"})
	require.NoError(t, err)

	issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
		Name:     "Original Service Key",
		ActorId:  "owner-namescopes",
		Scopes:   []string{"metrics:read"},
		Metadata: initialMeta,
	})
	require.NoError(t, err)
	oldKey := issueResp.IssuedApiKey

	rotateResp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
		KeyId:  oldKey.KeyId,
		Name:   new("Rotated Service Key"),
		Scopes: []string{"metrics:read", "logs:read"},
	})
	require.NoError(t, err)
	require.NotNil(t, rotateResp.IssuedApiKey)

	newKey := rotateResp.IssuedApiKey

	// Both overridden fields must be updated.
	assert.Equal(t, "Rotated Service Key", newKey.Name)
	assert.Equal(t, []string{"metrics:read", "logs:read"}, newKey.Scopes)

	// Non-overridden fields must be preserved.
	assert.Equal(t, oldKey.ActorId, newKey.ActorId)
	require.NotNil(t, newKey.Metadata)
	assert.Equal(t, oldKey.Metadata.AsMap(), newKey.Metadata.AsMap())

	// The old key must be revoked.
	assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, rotateResp.OldIssuedApiKey.Status)
}

// TestRotateIssuedAPIKey_EmptyMetadataClears verifies presence-based semantics:
// passing a non-nil but empty Struct for metadata clears metadata on the new
// key, distinguishing "absent" (inherit) from "explicit empty" (override).
func TestRotateIssuedAPIKey_EmptyMetadataClears(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	initialMeta, err := structpb.NewStruct(map[string]any{"keep": "me"})
	require.NoError(t, err)

	issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
		Name:     "Key With Metadata",
		ActorId:  "owner-empty-meta",
		Metadata: initialMeta,
	})
	require.NoError(t, err)
	oldKeyID := issueResp.IssuedApiKey.KeyId

	// Send an explicitly empty (but non-nil) Struct: this signals "clear it".
	emptyMeta, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)

	rotateResp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
		KeyId:    oldKeyID,
		Metadata: emptyMeta,
	})
	require.NoError(t, err)
	require.NotNil(t, rotateResp.IssuedApiKey)

	newKey := rotateResp.IssuedApiKey
	// "Cleared" is observable as nil or empty in the response; the key invariant
	// is that no fields from the old key's metadata leaked through.
	if newKey.Metadata != nil {
		assert.Empty(t, newKey.Metadata.AsMap(), "explicit empty metadata must clear inherited values")
	}
	// Sanity-check: the prior "keep" key from the old metadata must not appear.
	if newKey.Metadata != nil {
		_, leaked := newKey.Metadata.AsMap()["keep"]
		assert.False(t, leaked, "old metadata key 'keep' must not be inherited after explicit clear")
	}
}

// reviewed - @aeneasr - 2026-03-26
