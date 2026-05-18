package cache_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/cache"
	"github.com/ory-corp/talos/internal/contextx"
)

// TODO add advesarial tests

// TestBuildFullKey_Format verifies the cache key format is namespace:nid_hex:sha256_hex.
func TestBuildFullKey_Format(t *testing.T) {
	t.Parallel()

	nid := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	ctx := context.WithValue(context.Background(), contextx.NIDKey{}, nid)

	const (
		namespace  = "apikey"
		credential = "my-raw-secret"
	)

	key := cache.BuildFullKey(ctx, namespace, credential)

	hash := sha256.Sum256([]byte(credential))
	expected := fmt.Sprintf("%s:%s:%x", namespace, nid.String(), hash)
	assert.Equal(t, expected, key)

	// Verify the three colon-separated segments are present in the correct order.
	require.Contains(t, key, namespace+":")
	require.Contains(t, key, nid.String()+":")
	// SHA-256 produces a 32-byte (64 hex char) digest.
	segments := splitN(key, ":", 3)
	require.Len(t, segments, 3, "key must have exactly three colon-separated segments")
	assert.Equal(t, namespace, segments[0], "first segment must be namespace")
	assert.Equal(t, nid.String(), segments[1], "second segment must be NID")
	assert.Len(t, segments[2], 64, "third segment must be 64-character SHA-256 hex digest")
}

// TestBuildFullKey_DifferentCredentialsSameNID verifies that two different credentials
// under the same NID produce different cache keys (no credential collision).
func TestBuildFullKey_DifferentCredentialsSameNID(t *testing.T) {
	t.Parallel()

	nid := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	ctx := context.WithValue(context.Background(), contextx.NIDKey{}, nid)

	key1 := cache.BuildFullKey(ctx, "apikey", "credential-alpha")
	key2 := cache.BuildFullKey(ctx, "apikey", "credential-beta")

	assert.NotEqual(t, key1, key2, "different credentials must produce different keys")
}

// TestBuildFullKey_SameCredentialDifferentNIDs verifies that the same credential
// produces distinct keys for different network IDs, preventing cross-tenant cache hits.
func TestBuildFullKey_SameCredentialDifferentNIDs(t *testing.T) {
	t.Parallel()

	nid1 := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	nid2 := uuid.Must(uuid.FromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))

	ctx1 := context.WithValue(context.Background(), contextx.NIDKey{}, nid1)
	ctx2 := context.WithValue(context.Background(), contextx.NIDKey{}, nid2)

	const credential = "shared-credential"
	key1 := cache.BuildFullKey(ctx1, "apikey", credential)
	key2 := cache.BuildFullKey(ctx2, "apikey", credential)

	assert.NotEqual(t, key1, key2, "same credential under different NIDs must produce different keys")
}

// TestBuildFullKey_NIDIsolation verifies that the NID is embedded in the key such
// that a lookup by tenant A cannot match a cache entry stored by tenant B.
func TestBuildFullKey_NIDIsolation(t *testing.T) {
	t.Parallel()

	nidA := uuid.Must(uuid.FromString("cccccccc-cccc-cccc-cccc-cccccccccccc"))
	nidB := uuid.Must(uuid.FromString("dddddddd-dddd-dddd-dddd-dddddddddddd"))

	ctxA := context.WithValue(context.Background(), contextx.NIDKey{}, nidA)
	ctxB := context.WithValue(context.Background(), contextx.NIDKey{}, nidB)

	const credential = "top-secret-api-key"

	// Tenant A stores a key under its NID.
	storeKey := cache.BuildFullKey(ctxA, "apikey", credential)

	// Tenant B looks up the same raw credential under its own NID.
	lookupKey := cache.BuildFullKey(ctxB, "apikey", credential)

	assert.NotEqual(t, storeKey, lookupKey,
		"a lookup by tenant B must never match an entry stored by tenant A")

	// Double-check that nidA and nidB are both present in their respective keys.
	assert.Contains(t, storeKey, nidA.String())
	assert.Contains(t, lookupKey, nidB.String())
}

// splitN splits s into at most n substrings around sep, returning a slice.
// This is a thin local helper to avoid importing strings for a single call in tests.
func splitN(s, sep string, n int) []string {
	result := make([]string, 0, n)
	for range n - 1 {
		idx := indexOf(s, sep)
		if idx < 0 {
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	result = append(result, s)
	return result
}

func indexOf(s, sub string) int {
	for i := range len(s) - len(sub) + 1 {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// reviewed - @aeneasr - 2026-03-25
