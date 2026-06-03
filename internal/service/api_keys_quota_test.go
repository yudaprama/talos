package service_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/config"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// TestAPIKeyQuotaEnforcement verifies that quota.api_keys_max caps the number
// of non-revoked keys a tenant may hold. The cap covers issued and imported
// keys together. A cap of 0 (or absent) means unlimited.
func TestAPIKeyQuotaEnforcement(t *testing.T) {
	t.Parallel()

	t.Run("IssueApiKey rejects when at cap", func(t *testing.T) {
		t.Parallel()
		svc, ctx := setupTestServiceWithConfig(t, map[string]any{
			config.KeyQuotaAPIKeysMax.String(): 2,
		})

		for i := range 2 {
			_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
				Name:    fmt.Sprintf("Key %d", i),
				ActorId: "tester",
			})
			require.NoError(t, err)
		}

		_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Over cap",
			ActorId: "tester",
		})
		require.Error(t, err)

		var herodotErr *herodot.DefaultError
		require.ErrorAs(t, err, &herodotErr, "expected herodot error, got %T", err)
		assert.Equal(t, "api_key_quota_exceeded", herodotErr.IDField)
		assert.Equal(t, http.StatusPaymentRequired, herodotErr.CodeField)
	})

	t.Run("ImportAPIKey rejects when at cap", func(t *testing.T) {
		t.Parallel()
		svc, ctx := setupTestServiceWithConfig(t, map[string]any{
			config.KeyQuotaAPIKeysMax.String(): 1,
		})

		_, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "sk_live_first_key_abcdef",
			Name:    "First imported",
			ActorId: "tester",
		})
		require.NoError(t, err)

		_, err = svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "sk_live_second_key_zyxwvu",
			Name:    "Second imported",
			ActorId: "tester",
		})
		require.Error(t, err)

		var herodotErr *herodot.DefaultError
		require.ErrorAs(t, err, &herodotErr)
		assert.Equal(t, "api_key_quota_exceeded", herodotErr.IDField)
	})

	t.Run("cap counts issued plus imported", func(t *testing.T) {
		t.Parallel()
		svc, ctx := setupTestServiceWithConfig(t, map[string]any{
			config.KeyQuotaAPIKeysMax.String(): 2,
		})

		_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Issued one",
			ActorId: "tester",
		})
		require.NoError(t, err)

		_, err = svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "sk_live_combined_test_abc",
			Name:    "Imported one",
			ActorId: "tester",
		})
		require.NoError(t, err)

		// The combined total now matches the cap, so further creates fail.
		_, err = svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Issued two",
			ActorId: "tester",
		})
		require.Error(t, err)

		_, err = svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "sk_live_combined_test_def",
			Name:    "Imported two",
			ActorId: "tester",
		})
		require.Error(t, err)
	})

	t.Run("absent quota allows unlimited keys", func(t *testing.T) {
		t.Parallel()
		// No quota override: defaults to absent (paid tier semantics).
		svc, _, ctx := setupTestService(t)

		for i := range 5 {
			_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
				Name:    fmt.Sprintf("Unbounded %d", i),
				ActorId: "tester",
			})
			require.NoError(t, err)
		}
	})

	t.Run("zero quota cap allows unlimited keys", func(t *testing.T) {
		t.Parallel()
		// quotaCap <= 0 is the documented "unlimited" sentinel — enforceAPIKeyQuota
		// must short-circuit before counting.
		svc, ctx := setupTestServiceWithConfig(t, map[string]any{
			config.KeyQuotaAPIKeysMax.String(): 0,
		})

		for i := range 10 {
			_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
				Name:    fmt.Sprintf("Zero cap %d", i),
				ActorId: "tester",
			})
			require.NoError(t, err)
		}
	})

	t.Run("revoked keys do not count toward cap", func(t *testing.T) {
		t.Parallel()
		svc, ctx := setupTestServiceWithConfig(t, map[string]any{
			config.KeyQuotaAPIKeysMax.String(): 1,
		})

		first, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "First",
			ActorId: "tester",
		})
		require.NoError(t, err)

		_, err = svc.RevokeIssuedApiKey(ctx, &talosv2alpha1.RevokeIssuedApiKeyRequest{
			KeyId: first.IssuedApiKey.KeyId,
		})
		require.NoError(t, err)

		// Cap counts only non-revoked keys; another issue should succeed.
		_, err = svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "After revoke",
			ActorId: "tester",
		})
		require.NoError(t, err)
	})

	t.Run("BatchImportAPIKeys trims to headroom and rejects rest", func(t *testing.T) {
		t.Parallel()
		svc, ctx := setupTestServiceWithConfig(t, map[string]any{
			config.KeyQuotaAPIKeysMax.String(): 3,
		})

		_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Preexisting",
			ActorId: "tester",
		})
		require.NoError(t, err)

		// Cap is 3 with 1 already issued, so headroom is 2. We submit 4 imports
		// and expect the first two to succeed and the last two to be rejected.
		batch := []*talosv2alpha1.ImportApiKeyRequest{
			{RawKey: "sk_live_batch_one", Name: "One", ActorId: "tester"},
			{RawKey: "sk_live_batch_two", Name: "Two", ActorId: "tester"},
			{RawKey: "sk_live_batch_three", Name: "Three", ActorId: "tester"},
			{RawKey: "sk_live_batch_four", Name: "Four", ActorId: "tester"},
		}
		resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{
			Requests: batch,
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 4)

		assert.NotNil(t, resp.Results[0].ImportedApiKey)
		assert.NotNil(t, resp.Results[1].ImportedApiKey)

		require.NotNil(t, resp.Results[2].ErrorCode)
		assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_RESOURCE_EXHAUSTED, *resp.Results[2].ErrorCode)

		require.NotNil(t, resp.Results[3].ErrorCode)
		assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_RESOURCE_EXHAUSTED, *resp.Results[3].ErrorCode)
	})
}
