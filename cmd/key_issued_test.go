package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/ory/talos/internal/client/generated"
)

func TestGetIssuedAPIKeyCmd(t *testing.T) {
	// Not parallel: setupTestServer starts a real serve command in-process,
	// which registers metrics with prometheus.DefaultRegisterer. Parallel runs
	// of this test would panic with duplicate registration.

	tc := setupTestServer(t)

	t.Run("get existing key", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "get-test-key")

		stdout, _ := tc.execNoErr(t, "keys", "issued", "get", keyID, "--format", "json")

		var output client.IssuedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse get output: %s", stdout)
		assert.Equal(t, keyID, output.GetKeyId())
		assert.Equal(t, "get-test-key", output.GetName())
		assert.Equal(t, "test-user", output.GetActorId())
		assert.NotEmpty(t, string(output.GetStatus()))
	})

	t.Run("get non-existent key", func(t *testing.T) {
		_, stderr, err := tc.exec(t, "keys", "issued", "get", "non-existent-key-id")
		require.Error(t, err)
		assert.Contains(t, stderr, "get issued API key")
	})
}

func TestListIssuedAPIKeysCmd(t *testing.T) {
	// Not parallel: see TestGetIssuedAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	// Create a few keys with different owners
	tc.createAPIKey(t, "list-key-1")
	tc.createAPIKey(t, "list-key-2")
	tc.createAPIKey(t, "list-key-3")

	t.Run("list all keys", func(t *testing.T) {
		stdout, _ := tc.execNoErr(t, "keys", "issued", "list", "--format", "json")

		var resp client.ListIssuedApiKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp),
			"parse list output: %s", stdout)
		assert.GreaterOrEqual(t, len(resp.GetIssuedApiKeys()), 3, "should have at least 3 keys")
	})

	t.Run("list with page size", func(t *testing.T) {
		stdout, _ := tc.execNoErr(t, "keys", "issued", "list",
			"--page-size", "2",
			"--format", "json")

		var resp client.ListIssuedApiKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp),
			"parse list output: %s", stdout)
		assert.LessOrEqual(t, len(resp.GetIssuedApiKeys()), 2, "should have at most 2 keys with page size 2")
	})

	t.Run("list with actor filter", func(t *testing.T) {
		stdout, _ := tc.execNoErr(t, "keys", "issued", "list",
			"--actor", "test-user",
			"--format", "json")

		var resp client.ListIssuedApiKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp),
			"parse list output: %s", stdout)
		for _, k := range resp.GetIssuedApiKeys() {
			assert.Equal(t, "test-user", k.GetActorId(), "all keys should belong to test-user")
		}
	})
}

// TODO  Add more test cases where multiple fields are changed at once: TestUpdateIssuedAPIKeyCmd. Same for TestRotateIssuedAPIKeyCmd. In TestRotateIssuedAPIKeyCmd also add assertions that untouched variables remain the same.
func TestUpdateIssuedAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestGetIssuedAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("update name", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "update-name-key")

		stdout, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--name", "updated-name",
			"--format", "json")

		assert.Contains(t, stderr, "API key updated.")

		var output client.IssuedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse update output: %s", stdout)
		assert.Equal(t, keyID, output.GetKeyId())
		assert.Equal(t, "updated-name", output.GetName())
	})

	t.Run("update scopes", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "update-scopes-key")

		stdout, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--scopes", "admin,deploy",
			"--format", "json")

		assert.Contains(t, stderr, "API key updated.")

		var output client.IssuedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse update output: %s", stdout)
		assert.Equal(t, keyID, output.GetKeyId())
		assert.ElementsMatch(t, []string{"admin", "deploy"}, output.GetScopes())
	})

	t.Run("update allowed CIDRs", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "update-cidrs-key")

		stdout, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--allowed-cidrs", "192.168.1.0/24,10.0.0.0/8",
			"--format", "json")

		assert.Contains(t, stderr, "API key updated.")

		var output client.IssuedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse update output: %s", stdout)
		assert.Equal(t, keyID, output.GetKeyId())

		// Verify via SDK that IP restriction was set
		resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
			AdminGetIssuedApiKey(t.Context(), keyID).
			Execute()
		if httpResp != nil {
			defer httpResp.Body.Close()
		}
		require.NoError(t, err)
		ipRestriction, ok := resp.GetIpRestrictionOk()
		require.True(t, ok, "ip_restriction should be set")
		assert.Equal(t, []string{"192.168.1.0/24", "10.0.0.0/8"}, ipRestriction.GetAllowedCidrs())
	})

	t.Run("update non-existent key", func(t *testing.T) {
		_, stderr, err := tc.exec(t, "keys", "issued", "update", "non-existent-key-id",
			"--name", "new-name")
		require.Error(t, err)
		assert.Contains(t, stderr, "update issued API key")
	})
}

func TestUpdateIssuedAPIKeyCmd_RateLimit(t *testing.T) {
	// Not parallel: see TestGetIssuedAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("sets quota and window", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "rl-set-key")

		_, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--rate-limit-quota", "100",
			"--rate-limit-window", "5m",
			"--format", "json")
		assert.Contains(t, stderr, "API key updated.")

		policy := tc.getIssuedRateLimitPolicy(t, keyID)
		require.NotNil(t, policy, "rate limit policy should be set")
		assert.Equal(t, "100", policy.GetQuota())
		assert.Equal(t, "300s", policy.GetWindow())
	})

	t.Run("window without quota is rejected", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "rl-window-only-key")

		_, stderr, err := tc.exec(t, "keys", "issued", "update", keyID,
			"--rate-limit-window", "5m")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires --rate-limit-quota")
		_ = stderr
	})

	t.Run("quota zero is rejected with guidance", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "rl-zero-key")

		_, _, err := tc.exec(t, "keys", "issued", "update", keyID,
			"--rate-limit-quota", "0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--update-mask rate_limit_policy")
	})

	t.Run("update mask clears the policy", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "rl-clear-key")

		// First set a policy.
		tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--rate-limit-quota", "100",
			"--rate-limit-window", "5m")
		require.NotNil(t, tc.getIssuedRateLimitPolicy(t, keyID))

		// Then clear it via the AIP-134 update mask.
		_, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--update-mask", "rate_limit_policy")
		assert.Contains(t, stderr, "API key updated.")

		assert.Nil(t, tc.getIssuedRateLimitPolicy(t, keyID), "policy should be cleared")
	})
}

func TestUpdateIssuedAPIKeyCmd_Metadata(t *testing.T) {
	// Not parallel: see TestGetIssuedAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("bare empty metadata is rejected", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "md-empty-key")

		_, _, err := tc.exec(t, "keys", "issued", "update", keyID,
			"--metadata", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "{}")
	})

	t.Run("empty object clears metadata", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "md-clear-key")

		_, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--metadata", "{}",
			"--format", "json")
		assert.Contains(t, stderr, "API key updated.")
	})
}

func TestRotateIssuedAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestGetIssuedAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("rotate key", func(t *testing.T) {
		oldKeyID, _ := tc.createAPIKey(t, "rotate-test-key")

		stdout, stderr := tc.execNoErr(t, "keys", "issued", "rotate", oldKeyID,
			"--format", "json")

		assert.Contains(t, stderr, "API key rotated.")
		assert.Contains(t, stderr, "IMPORTANT")

		var output client.RotateIssuedApiKeyResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse rotate output: %s", stdout)
		newKey := output.GetIssuedApiKey()
		assert.NotEqual(t, oldKeyID, newKey.GetKeyId(), "new key ID should differ from old key ID")
		assert.NotEmpty(t, output.GetSecret(), "rotated key should have a secret")

		// Old key should be revoked
		tc.assertAPIKeyRevoked(t, oldKeyID)
	})

	t.Run("rotate with new name", func(t *testing.T) {
		oldKeyID, _ := tc.createAPIKey(t, "rotate-rename-key")

		stdout, _ := tc.execNoErr(t, "keys", "issued", "rotate", oldKeyID,
			"--name", "rotated-new-name",
			"--format", "json")

		var output client.RotateIssuedApiKeyResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse rotate output: %s", stdout)
		newKey := output.GetIssuedApiKey()
		assert.Equal(t, "rotated-new-name", newKey.GetName())
		assert.NotEmpty(t, output.GetSecret())
	})

	t.Run("rotate non-existent key", func(t *testing.T) {
		_, stderr, err := tc.exec(t, "keys", "issued", "rotate", "non-existent-key-id")
		require.Error(t, err)
		assert.Contains(t, stderr, "rotate issued API key")
	})
}

func TestUpdateIssuedAPIKeyCmd_UpdateMask(t *testing.T) {
	// Not parallel: see TestGetIssuedAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("clears name when mask names it and body sends empty", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "to-be-cleared")

		// Send --name "" with --update-mask name; server should clear the name.
		stdout, stderr := tc.execNoErr(t, "keys", "issued", "update", keyID,
			"--name", "",
			"--update-mask", "name",
			"--format", "json")

		assert.Contains(t, stderr, "API key updated.")

		var output client.IssuedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse update output: %s", stdout)
		assert.Empty(t, output.GetName(), "name should be cleared")

		// Confirm via a fresh GET.
		resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
			AdminGetIssuedApiKey(t.Context(), keyID).
			Execute()
		if httpResp != nil {
			defer httpResp.Body.Close()
		}
		require.NoError(t, err)
		assert.Empty(t, resp.GetName(), "GET should report empty name after mask-driven clear")
	})

	t.Run("rejects unknown mask path", func(t *testing.T) {
		keyID, _ := tc.createAPIKey(t, "mask-validation")

		_, _, err := tc.exec(t, "keys", "issued", "update", keyID,
			"--name", "anything",
			"--update-mask", "bogus_field")
		require.Error(t, err)
	})
}

// reviewed - @aeneasr - 2026-03-25
