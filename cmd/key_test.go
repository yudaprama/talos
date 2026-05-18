package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/x/cmdx"

	client "github.com/ory-corp/talos/internal/client/generated"
)

// UNIT TESTS - rawRow / rawTable

func TestRawRowHeaderColumnsMatch(t *testing.T) {
	t.Parallel()

	row := rawRow{
		raw:     "anything",
		header:  []string{"A", "B", "C"},
		columns: []string{"1", "2", "3"},
	}
	assert.Equal(t, []string{"A", "B", "C"}, row.Header())
	assert.Equal(t, []string{"1", "2", "3"}, row.Columns())
	assert.Equal(t, "anything", row.Interface())
}

func TestRawTableHeaderRowsMatch(t *testing.T) {
	t.Parallel()

	tbl := rawTable{
		raw:    "anything",
		header: []string{"A", "B"},
		rows:   [][]string{{"1", "2"}, {"3", "4"}},
	}
	assert.Equal(t, []string{"A", "B"}, tbl.Header())
	assert.Len(t, tbl.Table(), 2)
	assert.Equal(t, 2, tbl.Len())
	assert.Equal(t, "anything", tbl.Interface())
}

func TestApiKeyRow(t *testing.T) {
	t.Parallel()

	key := client.NewIssuedAPIKey()
	key.SetKeyId("key_abc123")
	key.SetName("production-api-key")
	key.SetActorId("user_xyz789")
	key.SetStatus(client.KEYSTATUS_KEY_STATUS_ACTIVE)
	key.SetScopes([]string{"read", "write", "admin"})

	row := apiKeyRow(key, key)

	assert.Equal(t, []string{"KEY ID", "NAME", "ACTOR ID", "STATUS", "SCOPES"}, row.Header())
	assert.Equal(t, []string{
		"key_abc123", "production-api-key", "user_xyz789",
		"KEY_STATUS_ACTIVE", "read, write, admin",
	}, row.Columns())
	assert.Same(t, key, row.Interface())
}

func TestSecretKeyRow(t *testing.T) {
	t.Parallel()

	resp := client.NewIssueAPIKeyResponse()
	apiKey := client.NewIssuedAPIKey()
	apiKey.SetKeyId("key_new")
	apiKey.SetName("new-key")
	apiKey.SetActorId("user_789")
	apiKey.SetStatus(client.KEYSTATUS_KEY_STATUS_ACTIVE)
	resp.SetIssuedApiKey(*apiKey)
	resp.SetSecret("sk_test_secret123")

	row := secretKeyRow(resp.GetIssuedApiKey(), resp.GetSecret(), resp)

	assert.Equal(t, []string{"KEY ID", "NAME", "ACTOR ID", "STATUS", "SCOPES", "SECRET"}, row.Header())
	assert.Equal(t, "sk_test_secret123", row.Columns()[5])
	assert.Same(t, resp, row.Interface())
}

func TestVerifyRow(t *testing.T) {
	t.Parallel()

	resp := client.NewVerifyAPIKeyResponse()
	resp.SetKeyId("key_valid123")
	resp.SetIsValid(true)
	resp.SetActorId("user_abc")
	resp.SetScopes([]string{"read", "write"})

	row := verifyRow(resp)

	assert.Equal(t, []string{"KEY ID", "IS VALID", "STATUS", "ACTOR ID", "SCOPES"}, row.Header())
	assert.Equal(t, "true", row.Columns()[1])
	assert.Same(t, resp, row.Interface())
}

func TestTokenRow(t *testing.T) {
	t.Parallel()

	resp := client.NewDeriveTokenResponse()
	token := client.NewToken()
	token.SetToken("eyJhbGciOiJIUzI1NiJ9.test.signature")
	resp.SetToken(*token)

	row := tokenRow(resp)

	assert.Equal(t, []string{"TOKEN", "EXPIRE TIME"}, row.Header())
	assert.Equal(t, "eyJhbGciOiJIUzI1NiJ9.test.signature", row.Columns()[0])
	assert.Same(t, resp, row.Interface())
}

func TestBatchVerifyTable(t *testing.T) {
	t.Parallel()

	r1 := client.NewVerifyAPIKeyResponse()
	r1.SetKeyId("key_1")
	r1.SetIsValid(true)
	r1.SetActorId("user_1")

	r2 := client.NewVerifyAPIKeyResponse()
	r2.SetKeyId("key_2")
	r2.SetIsValid(false)
	r2.SetErrorMessage("revoked")

	resp := client.NewBatchVerifyAPIKeysResponse()
	resp.SetResults([]client.VerifyAPIKeyResponse{*r1, *r2})

	tbl := batchVerifyTable(resp)

	assert.Equal(t, []string{"KEY ID", "IS VALID", "STATUS", "ACTOR ID", "SCOPES", "ERROR"}, tbl.Header())
	assert.Len(t, tbl.Table(), 2)
	assert.Equal(t, 2, tbl.Len())
	assert.Equal(t, "true", tbl.Table()[0][1])
	assert.Equal(t, "false", tbl.Table()[1][1])
	assert.Equal(t, "revoked", tbl.Table()[1][5])
}

// INTEGRATION TESTS - END-TO-END WITH TEST SERVER

func TestIssueAPIKeyCmd(t *testing.T) {
	// Not parallel: setupTestServer starts a real serve command in-process,
	// which registers metrics with prometheus.DefaultRegisterer. Parallel runs
	// of this test would panic with duplicate registration.

	tc := setupTestServer(t)

	t.Run("issue basic API key", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "issue", "test-key",
			"--actor", "user-123",
		)

		// Verify success message is in stderr
		assert.Contains(t, stderr, "API key issued.")
		// Verify data is in stdout
		assert.Contains(t, stdout, "test-key")

		resp, httpResp, err := tc.sdkClient().APIKeysAPI.
			AdminListIssuedAPIKeys(t.Context()).
			PageSize(10).
			Execute()
		if httpResp != nil {
			defer httpResp.Body.Close()
		}
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.GetIssuedApiKeys()), 1)

		found := false
		for _, k := range resp.GetIssuedApiKeys() {
			if k.GetName() == "test-key" {
				found = true
				break
			}
		}
		assert.True(t, found, "test-key should be in the list")
	})

	t.Run("issue API key with scopes", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "issue", "scoped-key",
			"--actor", "user-456",
			"--scopes", "read,write,admin",
		)

		assert.Contains(t, stderr, "API key issued.")
		assert.Contains(t, stdout, "read, write, admin")
	})

	t.Run("issue API key with TTL", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "issue", "ttl-key",
			"--actor", "user-789",
			"--ttl", "24h",
		)

		assert.Contains(t, stderr, "API key issued.")
		assert.Contains(t, stdout, "ttl-key")
	})

	t.Run("issue API key with metadata", func(t *testing.T) {
		metadata := `{"app":"test-app","env":"staging"}`
		stdout, stderr := tc.execNoErr(
			t, "keys", "issue", "metadata-key",
			"--actor", "user-metadata",
			"--metadata", metadata,
			"--format", "json",
		)

		assert.Contains(t, stderr, "API key issued.")
		assert.Contains(t, stdout, "user-metadata", "metadata should be in output: %s", stdout)
	})

	t.Run("issue API key with allowed CIDRs", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "issue", "cidr-key",
			"--actor", "user-cidr",
			"--allowed-cidrs", "10.0.0.0/8,192.168.0.0/16",
		)

		assert.Contains(t, stderr, "API key issued.")
		assert.Contains(t, stdout, "cidr-key")

		// Verify via SDK that IP restriction was set
		jsonOut, _ := tc.execNoErr(
			t, "keys", "issue", "cidr-key-json",
			"--actor", "user-cidr",
			"--allowed-cidrs", "127.0.0.1/32",
			"--format", "json",
		)
		var output client.IssueAPIKeyResponse
		require.NoError(t, json.Unmarshal([]byte(jsonOut), &output))
		apiKey := output.GetIssuedApiKey()
		require.NotEmpty(t, apiKey.GetKeyId())

		resp, httpResp, err := tc.sdkClient().APIKeysAPI.
			AdminGetIssuedAPIKey(t.Context(), apiKey.GetKeyId()).
			Execute()
		if httpResp != nil {
			defer httpResp.Body.Close()
		}
		require.NoError(t, err)
		ipRestriction, ok := resp.GetIpRestrictionOk()
		require.True(t, ok, "ip_restriction should be set")
		assert.Equal(t, []string{"127.0.0.1/32"}, ipRestriction.GetAllowedCidrs())
	})
}

func TestRevokeAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	keyID, _ := tc.createAPIKey(t, "test-key")

	stdout, stderr := tc.execNoErr(
		t, "keys", "revoke", keyID,
		"--reason", "key_compromise",
	)

	assert.Contains(t, stderr, "API key revoked.")
	assert.Contains(t, stdout, keyID)

	// Verify key was actually revoked
	tc.assertAPIKeyRevoked(t, keyID)

	// Double revoke returns conflict
	_, _, err := tc.exec(
		t, "keys", "revoke", keyID,
		"--reason", "key_compromise",
	)
	require.Error(t, err)
}

func TestDeriveTokenCmd(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	_, apiKeySecret := tc.createAPIKey(t, "test-key")

	t.Run("derive token with default TTL", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(t, "keys", "derive-token", apiKeySecret)

		assert.Contains(t, stderr, "Token derived.")
		// Should contain a JWT token (starts with eyJ) or Macaroon (starts with mc_v1_)
		assert.True(
			t,
			strings.Contains(stdout, "eyJ") || strings.Contains(stdout, "mc_v1_"),
			"output should contain a token",
		)
	})

	t.Run("derive token with custom TTL", func(t *testing.T) {
		_, stderr := tc.execNoErr(
			t, "keys", "derive-token", apiKeySecret,
			"--ttl", "2h",
		)

		assert.Contains(t, stderr, "Token derived.")
	})

	t.Run("derive token with macaroon algorithm", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "derive-token", apiKeySecret,
			"--algorithm", "macaroon",
			"--ttl", "1h",
		)

		assert.Contains(t, stderr, "Token derived.")
		assert.Contains(t, stdout, "mc_v1_")
	})

	t.Run("derive token with jwt algorithm", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "derive-token", apiKeySecret,
			"--algorithm", "jwt",
			"--ttl", "1h",
		)

		assert.Contains(t, stderr, "Token derived.")
		assert.Contains(t, stdout, "eyJ") // JWT tokens start with eyJ
	})
}

func TestVerifyAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	keyID, secret := tc.createAPIKey(t, "test-key")

	t.Run("verify valid API key", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(t, "keys", "verify", secret)

		assert.Contains(t, stderr, "API key is VALID")
		assert.Contains(t, stdout, keyID)
	})

	t.Run("verify valid API key with no-cache", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(t, "keys", "verify", secret, "--no-cache")

		assert.Contains(t, stderr, "API key is VALID")
		assert.Contains(t, stdout, keyID)
	})

	t.Run("verify nonexistent credential", func(t *testing.T) {
		stdout, stderr, err := tc.exec(
			t, "keys", "verify",
			"invalid_key_that_does_not_exist_1234567890",
		)

		// Unknown credentials are treated as imported keys; not found → is_valid=false
		require.True(t, errors.Is(err, cmdx.ErrNoPrintButFail),
			"should use FailSilently; err=%v stdout=%s stderr=%s", err, stdout, stderr)
		assert.Contains(t, stderr, "API key is INVALID")
	})
}

func TestVerifyAPIKeyCmd_RevokedKey(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	keyID, secret := tc.createAPIKey(t, "test-key")

	// Revoke the key
	tc.revokeAPIKey(t, keyID)

	// Try to verify revoked key
	stdout, stderr, err := tc.exec(t, "keys", "verify", secret)

	require.True(t, errors.Is(err, cmdx.ErrNoPrintButFail),
		"revoked key should use FailSilently; err=%v stdout=%s", err, stdout)
	assert.Contains(t, stderr, "API key is INVALID")
}

func TestAPIKeyLifecycle(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	// This integration test walks through the complete API key lifecycle
	tc := setupTestServer(t)

	// Step 1: Create API key via CLI
	keyID, apiKeySecret := tc.createAPIKey(t, "lifecycle-key")
	require.NotEmpty(t, apiKeySecret, "should have API key secret")
	t.Logf("Created API key: %s", keyID)

	// Step 2: Validate the key
	stdout, stderr, err := tc.exec(t, "keys", "verify", apiKeySecret)
	if err != nil {
		t.Logf("Validation failed: %v", err)
		t.Logf("Stdout: %s", stdout)
		t.Logf("Stderr: %s", stderr)
	}
	require.NoError(t, err, "validation should succeed for freshly created key")
	assert.Contains(t, stderr, "API key is VALID")

	// Step 3: Derive token from API key
	_, stderr = tc.execNoErr(
		t, "keys", "derive-token", apiKeySecret,
		"--ttl", "30m",
	)
	assert.Contains(t, stderr, "Token derived.")

	// Step 4: Revoke the key
	_, stderr = tc.execNoErr(
		t, "keys", "revoke", keyID,
		"--reason", "superseded",
	)
	assert.Contains(t, stderr, "API key revoked.")

	// Step 5: Verify the key is now invalid
	_, stderr, err = tc.exec(t, "keys", "verify", apiKeySecret)
	require.True(t, errors.Is(err, cmdx.ErrNoPrintButFail),
		"revoked key should use FailSilently: err=%v", err)
	assert.Contains(t, stderr, "API key is INVALID")
}

func TestListAPIKeysCmd(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	// Test that we can list API keys for a network
	tc := setupTestServer(t)

	// Create a few API keys via CLI
	tc.createAPIKey(t, "key-1")
	tc.createAPIKey(t, "key-2")
	tc.createAPIKey(t, "key-3")

	// List them via SDK (we don't have a list command yet, but we can verify the server persisted them)
	resp, httpResp, err := tc.sdkClient().APIKeysAPI.
		AdminListIssuedAPIKeys(t.Context()).
		PageSize(10).
		Execute()
	if httpResp != nil && httpResp.Body != nil {
		defer httpResp.Body.Close()
	}
	require.NoError(t, err)
	require.Len(t, resp.GetIssuedApiKeys(), 3)

	// Verify all keys are present
	names := make([]string, len(resp.GetIssuedApiKeys()))
	for i, key := range resp.GetIssuedApiKeys() {
		names[i] = key.GetName()
	}
	assert.ElementsMatch(t, []string{"key-1", "key-2", "key-3"}, names)
}

func TestAPIKeyOutputParsing(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	stdout, stderr := tc.execNoErr(
		t, "keys", "issue", "parse-test-key",
		"--actor", "user-parse",
		"--scopes", "read,write",
	)

	// Verify success message is in stderr
	assert.Contains(t, stderr, "API key issued.")
	assert.Contains(t, stderr, "IMPORTANT")
	assert.Contains(t, stderr, "will not be shown again")

	// Verify we can extract key information from stdout (table output)
	assert.Contains(t, stdout, "parse-test-key")
	assert.Contains(t, stdout, "user-parse")
	assert.Contains(t, stdout, "read, write")
}

func TestCommandErrorHandling(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("missing required actor flag", func(t *testing.T) {
		_, _, err := tc.exec(t, "keys", "issue", "test-key")
		require.Error(t, err)
		assert.ErrorContains(t, err, `required flag(s) "actor" not set`)
	})

	t.Run("invalid TTL format", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "issue", "test-key",
			"--actor", "user-123",
			"--ttl", "invalid-duration",
		)
		assert.Error(t, err)
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "issue", "test-key",
			"--actor", "user-123",
			"--algorithm", "invalid-algo",
		)
		assert.Error(t, err)
	})
}

func TestDeriveTokenJSON(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	// Test that derived tokens contain expected JWT fields
	tc := setupTestServer(t)

	_, apiKeySecret := tc.createAPIKey(t, "jwt-key")

	stdout, _ := tc.execNoErr(t, "keys", "derive-token", apiKeySecret)

	// Extract the token from table output (tab-separated)
	var token string
	for line := range strings.SplitSeq(stdout, "\n") {
		if strings.HasPrefix(line, "TOKEN\t") {
			for part := range strings.SplitSeq(line, "\t") {
				trimmed := strings.TrimSpace(part)
				if trimmed != "" && trimmed != "TOKEN" {
					token = trimmed
					break
				}
			}
			break
		}
	}

	require.NotEmpty(t, token, "should extract token from output")

	// If it's a JWT, we can parse the header (not verifying, just checking structure)
	if strings.HasPrefix(token, "eyJ") {
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3, "JWT should have 3 parts")
	}
}

func TestSelfRevokeAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("self-revoke with credential", func(t *testing.T) {
		keyID, secret := tc.createAPIKey(t, "self-revoke-key")

		_, stderr := tc.execNoErr(
			t, "keys", "self-revoke", secret,
			"--reason", "key_compromise",
		)

		assert.Contains(t, stderr, "API key self-revoked.")
		tc.assertAPIKeyRevoked(t, keyID)
	})

	t.Run("self-revoke invalid credential", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "self-revoke",
			"invalid-credential-that-does-not-exist",
			"--reason", "key_compromise",
		)
		require.Error(t, err)
	})
}

func TestBatchVerifyAPIKeysCmd(t *testing.T) {
	// Not parallel: see TestIssueAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	_, secret1 := tc.createAPIKey(t, "batch-key-1")
	_, secret2 := tc.createAPIKey(t, "batch-key-2")

	t.Run("batch verify valid keys", func(t *testing.T) {
		stdout, _ := tc.execNoErr(
			t, "keys", "batch-verify", secret1, secret2,
			"--format", "json",
		)

		var resp client.BatchVerifyAPIKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
		results := resp.GetResults()
		assert.Len(t, results, 2)
		assert.True(t, results[0].GetIsValid())
		assert.True(t, results[1].GetIsValid())
	})

	t.Run("batch verify with no-cache", func(t *testing.T) {
		stdout, _ := tc.execNoErr(
			t, "keys", "batch-verify", secret1, secret2,
			"--no-cache",
			"--format", "json",
		)

		var resp client.BatchVerifyAPIKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
		results := resp.GetResults()
		assert.Len(t, results, 2)
		assert.True(t, results[0].GetIsValid())
		assert.True(t, results[1].GetIsValid())
	})

	t.Run("batch verify with invalid key", func(t *testing.T) {
		stdout, _ := tc.execNoErr(
			t, "keys", "batch-verify",
			secret1, "invalid-credential-12345678901234",
			"--format", "json",
		)

		var resp client.BatchVerifyAPIKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
		results := resp.GetResults()
		assert.Len(t, results, 2)
		assert.True(t, results[0].GetIsValid())
		assert.False(t, results[1].GetIsValid())
	})
}

// reviewed - @aeneasr - 2026-03-25
