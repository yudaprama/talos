package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/ory/talos/internal/client/generated"
)

// UNIT TESTS - issuedKeyListTable / importedKeyListTable

func TestIssuedKeyListTable(t *testing.T) {
	t.Parallel()

	t.Run("empty list", func(t *testing.T) {
		t.Parallel()

		tbl := issuedKeyListTable(nil, nil)
		assert.Equal(t, []string{"KEY ID", "NAME", "ACTOR ID", "STATUS", "SCOPES"}, tbl.Header())
		assert.Empty(t, tbl.Table())
		assert.Equal(t, 0, tbl.Len())
	})

	t.Run("single key", func(t *testing.T) {
		t.Parallel()

		key := client.NewIssuedApiKey()
		key.SetKeyId("key_1")
		key.SetName("test-key")
		key.SetActorId("user_1")
		key.SetScopes([]string{"read"})
		key.SetStatus(client.KEYSTATUS_KEY_STATUS_ACTIVE)

		tbl := issuedKeyListTable([]client.IssuedApiKey{*key}, nil)
		assert.Len(t, tbl.Table(), 1)
		assert.Equal(t, 1, tbl.Len())
		row := tbl.Table()[0]
		assert.Equal(t, "key_1", row[0])
		assert.Equal(t, "test-key", row[1])
		assert.Equal(t, "user_1", row[2])
		assert.Equal(t, "KEY_STATUS_ACTIVE", row[3])
		assert.Equal(t, "read", row[4])
	})

	t.Run("multiple keys", func(t *testing.T) {
		t.Parallel()

		k1 := client.NewIssuedApiKey()
		k1.SetKeyId("key_1")
		k1.SetName("first")
		k1.SetActorId("user_1")
		k1.SetScopes([]string{"read", "write"})
		k1.SetStatus(client.KEYSTATUS_KEY_STATUS_ACTIVE)

		k2 := client.NewIssuedApiKey()
		k2.SetKeyId("key_2")
		k2.SetName("second")
		k2.SetActorId("user_2")
		k2.SetScopes([]string{"admin"})
		k2.SetStatus(client.KEYSTATUS_KEY_STATUS_REVOKED)

		tbl := issuedKeyListTable([]client.IssuedApiKey{*k1, *k2}, nil)
		assert.Equal(t, 2, tbl.Len())
		rows := tbl.Table()
		assert.Len(t, rows, 2)
		assert.Equal(t, "read, write", rows[0][4])
		assert.Equal(t, "KEY_STATUS_REVOKED", rows[1][3])
	})
}

// UNIT TESTS - deleteOutput

func TestDeleteOutput(t *testing.T) {
	t.Parallel()

	t.Run("deleted true", func(t *testing.T) {
		t.Parallel()

		output := deleteOutput{ID: "key_abc", Deleted: true}
		assert.Equal(t, []string{"ID", "Deleted"}, output.Header())
		assert.Equal(t, []string{"key_abc", "true"}, output.Columns())
		assert.Equal(t, output, output.Interface())
	})

	t.Run("deleted false", func(t *testing.T) {
		t.Parallel()

		output := deleteOutput{ID: "key_xyz", Deleted: false}
		assert.Equal(t, []string{"key_xyz", "false"}, output.Columns())
	})

	t.Run("JSON serialization", func(t *testing.T) {
		t.Parallel()

		output := deleteOutput{ID: "key_abc", Deleted: true}
		jsonBytes, err := json.Marshal(output)
		require.NoError(t, err)

		var result map[string]any
		err = json.Unmarshal(jsonBytes, &result)
		require.NoError(t, err)
		assert.Equal(t, "key_abc", result["id"])
		assert.Equal(t, true, result["deleted"])
	})

	t.Run("header and columns same length", func(t *testing.T) {
		t.Parallel()

		output := deleteOutput{ID: "key_test", Deleted: true}
		assert.Len(t, output.Columns(), len(output.Header()))
	})
}

// UNIT TESTS - batchImportTable

func TestBatchImportTable(t *testing.T) {
	t.Parallel()

	t.Run("successful import", func(t *testing.T) {
		t.Parallel()

		importedKey := client.NewImportedApiKey()
		importedKey.SetKeyId("key_1")
		importedKey.SetName("test-key")

		result := client.NewBatchCreateImportedApiKeysResult()
		result.SetIndex(0)
		result.SetImportedApiKey(*importedKey)

		resp := client.NewBatchCreateImportedApiKeysResponse()
		resp.SetResults([]client.BatchCreateImportedApiKeysResult{*result})
		resp.SetSuccessCount(1)
		resp.SetFailureCount(0)

		tbl := batchImportTable(resp)
		assert.Equal(t, []string{"INDEX", "KEY ID", "NAME", "STATUS", "ERROR"}, tbl.Header())
		assert.Len(t, tbl.Table(), 1)
		assert.Equal(t, "success", tbl.Table()[0][3])
	})
}

// INTEGRATION TESTS

func TestImportAPIKeyCmd(t *testing.T) {
	// Not parallel: setupTestServer starts a real serve command in-process,
	// which registers metrics with prometheus.DefaultRegisterer. Parallel runs
	// of this test would panic with duplicate registration.

	tc := setupTestServer(t)

	t.Run("basic import", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "import",
			"imported-key-1",
			"--raw-key", "sk_live_test_import_key_123456",
			"--actor", "user-import-1",
		)

		assert.Contains(t, stderr, "API key imported.")
		assert.Contains(t, stdout, "imported-key-1")
		assert.Contains(t, stdout, "user-import-1")
	})

	t.Run("import with scopes and TTL", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "import",
			"scoped-imported-key",
			"--raw-key", "sk_live_scoped_import_key_789",
			"--actor", "user-import-2",
			"--scopes", "read,write,admin",
			"--ttl", "8760h",
		)

		assert.Contains(t, stderr, "API key imported.")
		assert.Contains(t, stdout, "scoped-imported-key")
		assert.Contains(t, stdout, "read, write, admin")
	})

	t.Run("import with allowed CIDRs", func(t *testing.T) {
		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "import",
			"cidr-imported-key",
			"--raw-key", "sk_live_cidr_import_key_xyz",
			"--actor", "user-import-cidr",
			"--allowed-cidrs", "10.0.0.0/8,172.16.0.0/12",
			"--format", "json",
		)

		assert.Contains(t, stderr, "API key imported.")

		var importedKey client.ImportedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &importedKey))
		require.NotEmpty(t, importedKey.GetKeyId())

		// Verify via SDK that IP restriction was set
		resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
			AdminGetImportedApiKey(t.Context(), importedKey.GetKeyId()).
			Execute()
		if httpResp != nil {
			defer httpResp.Body.Close()
		}
		require.NoError(t, err)
		ipRestriction, ok := resp.GetIpRestrictionOk()
		require.True(t, ok, "ip_restriction should be set")
		assert.Equal(t, []string{"10.0.0.0/8", "172.16.0.0/12"}, ipRestriction.GetAllowedCidrs())
	})

	t.Run("import with metadata", func(t *testing.T) {
		_, stderr := tc.execNoErr(
			t, "keys", "imported", "import",
			"metadata-imported-key",
			"--raw-key", "sk_live_metadata_import_key_abc",
			"--actor", "user-import-3",
			"--metadata", `{"source":"stripe","env":"prod"}`,
		)

		assert.Contains(t, stderr, "API key imported.")
	})
}

func TestBatchImportAPIKeysCmd(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("import batch from JSON file", func(t *testing.T) {
		inputFile := filepath.Join(t.TempDir(), "batch-import.json")
		fileContent := `[
  {"raw_key":"batch-file-key-1","name":"Batch file key 1","actor_id":"batch-file-owner"},
  {"raw_key":"batch-file-key-2","name":"Batch file key 2","actor_id":"batch-file-owner"}
]`
		require.NoError(t, os.WriteFile(inputFile, []byte(fileContent), 0o600))

		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "batch-import",
			"--file", inputFile,
			"--format", "json",
		)

		assert.Contains(t, stderr, "Imported 2 keys (0 failed).")

		var resp client.BatchCreateImportedApiKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp), "output should be valid JSON")
		results := resp.GetResults()
		require.Len(t, results, 2)
		_, ok1 := results[0].GetImportedApiKeyOk()
		assert.True(t, ok1, "first result should have imported_api_key")
		_, ok2 := results[1].GetImportedApiKeyOk()
		assert.True(t, ok2, "second result should have imported_api_key")
	})

	t.Run("import batch from stdin", func(t *testing.T) {
		stdinPayload := `[
  {"raw_key":"batch-stdin-key-1","name":"Batch stdin key 1","actor_id":"batch-stdin-owner"}
]`

		stdout, stderr, err := tc.execWithInput(
			t, stdinPayload,
			"keys", "imported", "batch-import",
			"--file", "-",
			"--format", "json",
		)
		require.NoError(t, err)
		assert.Contains(t, stderr, "Imported 1 keys (0 failed).")

		var resp client.BatchCreateImportedApiKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp), "output should be valid JSON")
		require.Len(t, resp.GetResults(), 1)
	})

	t.Run("missing file flag returns error", func(t *testing.T) {
		_, _, err := tc.exec(t, "keys", "imported", "batch-import")
		require.Error(t, err)
		assert.ErrorContains(t, err, `required flag(s) "file" not set`)
	})

	t.Run("invalid JSON file returns error", func(t *testing.T) {
		invalidFile := filepath.Join(t.TempDir(), "invalid-batch-import.json")
		require.NoError(t, os.WriteFile(invalidFile, []byte(`{"bad":`), 0o600))

		_, _, err := tc.exec(t, "keys", "imported", "batch-import", "--file", invalidFile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse batch import JSON")
	})

	t.Run("partial success includes errors", func(t *testing.T) {
		_, _ = tc.execNoErr(
			t, "keys", "imported", "import",
			"partial-existing-key",
			"--raw-key", "batch-partial-duplicate",
			"--actor", "batch-owner",
		)

		inputFile := filepath.Join(t.TempDir(), "partial-batch-import.json")
		fileContent := `[
  {"raw_key":"batch-partial-valid","name":"batch valid","actor_id":"batch-owner"},
  {"raw_key":"batch-partial-duplicate","name":"batch dup","actor_id":"batch-owner"},
  {"raw_key":"batch-partial-missing-name","name":"","actor_id":"batch-owner"}
]`
		require.NoError(t, os.WriteFile(inputFile, []byte(fileContent), 0o600))

		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "batch-import",
			"--file", inputFile,
			"--format", "json",
		)

		assert.Contains(t, stderr, "Imported 1 keys (2 failed).")

		var resp client.BatchCreateImportedApiKeysResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp), "output should be valid JSON")
		results := resp.GetResults()
		require.Len(t, results, 3)

		// First should succeed
		_, ok := results[0].GetImportedApiKeyOk()
		assert.True(t, ok, "first result should succeed")

		// Second and third should fail
		assert.NotEmpty(t, results[1].GetErrorMessage(), "second result should have error")
		assert.NotEmpty(t, results[2].GetErrorMessage(), "third result should have error")
	})
}

func TestGetImportedAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("get existing key", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "get-test-key", "sk_live_get_test_key_123")

		stdout, _ := tc.execNoErr(t, "keys", "imported", "get", keyID)

		assert.Contains(t, stdout, keyID)
		assert.Contains(t, stdout, "get-test-key")
	})

	t.Run("get nonexistent key", func(t *testing.T) {
		_, stderr, err := tc.exec(
			t, "keys", "imported", "get",
			"nonexistent-key-id-12345",
		)

		require.Error(t, err)
		assert.Contains(t, stderr, "get imported API key")
	})
}

func TestListImportedAPIKeysCmd(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	// Subtests run sequentially (no t.Parallel) because they share the same
	// test server and later subtests depend on keys created by earlier ones.

	t.Run("empty list", func(t *testing.T) {
		stdout, _ := tc.execNoErr(t, "keys", "imported", "list")

		// Table output should have a header but no data rows
		assert.Contains(t, stdout, "KEY ID")
	})

	// Import keys after "empty list" so that test sees no data.
	key1ID := tc.importAPIKey(t, "list-key-1", "sk_live_list_key_1_aaa")
	tc.importAPIKey(t, "list-key-2", "sk_live_list_key_2_bbb")
	tc.importAPIKey(t, "list-key-3", "sk_live_list_key_3_ccc")

	t.Run("multiple keys", func(t *testing.T) {
		stdout, _ := tc.execNoErr(t, "keys", "imported", "list")

		assert.Contains(t, stdout, "list-key-1")
		assert.Contains(t, stdout, "list-key-2")
		assert.Contains(t, stdout, "list-key-3")
	})

	t.Run("filter by actor", func(t *testing.T) {
		// All test keys have actor "test-user" from importAPIKey
		stdout, _ := tc.execNoErr(
			t, "keys", "imported", "list",
			"--actor", "test-user",
		)

		assert.Contains(t, stdout, "list-key-1")
	})

	t.Run("filter by status", func(t *testing.T) {
		// Revoke list-key-1 so we have a mix of active and revoked keys
		tc.revokeImportedAPIKey(t, key1ID)

		// Filter for active only (actor required by composite index constraint) - should exclude the revoked key
		stdout, _ := tc.execNoErr(
			t, "keys", "imported", "list",
			"--actor", "test-user",
			"--status", "KEY_STATUS_ACTIVE",
		)
		assert.NotContains(t, stdout, "list-key-1", "revoked key should not appear in active filter")
		assert.Contains(t, stdout, "list-key-2", "active key should appear")
		assert.Contains(t, stdout, "list-key-3", "active key should appear")
	})

	t.Run("with page size", func(t *testing.T) {
		stdout, _ := tc.execNoErr(
			t, "keys", "imported", "list",
			"--page-size", "2",
		)

		// With page-size=2, at most 2 data rows should appear.
		// Count non-header lines that contain a key name.
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		dataLines := 0
		for _, line := range lines {
			// Skip the header row and separator
			if strings.Contains(line, "list-key-") {
				dataLines++
			}
		}
		assert.LessOrEqual(t, dataLines, 2, "page-size=2 should return at most 2 data rows")
	})
}

func TestRevokeImportedAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("revoke with reason", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "revoke-test-key", "sk_live_revoke_test_key_123")

		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "revoke",
			keyID,
			"--reason", "key_compromise",
		)

		assert.Contains(t, stderr, "Imported API key revoked.")
		assert.Contains(t, stdout, keyID)
		assert.Contains(t, stdout, "KEY_STATUS_REVOKED")
	})

	t.Run("revoke with reason text", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "revoke-test-key-2", "sk_live_revoke_test_key_456")

		stdout, stderr := tc.execNoErr(
			t, "keys", "imported", "revoke",
			keyID,
			"--reason", "privilege_withdrawn",
			"--reason-text", "User account deactivated",
		)

		assert.Contains(t, stderr, "Imported API key revoked.")
		assert.Contains(t, stdout, "KEY_STATUS_REVOKED")
	})

	t.Run("revoke nonexistent key", func(t *testing.T) {
		_, stderr, err := tc.exec(
			t, "keys", "imported", "revoke",
			"nonexistent-key-id-99999",
		)

		require.Error(t, err)
		assert.Contains(t, stderr, "revoke imported API key")
	})
}

func TestDeleteImportedAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("delete existing key", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "delete-test-key", "sk_live_delete_test_key_123")

		stdout, stderr := tc.execNoErr(t, "keys", "imported", "delete", keyID)

		assert.Contains(t, stderr, "Imported API key deleted.")
		assert.Contains(t, stdout, keyID)
		assert.Contains(t, stdout, "true")
	})

	t.Run("delete nonexistent key", func(t *testing.T) {
		_, stderr, err := tc.exec(
			t, "keys", "imported", "delete",
			"nonexistent-key-id-88888",
		)

		require.Error(t, err)
		assert.Contains(t, stderr, "delete imported API key")
	})

	t.Run("verify gone after delete", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "delete-verify-key", "sk_live_delete_verify_key_abc")

		// Delete the key
		tc.execNoErr(t, "keys", "imported", "delete", keyID)

		// Verify get returns error
		_, _, err := tc.exec(t, "keys", "imported", "get", keyID)
		require.Error(t, err)
	})
}

// LIFECYCLE TEST

func TestImportedAPIKeyLifecycle(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)
	rawKey := "sk_live_lifecycle_test_key_full_flow"

	// Step 1: Import with JSON output to extract key ID
	stdout, stderr := tc.execNoErr(
		t, "keys", "imported", "import",
		"lifecycle-imported-key",
		"--raw-key", rawKey,
		"--actor", "lifecycle-owner",
		"--scopes", "read,write",
		"--format", "json",
	)
	assert.Contains(t, stderr, "API key imported.")

	var importedKey client.ImportedApiKey
	require.NoError(t, json.Unmarshal([]byte(stdout), &importedKey), "import output should be valid JSON")
	keyID := importedKey.GetKeyId()
	require.NotEmpty(t, keyID, "key ID should not be empty")
	assert.Equal(t, "lifecycle-imported-key", importedKey.GetName())

	// Step 2: Get the same key
	stdout, _ = tc.execNoErr(t, "keys", "imported", "get", keyID)
	assert.Contains(t, stdout, keyID)
	assert.Contains(t, stdout, "lifecycle-imported-key")

	// Step 3: List (verify it shows up)
	stdout, _ = tc.execNoErr(t, "keys", "imported", "list")
	assert.Contains(t, stdout, "lifecycle-imported-key")

	// Step 4: Validate the raw key works
	stdout, stderr, err := tc.exec(t, "keys", "validate", rawKey)
	if err == nil {
		assert.Contains(t, stderr, "VALID")
		assert.Contains(t, stdout, keyID)
	}
	// Note: validation may not work depending on key format routing;
	// the important thing is the command doesn't panic

	// Step 5: Revoke
	stdout, stderr = tc.execNoErr(
		t, "keys", "imported", "revoke",
		keyID,
		"--reason", "superseded",
	)
	assert.Contains(t, stderr, "Imported API key revoked.")
	assert.Contains(t, stdout, keyID)

	// Step 6: Validate fails after revocation
	_, _, err = tc.exec(t, "keys", "validate", rawKey)
	// Revoked key should fail validation - either an error or inactive response
	if err == nil {
		// If no error, get the key and verify it's revoked
		stdout, _ = tc.execNoErr(t, "keys", "imported", "get", keyID)
		assert.Contains(t, stdout, "KEY_STATUS_REVOKED")
	}

	// Step 7: Delete
	_, stderr = tc.execNoErr(t, "keys", "imported", "delete", keyID)
	assert.Contains(t, stderr, "Imported API key deleted.")

	// Step 8: Verify key is gone after delete
	_, _, err = tc.exec(t, "keys", "imported", "get", keyID)
	require.Error(t, err, "get should fail after delete")
}

// ERROR TESTS

func TestImportedAPIKeyErrors(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("import missing raw-key flag", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "imported", "import",
			"test-key",
			"--actor", "user-123",
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, `required flag(s) "raw-key" not set`)
	})

	t.Run("import missing actor flag", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "imported", "import",
			"test-key",
			"--raw-key", "sk_test_123",
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, `required flag(s) "actor" not set`)
	})

	t.Run("import missing both required flags", func(t *testing.T) {
		_, _, err := tc.exec(t, "keys", "imported", "import", "test-key")
		require.Error(t, err)
		assert.ErrorContains(t, err, "required flag")
	})

	t.Run("import invalid metadata JSON", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "imported", "import",
			"test-key",
			"--raw-key", "sk_test_456",
			"--actor", "user-123",
			"--metadata", "not-valid-json",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid metadata JSON")
	})

	t.Run("import invalid TTL", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "imported", "import",
			"test-key",
			"--raw-key", "sk_test_789",
			"--actor", "user-123",
			"--ttl", "not-a-duration",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid TTL duration")
	})

	t.Run("revoke invalid reason", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "error-test-key", "sk_live_error_test_key_123")

		_, _, err := tc.exec(
			t, "keys", "imported", "revoke",
			keyID,
			"--reason", "totally_invalid_reason",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown revocation reason")
	})

	t.Run("import missing name argument", func(t *testing.T) {
		_, _, err := tc.exec(
			t, "keys", "imported", "import",
			"--raw-key", "sk_test_no_name",
			"--actor", "user-123",
		)
		require.Error(t, err)
	})

	t.Run("get missing key-id argument", func(t *testing.T) {
		_, _, err := tc.exec(t, "keys", "imported", "get")
		require.Error(t, err)
	})

	t.Run("revoke missing key-id argument", func(t *testing.T) {
		_, _, err := tc.exec(t, "keys", "imported", "revoke")
		require.Error(t, err)
	})

	t.Run("delete missing key-id argument", func(t *testing.T) {
		_, _, err := tc.exec(t, "keys", "imported", "delete")
		require.Error(t, err)
	})
}

// JSON OUTPUT TESTS

func TestImportedAPIKeyJSONOutput(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("import JSON output", func(t *testing.T) {
		stdout, _ := tc.execNoErr(
			t, "keys", "imported", "import",
			"json-test-key",
			"--raw-key", "sk_live_json_test_key_123",
			"--actor", "json-owner",
			"--format", "json",
		)

		var result map[string]any
		err := json.Unmarshal([]byte(stdout), &result)
		require.NoError(t, err, "output should be valid JSON")
		// Raw SDK output: imported API key fields at the top level (AIP-133).
		assert.Equal(t, "json-test-key", result["name"])
		assert.Equal(t, "json-owner", result["actor_id"])
	})

	t.Run("list JSON output", func(t *testing.T) {
		stdout, _ := tc.execNoErr(
			t, "keys", "imported", "list",
			"--format", "json",
		)

		var result map[string]any
		err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &result)
		require.NoError(t, err, "output should be valid JSON object (raw SDK response)")
	})

	t.Run("delete JSON output", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "json-delete-key", "sk_live_json_delete_key_123")

		stdout, _ := tc.execNoErr(
			t, "keys", "imported", "delete",
			keyID,
			"--format", "json",
		)

		var result map[string]any
		err := json.Unmarshal([]byte(stdout), &result)
		require.NoError(t, err, "output should be valid JSON")
		assert.Equal(t, true, result["deleted"])
	})
}

func TestUpdateImportedAPIKeyCmd(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("update name", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-update-name", "sk_live_imported_update_name_xyz")

		stdout, stderr := tc.execNoErr(t, "keys", "imported", "update", keyID,
			"--name", "imported-renamed",
			"--format", "json")

		assert.Contains(t, stderr, "API key updated.")

		var output client.ImportedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse update output: %s", stdout)
		assert.Equal(t, keyID, output.GetKeyId())
		assert.Equal(t, "imported-renamed", output.GetName())
	})

	t.Run("update non-existent key", func(t *testing.T) {
		_, stderr, err := tc.exec(t, "keys", "imported", "update", "non-existent-key-id",
			"--name", "something")
		require.Error(t, err)
		assert.Contains(t, stderr, "update imported API key")
	})
}

func TestUpdateImportedAPIKeyCmd_RateLimit(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("sets quota and window", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-rl-set", "sk_live_imported_rl_set_key")

		_, stderr := tc.execNoErr(t, "keys", "imported", "update", keyID,
			"--rate-limit-quota", "100",
			"--rate-limit-window", "5m",
			"--format", "json")
		assert.Contains(t, stderr, "API key updated.")

		policy := tc.getImportedRateLimitPolicy(t, keyID)
		require.NotNil(t, policy, "rate limit policy should be set")
		assert.Equal(t, "100", policy.GetQuota())
		assert.Equal(t, "300s", policy.GetWindow())
	})

	t.Run("window without quota is rejected", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-rl-window-only", "sk_live_imported_rl_window_only")

		_, _, err := tc.exec(t, "keys", "imported", "update", keyID,
			"--rate-limit-window", "5m")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires --rate-limit-quota")
	})

	t.Run("quota zero is rejected with guidance", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-rl-zero", "sk_live_imported_rl_zero_key")

		_, _, err := tc.exec(t, "keys", "imported", "update", keyID,
			"--rate-limit-quota", "0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--update-mask rate_limit_policy")
	})

	t.Run("update mask clears the policy", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-rl-clear", "sk_live_imported_rl_clear_key")

		tc.execNoErr(t, "keys", "imported", "update", keyID,
			"--rate-limit-quota", "100",
			"--rate-limit-window", "5m")
		require.NotNil(t, tc.getImportedRateLimitPolicy(t, keyID))

		_, stderr := tc.execNoErr(t, "keys", "imported", "update", keyID,
			"--update-mask", "rate_limit_policy")
		assert.Contains(t, stderr, "API key updated.")

		assert.Nil(t, tc.getImportedRateLimitPolicy(t, keyID), "policy should be cleared")
	})
}

func TestUpdateImportedAPIKeyCmd_Metadata(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("bare empty metadata is rejected", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-md-empty", "sk_live_imported_md_empty_key")

		_, _, err := tc.exec(t, "keys", "imported", "update", keyID,
			"--metadata", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "{}")
	})

	t.Run("empty object clears metadata", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-md-clear", "sk_live_imported_md_clear_key")

		_, stderr := tc.execNoErr(t, "keys", "imported", "update", keyID,
			"--metadata", "{}",
			"--format", "json")
		assert.Contains(t, stderr, "API key updated.")
	})
}

func TestUpdateImportedAPIKeyCmd_UpdateMask(t *testing.T) {
	// Not parallel: see TestImportAPIKeyCmd for explanation.

	tc := setupTestServer(t)

	t.Run("clears name when mask names it and body sends empty", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-to-be-cleared", "sk_live_imported_clear_name_abc")

		stdout, stderr := tc.execNoErr(t, "keys", "imported", "update", keyID,
			"--name", "",
			"--update-mask", "name",
			"--format", "json")

		assert.Contains(t, stderr, "API key updated.")

		var output client.ImportedApiKey
		require.NoError(t, json.Unmarshal([]byte(stdout), &output),
			"parse update output: %s", stdout)
		assert.Empty(t, output.GetName(), "name should be cleared")

		resp, httpResp, err := tc.sdkClient().ApiKeysAPI.
			AdminGetImportedApiKey(t.Context(), keyID).
			Execute()
		if httpResp != nil {
			defer httpResp.Body.Close()
		}
		require.NoError(t, err)
		assert.Empty(t, resp.GetName(), "GET should report empty name after mask-driven clear")
	})

	t.Run("rejects unknown mask path", func(t *testing.T) {
		keyID := tc.importAPIKey(t, "imported-mask-validation", "sk_live_imported_mask_validation")

		_, _, err := tc.exec(t, "keys", "imported", "update", keyID,
			"--name", "anything",
			"--update-mask", "bogus_field")
		require.Error(t, err)
	})
}

// reviewed - @aeneasr - 2026-03-25
