package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	client "github.com/ory-corp/talos/internal/client/generated"
)

func (s *APIKeyE2ETestSuite) TestImportAPIKey() {
	ctx := s.T().Context()

	s.Run("import external key", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("sk_live_51O9abc123xyz456def789ghi012jkl345mno678pqr901stu234vwx567yza890")
		req.SetName("Legacy Stripe Production Key")
		req.SetActorId("payment-service")
		req.SetTtl(fmt.Sprintf("%ds", int((365 * 24 * time.Hour).Seconds())))
		req.SetMetadata(map[string]any{
			"source":      "stripe",
			"environment": "production",
			"imported_at": time.Now().Format(time.RFC3339),
		})
		importResp := s.sdkImportAPIKey(ctx, req)

		s.NotEmpty(importResp.GetKeyId())
		s.Equal("Legacy Stripe Production Key", importResp.GetName())
		s.Equal("payment-service", importResp.GetActorId())
		s.Equal(client.KEYSTATUS_KEY_STATUS_ACTIVE, importResp.GetStatus())

		// Verify metadata was preserved
		importedMeta := importResp.GetMetadata()
		s.Equal("stripe", importedMeta["source"])
		s.Equal("production", importedMeta["environment"])
	})

	s.Run("import GitHub PAT", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD")
		req.SetName("GitHub PAT for CI/CD")
		req.SetActorId("ci-cd-pipeline")
		req.SetMetadata(map[string]any{
			"source": "github",
			"scope":  "repo,workflow",
		})
		importResp := s.sdkImportAPIKey(ctx, req)

		s.NotEmpty(importResp.GetKeyId())
		s.Equal("GitHub PAT for CI/CD", importResp.GetName())
	})

	s.Run("import key with missing required fields returns error", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("test_key_missing_fields")
		// Missing name and actor_id
		httpResp, err := s.sdkImportAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("verify imported key works", func() {
		rawKey := "test_verify_imported_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Verify Test Imported Key")
		req.SetActorId("verify-test-user")
		importResp := s.sdkImportAPIKey(ctx, req)

		// Verify the imported key works using the ORIGINAL raw key
		verifyResp := s.sdkVerify(ctx, rawKey)
		s.True(verifyResp.GetIsValid())
		s.Equal(importResp.GetKeyId(), verifyResp.GetKeyId())
		s.Equal("verify-test-user", verifyResp.GetActorId())
	})

	s.Run("import key with scopes", func() {
		rawKey := "test_scopes_imported_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Imported Key with Scopes")
		req.SetActorId("scoped-service")
		req.SetScopes([]string{"payments:read", "payments:write", "refunds:write"})
		req.SetMetadata(map[string]any{
			"source": "legacy-payment-system",
		})
		importResp := s.sdkImportAPIKey(ctx, req)

		// Verify scopes were stored correctly
		s.Equal([]string{"payments:read", "payments:write", "refunds:write"}, importResp.Scopes)

		// Get the imported key and verify scopes are retrieved
		getResp := s.sdkGetImportedAPIKey(ctx, importResp.GetKeyId())
		s.Equal([]string{"payments:read", "payments:write", "refunds:write"}, getResp.Scopes)

		// Verify the key works and scopes are returned in verification
		verifyResp := s.sdkVerify(ctx, rawKey)
		s.True(verifyResp.GetIsValid())
		s.Equal([]string{"payments:read", "payments:write", "refunds:write"}, verifyResp.Scopes)
	})

	s.Run("import key without scopes defaults to empty", func() {
		rawKey := "test_no_scopes_imported_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Imported Key without Scopes")
		req.SetActorId("no-scopes-user")
		importResp := s.sdkImportAPIKey(ctx, req)

		// Verify scopes are empty
		s.Empty(importResp.Scopes)

		// Get the imported key and verify empty scopes
		getResp := s.sdkGetImportedAPIKey(ctx, importResp.GetKeyId())
		s.Empty(getResp.Scopes)
	})
}

func (s *APIKeyE2ETestSuite) TestGetImportedAPIKey() {
	ctx := s.T().Context()

	s.Run("get imported key", func() {
		rawKey := "test_get_imported_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Get Test Imported Key")
		req.SetActorId("test-service")
		importResp := s.sdkImportAPIKey(ctx, req)
		keyID := importResp.GetKeyId()

		getResp := s.sdkGetImportedAPIKey(ctx, keyID)

		s.Equal(keyID, getResp.GetKeyId())
		s.Equal("Get Test Imported Key", getResp.GetName())
		s.Equal("test-service", getResp.GetActorId())
	})

	s.Run("get non-existent imported key returns error", func() {
		httpResp, err := s.sdkGetImportedAPIKeyExpectError(ctx, "non-existent-imported-key-12345")
		s.requireHTTPError(err, httpResp, http.StatusNotFound)
	})
}

func (s *APIKeyE2ETestSuite) TestListImportedAPIKeys() {
	ctx := s.T().Context()

	s.Run("list imported keys", func() {
		actorID := "list-imported-test-" + time.Now().Format("20060102150405")

		for i := range 3 {
			req := client.NewImportAPIKeyRequest()
			req.SetRawKey(fmt.Sprintf("test_list_%s_%d", actorID, i))
			req.SetName(fmt.Sprintf("Imported Key %d", i))
			req.SetActorId(actorID)
			s.sdkImportAPIKey(ctx, req)
		}

		pageSize := int32(10)
		listResp := s.sdkListImportedAPIKeys(ctx, &pageSize, nil, &actorID)

		s.GreaterOrEqual(len(listResp.ImportedApiKeys), 3)
		for _, key := range listResp.ImportedApiKeys {
			s.Equal(actorID, key.GetActorId())
		}
	})

	s.Run("list imported keys with status filter", func() {
		actorID := "list-status-imported-" + time.Now().Format("20060102150405")

		// Import and revoke a key
		importReq := client.NewImportAPIKeyRequest()
		importReq.SetRawKey(fmt.Sprintf("test_revoke_%s", actorID))
		importReq.SetName("To Be Revoked Imported")
		importReq.SetActorId(actorID)
		importResp := s.sdkImportAPIKey(ctx, importReq)

		// Revoke it
		s.sdkRevokeAPIKeyWithReason(ctx, importResp.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Import an active key
		activeReq := client.NewImportAPIKeyRequest()
		activeReq.SetRawKey(fmt.Sprintf("test_active_%s", actorID))
		activeReq.SetName("Active Imported Key")
		activeReq.SetActorId(actorID)
		s.sdkImportAPIKey(ctx, activeReq)

		// List only active keys
		pageSize := int32(10)
		activeList := s.sdkListImportedAPIKeys(ctx, &pageSize, nil, &actorID, "KEY_STATUS_ACTIVE")

		// Verify all returned keys are active
		for _, key := range activeList.ImportedApiKeys {
			s.Equal(client.KEYSTATUS_KEY_STATUS_ACTIVE, key.GetStatus())
		}
	})

	// TODO missing pagination tests
}

func (s *APIKeyE2ETestSuite) TestRevokeImportedAPIKey() {
	ctx := s.T().Context()

	s.Run("revoke imported key", func() {
		rawKey := "test_revoke_imported_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Revoke Test Imported Key")
		req.SetActorId("revoke-test-user")
		importResp := s.sdkImportAPIKey(ctx, req)
		keyID := importResp.GetKeyId()

		// Verify key works before revocation
		verifyBefore := s.sdkVerify(ctx, rawKey)
		s.True(verifyBefore.GetIsValid())

		// Revoke the key
		s.sdkRevokeAPIKeyWithReason(ctx, keyID,
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)
		revokedKey := s.sdkGetImportedAPIKey(ctx, keyID)
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, revokedKey.GetStatus())

		// Verify key no longer works (use cache bypass for immediate verification)
		verifyAfter := s.sdkVerifyNoCache(ctx, rawKey)
		s.False(verifyAfter.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, verifyAfter.GetErrorCode())
	})

	s.Run("revoke non-existent imported key returns error", func() {
		_, err := s.sdkRevokeImportedAPIKeyExpectError(ctx, "non-existent-imported-12345")
		s.Require().Error(err)
	})

	s.Run("double revocation returns conflict", func() {
		rawKey := "test_double_revoke_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Double Revoke Test")
		req.SetActorId("double-revoke-user")
		importResp := s.sdkImportAPIKey(ctx, req)

		// First revocation succeeds
		s.sdkRevokeAPIKeyWithReason(ctx, importResp.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Second revocation returns conflict
		httpResp, err := s.sdkRevokeImportedAPIKeyExpectError(ctx, importResp.GetKeyId())
		s.requireHTTPError(err, httpResp, http.StatusConflict)
	})
}

func (s *APIKeyE2ETestSuite) TestDeleteImportedAPIKey() {
	ctx := s.T().Context()

	s.Run("delete imported key", func() {
		rawKey := "test_delete_imported_" + time.Now().Format("20060102150405")

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Delete Test Imported Key")
		req.SetActorId("delete-test-user")
		importResp := s.sdkImportAPIKey(ctx, req)
		keyID := importResp.GetKeyId()

		// Delete the key
		s.sdkDeleteImportedAPIKey(ctx, keyID)

		// Verify key is deleted (get should fail)
		httpResp, err := s.sdkGetImportedAPIKeyExpectError(ctx, keyID)
		s.requireHTTPError(err, httpResp, http.StatusNotFound)

		// Verify key no longer works
		verifyResp := s.sdkVerify(ctx, rawKey)
		s.False(verifyResp.GetIsValid())
	})

	s.Run("delete non-existent imported key returns error", func() {
		httpResp, err := s.sdkDeleteImportedAPIKeyExpectError(ctx, "non-existent-delete-12345")
		s.requireHTTPError(err, httpResp, http.StatusNotFound)
	})
}

func (s *APIKeyE2ETestSuite) TestMigrationCoexistence() {
	ctx := s.T().Context()

	s.Run("imported and issued keys coexist for same owner", func() {
		actorID := "migration-coexist-" + time.Now().Format("20060102150405")
		rawKey := fmt.Sprintf("test_migration_%s", actorID)

		// Phase 1: Import legacy key
		importReq := client.NewImportAPIKeyRequest()
		importReq.SetRawKey(rawKey)
		importReq.SetName("Legacy Imported Key")
		importReq.SetActorId(actorID)
		importReq.SetMetadata(map[string]any{
			"migration_phase": "1",
			"source":          "legacy-system",
		})
		importResp := s.sdkImportAPIKey(ctx, importReq)

		// Phase 2: Create issued replacement key
		createReq := client.NewIssueAPIKeyRequest()
		createReq.SetName("Issued Replacement Key")
		createReq.SetActorId(actorID)
		createReq.SetScopes([]string{"payments:read", "payments:write"})
		createReq.SetMetadata(map[string]any{
			"migration_phase":       "2",
			"replaces_imported_key": importResp.GetKeyId(),
		})
		issuedResp := s.sdkIssueAPIKey(ctx, createReq)

		// Phase 3: Both keys work simultaneously
		verifyImported := s.sdkVerify(ctx, rawKey)
		s.True(verifyImported.GetIsValid(), "Imported key should work")

		verifyIssued := s.sdkVerify(ctx, issuedResp.GetSecret())
		s.True(verifyIssued.GetIsValid(), "Issued key should work")

		// Phase 4: List both keys for owner (using separate endpoints)
		pageSize := int32(10)
		issuedListResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)
		s.GreaterOrEqual(len(issuedListResp.IssuedApiKeys), 1, "Should have at least the issued key")

		importedListResp := s.sdkListImportedAPIKeys(ctx, &pageSize, nil, &actorID)
		s.GreaterOrEqual(len(importedListResp.ImportedApiKeys), 1, "Should have at least the imported key")

		// Phase 5: Complete migration by revoking imported key
		s.sdkRevokeAPIKeyWithReason(ctx, importResp.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED)

		// Phase 6: Verify imported key no longer works (use cache bypass for immediate verification)
		verifyImportedAfter := s.sdkVerifyNoCache(ctx, rawKey)
		s.False(verifyImportedAfter.GetIsValid())

		// Phase 7: Issued key still works
		verifyIssuedFinal := s.sdkVerify(ctx, issuedResp.GetSecret())
		s.True(verifyIssuedFinal.GetIsValid())
	})
}

func (s *APIKeyE2ETestSuite) TestImport_RateLimitPolicy() {
	ctx := s.T().Context()

	s.Run("import key with rate limit policy", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("test_import_rl_key_" + time.Now().Format("20060102150405.000"))
		req.SetName("Rate Limited Import")
		req.SetActorId("user-rl-import-1")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("500")
		rlPolicy.SetWindow("60s")
		req.SetRateLimitPolicy(*rlPolicy)

		resp := s.sdkImportAPIKey(ctx, req)
		s.True(resp.HasRateLimitPolicy())
		s.Equal("500", resp.RateLimitPolicy.GetQuota())
		s.Equal("60s", resp.RateLimitPolicy.GetWindow())
	})

	s.Run("import key without rate limit policy", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("test_import_no_rl_key_" + time.Now().Format("20060102150405.000"))
		req.SetName("No Rate Limit Import")
		req.SetActorId("user-no-rl-import-1")

		resp := s.sdkImportAPIKey(ctx, req)
		s.False(resp.HasRateLimitPolicy())
	})

	s.Run("get imported key returns rate limit policy", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("test_import_rl_get_key_" + time.Now().Format("20060102150405.000"))
		req.SetName("Rate Limited Import for Get")
		req.SetActorId("user-rl-import-get-1")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("500")
		rlPolicy.SetWindow("60s")
		req.SetRateLimitPolicy(*rlPolicy)

		importResp := s.sdkImportAPIKey(ctx, req)

		getResp := s.sdkGetImportedAPIKey(ctx, importResp.GetKeyId())
		s.True(getResp.HasRateLimitPolicy())
		s.Equal("500", getResp.RateLimitPolicy.GetQuota())
		s.Equal("60s", getResp.RateLimitPolicy.GetWindow())
	})

	s.Run("error - import with invalid rate limit quota", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("test_import_invalid_quota_" + time.Now().Format("20060102150405.000"))
		req.SetName("Invalid Quota Import")
		req.SetActorId("user-invalid-quota-1")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("-1")
		rlPolicy.SetWindow("60s")
		req.SetRateLimitPolicy(*rlPolicy)

		httpResp, err := s.sdkImportAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("error - import with invalid rate limit window", func() {
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("test_import_invalid_window_" + time.Now().Format("20060102150405.000"))
		req.SetName("Invalid Window Import")
		req.SetActorId("user-invalid-window-1")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("100")
		rlPolicy.SetWindow("0s")
		req.SetRateLimitPolicy(*rlPolicy)

		httpResp, err := s.sdkImportAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})
}

func (s *APIKeyE2ETestSuite) TestUpdateImportedAPIKey() {
	ctx := s.T().Context()

	// Import a key to update
	req := client.NewImportAPIKeyRequest()
	req.SetRawKey("update_imported_e2e_key_" + time.Now().Format("20060102150405.000"))
	req.SetName("Original Import Name")
	req.SetActorId("update-test-owner")
	req.SetScopes([]string{"read"})
	req.SetTtl(fmt.Sprintf("%ds", int((24 * time.Hour).Seconds())))
	imported := s.sdkImportAPIKey(ctx, req)
	keyID := imported.GetKeyId()

	s.Run("PATCH name via update_mask", func() {
		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateImportedAPIKeyRequest()
		body.SetName("Updated Import Name")

		updated, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateImportedAPIKey(ctx, keyID).
			AdminUpdateImportedAPIKeyRequest(*body).
			Execute()
		s.closeBody(httpResp)

		s.Require().NoError(err)
		s.Equal("Updated Import Name", updated.GetName())
		// scopes not in body — preserved (gateway auto-populates update_mask from body fields).
		s.Equal([]string{"read"}, updated.GetScopes())
	})

	s.Run("GET confirms name change persisted", func() {
		got := s.sdkGetImportedAPIKey(ctx, keyID)
		s.Equal("Updated Import Name", got.GetName())
	})

	s.Run("PATCH scopes and metadata", func() {
		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateImportedAPIKeyRequest()
		body.SetScopes([]string{"read", "write"})
		body.SetMetadata(map[string]any{"env": "production"})

		updated, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateImportedAPIKey(ctx, keyID).
			AdminUpdateImportedAPIKeyRequest(*body).
			Execute()
		s.closeBody(httpResp)

		s.Require().NoError(err)
		s.Equal([]string{"read", "write"}, updated.GetScopes())
		s.Equal("production", updated.GetMetadata()["env"])
	})

	s.Run("404 for non-existent hash", func() {
		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateImportedAPIKeyRequest()
		body.SetName("ghost key")

		_, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateImportedAPIKey(ctx, "nonexistenthash00000000000000000").
			AdminUpdateImportedAPIKeyRequest(*body).
			Execute()

		s.requireHTTPError(err, httpResp, http.StatusNotFound)
	})

	// TODO test more complex update masks here, and also for issued api keys.
}

func (s *APIKeyE2ETestSuite) TestRevokeImportedAPIKeyViaUnifiedEndpoint() {
	ctx := s.T().Context()

	// Import a key
	req := client.NewImportAPIKeyRequest()
	req.SetRawKey("revoke_unified_e2e_key_" + time.Now().Format("20060102150405.000"))
	req.SetName("Unified Revoke Test Key")
	req.SetActorId("unified-revoke-owner")
	req.SetTtl(fmt.Sprintf("%ds", int((24 * time.Hour).Seconds())))
	imported := s.sdkImportAPIKey(ctx, req)
	keyID := imported.GetKeyId()

	s.Run("revoke via unified endpoint returns 204", func() {
		s.sdkRevokeAPIKeyWithReason(ctx, keyID, client.REVOCATIONREASON_REVOCATION_REASON_UNSPECIFIED)
	})

	s.Run("get after revoke shows revoked status", func() {
		got := s.sdkGetImportedAPIKey(ctx, keyID)
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, got.GetStatus())
	})

	s.Run("re-revocation returns conflict", func() {
		httpResp, err := s.sdkRevokeImportedAPIKeyExpectError(ctx, keyID)
		s.requireHTTPError(err, httpResp, http.StatusConflict)
	})

	s.Run("404 for non-existent hash - not 500", func() {
		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.
			AdminRevokeAPIKey(ctx, "nonexistenthash00000000000000000").
			AdminRevokeAPIKeyBody(client.AdminRevokeAPIKeyBody{}).
			Execute()
		s.requireHTTPError(err, httpResp, http.StatusNotFound)
	})
}

// importKeyForDerive is a helper that imports a key with scopes and a 24h TTL, suitable for derive-token tests.
func (s *APIKeyE2ETestSuite) importKeyForDerive(ctx context.Context, rawKey, name, actorID string, scopes []string) *client.ImportedAPIKey {
	s.T().Helper()
	importReq := client.NewImportAPIKeyRequest()
	importReq.SetRawKey(rawKey)
	importReq.SetName(name)
	importReq.SetActorId(actorID)
	importReq.SetScopes(scopes)
	importReq.SetTtl(fmt.Sprintf("%ds", int((24 * time.Hour).Seconds())))
	return s.sdkImportAPIKey(ctx, importReq)
}

// deriveJWT is a helper that derives a JWT token from a credential with an optional scope restriction.
func (s *APIKeyE2ETestSuite) deriveJWT(ctx context.Context, credential string, scopes []string) *client.DeriveTokenResponse {
	s.T().Helper()
	deriveReq := client.NewDeriveTokenRequest()
	deriveReq.SetCredential(credential)
	deriveReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
	deriveReq.SetTtl("3600s")
	if scopes != nil {
		deriveReq.SetScopes(scopes)
	}
	return s.sdkDeriveToken(ctx, deriveReq)
}

func (s *APIKeyE2ETestSuite) TestDeriveTokenFromImportedKey() {
	ctx := s.T().Context()

	s.Run("derive JWT from imported key and verify", func() {
		rawKey := "derive_jwt_imported_" + time.Now().Format("20060102150405.000")

		importResp := s.importKeyForDerive(ctx, rawKey, "JWT Derive Import Test", "derive-jwt-user",
			[]string{"read:data", "write:data"})

		deriveResp := s.deriveJWT(ctx, rawKey, nil)

		derivedToken := deriveResp.Token.GetToken()
		s.True(strings.HasPrefix(derivedToken, "eyJ"), "derived token should be a JWT")

		// Verify the derived JWT via the self-service
		verifyResp := s.sdkVerify(ctx, derivedToken)
		s.True(verifyResp.GetIsValid())
		s.Equal(importResp.GetKeyId(), verifyResp.GetKeyId())
	})

	s.Run("derive JWT with restricted scopes from imported key", func() {
		rawKey := "derive_scoped_imported_" + time.Now().Format("20060102150405.000")

		s.importKeyForDerive(ctx, rawKey, "Scoped Derive Import Test", "derive-scoped-user",
			[]string{"read:data", "write:data", "admin"})

		deriveResp := s.deriveJWT(ctx, rawKey, []string{"read:data"})

		// Verify scopes in the derive response are restricted
		s.Equal([]string{"read:data"}, deriveResp.Token.Scopes)

		// Verify the derived JWT is valid
		verifyResp := s.sdkVerify(ctx, deriveResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())
	})

	s.Run("derive JWT from imported key then revoke - stateless capability model", func() {
		rawKey := "derive_revoke_imported_" + time.Now().Format("20060102150405.000")

		importResp := s.importKeyForDerive(ctx, rawKey, "Revoke Cascade Import Test", "derive-revoke-user",
			[]string{"read:data"})

		// Derive a JWT while the imported key is active
		deriveResp := s.deriveJWT(ctx, rawKey, nil)
		derivedToken := deriveResp.Token.GetToken()

		// Verify derived token works before revocation
		verifyBefore := s.sdkVerify(ctx, derivedToken)
		s.True(verifyBefore.GetIsValid())

		// Revoke the imported parent key
		s.sdkRevokeAPIKeyWithReason(ctx, importResp.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Derived token remains valid (stateless capability model)
		// Parent key revocation does not cascade to derived tokens for scalability
		verifyAfter := s.sdkVerify(ctx, derivedToken)
		s.True(verifyAfter.GetIsValid(), "derived token should remain valid after parent revocation (stateless)")

		// Attempting to derive NEW tokens from revoked parent should still fail (derivation-time check)
		newDeriveReq := client.NewDeriveTokenRequest()
		newDeriveReq.SetCredential(rawKey)
		newDeriveReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		newDeriveReq.SetTtl("3600s")
		err := s.sdkDeriveTokenExpectError(ctx, newDeriveReq)
		s.Error(err, "deriving new token from revoked parent should fail")
	})

	s.Run("derive Macaroon from imported key and verify", func() {
		rawKey := "derive_macaroon_imported_" + time.Now().Format("20060102150405.000")

		importResp := s.importKeyForDerive(ctx, rawKey, "Macaroon Derive Import Test", "derive-macaroon-user",
			[]string{"read:data"})

		// Derive a Macaroon from the imported key
		deriveReq := client.NewDeriveTokenRequest()
		deriveReq.SetCredential(rawKey)
		deriveReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		deriveReq.SetTtl("3600s")
		deriveResp := s.sdkDeriveToken(ctx, deriveReq)

		derivedToken := deriveResp.Token.GetToken()
		s.True(strings.HasPrefix(derivedToken, "mc_v1_"), "derived token should be a Macaroon")

		// Verify the derived Macaroon
		verifyResp := s.sdkVerify(ctx, derivedToken)
		s.True(verifyResp.GetIsValid())
		s.Equal(importResp.GetKeyId(), verifyResp.GetKeyId())
	})
}

// reviewed - @aeneasr - 2026-03-27
