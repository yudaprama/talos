package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	client "github.com/ory-corp/talos/internal/client/generated"
)

const statusFilterActive = "KEY_STATUS_ACTIVE"

func (s *APIKeyE2ETestSuite) TestGetIssuedAPIKey() {
	ctx := s.T().Context()

	s.Run("get existing key", func() {
		apiKey, _ := s.testServer.CreateTestAPIKey(s.T(), "Get Test Key")

		getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())

		s.Equal(apiKey.GetKeyId(), getResp.GetKeyId())
		s.Equal("Get Test Key", getResp.GetName())
		s.Equal(client.KEYSTATUS_KEY_STATUS_ACTIVE, getResp.GetStatus())
	})

	s.Run("get non-existent key returns error", func() {
		httpResp, err := s.sdkGetIssuedAPIKeyExpectError(ctx, "non-existent-key-id-12345")
		s.requireHTTPError(err, httpResp, http.StatusNotFound)
	})

	s.Run("get revoked key returns metadata", func() {
		apiKey, _ := s.testServer.CreateTestAPIKey(s.T(), "To Be Revoked")
		s.testServer.RevokeTestAPIKey(s.T(), apiKey.GetKeyId())

		getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, getResp.GetStatus())
	})
}

func (s *APIKeyE2ETestSuite) TestRotateIssuedAPIKey() {
	ctx := s.T().Context()

	s.Run("rotate key", func() {
		apiKey, oldSecret := s.testServer.CreateTestAPIKey(s.T(), "Original Name")

		rotateResp := s.sdkRotateIssuedAPIKey(ctx, apiKey.GetKeyId(), nil, nil, nil)

		// Verify response has new key with new key_id
		s.NotEmpty(rotateResp.GetSecret())
		s.NotEqual(apiKey.GetKeyId(), rotateResp.IssuedApiKey.GetKeyId())
		s.Equal("Original Name", rotateResp.IssuedApiKey.GetName()) // Name inherited
		s.Equal(apiKey.GetKeyId(), rotateResp.OldIssuedApiKey.GetKeyId())
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, rotateResp.OldIssuedApiKey.GetStatus()) // Old key always revoked

		// Verify new key works
		newVerify := s.sdkVerify(ctx, rotateResp.GetSecret())
		s.True(newVerify.GetIsValid(), "New key should be active")

		// Verify old key is revoked
		oldVerify := s.sdkVerify(ctx, oldSecret)
		s.False(oldVerify.GetIsValid(), "Old key should be revoked")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, oldVerify.GetErrorCode())
	})

	s.Run("rotate with new name and scopes", func() {
		apiKey, oldSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Old Name", "test-user",
			[]string{"read:users", "write:users", "delete:users"}, nil, nil)

		// Rotate with new name and reduced scopes
		newName := "New Name"
		rotateResp := s.sdkRotateIssuedAPIKey(ctx, apiKey.GetKeyId(), &newName, []string{"read:users"}, nil)

		// Verify response has updated name and scopes
		s.Equal("New Name", rotateResp.IssuedApiKey.GetName())
		s.Equal([]string{"read:users"}, rotateResp.IssuedApiKey.Scopes)

		// Verify old secret is revoked
		oldVerify := s.sdkVerify(ctx, oldSecret)
		s.False(oldVerify.GetIsValid(), "Old key should be revoked")

		// Verify new secret works and has the updated scopes
		newVerify := s.sdkVerify(ctx, rotateResp.GetSecret())
		s.True(newVerify.GetIsValid(), "New key should be active")
		s.Equal([]string{"read:users"}, newVerify.Scopes, "New key should have reduced scopes")
		s.NotContains(newVerify.Scopes, "write:users", "Old scope should be removed")
		s.NotContains(newVerify.Scopes, "delete:users", "Old scope should be removed")
	})

	s.Run("rotate with new metadata", func() {
		apiKey, oldSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Metadata Test Key", "test-service", nil, nil,
			map[string]any{
				"version": "1.0",
				"env":     "staging",
			})

		// Rotate with new metadata
		rotateResp := s.sdkRotateIssuedAPIKey(ctx, apiKey.GetKeyId(), nil, nil,
			map[string]any{
				"version": "2.0",
				"env":     "production",
				"region":  "us-east-1",
			})

		// Verify response has updated metadata
		s.Equal("2.0", rotateResp.IssuedApiKey.Metadata["version"])
		s.Equal("production", rotateResp.IssuedApiKey.Metadata["env"])
		s.Equal("us-east-1", rotateResp.IssuedApiKey.Metadata["region"])

		// Verify old secret is revoked
		oldVerify := s.sdkVerify(ctx, oldSecret)
		s.False(oldVerify.GetIsValid(), "Old key should be revoked")

		// Verify new secret works and has the updated metadata
		newVerify := s.sdkVerify(ctx, rotateResp.GetSecret())
		s.True(newVerify.GetIsValid(), "New key should be active")
		s.Equal("2.0", newVerify.Metadata["version"], "New key should have updated metadata")
		s.Equal("production", newVerify.Metadata["env"])
		s.Equal("us-east-1", newVerify.Metadata["region"])
	})

	s.Run("rotate with multiple fields via HTTP", func() {
		apiKey, oldSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"HTTP POST Test Key", "http-rotate-test",
			[]string{"read:users", "write:users"}, nil,
			map[string]any{
				"version": "1.0",
				"env":     "staging",
			})

		// Rotate with multiple fields via HTTP SDK
		newName := "Rotated via HTTP"
		rotateResp := s.sdkRotateIssuedAPIKey(
			ctx,
			apiKey.GetKeyId(),
			&newName,
			[]string{"read:users"},
			map[string]any{
				"version": "2.0",
				"env":     "production",
			},
		)

		// Verify response has all fields updated
		s.Equal("Rotated via HTTP", rotateResp.IssuedApiKey.GetName())
		s.Equal([]string{"read:users"}, rotateResp.IssuedApiKey.Scopes)
		s.Equal("2.0", rotateResp.IssuedApiKey.Metadata["version"])
		s.Equal("production", rotateResp.IssuedApiKey.Metadata["env"])
		s.NotEqual(apiKey.GetKeyId(), rotateResp.IssuedApiKey.GetKeyId()) // New key_id

		// Verify old secret is revoked
		oldVerify := s.sdkVerify(ctx, oldSecret)
		s.False(oldVerify.GetIsValid(), "Old key should be revoked")

		// Verify new secret works and has the updated claims
		newVerify := s.sdkVerify(ctx, rotateResp.GetSecret())
		s.True(newVerify.GetIsValid(), "New key should be active")
		s.Equal([]string{"read:users"}, newVerify.Scopes, "New key should have updated scopes")
		s.Equal("2.0", newVerify.Metadata["version"])
		s.Equal("production", newVerify.Metadata["env"])
	})

	s.Run("rotate non-existent key returns error", func() {
		httpResp, err := s.sdkRotateIssuedAPIKeyExpectError(ctx, "non-existent-key-12345", client.AdminRotateIssuedAPIKeyBody{})
		s.requireHTTPError(err, httpResp, http.StatusNotFound)
	})
}

func (s *APIKeyE2ETestSuite) TestListIssuedAPIKeys() {
	ctx := s.T().Context()

	s.Run("list all keys", func() {
		for i := range 3 {
			s.testServer.CreateTestAPIKey(s.T(), fmt.Sprintf("List Test Key %d", i))
		}

		pageSize := int32(100)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, nil, nil)
		s.GreaterOrEqual(len(listResp.IssuedApiKeys), 3)
	})

	s.Run("list keys with pagination", func() {
		for i := range 5 {
			s.testServer.CreateTestAPIKey(s.T(), fmt.Sprintf("Page Test Key %d", i))
		}

		// Get first page
		pageSize := int32(2)
		firstPage := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, nil, nil)
		s.LessOrEqual(len(firstPage.IssuedApiKeys), 2)
		s.Require().NotEmpty(firstPage.GetNextPageToken(), "should have next page token")

		// Get the second page
		nextToken := firstPage.GetNextPageToken()
		secondPage := s.sdkListIssuedAPIKeys(ctx, &pageSize, &nextToken, nil, nil)
		s.NotEmpty(secondPage.IssuedApiKeys)

		// Keys should be different
		s.NotEqual(firstPage.IssuedApiKeys[0].GetKeyId(), secondPage.IssuedApiKeys[0].GetKeyId())
	})

	s.Run("list keys via HTTP", func() {
		s.testServer.CreateTestAPIKey(s.T(), "HTTP List Test")

		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, nil, nil)
		s.NotEmpty(listResp.IssuedApiKeys)
	})
}

func (s *APIKeyE2ETestSuite) TestListIssuedAPIKeysByOwnerFilter() {
	ctx := s.T().Context()

	s.Run("list keys by actor", func() {
		actorID := "owner-list-test-user-123"

		for i := range 3 {
			s.testServer.CreateTestAPIKeyWithOptions(s.T(),
				fmt.Sprintf("Owner Key %d", i), actorID,
				[]string{"read"}, nil, nil)
		}

		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)

		s.GreaterOrEqual(len(listResp.IssuedApiKeys), 3)
		for _, key := range listResp.IssuedApiKeys {
			s.Equal(actorID, key.GetActorId())
		}
	})

	s.Run("list keys by actor includes only active by default", func() {
		actorID := "owner-active-test-user-456"

		apiKey1, _ := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Active Key 1", actorID, nil, nil, nil)

		s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Active Key 2", actorID, nil, nil, nil)

		revokedKey, _ := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"To Be Revoked", actorID, nil, nil, nil)
		s.testServer.RevokeTestAPIKey(s.T(), revokedKey.GetKeyId())

		// List with status=active
		pageSize := int32(10)
		statusFilter := statusFilterActive
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, &statusFilter)

		s.GreaterOrEqual(len(listResp.IssuedApiKeys), 2)

		// Verify apiKey1 is in the list
		found := false
		for _, key := range listResp.IssuedApiKeys {
			if key.GetKeyId() == apiKey1.GetKeyId() {
				found = true
				s.Equal(client.KEYSTATUS_KEY_STATUS_ACTIVE, key.GetStatus())
			}
		}
		s.True(found, "Active key should be in the list")
	})

	s.Run("list keys by actor with all statuses", func() {
		actorID := "owner-all-status-test-user-789"

		activeKey, _ := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Active Key", actorID, nil, nil, nil)

		revokedKey, _ := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Revoked Key", actorID, nil, nil, nil)
		s.testServer.RevokeTestAPIKey(s.T(), revokedKey.GetKeyId())

		// List all statuses (no status filter = all statuses)
		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)

		s.GreaterOrEqual(len(listResp.IssuedApiKeys), 2)

		foundActive := false
		foundRevoked := false
		for _, key := range listResp.IssuedApiKeys {
			if key.GetKeyId() == activeKey.GetKeyId() {
				foundActive = true
				s.Equal(client.KEYSTATUS_KEY_STATUS_ACTIVE, key.GetStatus())
			}
			if key.GetKeyId() == revokedKey.GetKeyId() {
				foundRevoked = true
				s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, key.GetStatus())
			}
		}
		s.True(foundActive, "Active key should be in the list")
		s.True(foundRevoked, "Revoked key should be in the list when include_all_statuses=true")
	})

	s.Run("list keys by actor via HTTP", func() {
		actorID := "http-owner-test-user-999"

		s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"HTTP Owner Key", actorID, nil, nil, nil)

		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)

		s.NotEmpty(listResp.IssuedApiKeys)
		s.Equal(actorID, listResp.IssuedApiKeys[0].GetActorId())
	})

	s.Run("list keys for non-existent actor returns empty", func() {
		actorID := "non-existent-owner-12345"
		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)
		s.Empty(listResp.IssuedApiKeys)
	})

	s.Run("status filter without actor_id returns error", func() {
		pageSize := int32(10)
		statusFilter := statusFilterActive
		httpResp, err := s.sdkListIssuedAPIKeysExpectError(ctx, &pageSize, nil, nil, &statusFilter)
		s.requireHTTPErrorContains(err, httpResp, "status filter must be combined with actor_id")
	})

	s.Run("status filter with actor_id succeeds", func() {
		actorID := "status-filter-test-user"

		s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Status Filter Test", actorID, nil, nil, nil)

		pageSize := int32(10)
		statusFilter := statusFilterActive
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, &statusFilter)
		s.NotEmpty(listResp.IssuedApiKeys)
	})

	s.Run("pagination with actor_id filter works correctly", func() {
		actorID := "pagination-filter-test-" + time.Now().Format("20060102150405")

		for i := range 5 {
			s.testServer.CreateTestAPIKeyWithOptions(s.T(),
				fmt.Sprintf("Pagination Filter Key %d", i), actorID,
				nil, nil, nil)
		}

		// Get first page with actor_id filter
		pageSize := int32(2)
		firstPage := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)
		s.LessOrEqual(len(firstPage.IssuedApiKeys), 2)

		// All keys should belong to the filtered actor
		for _, key := range firstPage.IssuedApiKeys {
			s.Equal(actorID, key.GetActorId())
		}

		// Verify pagination continues to work
		s.Require().NotEmpty(firstPage.GetNextPageToken(), "should have next page token")
		nextToken := firstPage.GetNextPageToken()
		secondPage := s.sdkListIssuedAPIKeys(ctx, &pageSize, &nextToken, &actorID, nil)
		s.NotEmpty(secondPage.IssuedApiKeys)

		for _, key := range secondPage.IssuedApiKeys {
			s.Equal(actorID, key.GetActorId())
		}

		// Keys should be different between pages
		s.NotEqual(firstPage.IssuedApiKeys[0].GetKeyId(), secondPage.IssuedApiKeys[0].GetKeyId())
	})
}

func (s *APIKeyE2ETestSuite) TestKeyRotationWorkflow() {
	ctx := s.T().Context()

	s.Run("complete key rotation workflow", func() {
		actorID := "rotation-test-user"

		// Step 1: Create original key
		originalKey, originalSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"production-service-key", actorID,
			[]string{"api:read", "api:write"}, nil,
			map[string]any{"environment": "production"})

		// Verify original key works
		verifyResp := s.sdkVerify(ctx, originalSecret)
		s.True(verifyResp.GetIsValid())

		// Step 2: Create new key (rotation)
		newKey, newSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"production-service-key-rotated", actorID,
			[]string{"api:read", "api:write"}, nil,
			map[string]any{
				"environment":   "production",
				"rotated_from":  originalKey.GetKeyId(),
				"rotation_date": time.Now().Format(time.RFC3339),
			})

		// Verify new key works
		verifyNewResp := s.sdkVerify(ctx, newSecret)
		s.True(verifyNewResp.GetIsValid())

		// Step 3: Both keys work during coexistence period
		verifyOriginal := s.sdkVerify(ctx, originalSecret)
		s.True(verifyOriginal.GetIsValid(), "Original key should still work during coexistence")

		// Step 4: Revoke old key
		s.sdkRevokeAPIKeyWithReason(ctx, originalKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED)

		// Step 5: Verify old key fails (use cache bypass for immediate verification)
		verifyRevoked := s.sdkVerifyNoCache(ctx, originalSecret)
		s.False(verifyRevoked.GetIsValid(), "Original key should fail after revocation")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, verifyRevoked.GetErrorCode())

		// Step 6: Verify new key still works
		verifyNewFinal := s.sdkVerify(ctx, newSecret)
		s.True(verifyNewFinal.GetIsValid(), "New key should continue working")

		// Step 7: Verify rotation is traceable
		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)

		// Find the new key and verify rotation metadata
		var foundNewKey *client.IssuedAPIKey
		for i := range listResp.IssuedApiKeys {
			if listResp.IssuedApiKeys[i].GetKeyId() == newKey.GetKeyId() {
				foundNewKey = &listResp.IssuedApiKeys[i]
				break
			}
		}
		s.Require().NotNil(foundNewKey, "New key should be in the list")

		metadata := foundNewKey.GetMetadata()
		s.Equal(originalKey.GetKeyId(), metadata["rotated_from"], "Rotation metadata should link to original key")
	})

	s.Run("rotation with TTL expiration", func() {
		actorID := "rotation-ttl-test"

		// Create key with short TTL
		ttl := "1s"
		originalKey, originalSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"short-ttl-key", actorID, nil, &ttl, nil)

		// Create replacement key before expiration
		_, newSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"replacement-key", actorID, nil, nil,
			map[string]any{
				"replaces": originalKey.GetKeyId(),
			})

		// Poll until the original key expires.
		s.Eventually(func() bool {
			return !s.sdkVerify(ctx, originalSecret).GetIsValid()
		}, 5*time.Second, 50*time.Millisecond, "original key should be inactive after TTL expiration")

		// Verify new key still works
		verifyNew := s.sdkVerify(ctx, newSecret)
		s.True(verifyNew.GetIsValid(), "New key should work after original expires")
	})

	s.Run("zero-downtime manual rotation - issue second then revoke first", func() {
		actorID := "customer_zerodt_001"

		// Step 1: Original key in production
		origKey, origSecret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Production Key", actorID,
			[]string{"chat:read", "chat:write"}, nil, nil)

		// Step 2: Issue replacement key while original is still active
		newReq := client.NewIssueAPIKeyRequest()
		newReq.SetName("Production Key (rotated)")
		newReq.SetActorId(actorID)
		newReq.SetScopes([]string{"chat:read", "chat:write"})
		newReq.SetMetadata(map[string]any{"replaces": origKey.GetKeyId()})
		newResp := s.sdkIssueAPIKey(ctx, newReq)
		newSecret := newResp.GetSecret()

		// Step 3: Both keys work during coexistence
		s.True(s.sdkVerify(ctx, origSecret).GetIsValid(), "original should still work")
		s.True(s.sdkVerify(ctx, newSecret).GetIsValid(), "new key should work")

		// Step 4: Customer deploys new key, admin revokes old one
		s.sdkRevokeAPIKeyWithReason(ctx, origKey.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED)

		// Step 5: Old key fails, new key continues
		verifyOld := s.sdkVerifyNoCache(ctx, origSecret)
		s.False(verifyOld.GetIsValid())
		s.True(s.sdkVerify(ctx, newSecret).GetIsValid(), "new key still works")
	})
}

func (s *APIKeyE2ETestSuite) TestUpdateIssuedAPIKey() {
	ctx := s.T().Context()

	// Create key with initial "free" plan metadata
	createReq := client.NewIssueAPIKeyRequest()
	createReq.SetName("Upgradeable Key")
	createReq.SetActorId("customer_upgrade_001")
	createReq.SetScopes([]string{"chat:read"})
	createReq.SetMetadata(map[string]any{"plan": "free", "max_tokens": float64(1000)})
	createResp := s.sdkIssueAPIKey(ctx, createReq)
	keyID := createResp.IssuedApiKey.GetKeyId()

	s.Run("update metadata and scopes via PATCH", func() {
		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateIssuedAPIKeyRequest()
		body.SetScopes([]string{"chat:read", "chat:write", "models:list"})
		body.SetMetadata(map[string]any{"plan": "pro", "max_tokens": float64(4000)})

		updatedKey, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateIssuedAPIKey(ctx, keyID).
			AdminUpdateIssuedAPIKeyRequest(*body).
			Execute()
		s.closeBody(httpResp)

		s.Require().NoError(err)

		s.Equal([]string{"chat:read", "chat:write", "models:list"}, updatedKey.Scopes)
		s.Equal("pro", updatedKey.Metadata["plan"])
		s.InDelta(float64(4000), updatedKey.Metadata["max_tokens"], 0.001)
	})

	s.Run("GET confirms changes persisted", func() {
		getResp := s.sdkGetIssuedAPIKey(ctx, keyID)
		s.Equal([]string{"chat:read", "chat:write", "models:list"}, getResp.Scopes)
		s.Equal("pro", getResp.Metadata["plan"])
	})

	s.Run("name unchanged after scopes-only update", func() {
		s.Equal("Upgradeable Key", s.sdkGetIssuedAPIKey(ctx, keyID).GetName())
	})
}

func (s *APIKeyE2ETestSuite) TestPaginationExactBoundary() {
	ctx := s.T().Context()

	actorID := "pagination-boundary-" + time.Now().Format("20060102150405")
	const pageSize = 5

	// Create exactly pageSize + 1 keys
	for i := range pageSize + 1 {
		s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			fmt.Sprintf("Boundary Key %d", i), actorID, nil, nil, nil)
	}

	// First page: exactly pageSize results and a non-empty next_page_token
	ps := int32(pageSize)
	firstPage := s.sdkListIssuedAPIKeys(ctx, &ps, nil, &actorID, nil)
	s.Len(firstPage.IssuedApiKeys, pageSize, "first page should have exactly pageSize keys")
	s.NotEmpty(firstPage.GetNextPageToken(), "first page should have a next_page_token")

	// Second page: exactly 1 result and empty next_page_token
	nextToken := firstPage.GetNextPageToken()
	secondPage := s.sdkListIssuedAPIKeys(ctx, &ps, &nextToken, &actorID, nil)
	s.Len(secondPage.IssuedApiKeys, 1, "second page should have exactly 1 key")
	s.Empty(secondPage.GetNextPageToken(), "second page should have no next_page_token")
}

func (s *APIKeyE2ETestSuite) TestUpdateMask() {
	ctx := s.T().Context()

	s.Run("single field update", func() {
		createReq := client.NewIssueAPIKeyRequest()
		createReq.SetName("Original Name")
		createReq.SetActorId("update-mask-test")
		createReq.SetScopes([]string{"read", "write"})
		createReq.SetMetadata(map[string]any{"env": "staging"})
		createResp := s.sdkIssueAPIKey(ctx, createReq)
		keyID := createResp.IssuedApiKey.GetKeyId()

		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateIssuedAPIKeyRequest()
		body.SetName("Updated Name")

		updated, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateIssuedAPIKey(ctx, keyID).
			AdminUpdateIssuedAPIKeyRequest(*body).
			Execute()
		s.closeBody(httpResp)
		s.Require().NoError(err)

		s.Equal("Updated Name", updated.GetName())
		s.Equal([]string{"read", "write"}, updated.Scopes, "scopes should be preserved")
		s.Equal("staging", updated.Metadata["env"], "metadata should be preserved")
	})

	s.Run("multiple field update", func() {
		createReq := client.NewIssueAPIKeyRequest()
		createReq.SetName("Multi Field Key")
		createReq.SetActorId("multi-field-test")
		createReq.SetScopes([]string{"read"})
		createResp := s.sdkIssueAPIKey(ctx, createReq)
		keyID := createResp.IssuedApiKey.GetKeyId()

		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateIssuedAPIKeyRequest()
		body.SetName("Multi Updated")
		body.SetScopes([]string{"read", "write", "admin"})

		updated, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateIssuedAPIKey(ctx, keyID).
			AdminUpdateIssuedAPIKeyRequest(*body).
			Execute()
		s.closeBody(httpResp)
		s.Require().NoError(err)

		s.Equal("Multi Updated", updated.GetName())
		s.Equal([]string{"read", "write", "admin"}, updated.Scopes)
	})

	s.Run("fields not in mask are preserved", func() {
		createReq := client.NewIssueAPIKeyRequest()
		createReq.SetName("Preserve Fields Key")
		createReq.SetActorId("preserve-test")
		createReq.SetScopes([]string{"alpha", "beta"})
		createReq.SetMetadata(map[string]any{"tier": "gold"})
		createResp := s.sdkIssueAPIKey(ctx, createReq)
		keyID := createResp.IssuedApiKey.GetKeyId()

		apiClient := s.setupSDKClient()
		body := client.NewAdminUpdateIssuedAPIKeyRequest()
		body.SetName("Only Name Changed")

		updated, httpResp, err := apiClient.APIKeysAPI.
			AdminUpdateIssuedAPIKey(ctx, keyID).
			AdminUpdateIssuedAPIKeyRequest(*body).
			Execute()
		s.closeBody(httpResp)
		s.Require().NoError(err)

		s.Equal("Only Name Changed", updated.GetName())
		s.Equal([]string{"alpha", "beta"}, updated.Scopes, "scopes not in mask should be unchanged")
		s.Equal("gold", updated.Metadata["tier"], "metadata not in mask should be unchanged")
	})

	s.Run("unknown field in update_mask query returns error", func() {
		createReq := client.NewIssueAPIKeyRequest()
		createReq.SetName("Unknown Mask Key")
		createReq.SetActorId("unknown-mask-test")
		createResp := s.sdkIssueAPIKey(ctx, createReq)
		keyID := createResp.IssuedApiKey.GetKeyId()

		// AIP-134 update_mask is hidden from the SDK (auto-populated by the gateway from
		// JSON body fields). Send the bad mask via raw HTTP query to exercise the
		// server-side validation path.
		bodyJSON := `{"issued_api_key":{"key_id":"` + keyID + `","name":"Should Fail"}}`
		req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
			s.testServer.HTTPURL+"/v2alpha1/admin/issuedApiKeys/"+keyID+"?update_mask=nonexistent_field",
			strings.NewReader(bodyJSON))
		s.Require().NoError(err)
		req.Header.Set("Content-Type", contentTypeJSON)

		httpResp, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)
		s.T().Cleanup(func() { _ = httpResp.Body.Close() })
		s.Equal(http.StatusBadRequest, httpResp.StatusCode)
	})
}

// reviewed - @aeneasr - 2026-03-27
