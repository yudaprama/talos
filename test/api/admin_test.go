package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	client "github.com/ory/talos/internal/client/generated"
)

// Sentinel errors for concurrent operation tests
var (
	errKeyShouldBeActive        = fmt.Errorf("key should be active after creation")
	errDerivedTokenEmpty        = fmt.Errorf("derived token should not be empty")
	errKeyStatusShouldBeRevoked = fmt.Errorf("key status should be revoked")
	errVerifyShouldShowInactive = fmt.Errorf("verify should show key as inactive after revocation")
)

func (s *APIKeyE2ETestSuite) TestAdmin_APIKeyCreation() {
	ctx := s.T().Context()

	s.Run("create with all fields", func() {
		metadata := map[string]any{
			"app": "test-app",
			"env": "staging",
		}

		req := client.NewIssueApiKeyRequest()
		req.SetName("Test API Key 1")
		req.SetActorId("user-123")
		req.SetScopes([]string{"read:users", "write:users"})
		req.SetTtl("86400s") // 24 hours
		req.SetMetadata(metadata)
		resp := s.sdkIssueAPIKey(ctx, req)

		s.NotEmpty(resp.IssuedApiKey.GetKeyId())
		secret := resp.GetSecret()
		s.NotEmpty(secret)
		s.True(strings.HasPrefix(secret, "talos_v1_"), "secret should have talos_v1_ prefix format")
		s.Equal("Test API Key 1", resp.IssuedApiKey.GetName())
		s.Equal("user-123", resp.IssuedApiKey.GetActorId())
		s.Equal([]string{"read:users", "write:users"}, resp.IssuedApiKey.Scopes)
		s.Equal(client.KEYSTATUS_KEY_STATUS_ACTIVE, resp.IssuedApiKey.GetStatus())
	})

	s.Run("create with minimal fields", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Minimal Key")
		req.SetActorId("service-456")
		resp := s.sdkIssueAPIKey(ctx, req)

		s.NotEmpty(resp.GetSecret())
		s.NotNil(resp.IssuedApiKey.ExpireTime) // Default TTL applied
	})
	s.Run("error - missing required fields", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Missing Owner")
		httpResp, err := s.sdkIssueAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_APIKeyRevocation() {
	ctx := s.T().Context()

	apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Key to Revoke")

	s.Run("revoke key", func() {
		s.sdkRevokeIssuedAPIKeyWithReason(ctx, apiKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)
		getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, getResp.GetStatus())
	})

	s.Run("revoked key fails verification", func() {
		verifyResp := s.sdkVerify(ctx, secret)
		s.False(verifyResp.GetIsValid())
		s.Contains(verifyResp.GetErrorMessage(), "revoked")
	})

	s.Run("double revocation returns conflict", func() {
		httpResp, err := s.sdkRevokeIssuedAPIKeyExpectError(ctx, apiKey.GetKeyId(), client.AdminRevokeIssuedApiKeyBody{
			Reason: client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE.Ptr(),
		})
		defer func() { _ = httpResp.Body.Close() }()
		s.requireHTTPError(err, httpResp, http.StatusConflict)
	})

	s.Run("cache bypass confirms immediate revocation", func() {
		key2, secret2 := s.testServer.CreateTestAPIKey(s.T(), "Immediate Revoke Key")

		// Verify it works first (populates cache)
		s.sdkVerify(ctx, secret2)

		// Revoke
		s.sdkRevokeIssuedAPIKeyWithReason(ctx, key2.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Cache bypass shows revocation immediately
		verifyResp := s.sdkVerifyNoCache(ctx, secret2)
		s.False(verifyResp.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, verifyResp.GetErrorCode())
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_TTLAndExpiration() {
	ctx := s.T().Context()

	s.Run("key with short TTL expires", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(), "Short TTL Key", "user-ttl", nil, new("1s"), nil)

		// Verify key works immediately
		verifyResp := s.sdkVerify(ctx, secret)
		s.True(verifyResp.GetIsValid())

		// Poll until the key expires and verification reports it as inactive.
		s.Eventually(func() bool {
			return !s.sdkVerify(ctx, secret).GetIsValid()
		}, 5*time.Second, 50*time.Millisecond, "key should be inactive after TTL expiration")
	})

	s.Run("key with 24h TTL has correct expire_time", func() {
		before := time.Now()
		req := client.NewIssueApiKeyRequest()
		req.SetName("24h TTL Key")
		req.SetActorId("user-ttl-24h")
		req.SetTtl("86400s")
		resp := s.sdkIssueAPIKey(ctx, req)

		expireTime := resp.IssuedApiKey.GetExpireTime()
		s.True(expireTime.After(before.Add(86399*time.Second)),
			"expire_time should be ~24h from now")
		s.True(expireTime.Before(time.Now().Add(86401*time.Second)),
			"expire_time should be ~24h from now")
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_TokenDerivation() {
	ctx := s.T().Context()

	_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(), "Token Source Key", "service-token", []string{"admin", "read:all", "write:all"}, nil, nil)

	s.Run("derive token with default TTL", func() {
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		tokenResp := s.sdkDeriveToken(ctx, req)
		s.NotEmpty(tokenResp.Token.GetToken())
		s.NotNil(tokenResp.Token.ExpireTime)
	})

	s.Run("derive token with custom TTL", func() {
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetTtl("1800s") // 30 minutes
		tokenResp := s.sdkDeriveToken(ctx, req)
		s.NotEmpty(tokenResp.Token.GetToken())
	})

	s.Run("derived tokens are different", func() {
		req1 := client.NewDeriveTokenRequest()
		req1.SetCredential(secret)
		token1Resp := s.sdkDeriveToken(ctx, req1)

		req2 := client.NewDeriveTokenRequest()
		req2.SetCredential(secret)
		token2Resp := s.sdkDeriveToken(ctx, req2)

		s.NotEqual(token1Resp.Token.GetToken(), token2Resp.Token.GetToken())
	})

	s.Run("derive token with custom claims", func() {
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetCustomClaims(map[string]any{
			"user_ip":    "192.168.1.100",
			"request_id": "req-abc-123",
		})
		tokenResp := s.sdkDeriveToken(ctx, req)
		s.NotEmpty(tokenResp.Token.GetToken())
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_ScopesAndPermissions() {
	ctx := s.T().Context()

	s.Run("create key with specific scopes", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Scoped Key")
		req.SetActorId("user-scoped")
		req.SetScopes([]string{"read:users", "read:posts", "write:posts"})
		resp := s.sdkIssueAPIKey(ctx, req)
		s.Equal([]string{"read:users", "read:posts", "write:posts"}, resp.IssuedApiKey.Scopes)
	})

	s.Run("create key with wildcard scope", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Admin Key")
		req.SetActorId("admin-1")
		req.SetScopes([]string{"*"})
		resp := s.sdkIssueAPIKey(ctx, req)
		s.Equal([]string{"*"}, resp.IssuedApiKey.Scopes)
	})

	s.Run("create key with no scopes", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("No Scope Key")
		req.SetActorId("user-limited")
		resp := s.sdkIssueAPIKey(ctx, req)
		s.Empty(resp.IssuedApiKey.Scopes)
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_MetadataHandling() {
	ctx := s.T().Context()

	s.Run("complex nested metadata", func() {
		metadata := map[string]any{
			"app_version": "2.1.0",
			"environment": "production",
			"tags":        []any{"api", "v2alpha1", "premium"},
			"settings": map[string]any{
				"features": []any{"advanced", "analytics"},
			},
		}

		req := client.NewIssueApiKeyRequest()
		req.SetName("Metadata Test Key")
		req.SetActorId("service-meta")
		req.SetMetadata(metadata)
		resp := s.sdkIssueAPIKey(ctx, req)
		s.NotNil(resp.IssuedApiKey.Metadata)

		storedMeta := resp.IssuedApiKey.GetMetadata()
		s.Equal("2.1.0", storedMeta["app_version"])
		s.Equal("production", storedMeta["environment"])
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_ErrorConditions() {
	ctx := s.T().Context()

	s.Run("empty owner ID", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("No Owner ID Key")
		httpResp, err := s.sdkIssueAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("empty name", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetActorId("user-123")
		httpResp, err := s.sdkIssueAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("revoke non-existent key", func() {
		_, err := s.sdkRevokeIssuedAPIKeyExpectError(ctx, "non-existent-key-id-12345", client.AdminRevokeIssuedApiKeyBody{})
		s.Require().Error(err)
	})
}

func (s *APIKeyE2ETestSuite) TestConcurrentOperations() {
	ctx := s.T().Context()
	numConcurrent := 4

	s.Run("concurrent lifecycle tests", func() {
		g, ctx := errgroup.WithContext(ctx)

		for i := range numConcurrent {
			index := i
			g.Go(func() error {
				createReq := client.NewIssueApiKeyRequest()
				createReq.SetName(fmt.Sprintf("Concurrent Key %d", index))
				createReq.SetActorId(fmt.Sprintf("service-%d", index))
				createReq.SetScopes([]string{"read", "write"})

				apiClient := s.setupSDKClient()
				createResp, httpResp, err := apiClient.ApiKeysAPI.
					AdminIssueApiKey(ctx).
					IssueApiKeyRequest(*createReq).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					return fmt.Errorf("create failed: %w", err)
				}

				keyID := createResp.IssuedApiKey.GetKeyId()
				secret := createResp.GetSecret()

				verifyReq := client.NewVerifyApiKeyRequest()
				verifyReq.SetCredential(secret)
				verifyResp, httpResp, err := apiClient.ApiKeysAPI.
					AdminVerifyApiKey(ctx).
					VerifyApiKeyRequest(*verifyReq).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					return fmt.Errorf("verify failed: %w", err)
				}
				if !verifyResp.GetIsValid() {
					return errKeyShouldBeActive
				}

				deriveReq := client.NewDeriveTokenRequest()
				deriveReq.SetCredential(secret)
				deriveReq.SetTtl("600s") // 10 minutes
				tokenResp, httpResp, err := apiClient.ApiKeysAPI.
					AdminDeriveToken(ctx).
					DeriveTokenRequest(*deriveReq).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					return fmt.Errorf("derive token failed: %w", err)
				}
				if tokenResp.Token.GetToken() == "" {
					return errDerivedTokenEmpty
				}

				revokeBody := client.NewAdminRevokeIssuedApiKeyBody()
				revokeBody.SetReason(client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)
				_, httpResp, err = apiClient.ApiKeysAPI.
					AdminRevokeIssuedApiKey(ctx, keyID).
					AdminRevokeIssuedApiKeyBody(*revokeBody).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					return fmt.Errorf("revoke failed: %w", err)
				}
				getAfterRevoke, httpResp, err := apiClient.ApiKeysAPI.
					AdminGetIssuedApiKey(ctx, keyID).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					return fmt.Errorf("get after revoke failed: %w", err)
				}
				if getAfterRevoke.GetStatus() != client.KEYSTATUS_KEY_STATUS_REVOKED {
					return errKeyStatusShouldBeRevoked
				}

				// Verify revoked key fails (use cache bypass for immediate verification)
				apiClientNoCache := s.setupSDKClient()
				apiClientNoCache.GetConfig().AddDefaultHeader("Cache-Control", "no-cache")
				verifyReq2 := client.NewVerifyApiKeyRequest()
				verifyReq2.SetCredential(secret)
				verifyResp2, httpResp, err := apiClientNoCache.ApiKeysAPI.
					AdminVerifyApiKey(ctx).
					VerifyApiKeyRequest(*verifyReq2).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					return fmt.Errorf("verify failed: %w", err)
				}
				if verifyResp2.GetIsValid() {
					return errVerifyShouldShowInactive
				}

				return nil
			})
		}

		err := g.Wait()
		s.NoError(err, "Concurrent lifecycle tests should succeed")
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_RateLimitPolicy() {
	ctx := s.T().Context()

	s.Run("create key with rate limit policy", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Rate Limited Key")
		req.SetActorId("user-rl-1")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("1000")
		rlPolicy.SetWindow("3600s")
		req.SetRateLimitPolicy(*rlPolicy)

		resp := s.sdkIssueAPIKey(ctx, req)
		s.True(resp.IssuedApiKey.HasRateLimitPolicy())
		s.Equal("1000", resp.IssuedApiKey.RateLimitPolicy.GetQuota())
		s.Equal("3600s", resp.IssuedApiKey.RateLimitPolicy.GetWindow())
	})

	s.Run("create key without rate limit policy", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("No Rate Limit Key")
		req.SetActorId("user-rl-2")

		resp := s.sdkIssueAPIKey(ctx, req)
		s.False(resp.IssuedApiKey.HasRateLimitPolicy())
	})

	s.Run("get key returns rate limit policy", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("RL Get Test Key")
		req.SetActorId("user-rl-3")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("500")
		rlPolicy.SetWindow("1800s")
		req.SetRateLimitPolicy(*rlPolicy)

		createResp := s.sdkIssueAPIKey(ctx, req)

		getResp := s.sdkGetIssuedAPIKey(ctx, createResp.IssuedApiKey.GetKeyId())
		s.True(getResp.HasRateLimitPolicy())
		s.Equal("500", getResp.RateLimitPolicy.GetQuota())
		s.Equal("1800s", getResp.RateLimitPolicy.GetWindow())
	})

	s.Run("list keys returns rate limit policy", func() {
		actorID := "user-rl-list-4"
		req := client.NewIssueApiKeyRequest()
		req.SetName("RL List Test Key")
		req.SetActorId(actorID)
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("2000")
		rlPolicy.SetWindow("7200s")
		req.SetRateLimitPolicy(*rlPolicy)

		s.sdkIssueAPIKey(ctx, req)

		pageSize := int32(10)
		listResp := s.sdkListIssuedAPIKeys(ctx, &pageSize, nil, &actorID, nil)
		s.Require().Len(listResp.IssuedApiKeys, 1)
		s.True(listResp.IssuedApiKeys[0].HasRateLimitPolicy())
		s.Equal("2000", listResp.IssuedApiKeys[0].RateLimitPolicy.GetQuota())
		s.Equal("7200s", listResp.IssuedApiKeys[0].RateLimitPolicy.GetWindow())
	})

	s.Run("rotate key preserves rate limit from original", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("RL Rotate Preserve Key")
		req.SetActorId("user-rl-5")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("1000")
		rlPolicy.SetWindow("3600s")
		req.SetRateLimitPolicy(*rlPolicy)

		createResp := s.sdkIssueAPIKey(ctx, req)

		rotateResp := s.sdkRotateIssuedAPIKey(ctx, createResp.IssuedApiKey.GetKeyId(), nil, nil, nil)
		s.True(rotateResp.IssuedApiKey.HasRateLimitPolicy())
		s.Equal("1000", rotateResp.IssuedApiKey.RateLimitPolicy.GetQuota())
		s.Equal("3600s", rotateResp.IssuedApiKey.RateLimitPolicy.GetWindow())
	})

	s.Run("rotate key with new rate limit overrides original", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("RL Rotate Override Key")
		req.SetActorId("user-rl-6")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("1000")
		rlPolicy.SetWindow("3600s")
		req.SetRateLimitPolicy(*rlPolicy)

		createResp := s.sdkIssueAPIKey(ctx, req)

		apiClient := s.setupSDKClient()
		rotateBody := client.NewAdminRotateIssuedApiKeyBody()
		newRlPolicy := client.NewRateLimitPolicy()
		newRlPolicy.SetQuota("500")
		newRlPolicy.SetWindow("1800s")
		rotateBody.SetRateLimitPolicy(*newRlPolicy)

		rotateResp, httpResp, err := apiClient.ApiKeysAPI.
			AdminRotateIssuedApiKey(ctx, createResp.IssuedApiKey.GetKeyId()).
			AdminRotateIssuedApiKeyBody(*rotateBody).
			Execute()
		s.Require().NoError(err)
		if httpResp != nil && httpResp.Body != nil {
			s.T().Cleanup(func() { _ = httpResp.Body.Close() })
		}
		s.True(rotateResp.IssuedApiKey.HasRateLimitPolicy())
		s.Equal("500", rotateResp.IssuedApiKey.RateLimitPolicy.GetQuota())
		s.Equal("1800s", rotateResp.IssuedApiKey.RateLimitPolicy.GetWindow())
	})

	s.Run("error - rate limit quota must be positive", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Zero Quota Key")
		req.SetActorId("user-rl-7")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("0")
		rlPolicy.SetWindow("3600s")
		req.SetRateLimitPolicy(*rlPolicy)

		httpResp, err := s.sdkIssueAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("error - rate limit window must be positive", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("Zero Window Key")
		req.SetActorId("user-rl-8")
		rlPolicy := client.NewRateLimitPolicy()
		rlPolicy.SetQuota("1000")
		rlPolicy.SetWindow("0s")
		req.SetRateLimitPolicy(*rlPolicy)

		httpResp, err := s.sdkIssueAPIKeyExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_IdempotentKeyCreation() {
	ctx := s.T().Context()

	s.Run("same request_id returns same key", func() {
		requestID := "unique-request-" + time.Now().Format("20060102150405")

		req := client.NewIssueApiKeyRequest()
		req.SetName("Idempotent Key")
		req.SetActorId("customer_idempotent_001")
		req.SetScopes([]string{"chat:read"})
		req.SetRequestId(requestID)

		// First request
		resp1 := s.sdkIssueAPIKey(ctx, req)

		// Retry with same request_id
		resp2 := s.sdkIssueAPIKey(ctx, req)

		// Same key returned
		s.Equal(resp1.IssuedApiKey.GetKeyId(), resp2.IssuedApiKey.GetKeyId(),
			"same request_id should return same key")
	})

	s.Run("different request_id creates different key", func() {
		req1 := client.NewIssueApiKeyRequest()
		req1.SetName("Idempotent Key A")
		req1.SetActorId("customer_idempotent_002")
		req1.SetRequestId("request-a-" + time.Now().Format("20060102150405"))

		req2 := client.NewIssueApiKeyRequest()
		req2.SetName("Idempotent Key B")
		req2.SetActorId("customer_idempotent_002")
		req2.SetRequestId("request-b-" + time.Now().Format("20060102150405"))

		resp1 := s.sdkIssueAPIKey(ctx, req1)
		resp2 := s.sdkIssueAPIKey(ctx, req2)

		s.NotEqual(resp1.IssuedApiKey.GetKeyId(), resp2.IssuedApiKey.GetKeyId(),
			"different request_ids should create different keys")
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_HealthAndVersion() {
	s.Run("health alive endpoint responds", func() {
		resp, err := http.Get(s.testServer.HTTPURL + "/health/alive") //nolint:noctx // test
		s.Require().NoError(err)
		s.T().Cleanup(func() { _ = resp.Body.Close() })
		s.Equal(http.StatusOK, resp.StatusCode)
	})

	s.Run("health ready endpoint responds", func() {
		resp, err := http.Get(s.testServer.HTTPURL + "/health/ready") //nolint:noctx // test
		s.Require().NoError(err)
		s.T().Cleanup(func() { _ = resp.Body.Close() })
		s.Equal(http.StatusOK, resp.StatusCode)
	})

	s.Run("version endpoint responds", func() {
		resp, err := http.Get(s.testServer.HTTPURL + "/version") //nolint:noctx // test
		s.Require().NoError(err)
		s.T().Cleanup(func() { _ = resp.Body.Close() })
		s.Equal(http.StatusOK, resp.StatusCode)
	})
}

// TODO what about pagination and listing? also do we cover import and isused keys the same?

// reviewed - @aeneasr - 2026-03-27
