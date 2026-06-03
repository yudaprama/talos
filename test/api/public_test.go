package api_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	client "github.com/ory/talos/internal/client/generated"
)

func (s *APIKeyE2ETestSuite) TestPublic_Verification() {
	ctx := s.T().Context()

	s.Run("verify via public endpoint", func() {
		apiKey, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Self-service Test", "customer_gw_001",
			[]string{"chat:read", "chat:write", "models:list"},
			nil, map[string]any{"plan": "pro", "tier": "enterprise"})
		resp := s.sdkVerify(ctx, secret)
		s.Equal(apiKey.GetKeyId(), resp.GetKeyId())
		s.True(resp.GetIsValid())
		s.Equal("customer_gw_001", resp.GetActorId())
		s.Equal([]string{"chat:read", "chat:write", "models:list"}, resp.Scopes)
		s.Equal("pro", resp.Metadata["plan"])
		s.Equal("enterprise", resp.Metadata["tier"])
	})

	s.Run("public handles revoked keys", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Revoke Test")
		s.testServer.RevokeTestAPIKey(s.T(), apiKey.GetKeyId())
		resp := s.sdkVerify(ctx, secret)
		s.False(resp.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, resp.GetErrorCode())
	})

	s.Run("public handles expired keys", func() {
		ttl := "1s"
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(), "Expired Key", "test-user", nil, &ttl, nil)
		s.Eventually(func() bool {
			return !s.sdkVerify(ctx, secret).GetIsValid()
		}, 5*time.Second, 50*time.Millisecond, "key should be inactive after TTL expiration")
	})
}

func (s *APIKeyE2ETestSuite) TestPublic_DerivedTokenVerification() {
	ctx := s.T().Context()

	s.Run("verify valid derived token", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Token Test Key")
		derivedToken := s.testServer.DeriveTestToken(s.T(), secret)
		resp := s.sdkVerify(ctx, derivedToken)
		s.True(resp.GetIsValid())
		s.Equal(apiKey.GetKeyId(), resp.GetKeyId())
	})

	s.Run("verify expired derived token fails", func() {
		ttl := "5s"
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(), "Short TTL Key", "test-user", nil, &ttl, nil)

		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetTtl("1s")
		tokenResp := s.sdkDeriveToken(ctx, req)

		s.Eventually(func() bool {
			return !s.sdkVerify(ctx, tokenResp.Token.GetToken()).GetIsValid()
		}, 5*time.Second, 50*time.Millisecond, "derived token should be inactive after TTL expiration")
	})

	s.Run("verify expired macaroon derived token fails", func() {
		ttl := "5s"
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(), "Short TTL Macaroon Key", "test-user", nil, &ttl, nil)

		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetTtl("1s")
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		tokenResp := s.sdkDeriveToken(ctx, req)

		s.Eventually(func() bool {
			return !s.sdkVerify(ctx, tokenResp.Token.GetToken()).GetIsValid()
		}, 5*time.Second, 50*time.Millisecond, "derived macaroon should be inactive after TTL expiration")
	})

	s.Run("verify malformed token fails", func() {
		malformedTokens := []string{
			"not-a-valid-token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
			"12345",
		}

		for _, token := range malformedTokens {
			resp := s.sdkVerify(ctx, token)
			s.False(resp.GetIsValid(), "token should be invalid: %s", token)
		}
	})
}

func (s *APIKeyE2ETestSuite) TestHTTP_Public_BatchVerify() {
	ctx := s.T().Context()

	s.Run("batch verify with mix of valid, invalid, and revoked", func() {
		// Create valid keys
		_, secret1 := s.testServer.CreateTestAPIKey(s.T(), "Batch Valid 1")
		_, secret2 := s.testServer.CreateTestAPIKey(s.T(), "Batch Valid 2")

		// Create and revoke a key
		revokedKey, secret3 := s.testServer.CreateTestAPIKey(s.T(), "Batch Revoked")
		s.testServer.RevokeTestAPIKey(s.T(), revokedKey.GetKeyId())

		credentials := []string{secret1, secret2, secret3, "totally_invalid_credential"}
		resp := s.sdkBatchVerify(ctx, credentials)

		s.Len(resp.Results, 4)
		s.True(resp.Results[0].GetIsValid(), "first key should be active")
		s.True(resp.Results[1].GetIsValid(), "second key should be active")
		s.False(resp.Results[2].GetIsValid(), "revoked key should be inactive")
		s.False(resp.Results[3].GetIsValid(), "invalid credential should be inactive")
	})
}

func (s *APIKeyE2ETestSuite) TestHTTP_Public_ErrorScenarios() {
	s.Run("400 Bad Request - malformed JSON", func() {
		ctx, cancel := context.WithTimeout(s.T().Context(), 5*time.Second)
		defer cancel()

		malformedJSON := []byte(`{"name": "test", "broken}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.testServer.HTTPURL+pathKeys, bytes.NewReader(malformedJSON))
		s.Require().NoError(err)
		req.Header.Set("Content-Type", contentTypeJSON)

		resp, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)
		s.T().Cleanup(func() { _ = resp.Body.Close() })

		s.Equal(http.StatusBadRequest, resp.StatusCode)
	})
}

func (s *APIKeyE2ETestSuite) TestHTTP_Public_RateLimitHeaders() {
	ctx := s.T().Context()

	s.Run("verify key with rate limit policy headers", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("rate-limit-header-test")
		req.SetActorId("test-user")
		quota := "100"
		window := "3600s"
		req.SetRateLimitPolicy(client.RateLimitPolicy{
			Quota:  &quota,
			Window: &window,
		})

		issueResp := s.sdkIssueAPIKey(ctx, req)

		resp := s.sdkVerifyRaw(ctx, issueResp.GetSecret())
		s.T().Cleanup(func() { _ = resp.Body.Close() })
		s.Equal(http.StatusOK, resp.StatusCode)
		s.NotEmpty(resp.Header.Get("Ratelimit-Policy"), "expected Ratelimit-Policy header on verify response")
		s.Contains(resp.Header.Get("Ratelimit-Policy"), "q=100", "policy should contain quota")
		s.Contains(resp.Header.Get("Ratelimit-Policy"), "w=3600", "policy should contain window")
	})

	s.Run("verify key without rate limit policy has no headers", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "no-rate-limit-test")

		resp := s.sdkVerifyRaw(ctx, secret)
		s.T().Cleanup(func() { _ = resp.Body.Close() })
		s.Equal(http.StatusOK, resp.StatusCode)
		s.Empty(resp.Header.Get("Ratelimit-Policy"), "should not have Ratelimit-Policy header")
		s.Empty(resp.Header.Get("Ratelimit"), "should not have Ratelimit header")
		s.Empty(resp.Header.Get("Retry-After"), "should not have Retry-After header")
	})

	s.Run("non verify endpoint has no rate limit headers", func() {
		apiKey, _ := s.testServer.CreateTestAPIKey(s.T(), "admin-endpoint-test")
		keyID := apiKey.GetKeyId()

		getReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
			s.testServer.HTTPURL+"/v2alpha1/admin/issuedApiKeys/"+keyID, nil)
		s.Require().NoError(err)

		resp, err := http.DefaultClient.Do(getReq)
		s.Require().NoError(err)
		s.T().Cleanup(func() { _ = resp.Body.Close() })

		s.Empty(resp.Header.Get("Ratelimit-Policy"), "admin endpoint should not have Ratelimit-Policy")
		s.Empty(resp.Header.Get("Ratelimit"), "admin endpoint should not have Ratelimit")
		s.Empty(resp.Header.Get("Retry-After"), "admin endpoint should not have Retry-After")
	})
}

func (s *APIKeyE2ETestSuite) TestHTTP_Public_ConcurrentRequests() {
	s.Run("concurrent verify requests", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Concurrent Test Key")

		numConcurrent := 20
		errChan := make(chan error, numConcurrent)

		for range numConcurrent {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						errChan <- fmt.Errorf("panic: %v", r)
					}
				}()

				apiClient := s.setupSDKClient()
				req := client.NewVerifyApiKeyRequest()
				req.SetCredential(secret)

				resp, httpResp, err := apiClient.ApiKeysAPI.
					AdminVerifyApiKey(s.T().Context()).
					VerifyApiKeyRequest(*req).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					errChan <- err
					return
				}
				if !resp.GetIsValid() {
					errChan <- errors.New("key should be active")
					return
				}
				errChan <- nil
			}()
		}

		for range numConcurrent {
			err := <-errChan
			s.NoError(err, "concurrent request should succeed")
		}
	})

	s.Run("concurrent create requests", func() {
		numConcurrent := 10
		errChan := make(chan error, numConcurrent)

		for i := range numConcurrent {
			go func(idx int) {
				defer func() {
					if r := recover(); r != nil {
						errChan <- fmt.Errorf("panic in goroutine %d: %v", idx, r)
					}
				}()

				apiClient := s.setupSDKClient()
				req := client.NewIssueApiKeyRequest()
				req.SetName(fmt.Sprintf("Concurrent Key %d", idx))
				req.SetActorId(fmt.Sprintf("user-%d", idx))
				req.SetScopes([]string{"read"})

				resp, httpResp, err := apiClient.ApiKeysAPI.
					AdminIssueApiKey(s.T().Context()).
					IssueApiKeyRequest(*req).
					Execute()
				if httpResp != nil && httpResp.Body != nil {
					_ = httpResp.Body.Close()
				}
				if err != nil {
					errChan <- err
					return
				}
				if resp.IssuedApiKey.GetKeyId() == "" {
					errChan <- fmt.Errorf("key %d has empty KeyId", idx)
					return
				}
				errChan <- nil
			}(i)
		}

		for range numConcurrent {
			err := <-errChan
			s.NoError(err, "concurrent create should succeed")
		}
	})
}

// reviewed - @aeneasr - 2026-03-27
