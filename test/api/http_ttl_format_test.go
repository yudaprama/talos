package api_test

import (
	"fmt"
	"time"

	client "github.com/ory-corp/talos/internal/client/generated"
)

func (s *APIKeyE2ETestSuite) TestHTTP_TTLFormats() {
	createKeyTests := []struct {
		name             string
		ttl              string
		expectedDuration time.Duration
	}{
		{name: "Go duration hours", ttl: "24h", expectedDuration: 24 * time.Hour},
		{name: "Go duration compound", ttl: "1h30m", expectedDuration: 90 * time.Minute},
		{name: "protobuf seconds", ttl: "86400s", expectedDuration: 24 * time.Hour},
	}

	for _, tc := range createKeyTests {
		s.Run(fmt.Sprintf("create API key with %s TTL format", tc.name), func() {
			ctx := s.T().Context()
			before := time.Now()

			req := client.NewIssueAPIKeyRequest()
			req.SetName("TTL Format Test - " + tc.name)
			req.SetActorId("ttl-test-user")
			req.SetScopes([]string{"read"})
			req.SetTtl(tc.ttl)

			resp := s.sdkIssueAPIKey(ctx, req)

			s.Require().NotNil(resp.IssuedApiKey, "API key should be present")
			s.NotEmpty(resp.IssuedApiKey.GetKeyId(), "key ID should be set")
			s.True(resp.IssuedApiKey.HasExpireTime(), "expires_at must be set when TTL is provided")

			expiresAt := resp.IssuedApiKey.GetExpireTime()
			s.True(expiresAt.After(before.Add(tc.expectedDuration-time.Second)),
				"expires_at %v should be at least %v from before request %v", expiresAt, tc.expectedDuration, before)
			s.True(expiresAt.Before(time.Now().Add(tc.expectedDuration+time.Second)),
				"expires_at %v should be at most %v from now", expiresAt, tc.expectedDuration)
		})
	}

	deriveTokenTests := []struct {
		name             string
		ttl              string
		expectedDuration time.Duration
	}{
		{name: "Go duration hours", ttl: "1h", expectedDuration: time.Hour},
		{name: "Go duration minutes", ttl: "30m", expectedDuration: 30 * time.Minute},
	}

	for _, tc := range deriveTokenTests {
		s.Run(fmt.Sprintf("derive token with %s TTL format", tc.name), func() {
			ctx := s.T().Context()
			before := time.Now()

			_, secret := s.testServer.CreateTestAPIKey(s.T(), "TTL Format Derive - "+tc.name)

			req := client.NewDeriveTokenRequest()
			req.SetCredential(secret)
			req.SetTtl(tc.ttl)

			resp := s.sdkDeriveToken(ctx, req)

			s.Require().NotNil(resp.Token, "token should be present")
			s.NotEmpty(resp.Token.GetToken(), "token string should be set")
			s.True(resp.Token.HasExpireTime(), "expires_at must be set on derived token")

			expiresAt := resp.Token.GetExpireTime()
			s.True(expiresAt.After(before.Add(tc.expectedDuration-time.Second)),
				"token expires_at %v should be at least %v from before request %v", expiresAt, tc.expectedDuration, before)
			s.True(expiresAt.Before(time.Now().Add(tc.expectedDuration+time.Second)),
				"token expires_at %v should be at most %v from now", expiresAt, tc.expectedDuration)
		})
	}

	s.Run("import API key with Go duration TTL format", func() {
		ctx := s.T().Context()
		before := time.Now()

		req := client.NewImportAPIKeyRequest()
		req.SetRawKey("sk_test_ttlformat_" + time.Now().Format("20060102150405"))
		req.SetName("TTL Format Import Test")
		req.SetActorId("ttl-test-user")
		req.SetScopes([]string{"read"})
		req.SetTtl("720h")
		req.SetMetadata(map[string]any{"source": "ttl-format-test"})

		resp := s.sdkImportAPIKey(ctx, req)

		s.Require().NotNil(resp, "imported API key should be present")
		s.True(resp.HasExpireTime(), "expires_at must be set on imported key with TTL")

		expiresAt := resp.GetExpireTime()
		s.True(expiresAt.After(before.Add(720*time.Hour-time.Second)),
			"imported key expires_at %v should be at least 720h from before request %v", expiresAt, before)
		s.True(expiresAt.Before(time.Now().Add(720*time.Hour+time.Second)),
			"imported key expires_at %v should be at most 720h from now", expiresAt)
	})
}

// reviewed - @aeneasr - 2026-03-27
