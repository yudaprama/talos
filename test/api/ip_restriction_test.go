package api_test

import (
	"fmt"

	client "github.com/ory/talos/internal/client/generated"
)

func (s *APIKeyE2ETestSuite) TestIPRestrictionOnImportedAPIKeys() {
	ctx := s.T().Context()

	s.Run("import key with IP allowlist - storage round-trip", func() {
		rawKey := fmt.Sprintf("imported-ip-test-key-%s", s.T().Name())
		req := client.NewImportApiKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Imported IP Restricted Key")
		req.SetActorId("enterprise_imported_ip_001")

		ipRestriction := client.NewIPRestriction()
		ipRestriction.SetAllowedCidrs([]string{"203.0.113.0/24", "2001:db8::/32"})
		req.SetIpRestriction(*ipRestriction)

		imported := s.sdkImportAPIKey(ctx, req)

		// Verify IP restriction was stored
		s.True(imported.HasIpRestriction())
		s.Equal([]string{"203.0.113.0/24", "2001:db8::/32"}, imported.IpRestriction.AllowedCidrs)

		// GET also returns the IP restriction
		getResp := s.sdkGetImportedAPIKey(ctx, imported.GetKeyId())
		s.True(getResp.HasIpRestriction())
		s.Equal([]string{"203.0.113.0/24", "2001:db8::/32"}, getResp.IpRestriction.AllowedCidrs)
	})

	s.Run("verification from non-allowed IP returns IP_NOT_ALLOWED", func() {
		rawKey := fmt.Sprintf("imported-ip-blocked-key-%s", s.T().Name())
		req := client.NewImportApiKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Imported IP Blocked Key")
		req.SetActorId("enterprise_imported_ip_002")

		ipRestriction := client.NewIPRestriction()
		// Only allow a specific IP that won't match the test server request (127.0.0.1)
		ipRestriction.SetAllowedCidrs([]string{"198.51.100.0/24"})
		req.SetIpRestriction(*ipRestriction)

		s.sdkImportAPIKey(ctx, req)

		// Verification from test server (127.0.0.1) should fail due to IP restriction
		verifyResp := s.sdkVerify(ctx, rawKey)
		s.False(verifyResp.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_IP_NOT_ALLOWED, verifyResp.GetErrorCode())
	})
}

func (s *APIKeyE2ETestSuite) TestIPRestrictionOnAPIKeys() {
	ctx := s.T().Context()

	s.Run("create key with IP allowlist", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("IP Restricted Key")
		req.SetActorId("enterprise_ip_001")
		req.SetScopes([]string{"api:read"})

		ipRestriction := client.NewIPRestriction()
		ipRestriction.SetAllowedCidrs([]string{"203.0.113.0/24", "2001:db8::/32"})
		req.SetIpRestriction(*ipRestriction)

		resp := s.sdkIssueAPIKey(ctx, req)

		// Verify IP restriction stored
		key := resp.IssuedApiKey
		s.True(key.HasIpRestriction())
		s.Equal([]string{"203.0.113.0/24", "2001:db8::/32"}, key.IpRestriction.AllowedCidrs)

		// GET also returns the IP restriction
		getResp := s.sdkGetIssuedAPIKey(ctx, key.GetKeyId())
		s.True(getResp.HasIpRestriction())
		s.Equal([]string{"203.0.113.0/24", "2001:db8::/32"}, getResp.IpRestriction.AllowedCidrs)
	})

	s.Run("verification from non-allowed IP returns IP_NOT_ALLOWED", func() {
		req := client.NewIssueApiKeyRequest()
		req.SetName("IP Blocked Key")
		req.SetActorId("enterprise_ip_002")
		ipRestriction := client.NewIPRestriction()
		// Only allow a specific IP that won't match our test request
		ipRestriction.SetAllowedCidrs([]string{"198.51.100.0/24"})
		req.SetIpRestriction(*ipRestriction)

		resp := s.sdkIssueAPIKey(ctx, req)
		secret := resp.GetSecret()

		// Verification from test server (127.0.0.1) should fail
		verifyResp := s.sdkVerify(ctx, secret)
		s.False(verifyResp.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_IP_NOT_ALLOWED, verifyResp.GetErrorCode())
	})
}

// reviewed - @aeneasr - 2026-03-27
