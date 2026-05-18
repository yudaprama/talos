package api_test

import (
	"net/http"

	client "github.com/ory-corp/talos/internal/client/generated"
)

func (s *APIKeyE2ETestSuite) TestPublic_SelfRevoke() {
	ctx := s.T().Context()

	s.Run("self-revoke issued key", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Self-Revoke Issued")

		// Verify key is active
		verifyResp := s.testServer.VerifyTestToken(s.T(), secret)
		s.True(verifyResp.GetIsValid())

		// Self-revoke
		s.sdkSelfRevoke(ctx, secret, client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Verify key is no longer active
		verifyResp = s.testServer.VerifyTestToken(s.T(), secret)
		s.False(verifyResp.GetIsValid())

		// Verify status via admin
		getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, getResp.GetStatus())
		s.Equal(client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE, getResp.GetRevocationReason())
	})

	s.Run("self-revoke imported key", func() {
		importSecret := "self-revoke-imported-secret-e2e-test"
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(importSecret)
		req.SetName("Self-Revoke Imported")
		req.SetActorId("owner-import-e2e")
		s.sdkImportAPIKey(ctx, req)

		// Verify imported key is active
		verifyResp := s.testServer.VerifyTestToken(s.T(), importSecret)
		s.True(verifyResp.GetIsValid())

		// Self-revoke
		s.sdkSelfRevoke(ctx, importSecret, client.REVOCATIONREASON_REVOCATION_REASON_AFFILIATION_CHANGED)

		// Verify imported key is no longer active
		verifyResp = s.testServer.VerifyTestToken(s.T(), importSecret)
		s.False(verifyResp.GetIsValid())
	})

	s.Run("self-revoke stores reason", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Self-Revoke Reason Check")

		s.sdkSelfRevoke(ctx, secret, client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED)

		getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())
		s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, getResp.GetStatus())
		s.Equal(client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED, getResp.GetRevocationReason())
	})

	s.Run("self-revoke rejects PRIVILEGE_WITHDRAWN", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Self-Revoke Privilege Test")

		req := client.NewSelfRevokeAPIKeyRequest()
		req.SetCredential(secret)
		req.SetReason(client.REVOCATIONREASON_REVOCATION_REASON_PRIVILEGE_WITHDRAWN)
		httpResp, err := s.sdkSelfRevokeExpectError(ctx, req)
		s.requireHTTPErrorContains(err, httpResp, "PRIVILEGE_WITHDRAWN")
	})

	s.Run("self-revoke rejects empty credential", func() {
		req := client.NewSelfRevokeAPIKeyRequest()
		req.SetCredential("")
		httpResp, err := s.sdkSelfRevokeExpectError(ctx, req)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("self-revoke invalid credential returns error", func() {
		req := client.NewSelfRevokeAPIKeyRequest()
		req.SetCredential("totally-invalid-credential-xyz")
		_, err := s.sdkSelfRevokeExpectError(ctx, req)
		s.Require().Error(err)
	})

	s.Run("self-revoke already revoked key is idempotent", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Self-Revoke Idempotent")

		// Admin revoke first
		s.testServer.RevokeTestAPIKey(s.T(), apiKey.GetKeyId())

		// Self-revoke should succeed (idempotent)
		s.sdkSelfRevoke(ctx, secret, client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)
	})

	s.Run("self-revoke with UNSPECIFIED reason succeeds", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Self-Revoke Unspecified")

		s.sdkSelfRevoke(ctx, secret, client.REVOCATIONREASON_REVOCATION_REASON_UNSPECIFIED)

		// Key should be revoked
		verifyResp := s.testServer.VerifyTestToken(s.T(), secret)
		s.False(verifyResp.GetIsValid())
	})
}

func (s *APIKeyE2ETestSuite) TestAdmin_AdminRevokeWithReasons() {
	ctx := s.T().Context()

	s.Run("admin revoke with each reason stores correctly", func() {
		reasons := []client.RevocationReason{
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE,
			client.REVOCATIONREASON_REVOCATION_REASON_AFFILIATION_CHANGED,
			client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED,
		}

		for _, reason := range reasons {
			s.Run(string(reason), func() {
				apiKey, _ := s.testServer.CreateTestAPIKey(s.T(), "Reason-"+string(reason))

				s.sdkRevokeAPIKeyWithReason(ctx, apiKey.GetKeyId(), reason)

				getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())
				s.Equal(client.KEYSTATUS_KEY_STATUS_REVOKED, getResp.GetStatus())
				s.Equal(reason, getResp.GetRevocationReason())
			})
		}
	})

	s.Run("admin revoke with PRIVILEGE_WITHDRAWN and reason_text", func() {
		apiKey, _ := s.testServer.CreateTestAPIKey(s.T(), "Privilege Withdrawn E2E")

		s.sdkRevokeAPIKeyWithReason(ctx, apiKey.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_PRIVILEGE_WITHDRAWN, "Employee terminated")

		getResp := s.sdkGetIssuedAPIKey(ctx, apiKey.GetKeyId())
		s.Equal(client.REVOCATIONREASON_REVOCATION_REASON_PRIVILEGE_WITHDRAWN, getResp.GetRevocationReason())
		s.Equal("Employee terminated", getResp.GetRevocationDescription())
	})

	s.Run("admin revoke with reason_text on wrong reason returns error", func() {
		apiKey, _ := s.testServer.CreateTestAPIKey(s.T(), "Wrong Reason Text E2E")

		httpResp, err := s.sdkRevokeAPIKeyWithReasonAndTextExpectError(ctx, apiKey.GetKeyId(),
			client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE, "This should be rejected")
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("verification fails with REVOKED error code after admin revocation of issued key", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Admin Revoke Verify Issued")

		verifyResp := s.sdkVerify(ctx, secret)
		s.True(verifyResp.GetIsValid())

		s.sdkRevokeAPIKeyWithReason(ctx, apiKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		verifyAfter := s.sdkVerifyNoCache(ctx, secret)
		s.False(verifyAfter.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, verifyAfter.GetErrorCode(),
			"exact error code should be VERIFICATION_ERROR_REVOKED, not just inactive")
	})

	s.Run("verification fails with REVOKED error code after admin revocation of imported key", func() {
		rawKey := "admin-revoke-verify-imported-e2e-test"
		req := client.NewImportAPIKeyRequest()
		req.SetRawKey(rawKey)
		req.SetName("Admin Revoke Verify Imported")
		req.SetActorId("admin-revoke-verify-owner")
		imported := s.sdkImportAPIKey(ctx, req)

		verifyResp := s.sdkVerify(ctx, rawKey)
		s.True(verifyResp.GetIsValid())

		s.sdkRevokeAPIKeyWithReason(ctx, imported.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_PRIVILEGE_WITHDRAWN)

		verifyAfter := s.sdkVerifyNoCache(ctx, rawKey)
		s.False(verifyAfter.GetIsValid())
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, verifyAfter.GetErrorCode(),
			"exact error code should be VERIFICATION_ERROR_REVOKED, not just inactive")
	})
}

// reviewed - @aeneasr - 2026-03-27
