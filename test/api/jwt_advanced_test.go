package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	client "github.com/ory/talos/internal/client/generated"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/testutil"
	testutiltesting "github.com/ory/talos/internal/testutil/testserver"
)

func (s *APIKeyE2ETestSuite) TestGetJWKS() {
	ctx := s.T().Context()

	s.Run("get JWKS", func() {
		jwksResp := s.sdkGetJWKS(ctx)
		s.NotNil(jwksResp.Jwks)

		// Parse JWKS as map
		jwksMap := jwksResp.Jwks
		s.Contains(jwksMap, "keys", "JWKS should contain 'keys' field")

		// Verify keys array exists and has entries
		keys, ok := jwksMap["keys"].([]any)
		s.True(ok, "keys should be an array")
		s.Require().NotEmpty(keys, "JWKS should contain at least one key")

		// Verify first key has required fields
		firstKey, ok := keys[0].(map[string]any)
		s.True(ok, "key should be an object")
		s.Contains(firstKey, "kid", "key should have kid")
		s.Contains(firstKey, "kty", "key should have kty")
		s.Contains(firstKey, "use", "key should have use")
		s.Contains(firstKey, "alg", "key should have alg")
	})

	s.Run("get JWKS via HTTP well-known endpoint", func() {
		jwksResp := s.sdkGetJWKS(ctx)
		s.NotNil(jwksResp.Jwks)

		jwksMap := jwksResp.Jwks
		s.Contains(jwksMap, "keys", "JWKS should contain 'keys' field")

		keys, ok := jwksMap["keys"].([]any)
		s.True(ok, "keys should be an array")
		s.NotEmpty(keys, "JWKS should contain signing keys")
	})

	s.Run("JWKS keys can verify derived JWTs", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWKS Verify Key")

		// Derive JWT
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)
		jwt := tokenResp.Token.GetToken()

		// Parse JWT header to get kid
		parts := strings.Split(jwt, ".")
		s.Require().Len(parts, 3)
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		s.Require().NoError(err)
		var header map[string]any
		s.Require().NoError(json.Unmarshal(headerBytes, &header))

		// JWKS should contain the signing key
		jwksResp := s.sdkGetJWKS(ctx)
		keys, _ := jwksResp.Jwks["keys"].([]any)
		kid := header["kid"]

		found := false
		for _, k := range keys {
			key, _ := k.(map[string]any)
			if key["kid"] == kid {
				found = true
				break
			}
		}
		s.True(found, "JWKS should contain the key used to sign the JWT (kid=%v)", kid)
	})

	s.Run("JWKS contains active signing keys", func() {
		jwksResp := s.sdkGetJWKS(ctx)
		jwksMap := jwksResp.Jwks
		keys, _ := jwksMap["keys"].([]any)

		for _, k := range keys {
			key, _ := k.(map[string]any)
			s.NotEmpty(key["kid"], "kid should not be empty")
			s.NotEmpty(key["kty"], "kty should not be empty")

			// Public key material should be present
			// For EdDSA: x field, For RSA: n and e fields
			hasPublicKey := key["x"] != nil || (key["n"] != nil && key["e"] != nil)
			s.True(hasPublicKey, "Key should have public key material")
		}
	})

	s.Run("HMAC secrets are never exposed in JWKS", func() {
		jwksResp := s.sdkGetJWKS(ctx)
		keys, _ := jwksResp.Jwks["keys"].([]any)
		s.NotEmpty(keys, "JWKS should contain at least one key")

		for _, k := range keys {
			key, _ := k.(map[string]any)
			s.NotEqual("oct", key["kty"], "JWKS must not contain symmetric (oct) keys")
			s.NotContains(key, "k", "JWKS must not expose raw symmetric key material (k field)")
			alg, _ := key["alg"].(string)
			s.False(strings.HasPrefix(alg, "HS"), "JWKS must not contain HMAC algorithms (got alg=%q)", alg)
		}
	})
}

func (s *APIKeyE2ETestSuite) TestJWTSignatureTampering() {
	ctx := s.T().Context()

	s.Run("tampered JWT signature fails verification", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWT Tamper Test")

		// Derive JWT token
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)

		validJWT := tokenResp.Token.GetToken()
		s.NotEmpty(validJWT)

		// Verify original JWT works
		verifyValid := s.sdkVerify(ctx, validJWT)
		s.True(verifyValid.GetIsValid(), "Original JWT should be valid")

		// Tamper with the JWT by modifying the signature
		parts := strings.Split(validJWT, ".")
		s.Require().Len(parts, 3, "JWT should have 3 parts (header.payload.signature)")

		// Corrupt the signature
		tamperedSignature := parts[2] + "TAMPERED"
		tamperedJWT := strings.Join([]string{parts[0], parts[1], tamperedSignature}, ".")

		// Verify tampered JWT fails
		verifyTampered := s.sdkVerify(ctx, tamperedJWT)
		s.False(verifyTampered.GetIsValid(), "Tampered JWT should fail verification")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_SIGNATURE_INVALID, verifyTampered.GetErrorCode())
	})

	s.Run("modified JWT payload fails verification", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWT Payload Tamper Test")

		// Derive JWT with custom claims
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		req.SetCustomClaims(map[string]any{
			"user_id": "user-123",
			"role":    "viewer",
		})
		tokenResp := s.sdkDeriveToken(ctx, req)

		validJWT := tokenResp.Token.GetToken()

		// Parse JWT payload
		parts := strings.Split(validJWT, ".")
		s.Require().Len(parts, 3)

		// Decode payload
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		s.Require().NoError(err)

		var payload map[string]any
		err = json.Unmarshal(payloadBytes, &payload)
		s.Require().NoError(err)

		// Modify the payload (change role from viewer to admin)
		payload["role"] = "admin"

		// Re-encode modified payload
		modifiedPayloadBytes, err := json.Marshal(payload)
		s.Require().NoError(err)
		modifiedPayload := base64.RawURLEncoding.EncodeToString(modifiedPayloadBytes)

		// Construct tampered JWT with modified payload but original signature
		tamperedJWT := strings.Join([]string{parts[0], modifiedPayload, parts[2]}, ".")

		// Verify tampered JWT fails
		verifyTampered := s.sdkVerify(ctx, tamperedJWT)
		s.False(verifyTampered.GetIsValid(), "JWT with modified payload should fail verification")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_SIGNATURE_INVALID, verifyTampered.GetErrorCode())
	})

	s.Run("completely invalid JWT format fails gracefully", func() {
		invalidJWTs := []string{
			"not-a-jwt-token",
			"header.payload",                           // Missing signature
			"header.payload.signature.extra",           // Too many parts
			"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.", // None algorithm
		}

		for _, invalidJWT := range invalidJWTs {
			resp := s.sdkVerify(ctx, invalidJWT)
			s.False(resp.GetIsValid(), "Invalid JWT should not be active: %s", invalidJWT)
			s.NotEmpty(resp.GetErrorMessage(), "Should have error message for: %s", invalidJWT)
		}
	})
}

// Derived tokens are stateless capability tokens that remain valid until expiration.
// Parent key revocation does not cascade to derived tokens for scalability.
func (s *APIKeyE2ETestSuite) TestStatelessTokenVerification() {
	ctx := s.T().Context()

	s.Run("derived JWT remains valid after parent revocation", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Cascading JWT Parent")

		// Derive JWT from parent key
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)
		derivedJWT := tokenResp.Token.GetToken()

		// Verify derived JWT works before revocation
		verifyBefore := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyBefore.GetIsValid(), "Derived JWT should be valid before parent revocation")

		// Revoke parent API key
		s.sdkRevokeIssuedAPIKeyWithReason(ctx, apiKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Verify parent key is revoked (use cache bypass for immediate verification)
		verifyParent := s.sdkVerifyNoCache(ctx, secret)
		s.False(verifyParent.GetIsValid(), "Parent key should be revoked")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_REVOKED, verifyParent.GetErrorCode())

		// Derived JWT remains valid (stateless capability model)
		verifyAfter := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyAfter.GetIsValid(), "Derived JWT should remain valid after parent revocation (stateless)")
		s.NotEmpty(verifyAfter.GetKeyId(), "Should have key_id from token claims")
	})

	s.Run("derived Macaroon remains valid after parent revocation", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Cascading Macaroon Parent")

		// Derive Macaroon token
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)
		derivedMacaroon := tokenResp.Token.GetToken()

		// Verify macaroon works before revocation
		verifyBefore := s.sdkVerify(ctx, derivedMacaroon)
		s.True(verifyBefore.GetIsValid(), "Derived Macaroon should be valid before parent revocation")

		// Revoke parent key
		s.sdkRevokeIssuedAPIKeyWithReason(ctx, apiKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Derived Macaroon remains valid (stateless capability model)
		verifyAfter := s.sdkVerify(ctx, derivedMacaroon)
		s.True(verifyAfter.GetIsValid(), "Macaroon should remain valid after parent revocation (stateless)")
		s.NotEmpty(verifyAfter.GetKeyId(), "Should have key_id from token claims")
	})

	s.Run("expired tokens are still rejected", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Expired Token Parent")

		// Derive token with very short TTL (1 second)
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("1s")
		tokenResp := s.sdkDeriveToken(ctx, req)
		derivedJWT := tokenResp.Token.GetToken()

		// Poll until the token expires and verification reports it as inactive.
		s.Eventually(func() bool {
			return !s.sdkVerify(ctx, derivedJWT).GetIsValid()
		}, 5*time.Second, 50*time.Millisecond, "expired JWT should be rejected")
	})

	s.Run("cannot derive NEW tokens from revoked parent", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Revoked Derivation Parent")

		// Revoke the parent key
		s.sdkRevokeIssuedAPIKeyWithReason(ctx, apiKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// Attempt to derive token from revoked parent should fail
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")

		// This should fail because parent is revoked
		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.AdminDeriveToken(ctx).DeriveTokenRequest(*req).Execute()
		if httpResp != nil && httpResp.Body != nil {
			_ = httpResp.Body.Close()
		}
		s.Error(err, "Should not be able to derive token from revoked parent")
	})

	s.Run("multiple derived tokens all remain valid after parent revocation", func() {
		apiKey, secret := s.testServer.CreateTestAPIKey(s.T(), "Multiple Tokens Cascading Parent")

		// Derive multiple JWT tokens
		derivedTokens := make([]string, 0, 3)
		for i := range 3 {
			req := client.NewDeriveTokenRequest()
			req.SetCredential(secret)
			req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
			req.SetTtl("3600s")
			req.SetCustomClaims(map[string]any{
				"session_id": i,
			})
			tokenResp := s.sdkDeriveToken(ctx, req)
			derivedTokens = append(derivedTokens, tokenResp.Token.GetToken())
		}

		// Verify all tokens work before revocation
		for i, token := range derivedTokens {
			resp := s.sdkVerify(ctx, token)
			s.True(resp.GetIsValid(), "Token %d should be valid before revocation", i)
		}

		// Revoke parent key
		s.sdkRevokeIssuedAPIKeyWithReason(ctx, apiKey.GetKeyId(), client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE)

		// All derived tokens remain valid (stateless capability model)
		for i, token := range derivedTokens {
			resp := s.sdkVerify(ctx, token)
			s.True(resp.GetIsValid(), "Token %d should remain valid after parent revocation (stateless)", i)
			s.NotEmpty(resp.GetKeyId(), "Should have key_id from token claims")
		}
	})
}

func (s *APIKeyE2ETestSuite) TestDerivedTokenReDerivationPrevented() {
	ctx := s.T().Context()

	s.Run("derived JWT cannot be used to derive another token", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Re-Derive JWT Parent")

		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)
		derivedJWT := tokenResp.Token.GetToken()

		reReq := client.NewDeriveTokenRequest()
		reReq.SetCredential(derivedJWT)
		reReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		reReq.SetTtl("3600s")

		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.AdminDeriveToken(ctx).DeriveTokenRequest(*reReq).Execute()
		// Spec: derived tokens must be rejected with HTTP 400 (bad_request errdef code).
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("derived macaroon cannot be used to derive another token", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Re-Derive Macaroon Parent")

		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)
		derivedMacaroon := tokenResp.Token.GetToken()

		reReq := client.NewDeriveTokenRequest()
		reReq.SetCredential(derivedMacaroon)
		reReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		reReq.SetTtl("3600s")

		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.AdminDeriveToken(ctx).DeriveTokenRequest(*reReq).Execute()
		// Spec: derived tokens must be rejected with HTTP 400 (bad_request errdef code).
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})
}

func (s *APIKeyE2ETestSuite) TestJWTCustomClaimsPreservation() {
	ctx := s.T().Context()

	s.Run("custom claims are preserved in JWT and returned on verification", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Custom Claims Test")

		// Derive JWT with rich custom claims
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		req.SetCustomClaims(map[string]any{
			"user_id":    "user-12345",
			"session_id": "sess-abcdef",
			"ip_address": "192.168.1.100",
			"features":   []any{"gpt-4", "vision", "dalle"},
			"limits": map[string]any{
				"max_tokens":       4000,
				"requests_per_min": 100,
			},
		})
		tokenResp := s.sdkDeriveToken(ctx, req)
		derivedJWT := tokenResp.Token.GetToken()

		// Verify JWT and check custom claims are returned
		verifyResp := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyResp.GetIsValid())

		// Verify custom claims are present in metadata
		s.NotNil(verifyResp.Metadata, "Metadata should contain custom claims")

		metadata := verifyResp.Metadata
		s.Equal("user-12345", metadata["user_id"])
		s.Equal("sess-abcdef", metadata["session_id"])
		s.Equal("192.168.1.100", metadata["ip_address"])

		// Verify nested structures are preserved
		features, ok := metadata["features"].([]any)
		s.True(ok, "features should be an array")
		s.Contains(features, "gpt-4")
		s.Contains(features, "vision")

		limits, ok := metadata["limits"].(map[string]any)
		s.True(ok, "limits should be a map")
		s.InDelta(float64(4000), limits["max_tokens"], 0.001)
	})

	s.Run("JWT without custom claims returns empty metadata", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "No Claims Test")

		// Derive JWT without custom claims
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)

		// Verify JWT
		verifyResp := s.sdkVerify(ctx, tokenResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())

		// Metadata should be nil or empty
		if verifyResp.Metadata != nil {
			s.Empty(verifyResp.Metadata, "Metadata should be empty when no custom claims provided")
		}
	})
}

func (s *APIKeyE2ETestSuite) TestJWTScopeRestriction() {
	ctx := s.T().Context()

	s.Run("derived JWT can have restricted scopes", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Broad Scope Key", "scope-test-user",
			[]string{"models:read", "models:write", "completions:create", "embeddings:create"},
			nil, nil)

		// Derive JWT with restricted scopes (subset of parent)
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		req.SetScopes([]string{"completions:create"})
		tokenResp := s.sdkDeriveToken(ctx, req)

		// Verify JWT has restricted scopes
		verifyResp := s.sdkVerify(ctx, tokenResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())

		s.Equal([]string{"completions:create"}, verifyResp.Scopes)
		s.NotContains(verifyResp.Scopes, "models:write", "Restricted JWT should not have parent's full scopes")
		s.NotContains(verifyResp.Scopes, "embeddings:create")
	})

	s.Run("JWT inherits parent scopes if none specified", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Parent Scope Key", "inherit-test",
			[]string{"read:data", "write:data"}, nil, nil)

		// Derive JWT without specifying scopes (should inherit)
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)

		// Verify JWT has parent's scopes
		verifyResp := s.sdkVerify(ctx, tokenResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())
		s.ElementsMatch([]string{"read:data", "write:data"}, verifyResp.Scopes)
	})
}

func (s *APIKeyE2ETestSuite) TestMacaroonScopeRestriction() {
	ctx := s.T().Context()

	s.Run("derived macaroon can have restricted scopes", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Broad Scope Macaroon Key", "macaroon-scope-test-user",
			[]string{"models:read", "models:write", "completions:create", "embeddings:create"},
			nil, nil)

		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		req.SetTtl("3600s")
		req.SetScopes([]string{"completions:create"})
		tokenResp := s.sdkDeriveToken(ctx, req)

		verifyResp := s.sdkVerify(ctx, tokenResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())

		s.Equal([]string{"completions:create"}, verifyResp.Scopes)
		s.NotContains(verifyResp.Scopes, "models:write", "Restricted macaroon should not have parent's full scopes")
		s.NotContains(verifyResp.Scopes, "embeddings:create")
	})

	s.Run("macaroon inherits parent scopes if none specified", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Parent Scope Macaroon Key", "macaroon-inherit-test",
			[]string{"read:data", "write:data"}, nil, nil)

		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		req.SetTtl("3600s")
		tokenResp := s.sdkDeriveToken(ctx, req)

		verifyResp := s.sdkVerify(ctx, tokenResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())
		s.ElementsMatch([]string{"read:data", "write:data"}, verifyResp.Scopes)
	})
}

func (s *APIKeyE2ETestSuite) TestHMACSecretNonExposure() {
	ctx := s.T().Context()

	s.Run("HMAC signing secret is never exposed via API", func() {
		// Issue an API key and capture the secret returned at creation time.
		issueReq := client.NewIssueAPIKeyRequest()
		issueReq.SetName("HMAC Non-Exposure Test")
		issueReq.SetActorId("hmac-test-user")
		issueReq.SetScopes([]string{"read", "write"})
		issueResp := s.sdkIssueAPIKey(ctx, issueReq)
		secret := issueResp.GetSecret()
		keyID := issueResp.IssuedApiKey.GetKeyId()
		s.NotEmpty(secret, "IssueAPIKey must return a secret on creation")

		// GET single issued key must not contain the secret.
		getResp := s.sdkGetIssuedAPIKey(ctx, keyID)
		getJSON, err := json.Marshal(getResp)
		s.Require().NoError(err)
		s.NotContains(string(getJSON), secret,
			"GET issued key response must not contain the HMAC secret")

		// LIST issued keys must not contain the secret.
		actorID := "hmac-test-user"
		listResp := s.sdkListIssuedAPIKeys(ctx, nil, nil, &actorID, nil)
		listJSON, err := json.Marshal(listResp)
		s.Require().NoError(err)
		s.NotContains(string(listJSON), secret,
			"LIST issued keys response must not contain the HMAC secret")

		// JWKS endpoint must not contain HMAC key material.
		jwksResp := s.sdkGetJWKS(ctx)
		jwksJSON, err := json.Marshal(jwksResp)
		s.Require().NoError(err)
		s.NotContains(string(jwksJSON), secret,
			"JWKS response must not contain the HMAC secret")

		// Verify JWKS has no symmetric key types.
		keys, _ := jwksResp.Jwks["keys"].([]any)
		for _, k := range keys {
			key, _ := k.(map[string]any)
			s.NotEqual("oct", key["kty"],
				"JWKS must not contain symmetric (oct) key types")
			s.NotContains(key, "k",
				"JWKS must not expose raw symmetric key material")
		}
	})
}

func (s *APIKeyE2ETestSuite) TestDerivedTokenReDerivationPreventedCrossAlgorithm() {
	ctx := s.T().Context()

	s.Run("derived JWT cannot derive a macaroon", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Cross Re-Derive JWT->Mac")

		// Derive a JWT from the API key.
		jwtReq := client.NewDeriveTokenRequest()
		jwtReq.SetCredential(secret)
		jwtReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		jwtReq.SetTtl("3600s")
		jwtResp := s.sdkDeriveToken(ctx, jwtReq)
		derivedJWT := jwtResp.Token.GetToken()

		// Attempt to derive a macaroon using the derived JWT as credential.
		reReq := client.NewDeriveTokenRequest()
		reReq.SetCredential(derivedJWT)
		reReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		reReq.SetTtl("3600s")

		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.AdminDeriveToken(ctx).DeriveTokenRequest(*reReq).Execute()
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("derived macaroon cannot derive a JWT", func() {
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "Cross Re-Derive Mac->JWT")

		// Derive a macaroon from the API key.
		macReq := client.NewDeriveTokenRequest()
		macReq.SetCredential(secret)
		macReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		macReq.SetTtl("3600s")
		macResp := s.sdkDeriveToken(ctx, macReq)
		derivedMacaroon := macResp.Token.GetToken()

		// Attempt to derive a JWT using the derived macaroon as credential.
		reReq := client.NewDeriveTokenRequest()
		reReq.SetCredential(derivedMacaroon)
		reReq.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		reReq.SetTtl("3600s")

		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.AdminDeriveToken(ctx).DeriveTokenRequest(*reReq).Execute()
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})
}

func (s *APIKeyE2ETestSuite) TestMacaroonScopeEscalationPrevention() {
	ctx := s.T().Context()

	s.Run("macaroon with restricted scopes only has requested subset", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Macaroon Scope Escalation Key", "scope-escalation-user",
			[]string{"read", "write", "admin"}, nil, nil)

		// Derive macaroon with restricted scope (subset of parent).
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		req.SetTtl("3600s")
		req.SetScopes([]string{"read"})
		tokenResp := s.sdkDeriveToken(ctx, req)

		// Verify the derived macaroon only has the restricted scope.
		verifyResp := s.sdkVerify(ctx, tokenResp.Token.GetToken())
		s.True(verifyResp.GetIsValid())
		s.Equal([]string{"read"}, verifyResp.Scopes,
			"derived macaroon must only contain the requested subset of scopes")
		s.NotContains(verifyResp.Scopes, "write")
		s.NotContains(verifyResp.Scopes, "admin")
	})

	s.Run("macaroon derivation with scope not in parent is rejected", func() {
		_, secret := s.testServer.CreateTestAPIKeyWithOptions(s.T(),
			"Macaroon Scope Escalation Reject Key", "scope-escalation-reject-user",
			[]string{"read", "write", "admin"}, nil, nil)

		// Attempt to derive macaroon with a scope not present in the parent.
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON)
		req.SetTtl("3600s")
		req.SetScopes([]string{"delete"})

		apiClient := s.setupSDKClient()
		_, httpResp, err := apiClient.APIKeysAPI.AdminDeriveToken(ctx).DeriveTokenRequest(*req).Execute()
		s.Require().Error(err, "deriving with out-of-parent scope must fail")
		s.Require().NotNil(httpResp, "HTTP response should not be nil")
		s.closeBody(httpResp)
		s.Contains([]int{http.StatusBadRequest, http.StatusForbidden}, httpResp.StatusCode,
			"scope escalation must be rejected with 400 or 403")
	})
}

// TestJWKRotationInvalidatesDerivedTokens verifies that rotating the JWT signing
// key invalidates existing derived JWTs when using revoke mode, and preserves
// them when using graceful mode.
func (s *APIKeyE2ETestSuite) TestJWKRotationInvalidatesDerivedTokens() {
	ctx := s.T().Context()

	deriveJWT := func(secret string) string {
		s.T().Helper()
		req := client.NewDeriveTokenRequest()
		req.SetCredential(secret)
		req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
		req.SetTtl("3600s")
		resp := s.sdkDeriveToken(ctx, req)
		return resp.Token.GetToken()
	}

	// Each subtest mutates the signing key config. Save the original URLs and
	// restore them before each subtest so they don't interfere with each other.
	originalURLs := s.testServer.Provider.Strings(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs)
	resetSigningKeys := func() {
		s.T().Helper()
		s.Require().NoError(s.testServer.Provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, originalURLs))
	}

	s.Run("revoke mode invalidates existing derived JWTs", func() {
		resetSigningKeys()
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWK Rotation Revoke")

		// Derive JWT signed with the current key
		derivedJWT := deriveJWT(secret)

		// Verify it works before rotation
		verifyBefore := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyBefore.GetIsValid(), "Derived JWT should be valid before JWK rotation")

		// Rotate signing key: replace with a completely new key (revoke mode)
		newKeyURL := testutil.TestSigningKeyJWKSURL(s.T())
		s.Require().NoError(s.testServer.Provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{newKeyURL}))

		// The old derived JWT should now fail signature verification.
		// Use no-cache to bypass the verification result cache — in production,
		// this cache is the reason revoked signing keys don't take effect immediately.
		verifyAfter := s.sdkVerifyNoCache(ctx, derivedJWT)
		s.False(verifyAfter.GetIsValid(), "Derived JWT must be invalid after JWK rotation with revoke")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_SIGNATURE_INVALID, verifyAfter.GetErrorCode())
	})

	s.Run("graceful mode keeps existing derived JWTs valid", func() {
		resetSigningKeys()
		currentURLs := s.testServer.Provider.Strings(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs)
		s.Require().NotEmpty(currentURLs, "signing key URLs must be configured")

		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWK Rotation Graceful")

		// Derive JWT signed with the current key
		derivedJWT := deriveJWT(secret)

		verifyBefore := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyBefore.GetIsValid(), "Derived JWT should be valid before graceful rotation")

		// Graceful rotation: add a new key with a different kid but keep the old one.
		// Production keys use UUID-based kids so they never collide.
		_, newPriv, err := ed25519.GenerateKey(rand.Reader)
		s.Require().NoError(err)
		newKeyURL := testutil.TestSigningKeyJWKSURLWithKey(s.T(), newPriv, "test-signing-key-2")
		gracefulURLs := append([]string{newKeyURL}, currentURLs...)
		s.Require().NoError(s.testServer.Provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, gracefulURLs))

		// The old derived JWT should still verify because the old key is retained
		verifyAfter := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyAfter.GetIsValid(), "Derived JWT should remain valid after graceful JWK rotation")
	})

	s.Run("new tokens use new signing key after rotation", func() {
		resetSigningKeys()
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWK Rotation New Token")

		// Derive JWT with the old key
		oldJWT := deriveJWT(secret)

		verifyOld := s.sdkVerify(ctx, oldJWT)
		s.True(verifyOld.GetIsValid(), "Old JWT should be valid before rotation")

		// Rotate signing key (revoke mode)
		newKeyURL := testutil.TestSigningKeyJWKSURL(s.T())
		s.Require().NoError(s.testServer.Provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{newKeyURL}))

		// Derive a new JWT — it should be signed with the new key
		newJWT := deriveJWT(secret)

		// New JWT should be valid (signed with current key)
		verifyNew := s.sdkVerify(ctx, newJWT)
		s.True(verifyNew.GetIsValid(), "New JWT derived after rotation should be valid")

		// Old JWT should be invalid (old key is gone).
		// Use no-cache to bypass the verification result cache.
		verifyOldAfter := s.sdkVerifyNoCache(ctx, oldJWT)
		s.False(verifyOldAfter.GetIsValid(), "Old JWT must be invalid after JWK rotation with revoke")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_SIGNATURE_INVALID, verifyOldAfter.GetErrorCode())
	})

	s.Run("derived tokens skip verification cache", func() {
		resetSigningKeys()
		_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWK Rotation No Cache")

		derivedJWT := deriveJWT(secret)

		// Verify once — derived tokens should NOT be cached
		verifyBefore := s.sdkVerify(ctx, derivedJWT)
		s.True(verifyBefore.GetIsValid(), "Derived JWT should be valid before rotation")

		// Rotate signing key (revoke mode)
		newKeyURL := testutil.TestSigningKeyJWKSURL(s.T())
		s.Require().NoError(s.testServer.Provider.Set(ctx, config.KeyCredentialsDerivedTokensJWTSigningKeysURLs, []string{newKeyURL}))

		// Even without no-cache header, derived tokens are verified fresh every time
		verifyAfter := s.sdkVerify(ctx, derivedJWT)
		s.False(verifyAfter.GetIsValid(),
			"Derived JWT should be rejected after JWK rotation even without cache bypass")
		s.Equal(client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_SIGNATURE_INVALID, verifyAfter.GetErrorCode())
	})
}

// TestJWTKidHintRoutesToExpectedKey asserts that derived JWTs from the default
// test server include a protected-header kid that matches the server's sole
// advertised JWKS kid. Unlike the weaker "kid exists somewhere in JWKS" check,
// this verifies the full signing pipeline writes the key ID every verifier
// needs to pick the right public key.
func (s *APIKeyE2ETestSuite) TestJWTKidHintRoutesToExpectedKey() {
	ctx := s.T().Context()

	_, secret := s.testServer.CreateTestAPIKey(s.T(), "JWT Kid Routing")

	req := client.NewDeriveTokenRequest()
	req.SetCredential(secret)
	req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
	req.SetTtl("3600s")
	tokenResp := s.sdkDeriveToken(ctx, req)

	header := decodeJWTHeader(s.T(), tokenResp.Token.GetToken())

	jwksResp := s.sdkGetJWKS(ctx)
	keys, ok := jwksResp.Jwks["keys"].([]any)
	s.Require().True(ok, "JWKS keys must be an array")
	s.Require().Len(keys, 1, "default test server must expose exactly one signing key")

	only, ok := keys[0].(map[string]any)
	s.Require().True(ok, "JWKS entry must be a JSON object")
	s.Equal(only["kid"], header["kid"], "JWT header kid must equal the sole JWKS kid")
}

// TestJWTKidHintSelectsConfiguredKey is the regression guard for the
// signing_key_id selection logic. It boots a dedicated test server with two
// Ed25519 keys in the JWKS — where default selection would prefer kid-B because
// of use="sig" — and a signing_key_id hint pinning kid-A. The resulting JWT
// header kid must equal the hint, proving the hint overrides the default
// heuristic end-to-end through the HTTP data path.
func (s *APIKeyE2ETestSuite) TestJWTKidHintSelectsConfiguredKey() {
	t := s.T()
	ctx := t.Context()

	jwksURL := testutil.TestTwoKeyJWKSURL(t, "kid-A", "kid-B", true)
	const hintKID = "kid-A"

	ts := testutiltesting.NewTestServer(t, testutiltesting.WithConfigOverrides(map[string]any{
		config.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String(): []string{jwksURL},
		config.KeyCredentialsDerivedTokensJWTSigningKeyID.String():    hintKID,
	}))

	_, secret := ts.CreateTestAPIKey(t, "JWT Kid Hint Override")

	apiClient := newSDKClient(ts.HTTPURL)

	req := client.NewDeriveTokenRequest()
	req.SetCredential(secret)
	req.SetAlgorithm(client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT)
	req.SetTtl("3600s")
	tokenResp, httpResp, err := apiClient.APIKeysAPI.
		AdminDeriveToken(ctx).
		DeriveTokenRequest(*req).
		Execute()
	s.Require().NoError(err, "derive token on multi-key server")
	if httpResp != nil && httpResp.Body != nil {
		t.Cleanup(func() { _ = httpResp.Body.Close() })
	}
	s.Require().NotNil(tokenResp.Token)

	header := decodeJWTHeader(t, tokenResp.Token.GetToken())
	s.Equal(hintKID, header["kid"],
		"JWT header kid must equal signing_key_id hint even when another key carries use=sig")
}

// decodeJWTHeader splits a JWT and base64url-decodes the protected header.
func decodeJWTHeader(t testingT, jwtStr string) map[string]any {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	return header
}

// testingT is a minimal subset of the *testing.T surface used by decodeJWTHeader.
// It lets the helper accept both suite-owned tests and nested *testing.T values.
type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

// newSDKClient returns a fresh SDK client aimed at the given test server URL.
func newSDKClient(httpURL string) *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{{URL: httpURL}}
	return client.NewAPIClient(cfg)
}

// reviewed - @aeneasr - 2026-03-27
