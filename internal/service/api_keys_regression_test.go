package service_test

import (
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/errdef"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// TestDeriveToken_ScopeRestriction tests that derived tokens correctly restrict scopes
// Regression test for bug where derived tokens inherited all parent scopes instead of requested subset
func TestDeriveToken_ScopeRestriction(t *testing.T) {
	t.Parallel()

	svc, verifier, ctx := setupTestService(t)

	// Create a master API key with multiple scopes
	createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "master-key",
		ActorId: "test-org",
		Scopes:  []string{"models:read", "models:write", "completions:create", "embeddings:create"},
	})
	require.NoError(t, err)
	require.NotNil(t, createResp)
	masterSecret := createResp.Secret

	t.Run("derive token with restricted scopes", func(t *testing.T) {
		// Derive a token with only one scope (should restrict from 4 to 1)
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: masterSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"completions:create"}, // Only 1 of 4 parent scopes
		})

		require.NoError(t, err, "DeriveToken should succeed with subset of parent scopes")
		require.NotNil(t, deriveResp)
		require.NotNil(t, deriveResp.Token)

		// Verify the derived token has restricted scopes
		assert.Equal(t, []string{"completions:create"}, deriveResp.Token.Scopes)
		assert.NotContains(t, deriveResp.Token.Scopes, "models:read")
		assert.NotContains(t, deriveResp.Token.Scopes, "models:write")
		assert.NotContains(t, deriveResp.Token.Scopes, "embeddings:create")

		// Verify the token itself when parsed
		derivedToken := deriveResp.Token.Token
		require.NotEmpty(t, derivedToken)

		// Verify the derived token can be verified (proves it's valid)
		verifyKey, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err)
		require.NotNil(t, verifyKey)
		// Note: verifyKey.Scopes is a JSON string, not []string, so we don't compare it here
		// The important verification is that deriveResp.Token.Scopes is correct (checked above)
	})

	t.Run("derive token with multiple restricted scopes", func(t *testing.T) {
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: masterSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(30 * time.Minute),
			Scopes:     []string{"models:read", "completions:create"}, // 2 of 4 scopes
		})

		require.NoError(t, err)
		require.NotNil(t, deriveResp)
		assert.Equal(t, []string{"models:read", "completions:create"}, deriveResp.Token.Scopes)
	})

	t.Run("derive token without specifying scopes inherits all parent scopes", func(t *testing.T) {
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: masterSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			// Scopes intentionally omitted - should inherit all parent scopes
		})

		require.NoError(t, err)
		require.NotNil(t, deriveResp)

		// Should have all 4 parent scopes
		assert.Len(t, deriveResp.Token.Scopes, 4)
		assert.Contains(t, deriveResp.Token.Scopes, "models:read")
		assert.Contains(t, deriveResp.Token.Scopes, "models:write")
		assert.Contains(t, deriveResp.Token.Scopes, "completions:create")
		assert.Contains(t, deriveResp.Token.Scopes, "embeddings:create")
	})
}

// TestDeriveToken_ScopeValidation tests that derived tokens cannot have scopes not present in parent
// Regression test for scope validation (should reject scopes not in parent key)
func TestDeriveToken_ScopeValidation(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Create a parent key with limited scopes
	createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "limited-key",
		ActorId: "test-user",
		Scopes:  []string{"read", "write"},
	})
	require.NoError(t, err)
	parentSecret := createResp.Secret

	t.Run("reject token with scope not in parent", func(t *testing.T) {
		_, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"admin"}, // "admin" not in parent scopes
		})

		require.Error(t, err, "DeriveToken should reject scope not present in parent")
		// Check that it's a forbidden error
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr), "error should be a herodot error")
		require.True(t, errors.Is(err, errdef.ErrForbidden()), "error should be ErrForbidden")
		// Check the reason contains the expected message
		assert.Contains(t, herodotErr.ReasonField, "requested scope 'admin' not available in parent key")
	})

	t.Run("reject token with mixed valid and invalid scopes", func(t *testing.T) {
		_, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"read", "delete"}, // "read" valid, "delete" invalid
		})

		require.Error(t, err, "DeriveToken should reject if any scope is invalid")
		// Check that it's a forbidden error
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr), "error should be a herodot error")
		require.True(t, errors.Is(err, errdef.ErrForbidden()), "error should be ErrForbidden")
		// Check the reason contains the expected message
		assert.Contains(t, herodotErr.ReasonField, "requested scope 'delete' not available in parent key")
	})

	t.Run("accept token with valid subset of parent scopes", func(t *testing.T) {
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"read"}, // Valid subset
		})

		require.NoError(t, err, "DeriveToken should accept valid subset of scopes")
		require.NotNil(t, deriveResp)
		assert.Equal(t, []string{"read"}, deriveResp.Token.Scopes)
	})
}

// reviewed - @aeneasr - 2026-03-26
