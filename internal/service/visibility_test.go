package service_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ory/herodot"

	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// TestIssueAPIKey_Visibility tests the visibility field when issuing API keys.
func TestIssueAPIKey_Visibility(t *testing.T) {
	t.Parallel()

	t.Run("public visibility with configured prefix", func(t *testing.T) {
		t.Parallel()

		svc, ctx := setupTestAdminWithPublicPrefix(t, "pk_test")

		resp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:       "Public API Key",
			ActorId:    "user-pub-1",
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.IssuedApiKey)

		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC, resp.IssuedApiKey.Visibility)
		assert.True(t, strings.HasPrefix(resp.Secret, "pk_test_v1_"),
			"public key secret should start with pk_test_v1_, got: %s", resp.Secret)
	})

	t.Run("secret visibility is default", func(t *testing.T) {
		t.Parallel()

		svc, _, ctx := setupTestService(t)

		resp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    "Default Secret Key",
			ActorId: "user-sec-1",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.IssuedApiKey)

		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET, resp.IssuedApiKey.Visibility)
		assert.True(t, strings.HasPrefix(resp.Secret, "talos_v1_"),
			"secret key should start with talos_v1_, got: %s", resp.Secret)
	})

	t.Run("public visibility without configured prefix returns error", func(t *testing.T) {
		t.Parallel()

		// Use standard setupTestService which does NOT configure public_current
		svc, _, ctx := setupTestService(t)

		resp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:       "Should Fail Public Key",
			ActorId:    "user-fail-1",
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC,
		})
		require.Error(t, err)
		assert.Nil(t, resp)

		var herodotErr *herodot.DefaultError
		if errors.As(err, &herodotErr) {
			assert.Contains(t, herodotErr.ReasonField, "public key prefix not configured")
		} else {
			assert.Contains(t, err.Error(), "public key prefix not configured")
		}
	})

	t.Run("explicit secret visibility", func(t *testing.T) {
		t.Parallel()

		svc, ctx := setupTestAdminWithPublicPrefix(t, "pk_test")

		resp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:       "Explicit Secret Key",
			ActorId:    "user-sec-2",
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.IssuedApiKey)

		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET, resp.IssuedApiKey.Visibility)
		assert.True(t, strings.HasPrefix(resp.Secret, "talos_v1_"),
			"explicit secret key should use standard prefix, got: %s", resp.Secret)
	})
}

// TestImportAPIKey_Visibility tests the visibility field when importing API keys.
func TestImportAPIKey_Visibility(t *testing.T) {
	t.Parallel()

	t.Run("import with public visibility", func(t *testing.T) {
		t.Parallel()

		svc, _, ctx := setupTestService(t)

		resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:     "external_public_key_12345678",
			Name:       "Public Imported Key",
			ActorId:    "import-owner-pub",
			Ttl:        durationpb.New(24 * time.Hour),
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp)

		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC, resp.Visibility)

		// Retrieve and verify visibility persisted
		getResp, err := svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{
			KeyId: resp.KeyId,
		})
		require.NoError(t, err)
		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC, getResp.Visibility)
	})

	t.Run("import with default visibility is secret", func(t *testing.T) {
		t.Parallel()

		svc, _, ctx := setupTestService(t)

		resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:  "external_default_vis_key_12345678",
			Name:    "Default Visibility Imported Key",
			ActorId: "import-owner-def",
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp)

		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET, resp.Visibility)
	})
}

// TestDeriveToken_VisibilityClaim tests that derived tokens include the correct visibility claim.
func TestDeriveToken_VisibilityClaim(t *testing.T) {
	t.Parallel()

	t.Run("public key produces public visibility claim in JWT", func(t *testing.T) {
		t.Parallel()

		svc, ctx := setupTestAdminWithPublicPrefix(t, "pk_test")
		ver := svc.Verifier()

		// Issue a PUBLIC key
		issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:       "Public Key for Token",
			ActorId:    "derive-pub-owner",
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC,
			Ttl:        durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, issueResp)

		// Derive a JWT from the public key
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: issueResp.Secret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, deriveResp.Token)

		// Parse the JWT without verification to inspect claims
		parsedToken, err := jwt.Parse([]byte(deriveResp.Token.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		var vis string
		err = parsedToken.Get("vis", &vis)
		require.NoError(t, err, "JWT should contain vis claim")
		assert.Equal(t, "public", vis)

		// Also verify the token is valid via the verifier
		verifyResult, _, err := ver.VerifyAPIKey(ctx, deriveResp.Token.Token)
		require.NoError(t, err)
		require.NotNil(t, verifyResult)
	})

	t.Run("secret key produces secret visibility claim in JWT", func(t *testing.T) {
		t.Parallel()

		svc, _, ctx := setupTestService(t)

		// Issue a SECRET key (default)
		issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    "Secret Key for Token",
			ActorId: "derive-sec-owner",
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)

		// Derive a JWT
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: issueResp.Secret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, deriveResp.Token)

		// Parse the JWT to inspect claims
		parsedToken, err := jwt.Parse([]byte(deriveResp.Token.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		var vis string
		err = parsedToken.Get("vis", &vis)
		require.NoError(t, err, "JWT should contain vis claim")
		assert.Equal(t, "secret", vis)
	})
}

// TestVerifyAPIKey_Visibility tests that verified API keys return correct visibility.
func TestVerifyAPIKey_Visibility(t *testing.T) {
	t.Parallel()

	t.Run("verify public issued key returns public visibility", func(t *testing.T) {
		t.Parallel()

		svc, ctx := setupTestAdminWithPublicPrefix(t, "pk_test")
		ver := svc.Verifier()

		// Issue a PUBLIC key
		issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:       "Public Key for Verify",
			ActorId:    "verify-pub-owner",
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC,
		})
		require.NoError(t, err)

		// Verify the key
		dbKey, _, err := ver.VerifyAPIKey(ctx, issueResp.Secret)
		require.NoError(t, err)
		require.NotNil(t, dbKey)

		assert.Equal(t, int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC), dbKey.Visibility)
	})

	t.Run("verify secret issued key returns secret visibility", func(t *testing.T) {
		t.Parallel()

		svc, _, ctx := setupTestService(t)
		ver := svc.Verifier()

		// Issue a SECRET key (default)
		issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    "Secret Key for Verify",
			ActorId: "verify-sec-owner",
		})
		require.NoError(t, err)

		// Verify the key
		dbKey, _, err := ver.VerifyAPIKey(ctx, issueResp.Secret)
		require.NoError(t, err)
		require.NotNil(t, dbKey)

		assert.Equal(t, int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET), dbKey.Visibility)
	})
}

// TestRotateIssuedAPIKey_Visibility tests that rotated keys inherit visibility.
func TestRotateIssuedAPIKey_Visibility(t *testing.T) {
	t.Parallel()

	t.Run("rotated public key inherits public visibility", func(t *testing.T) {
		t.Parallel()

		svc, ctx := setupTestAdminWithPublicPrefix(t, "pk_test")

		// Issue a PUBLIC key
		issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:       "Public Key to Rotate",
			ActorId:    "rotate-pub-owner",
			Visibility: talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC,
			Ttl:        durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, issueResp)

		// Rotate without specifying visibility
		rotateResp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
			KeyId: issueResp.IssuedApiKey.KeyId,
		})
		require.NoError(t, err)
		require.NotNil(t, rotateResp)
		require.NotNil(t, rotateResp.IssuedApiKey)

		// New key should inherit PUBLIC visibility
		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC, rotateResp.IssuedApiKey.Visibility)

		// New secret should use the public prefix
		assert.True(t, strings.HasPrefix(rotateResp.Secret, "pk_test_v1_"),
			"rotated public key secret should use public prefix, got: %s", rotateResp.Secret)

		// Old key should also show PUBLIC visibility
		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC, rotateResp.OldIssuedApiKey.Visibility)
	})

	t.Run("rotated secret key stays secret", func(t *testing.T) {
		t.Parallel()

		svc, _, ctx := setupTestService(t)

		// Issue a SECRET key
		issueResp, err := svc.IssueAPIKey(ctx, &talosv2alpha1.IssueAPIKeyRequest{
			Name:    "Secret Key to Rotate",
			ActorId: "rotate-sec-owner",
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)

		// Rotate without specifying visibility
		rotateResp, err := svc.RotateIssuedAPIKey(ctx, &talosv2alpha1.RotateIssuedAPIKeyRequest{
			KeyId: issueResp.IssuedApiKey.KeyId,
		})
		require.NoError(t, err)
		require.NotNil(t, rotateResp)

		// New key should stay SECRET
		assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET, rotateResp.IssuedApiKey.Visibility)

		// Secret should use standard prefix
		assert.True(t, strings.HasPrefix(rotateResp.Secret, "talos_v1_"),
			"rotated secret key should use standard prefix, got: %s", rotateResp.Secret)
	})
}

// reviewed - @aeneasr - 2026-03-26
