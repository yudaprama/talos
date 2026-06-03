package service_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"buf.build/go/protovalidate"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/clientip"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/crypto"
	cryptotoken "github.com/ory/talos/internal/crypto/token"
	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/metrics"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/testutil"

	"github.com/prometheus/client_golang/prometheus"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// TestIssueAPIKey tests the IssueApiKey service method
func TestIssueAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		req         *talosv2alpha1.IssueApiKeyRequest
		wantErr     bool
		errContains string
		validate    func(*testing.T, *talosv2alpha1.IssueApiKeyResponse)
	}{
		{
			name: "success - create with all fields",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "Test API Key",
				ActorId: "user-123",
				Scopes:  []string{"read:users", "write:users"},
				Ttl:     durationpb.New(24 * time.Hour),
				Metadata: func() *structpb.Struct {
					m, _ := structpb.NewStruct(map[string]any{
						"app": "test-app",
						"env": "production",
					})
					return m
				}(),
			},
			wantErr: false,
			validate: func(t *testing.T, resp *talosv2alpha1.IssueApiKeyResponse) {
				t.Helper()
				require.NotNil(t, resp.IssuedApiKey)
				assert.NotEmpty(t, resp.IssuedApiKey.KeyId)
				assert.NotEmpty(t, resp.Secret)
				assert.Equal(t, "Test API Key", resp.IssuedApiKey.Name)
				assert.Equal(t, "user-123", resp.IssuedApiKey.ActorId)
				assert.Equal(t, []string{"read:users", "write:users"}, resp.IssuedApiKey.Scopes)
				assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE, resp.IssuedApiKey.Status)
				assert.NotNil(t, resp.IssuedApiKey.ExpireTime)
				assert.NotNil(t, resp.IssuedApiKey.Metadata)
			},
		},
		{
			name: "success - create with minimal fields",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "Minimal Key",
				ActorId: "service-456",
			},
			wantErr: false,
			validate: func(t *testing.T, resp *talosv2alpha1.IssueApiKeyResponse) {
				t.Helper()
				require.NotNil(t, resp.IssuedApiKey)
				assert.NotEmpty(t, resp.Secret)
				assert.Equal(t, "Minimal Key", resp.IssuedApiKey.Name)
				assert.Equal(t, "service-456", resp.IssuedApiKey.ActorId)
				assert.Empty(t, resp.IssuedApiKey.Scopes)
				// Default TTL should be applied
				assert.NotNil(t, resp.IssuedApiKey.ExpireTime)
			},
		},
		{
			name: "error - missing name",
			req: &talosv2alpha1.IssueApiKeyRequest{
				ActorId: "user-123",
			},
			wantErr:     true,
			errContains: "name: value length must be at least 1",
		},
		{
			name: "error - missing actor_id",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name: "Test Key",
			},
			wantErr:     true,
			errContains: "actor_id: value length must be at least 1",
		},
		{
			name: "success - empty scopes array",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "No Scope Key",
				ActorId: "user-123",
				Scopes:  []string{},
			},
			wantErr: false,
			validate: func(t *testing.T, resp *talosv2alpha1.IssueApiKeyResponse) {
				t.Helper()
				assert.Empty(t, resp.IssuedApiKey.Scopes)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, _, ctx := setupTestService(t)

			resp, err := svc.IssueApiKey(ctx, tt.req)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					// For herodot errors, check the reason field
					var herodotErr *herodot.DefaultError
					if errors.As(err, &herodotErr) {
						assert.Contains(t, herodotErr.ReasonField, tt.errContains)
					} else {
						assert.Contains(t, err.Error(), tt.errContains)
					}
				}
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				if tt.validate != nil {
					tt.validate(t, resp)
				}
			}
		})
	}
}

// TestGetIssuedAPIKey tests the GetIssuedAPIKey service method
func TestGetIssuedAPIKey(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Create a test key
	createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Test Get Key",
		ActorId: "user-789",
		Scopes:  []string{"read", "write"},
	})
	require.NoError(t, err)
	keyID := createResp.IssuedApiKey.KeyId

	tests := []struct {
		name        string
		keyID       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "success - get existing key",
			keyID:   keyID,
			wantErr: false,
		},
		{
			name:        "error - key not found",
			keyID:       "non-existent-key-id-12345",
			wantErr:     true,
			errContains: "not found",
		},
		{
			name:        "error - empty key ID",
			keyID:       "",
			wantErr:     true,
			errContains: "key_id: value length must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp, err := svc.GetIssuedAPIKey(ctx, &talosv2alpha1.GetIssuedApiKeyRequest{
				KeyId: tt.keyID,
			})

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					// For herodot errors, check the reason field
					var herodotErr *herodot.DefaultError
					if errors.As(err, &herodotErr) {
						assert.Contains(t, herodotErr.ReasonField, tt.errContains)
					} else {
						assert.Contains(t, err.Error(), tt.errContains)
					}
				}
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				// resp is directly IssuedApiKey
				assert.Equal(t, keyID, resp.KeyId)
				assert.Equal(t, "Test Get Key", resp.Name)
				assert.Equal(t, []string{"read", "write"}, resp.Scopes)
			}
		})
	}
}

// TestListIssuedAPIKeys tests the ListIssuedAPIKeys service method
func TestListIssuedAPIKeys(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	// Create multiple test keys with different attributes
	keys := []struct {
		name    string
		actorID string
		scopes  []string
	}{
		{"Key 1", "user-1", []string{"read"}},
		{"Key 2", "user-1", []string{"write"}},
		{"Key 3", "service-1", []string{"admin"}},
		{"Key 4", "user-2", []string{"read", "write"}},
		{"Key 5", "service-2", []string{"read"}},
	}

	for _, k := range keys {
		_, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    k.name,
			ActorId: k.actorID,
			Scopes:  k.scopes,
		})
		require.NoError(t, err)
	}

	tests := []struct {
		name            string
		req             *talosv2alpha1.ListIssuedApiKeysRequest
		wantMinCount    int
		wantHasNextPage bool
	}{
		{
			name: "list all keys",
			req: &talosv2alpha1.ListIssuedApiKeysRequest{
				PageSize: 50,
			},
			wantMinCount:    5,
			wantHasNextPage: false,
		},
		{
			name: "filter by actor_id user-1",
			req: &talosv2alpha1.ListIssuedApiKeysRequest{
				Filter:   `actor_id="user-1"`,
				PageSize: 50,
			},
			wantMinCount:    2,
			wantHasNextPage: false,
		},
		{
			name: "filter by status active with owner",
			req: &talosv2alpha1.ListIssuedApiKeysRequest{
				Filter:   `actor_id="user-1" AND status=KEY_STATUS_ACTIVE`,
				PageSize: 50,
			},
			wantMinCount:    2,
			wantHasNextPage: false,
		},
		{
			name: "pagination - first page",
			req: &talosv2alpha1.ListIssuedApiKeysRequest{
				PageSize: 2,
			},
			wantMinCount:    2,
			wantHasNextPage: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.ListIssuedAPIKeys(ctx, tt.req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.GreaterOrEqual(t, len(resp.IssuedApiKeys), tt.wantMinCount)

			if tt.wantHasNextPage {
				assert.NotEmpty(t, resp.NextPageToken)
			}
		})
	}

	// Test pagination continuation
	t.Run("pagination - multiple pages", func(t *testing.T) {
		// Get first page
		resp1, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedApiKeysRequest{
			PageSize: 2,
		})
		require.NoError(t, err)
		assert.Len(t, resp1.IssuedApiKeys, 2)
		assert.NotEmpty(t, resp1.NextPageToken)

		// Get second page
		resp2, err := svc.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedApiKeysRequest{
			PageSize:  2,
			PageToken: resp1.NextPageToken,
		})
		require.NoError(t, err)
		assert.Len(t, resp2.IssuedApiKeys, 2)

		// Verify no overlap
		page1IDs := make(map[string]bool)
		for _, key := range resp1.IssuedApiKeys {
			page1IDs[key.KeyId] = true
		}
		for _, key := range resp2.IssuedApiKeys {
			assert.False(t, page1IDs[key.KeyId], "pages should not overlap")
		}
	})
}

// TestRevokeIssuedAPIKey tests the RevokeIssuedApiKey service method
func TestRevokeIssuedAPIKey(t *testing.T) {
	t.Parallel()

	svc, verifier, ctx := setupTestService(t)

	// Create a test key for revocation
	createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Key to Revoke",
		ActorId: "user-revoke",
	})
	require.NoError(t, err)
	keyID := createResp.IssuedApiKey.KeyId
	secret := createResp.Secret

	tests := []struct {
		name        string
		keyID       string
		reason      talosv2alpha1.RevocationReason
		wantErr     bool
		errContains string
	}{
		{
			name:    "success - revoke key with reason",
			keyID:   keyID,
			reason:  talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr: false,
		},
		{
			name:        "error - revoke non-existent key",
			keyID:       uuid.Must(uuid.NewV4()).String(),
			reason:      talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr:     true,
			errContains: "API key not found",
		},
		{
			name:        "error - malformed key ID",
			keyID:       "not-a-valid-uuid",
			reason:      talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr:     true,
			errContains: "API key not found",
		},
		{
			name:        "error - empty key ID",
			keyID:       "",
			reason:      talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr:     true,
			errContains: "key_id: value length must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.RevokeIssuedApiKey(ctx, &talosv2alpha1.RevokeIssuedApiKeyRequest{
				KeyId:  tt.keyID,
				Reason: tt.reason,
			})

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					// For herodot errors, check the reason field
					var herodotErr *herodot.DefaultError
					if errors.As(err, &herodotErr) {
						assert.Contains(t, herodotErr.ReasonField, tt.errContains)
					} else {
						assert.Contains(t, err.Error(), tt.errContains)
					}
				}
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				// Verify revocation by fetching the key
				getResp, getErr := svc.GetIssuedAPIKey(ctx, &talosv2alpha1.GetIssuedApiKeyRequest{KeyId: tt.keyID})
				require.NoError(t, getErr)
				assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, getResp.Status)
			}
		})
	}

	// Test that revoked key cannot be verified
	t.Run("revoked key fails verification", func(t *testing.T) {
		_, _, err := verifier.VerifyAPIKey(ctx, secret)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	// Test double revocation returns conflict
	t.Run("double revocation returns conflict", func(t *testing.T) {
		// Try to revoke again
		_, err := svc.RevokeIssuedApiKey(ctx, &talosv2alpha1.RevokeIssuedApiKeyRequest{
			KeyId:  keyID,
			Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "conflict")
	})
}

// TestVerifyAPIKey_DerivedTokens tests verification of derived JWT tokens
// This is a CRITICAL test - derived tokens were created but never verified!
func TestVerifyAPIKey_DerivedTokens(t *testing.T) {
	t.Parallel()

	svc, verifier, ctx := setupTestService(t)

	// Create a parent API key
	createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Parent Key",
		ActorId: "service-token-test",
		Scopes:  []string{"read:users", "write:users", "admin"},
		Ttl:     durationpb.New(24 * time.Hour),
	})
	require.NoError(t, err)
	parentSecret := createResp.Secret

	t.Run("verify valid derived token", func(t *testing.T) {
		// Derive a token
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, deriveResp.Token)
		derivedToken := deriveResp.Token.Token

		// VERIFY THE DERIVED TOKEN (this is what was missing!)
		verifyResult, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err, "derived token should be verifiable")
		require.NotNil(t, verifyResult)

		assert.Equal(t, createResp.IssuedApiKey.KeyId, verifyResult.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), verifyResult.Status)
		assert.NotEmpty(t, verifyResult.Scopes)
	})

	t.Run("verify derived token with restricted scopes", func(t *testing.T) {
		// Derive token with restricted scopes
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"read:users"}, // Only 1 of 3 parent scopes
		})
		require.NoError(t, err)
		derivedToken := deriveResp.Token.Token

		// Verify the derived token
		verifyResult, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err)
		require.NotNil(t, verifyResult)

		// Scopes should be restricted
		assert.Contains(t, string(verifyResult.Scopes), "read:users")
	})

	t.Run("derive with scope not in parent key is forbidden", func(t *testing.T) {
		_, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"write:billing"}, // not in parent ["read:users", "write:users", "admin"]
		})
		require.Error(t, err)
		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, 403, herr.CodeField)
		assert.Contains(t, herr.Reason(), "write:billing")
	})

	t.Run("verify expired derived token fails", func(t *testing.T) {
		// Build a pre-expired JWT using a fresh service instance with a known
		// signing key. This avoids any time.Sleep in the test.
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		const expiredKeyID = "expired-test-key"
		jwksURL := testutil.TestSigningKeyJWKSURLWithKey(t, privKey, expiredKeyID)

		expiredCtx := t.Context()
		expiredDriver, driverErr := testutil.InitDriver(t, "")
		require.NoError(t, driverErr)
		t.Cleanup(func() { _ = expiredDriver.Close() })

		expiredProvider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(map[string]any{
			config.KeyCredentialsDerivedTokensJWTSigningKeysURLs.String(): []string{jwksURL},
		}))
		expiredKeyService, ksErr := crypto.NewKeyService(expiredCtx, expiredProvider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
		require.NoError(t, ksErr)
		pv, pvErr := protovalidate.New()
		require.NoError(t, pvErr)

		expiredTracker := lastused.New(expiredCtx, expiredDriver, lastused.Config{
			QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
		})
		t.Cleanup(expiredTracker.Close)

		expiredSvc := service.NewAdminFromProvider(expiredDriver, expiredProvider, events.NewNoopEmitter(), expiredKeyService, cache.NewNoopCache[db.IssuedApiKey](), pv, metrics.New(prometheus.NewRegistry()), expiredTracker)
		expiredVerifier := expiredSvc.Verifier()

		// Issue a key in the expired service
		expiredCreateResp, createErr := expiredSvc.IssueApiKey(expiredCtx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "Expired Token Parent",
			ActorId: "expired-owner",
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, createErr)

		// Manually build a JWT with exp already in the past using the same private key.
		signer, signerErr := cryptotoken.NewJWTSigner(privKey, expiredKeyID)
		require.NoError(t, signerErr)

		claims := cryptotoken.NewClaims()
		claims.SetTokenID(crypto.GenerateKeyID())
		claims.SetSubject(expiredCreateResp.IssuedApiKey.KeyId)
		claims.SetKeyID(expiredCreateResp.IssuedApiKey.KeyId)
		claims.SetParentID(expiredCreateResp.IssuedApiKey.KeyId)
		now := time.Now().UTC()
		claims.SetIssuedAt(now.Add(-2 * time.Second))
		claims.SetNotBefore(now.Add(-2 * time.Second))
		claims.SetExpiration(now.Add(-1 * time.Second)) // already expired
		claims.SetTokenType(cryptotoken.TokenTypeDerived)

		expiredToken, signErr := signer.Sign(expiredCtx, claims)
		require.NoError(t, signErr)

		// Verify should fail because the token is expired
		_, _, err = expiredVerifier.VerifyAPIKey(expiredCtx, expiredToken)
		require.Error(t, err, "expired token should fail verification")
	})

	t.Run("derived token remains valid after parent revocation", func(t *testing.T) {
		// Derive token while parent is active
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: parentSecret,
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		derivedToken := deriveResp.Token.Token

		// Revoke the parent key
		_, err = svc.RevokeIssuedApiKey(ctx, &talosv2alpha1.RevokeIssuedApiKeyRequest{
			KeyId:  createResp.IssuedApiKey.KeyId,
			Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		})
		require.NoError(t, err)

		// Derived token remains valid (stateless capability model)
		result, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err, "derived token should remain valid after parent revocation (stateless)")
		require.NotNil(t, result)
	})

	t.Run("verify malformed token fails", func(t *testing.T) {
		malformedTokens := []string{
			"not-a-token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
			"",
			"12345",
		}

		for _, token := range malformedTokens {
			_, _, err := verifier.VerifyAPIKey(ctx, token)
			assert.Error(t, err, "malformed token should fail: %s", token)
		}
	})

	// todo more advesarial and unhappy path cases
}

// TestMetadataHandling tests metadata storage and retrieval
func TestMetadataHandling(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	t.Run("complex nested metadata", func(t *testing.T) {
		metadata, err := structpb.NewStruct(map[string]any{
			"app_version": "2.1.0",
			"environment": "production",
			"tags":        []any{"api", "v2alpha1", "premium"},
			"settings": map[string]any{
				"features": []any{"advanced", "analytics"},
				"limits": map[string]any{
					"rate":  1000,
					"burst": 100,
				},
			},
		})
		require.NoError(t, err)

		createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:     "Metadata Test Key",
			ActorId:  "service-meta",
			Metadata: metadata,
		})
		require.NoError(t, err)

		// Retrieve and verify metadata
		getResp, err := svc.GetIssuedAPIKey(ctx, &talosv2alpha1.GetIssuedApiKeyRequest{
			KeyId: createResp.IssuedApiKey.KeyId,
		})
		require.NoError(t, err)
		require.NotNil(t, getResp.Metadata)

		storedMeta := getResp.Metadata.AsMap()
		assert.Equal(t, "2.1.0", storedMeta["app_version"])
		assert.Equal(t, "production", storedMeta["environment"])
	})

	t.Run("nil metadata is accepted", func(t *testing.T) {
		createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:     "No Metadata Key",
			ActorId:  "user-123",
			Metadata: nil,
		})
		require.NoError(t, err)

		_, err = svc.GetIssuedAPIKey(ctx, &talosv2alpha1.GetIssuedApiKeyRequest{
			KeyId: createResp.IssuedApiKey.KeyId,
		})
		require.NoError(t, err)
		// Metadata might be nil or empty - just verify key can be retrieved
	})
}

// TestDeriveToken_ImportedKeys tests token derivation from imported keys.
// This validates the fix for the bug where verifyJWTCredential and
// verifyMacaroonCredential only checked api_keys, not imported_api_keys.
func TestDeriveToken_ImportedKeys(t *testing.T) {
	t.Parallel()

	t.Run("derive JWT from imported key and verify", func(t *testing.T) {
		t.Parallel()
		svc, verifier, ctx := setupTestService(t)

		// Import a key
		importResp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "imported_key_jwt_test_1234567890",
			Name:    "JWT Derive Test Key",
			ActorId: "jwt-derive-user",
			Scopes:  []string{"read:data", "write:data"},
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, importResp)
		imported := importResp

		// Derive a JWT from the imported key
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: "imported_key_jwt_test_1234567890",
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, deriveResp.Token)

		derivedToken := deriveResp.Token.Token
		assert.True(t, strings.HasPrefix(derivedToken, "eyJ"), "derived token should be a JWT")

		// Verify the derived JWT
		verifyResult, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err, "derived JWT from imported key should be verifiable")
		require.NotNil(t, verifyResult)
		assert.Equal(t, imported.KeyId, verifyResult.KeyID)
		assert.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), verifyResult.Status)
	})

	t.Run("derive Macaroon from imported key and verify", func(t *testing.T) {
		t.Parallel()
		svc, verifier, ctx := setupTestService(t)

		// Import a key
		importResp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "imported_key_macaroon_test_1234567890",
			Name:    "Macaroon Derive Test Key",
			ActorId: "macaroon-derive-user",
			Scopes:  []string{"read:data"},
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, importResp)
		imported := importResp

		// Derive a Macaroon from the imported key
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: "imported_key_macaroon_test_1234567890",
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_MACAROON,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, deriveResp.Token)

		derivedToken := deriveResp.Token.Token
		assert.True(t, strings.HasPrefix(derivedToken, "mc_v1_"), "derived token should be a Macaroon")

		// Verify the derived Macaroon
		verifyResult, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err, "derived Macaroon from imported key should be verifiable")
		require.NotNil(t, verifyResult)
		assert.Equal(t, imported.KeyId, verifyResult.KeyID)
	})

	t.Run("derive JWT with scope restriction from imported key", func(t *testing.T) {
		t.Parallel()
		svc, verifier, ctx := setupTestService(t)

		// Import a key with multiple scopes
		_, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "imported_key_scope_test_1234567890",
			Name:    "Scope Restriction Test Key",
			ActorId: "scope-test-user",
			Scopes:  []string{"read:data", "write:data", "admin"},
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)

		// Derive a JWT with restricted scopes
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: "imported_key_scope_test_1234567890",
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
			Scopes:     []string{"read:data"},
		})
		require.NoError(t, err)

		// Verify the derived JWT succeeds
		verifyResult, _, err := verifier.VerifyAPIKey(ctx, deriveResp.Token.Token)
		require.NoError(t, err)
		require.NotNil(t, verifyResult)

		// VerifyAPIKey returns the parent DB key; scope restriction is in the JWT claims.
		// The derive response reflects the restricted scopes.
		assert.Equal(t, []string{"read:data"}, deriveResp.Token.Scopes)
	})

	t.Run("derived token from imported key remains valid after parent revocation", func(t *testing.T) {
		t.Parallel()
		svc, verifier, ctx := setupTestService(t)

		// Import a key
		importResp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "imported_key_revoke_test_1234567890",
			Name:    "Stateless Token Test Key",
			ActorId: "stateless-token-user",
			Scopes:  []string{"read:data"},
			Ttl:     durationpb.New(24 * time.Hour),
		})
		require.NoError(t, err)
		require.NotNil(t, importResp)
		imported := importResp

		// Derive a JWT while the imported key is active
		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: "imported_key_revoke_test_1234567890",
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(time.Hour),
		})
		require.NoError(t, err)
		derivedToken := deriveResp.Token.Token

		// Verify derived token works before revocation
		_, _, err = verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err)

		// Revoke the imported parent key
		_, err = svc.RevokeImportedApiKey(ctx, &talosv2alpha1.RevokeImportedApiKeyRequest{
			KeyId:  imported.KeyId,
			Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		})
		require.NoError(t, err)

		// Derived token remains valid (stateless capability model)
		result, _, err := verifier.VerifyAPIKey(ctx, derivedToken)
		require.NoError(t, err, "derived token should remain valid after parent is revoked (stateless)")
		require.NotNil(t, result)
	})

	t.Run("derive from imported key with custom claims", func(t *testing.T) {
		t.Parallel()
		svc, verifier, ctx := setupTestService(t)

		metadata, err := structpb.NewStruct(map[string]any{
			"env":    "production",
			"region": "us-east-1",
		})
		require.NoError(t, err)

		// Import a key with metadata
		_, err = svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:   "imported_key_claims_test_1234567890",
			Name:     "Custom Claims Test Key",
			ActorId:  "claims-test-user",
			Scopes:   []string{"read:data"},
			Ttl:      durationpb.New(24 * time.Hour),
			Metadata: metadata,
		})
		require.NoError(t, err)

		// Derive JWT with custom claims
		customClaims, err := structpb.NewStruct(map[string]any{
			"request_id": "req-12345",
		})
		require.NoError(t, err)

		deriveResp, err := svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential:   "imported_key_claims_test_1234567890",
			Algorithm:    talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:          durationpb.New(time.Hour),
			CustomClaims: customClaims,
		})
		require.NoError(t, err)

		// Verify the derived JWT succeeds
		verifyResult, _, err := verifier.VerifyAPIKey(ctx, deriveResp.Token.Token)
		require.NoError(t, err)
		require.NotNil(t, verifyResult)

		// Claims from the derive response should include custom claims
		require.NotNil(t, deriveResp.Token.Claims)
		claimsMap := deriveResp.Token.Claims.AsMap()
		assert.Equal(t, "req-12345", claimsMap["request_id"])
		// Parent metadata should be merged
		assert.Equal(t, "production", claimsMap["env"])
		assert.Equal(t, "us-east-1", claimsMap["region"])
	})

	t.Run("derive from imported key with TTL exceeding parent expiry fails", func(t *testing.T) {
		t.Parallel()
		svc, _, ctx := setupTestService(t)

		// Import a key with short TTL
		_, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  "imported_key_ttl_test_1234567890",
			Name:    "TTL Validation Test Key",
			ActorId: "ttl-test-user",
			Scopes:  []string{"read:data"},
			Ttl:     durationpb.New(time.Hour), // Parent expires in 1 hour
		})
		require.NoError(t, err)

		// Try to derive a token with TTL exceeding the parent expiry
		_, err = svc.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
			Credential: "imported_key_ttl_test_1234567890",
			Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
			Ttl:        durationpb.New(2 * time.Hour), // Exceeds parent's 1 hour
		})
		require.Error(t, err, "derived TTL should not exceed parent expiry")
	})
}

func TestDeriveToken_IssuedKeyCustomACLCannotOverride(t *testing.T) {
	t.Parallel()

	svc, verifier, ctx := setupTestService(t)

	issueResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "ACL Override Issued Parent",
		ActorId: "acl-test-issued-owner",
		Scopes:  []string{"read:data"},
		IpRestriction: &talosv2alpha1.IPRestriction{
			AllowedCidrs: []string{"192.168.1.0/24"},
		},
	})
	require.NoError(t, err)

	customClaims, err := structpb.NewStruct(map[string]any{
		"trace_id": "trace-abc",
	})
	require.NoError(t, err)

	deriveReq := httptest.NewRequest(http.MethodGet, "/", nil)
	deriveReq.RemoteAddr = "192.168.1.10:443"
	deriveCtx := clientip.WithRequestInfo(ctx, deriveReq)

	deriveResp, err := svc.DeriveToken(deriveCtx, &talosv2alpha1.DeriveTokenRequest{
		Credential:   issueResp.Secret,
		Algorithm:    talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
		Ttl:          durationpb.New(time.Hour),
		CustomClaims: customClaims,
	})
	require.NoError(t, err)
	require.NotNil(t, deriveResp.Token)

	claimsMap := deriveResp.Token.Claims.AsMap()
	_, hasACL := claimsMap["acl"]
	assert.False(t, hasACL, "reserved acl claim must not appear in custom claim response")
	assert.Equal(t, "trace-abc", claimsMap["trace_id"])

	allowedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	allowedReq.RemoteAddr = "192.168.1.10:443"
	allowedCtx := clientip.WithRequestInfo(ctx, allowedReq)
	_, _, err = verifier.VerifyAPIKey(allowedCtx, deriveResp.Token.Token)
	require.NoError(t, err)

	deniedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	deniedReq.RemoteAddr = "10.0.0.5:443"
	deniedCtx := clientip.WithRequestInfo(ctx, deniedReq)
	_, _, err = verifier.VerifyAPIKey(deniedCtx, deriveResp.Token.Token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errdef.ErrIPNotAllowed()), "expected CIDR policy from parent to remain enforced")
}

func TestDeriveToken_UsesConfiguredIssuer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)

	provider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(map[string]any{
		config.KeyCredentialsIssuer.String():                  "https://custom.issuer.example.com",
		config.KeyCredentialsDerivedTokensDefaultTTL.String(): "1h",
	}))

	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)
	pv, err := protovalidate.New()
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	srv := service.NewAdminFromProvider(driver, provider, events.NewNoopEmitter(), keyService, cache.NewNoopCache[db.IssuedApiKey](), pv, metrics.New(prometheus.NewRegistry()), tracker)

	// Create API key
	createResp, err := srv.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Test Key for Issuer",
		ActorId: "test-owner",
		Ttl:     durationpb.New(24 * time.Hour),
	})
	require.NoError(t, err)

	// Derive JWT token
	jwtResp, err := srv.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
		Credential: createResp.Secret,
		Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_JWT,
	})
	require.NoError(t, err)

	// Parse JWT to extract issuer claim
	parsedToken, err := jwt.Parse([]byte(jwtResp.Token.Token), jwt.WithVerify(false))
	require.NoError(t, err)

	issuer, ok := parsedToken.Issuer()
	require.True(t, ok)
	require.Equal(t, "https://custom.issuer.example.com", issuer)

	// Derive Macaroon token
	macResp, err := srv.DeriveToken(ctx, &talosv2alpha1.DeriveTokenRequest{
		Credential: createResp.Secret,
		Algorithm:  talosv2alpha1.TokenAlgorithm_TOKEN_ALGORITHM_MACAROON,
	})
	require.NoError(t, err)

	// Verify macaroon was created (detailed macaroon location verification
	// is tested indirectly via verification tests)
	require.NotEmpty(t, macResp.Token.Token)
}

// TestTTLEdgeCases tests edge cases for TTL handling
func TestTTLEdgeCases(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	tests := []struct {
		name        string
		ttl         *durationpb.Duration
		wantErr     bool
		errContains string
	}{
		{
			name:    "nil TTL uses default",
			ttl:     nil,
			wantErr: false,
		},
		{
			name:        "zero TTL rejected by validation",
			ttl:         durationpb.New(0),
			wantErr:     true,
			errContains: "ttl",
		},
		{
			name:    "very long TTL",
			ttl:     durationpb.New(365 * 24 * time.Hour),
			wantErr: false,
		},
		{
			name:        "negative TTL rejected by validation",
			ttl:         durationpb.New(-1 * time.Hour),
			wantErr:     true,
			errContains: "ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
				Name:    "TTL Test Key",
				ActorId: "user-ttl",
				Ttl:     tt.ttl,
			})

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					// For herodot errors, check the reason field
					var herodotErr *herodot.DefaultError
					if errors.As(err, &herodotErr) {
						assert.Contains(t, herodotErr.ReasonField, tt.errContains)
					} else {
						assert.Contains(t, err.Error(), tt.errContains)
					}
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotNil(t, resp.IssuedApiKey.ExpireTime)
			}
		})
	}
}

// issueKeyForUpdate is a helper that issues a unique key for a single update subtest.
func issueKeyForUpdate(t *testing.T, svc *service.Admin, ctx context.Context, nameSuffix string, scopes []string) *talosv2alpha1.IssuedApiKey {
	t.Helper()
	resp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Original " + nameSuffix,
		ActorId: "user-update-test",
		Scopes:  scopes,
		Ttl:     durationpb.New(24 * time.Hour),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.IssuedApiKey)
	return resp.IssuedApiKey
}

// TestUpdateIssuedAPIKey tests the UpdateIssuedAPIKey endpoint (AIP-134)
func TestUpdateIssuedAPIKey(t *testing.T) {
	t.Parallel()
	svc, _, ctx := setupTestService(t)

	t.Run("update name without mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "Name", []string{"read:users", "write:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				Name:  "Updated Name",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", resp.Name)
		assert.Equal(t, []string{"read:users", "write:users"}, resp.Scopes)
	})

	t.Run("update name only via update_mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "NameMask", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				Name:  "Masked Name",
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Masked Name", resp.Name)
		assert.Equal(t, []string{"read:users"}, resp.Scopes) // preserved
	})

	t.Run("mask excludes field — scopes sent but not in mask are ignored", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "MaskExcl", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:  key.KeyId,
				Name:   "Name Changed",
				Scopes: []string{"admin"},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Name Changed", resp.Name)
		assert.Equal(t, []string{"read:users"}, resp.Scopes) // unchanged
	})

	t.Run("update scopes via mask — name sent but not in mask is ignored", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "ScopesMask", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:  key.KeyId,
				Name:   "Should Not Change",
				Scopes: []string{"read:users", "write:users"},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"scopes"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Original ScopesMask", resp.Name)                   // unchanged
		assert.Equal(t, []string{"read:users", "write:users"}, resp.Scopes) // changed
	})

	t.Run("update scopes without mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "ScopesNoMask", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:  key.KeyId,
				Scopes: []string{"read:users", "write:users"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"read:users", "write:users"}, resp.Scopes)
	})

	t.Run("update metadata via mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "MetaMask", []string{"read:users"})
		meta, err := structpb.NewStruct(map[string]any{"env": "production"})
		require.NoError(t, err)
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:    key.KeyId,
				Name:     "Should Not Change",
				Metadata: meta,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"metadata"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Original MetaMask", resp.Name) // unchanged
		assert.Equal(t, "production", resp.Metadata.AsMap()["env"])
	})

	t.Run("set rate_limit_policy via mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "RLSet", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  1000,
					Window: durationpb.New(60 * time.Second),
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"rate_limit_policy"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.RateLimitPolicy)
		assert.Equal(t, int64(1000), resp.RateLimitPolicy.Quota)
	})

	t.Run("clear rate_limit_policy via mask with nil policy", func(t *testing.T) {
		t.Parallel()
		createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "RL Clear Key",
			ActorId: "user-update-test",
			Ttl:     durationpb.New(24 * time.Hour),
			RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(time.Hour),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, createResp.IssuedApiKey.RateLimitPolicy)

		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:           createResp.IssuedApiKey.KeyId,
				RateLimitPolicy: nil,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"rate_limit_policy"},
			},
		})
		require.NoError(t, err)
		assert.Nil(t, resp.RateLimitPolicy)
	})

	t.Run("clear rate_limit_policy alongside other fields in mask", func(t *testing.T) {
		t.Parallel()
		createResp, err := svc.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
			Name:    "RL Clear Multi Key",
			ActorId: "user-update-test",
			Ttl:     durationpb.New(24 * time.Hour),
			RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(time.Hour),
			},
		})
		require.NoError(t, err)
		require.NotNil(t, createResp.IssuedApiKey.RateLimitPolicy)

		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:           createResp.IssuedApiKey.KeyId,
				Name:            "Cleared RL",
				RateLimitPolicy: nil,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "rate_limit_policy"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Cleared RL", resp.Name)
		assert.Nil(t, resp.RateLimitPolicy)
	})

	t.Run("update multiple fields without mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "Multi", []string{"read:users"})
		meta, err := structpb.NewStruct(map[string]any{"region": "us-west-2"})
		require.NoError(t, err)
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:    key.KeyId,
				Name:     "Multi-Update Name",
				Scopes:   []string{"admin"},
				Metadata: meta,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Multi-Update Name", resp.Name)
		assert.Equal(t, []string{"admin"}, resp.Scopes)
		assert.Equal(t, "us-west-2", resp.Metadata.AsMap()["region"])
	})

	t.Run("update metadata without mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "MetaNoMask", []string{"read:users"})
		meta, err := structpb.NewStruct(map[string]any{"env": "staging"})
		require.NoError(t, err)
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:    key.KeyId,
				Metadata: meta,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.Metadata)
		assert.Equal(t, "staging", resp.Metadata.AsMap()["env"])
		assert.Equal(t, "Original MetaNoMask", resp.Name) // unchanged
	})

	t.Run("set rate_limit_policy without mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "RLNoMask", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  500,
					Window: durationpb.New(time.Hour),
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.RateLimitPolicy)
		assert.Equal(t, int64(500), resp.RateLimitPolicy.Quota)
	})

	t.Run("set ip_restriction via mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "IPMask", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				IpRestriction: &talosv2alpha1.IPRestriction{
					AllowedCidrs: []string{"10.0.0.0/8"},
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"ip_restriction"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.IpRestriction)
		assert.Contains(t, resp.IpRestriction.AllowedCidrs, "10.0.0.0/8")
	})

	t.Run("set ip_restriction without mask", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "IPNoMask", []string{"read:users"})
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				IpRestriction: &talosv2alpha1.IPRestriction{
					AllowedCidrs: []string{"192.168.0.0/16"},
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.IpRestriction)
		assert.Contains(t, resp.IpRestriction.AllowedCidrs, "192.168.0.0/16")
	})

	t.Run("rate_limit_policy excluded from mask is not applied", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "RLExclMask", []string{"read:users"})
		// Send rate_limit_policy in request but NOT in mask — must be ignored
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				Name:  "Name Changed",
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  9999,
					Window: durationpb.New(time.Hour),
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Name Changed", resp.Name)
		assert.Nil(t, resp.RateLimitPolicy) // not applied
	})

	t.Run("ip_restriction excluded from mask is not applied", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "IPExclMask", []string{"read:users"})
		// Send ip_restriction in request but NOT in mask — must be ignored
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				Name:  "Name Changed",
				IpRestriction: &talosv2alpha1.IPRestriction{
					AllowedCidrs: []string{"10.0.0.0/8"},
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Name Changed", resp.Name)
		assert.Nil(t, resp.IpRestriction) // not applied
	})

	t.Run("nil rate_limit_policy without mask does not clear existing policy", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "RLNilNoMask", []string{"read"})
		// First set a rate limit policy
		_, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  500,
					Window: durationpb.New(time.Hour),
				},
			},
		})
		require.NoError(t, err)

		// No mask, nil RateLimitPolicy — presence-based path skips nil fields
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:           key.KeyId,
				Name:            "Updated Name",
				RateLimitPolicy: nil,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.RateLimitPolicy, "existing rate limit must be preserved")
		assert.Equal(t, int64(500), resp.RateLimitPolicy.Quota)
	})

	t.Run("nil rate_limit_policy excluded from mask does not clear existing policy", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "RLNilExclMask", []string{"read"})
		// First set a rate limit policy
		_, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  500,
					Window: durationpb.New(time.Hour),
				},
			},
		})
		require.NoError(t, err)

		// rate_limit_policy is NOT in mask — nil value must not clear
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:           key.KeyId,
				Name:            "Updated Name",
				RateLimitPolicy: nil,
			},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"name"}},
		})
		require.NoError(t, err)
		require.NotNil(t, resp.RateLimitPolicy, "existing rate limit must be preserved")
		assert.Equal(t, int64(500), resp.RateLimitPolicy.Quota)
	})

	t.Run("multiple fields in mask simultaneously including rate_limit and ip_restriction", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "MultiMask", []string{"read:users"})
		meta, err := structpb.NewStruct(map[string]any{"tier": "gold"})
		require.NoError(t, err)
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:    key.KeyId,
				Name:     "Multi Masked",
				Scopes:   []string{"read:users", "write:users"},
				Metadata: meta,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  100,
					Window: durationpb.New(time.Minute),
				},
				IpRestriction: &talosv2alpha1.IPRestriction{
					AllowedCidrs: []string{"172.16.0.0/12"},
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "scopes", "metadata", "rate_limit_policy", "ip_restriction"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Multi Masked", resp.Name)
		assert.Equal(t, []string{"read:users", "write:users"}, resp.Scopes)
		assert.Equal(t, "gold", resp.Metadata.AsMap()["tier"])
		require.NotNil(t, resp.RateLimitPolicy)
		assert.Equal(t, int64(100), resp.RateLimitPolicy.Quota)
		require.NotNil(t, resp.IpRestriction)
		assert.Contains(t, resp.IpRestriction.AllowedCidrs, "172.16.0.0/12")
	})

	t.Run("update non-existent key returns 404", func(t *testing.T) {
		t.Parallel()
		_, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: "non-existent-key-id",
				Name:  "Should Fail",
			},
		})
		require.Error(t, err)
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr))
		assert.Contains(t, herodotErr.ReasonField, "not found")
	})

	t.Run("update revoked key succeeds", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "Revoked", []string{})
		_, err := svc.RevokeIssuedApiKey(ctx, &talosv2alpha1.RevokeIssuedApiKeyRequest{
			KeyId:  key.KeyId,
			Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		})
		require.NoError(t, err)
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: key.KeyId,
				Name:  "Updated Revoked Key",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated Revoked Key", resp.Name)
		assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, resp.Status)
	})

	t.Run("update with empty key_id fails validation", func(t *testing.T) {
		t.Parallel()
		_, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId: "",
				Name:  "Should Fail",
			},
		})
		require.Error(t, err)
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr))
		assert.Contains(t, herodotErr.ErrorField, "malformed")
	})

	// AIP-134 / google.protobuf.FieldMask only allows paths that name fields
	// of the resource. Sub-paths into a google.protobuf.Struct (such as
	// "metadata.plan") are not valid mask entries and must be rejected with
	// INVALID_ARGUMENT. Clients clear or replace metadata as a whole.
	t.Run("dotted metadata sub-path is rejected with INVALID_ARGUMENT", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "DottedMeta", []string{"read:users"})
		meta, err := structpb.NewStruct(map[string]any{"plan": "premium"})
		require.NoError(t, err)
		_, err = svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:    key.KeyId,
				Metadata: meta,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"metadata.plan"},
			},
		})
		require.Error(t, err)
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr))
		assert.Equal(t, 400, herodotErr.CodeField)
		assert.Contains(t, herodotErr.ReasonField, "metadata.plan")
	})

	// Server-managed fields on IssuedApiKey (status, timestamps, revocation_*)
	// must be ignored on input even when set in the embedded resource.
	t.Run("server-managed fields in embedded resource are ignored", func(t *testing.T) {
		t.Parallel()
		key := issueKeyForUpdate(t, svc, ctx, "ServerManaged", []string{"read:users"})
		futureTime := timestamppb.New(time.Now().Add(99 * 365 * 24 * time.Hour))
		resp, err := svc.UpdateIssuedAPIKey(ctx, &talosv2alpha1.UpdateIssuedApiKeyRequest{
			IssuedApiKey: &talosv2alpha1.IssuedApiKey{
				KeyId:      key.KeyId,
				Name:       "Renamed",
				Status:     talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED,
				CreateTime: futureTime,
				UpdateTime: futureTime,
				ExpireTime: futureTime,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Renamed", resp.Name)
		assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE, resp.Status,
			"client-supplied status must be ignored")
		assert.NotEqual(t, futureTime.AsTime(), resp.CreateTime.AsTime(),
			"client-supplied create_time must be ignored")
	})
}

// TODO generally add a test that ensures key operations send events with the right payload.

// TestIssueAPIKey_Idempotency tests that IssueApiKey honours request_id as an AIP-133
// idempotency key: the second call returns the same key without the secret.
func TestIssueAPIKey_Idempotency(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	req := &talosv2alpha1.IssueApiKeyRequest{
		Name:      "Idempotent Key",
		ActorId:   "user-idem-123",
		RequestId: "idem-req-001",
	}

	// First call — creates the key and returns the secret.
	resp1, err := svc.IssueApiKey(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp1.IssuedApiKey)
	assert.NotEmpty(t, resp1.Secret, "first call should return the secret")
	keyID := resp1.IssuedApiKey.KeyId

	// Second call with the same request_id — must return the same key_id.
	resp2, err := svc.IssueApiKey(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp2.IssuedApiKey)
	assert.Equal(t, keyID, resp2.IssuedApiKey.KeyId, "idempotent replay must return the same key_id")
	assert.Empty(t, resp2.Secret, "idempotent replay must not return the secret")
}

// TestIssueAPIKey_NoRequestID_CreatesDuplicate tests that omitting request_id creates
// independent keys on repeated calls (no idempotency enforced).
func TestIssueAPIKey_NoRequestID_CreatesDuplicate(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	req := &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Duplicate Key",
		ActorId: "user-dup-456",
	}

	resp1, err := svc.IssueApiKey(ctx, req)
	require.NoError(t, err)

	resp2, err := svc.IssueApiKey(ctx, req)
	require.NoError(t, err)

	assert.NotEqual(t, resp1.IssuedApiKey.KeyId, resp2.IssuedApiKey.KeyId,
		"without request_id each call must produce a distinct key")
}

// TestImportAPIKey_Idempotency tests that ImportAPIKey honours request_id as an AIP-133
// idempotency key: the second call returns the same imported key.
func TestImportAPIKey_Idempotency(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	req := &talosv2alpha1.ImportApiKeyRequest{
		RawKey:    "idem_import_key_1234567890abcdef",
		Name:      "Idempotent Import Key",
		ActorId:   "user-idem-import",
		RequestId: "idem-import-req-001",
	}

	// First call — imports the key.
	resp1, err := svc.ImportAPIKey(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	keyID := resp1.KeyId

	// Second call with the same request_id — must return the same key_id.
	resp2, err := svc.ImportAPIKey(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, keyID, resp2.KeyId, "idempotent replay must return the same key_id")
}

// TODO we need batch operation tests - especially testing inserting large numbers and testing conflicts partial and full. have a much more extensive test sujite for that.

// reviewed - @aeneasr - 2026-03-26
