package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ory/herodot"

	"github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/service"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

func TestImportAPIKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		rawKey      string
		params      func(string) *talosv2alpha1.ImportAPIKeyRequest
		wantErr     bool
		errContains string
	}{
		{
			name:   "success - import Stripe key",
			rawKey: "sk_live_abc123xyz789",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				metadata, _ := structpb.NewStruct(map[string]any{
					"source": "stripe",
					"env":    "production",
				})

				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:   "sk_live_abc123xyz789",
					Name:     "Stripe Production Key",
					ActorId:  "payment-processor",
					Ttl:      durationpb.New(time.Hour * 24 * 365), // 1 year
					Metadata: metadata,
				}
			},
			wantErr: false,
		},
		{
			name:   "success - import GitHub PAT",
			rawKey: "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				metadata, _ := structpb.NewStruct(map[string]any{
					"source": "github",
				})

				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:   "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
					Name:     "GitHub Personal Access Token",
					ActorId:  "developer-001",
					Ttl:      durationpb.New(time.Hour * 24 * 90), // 90 days
					Metadata: metadata,
				}
			},
			wantErr: false,
		},
		{
			name:   "error - conflict with generated key pattern",
			rawKey: "prod_v1_0ujsswThIGTUYm2K8Fj63K_AbC3XyZ789", // Base62 key ID (22 chars), 10 char base58 checksum
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:   "prod_v1_Qixc9eno7AsY9gYxGU2tAFZf36gyPhnx2nNUpNvqexZun1jq7raV7c8VkrhyqPZR_AbC3XyZ789", // New format with timestamp+UUID identifier
					Name:     "Should Fail",
					ActorId:  "test",
					Ttl:      durationpb.New(time.Hour * 24),
					Metadata: nil,
				}
			},
			wantErr:     true,
			errContains: "format conflicts with issued api key pattern",
		},
		{
			name:   "error - conflict with derived JWT pattern",
			rawKey: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
					Name:    "JWT-like Import",
					ActorId: "test",
					Ttl:     durationpb.New(time.Hour * 24),
				}
			},
			wantErr:     true,
			errContains: "format conflicts with derived token pattern",
		},
		{
			name:   "error - conflict with derived macaroon pattern",
			rawKey: "mc_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQx4Y2FweWxvYWQ",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:  "mc_v1_AgETaHR0cHM6Ly9leGFtcGxlLmNvbQx4Y2FweWxvYWQ",
					Name:    "Macaroon-like Import",
					ActorId: "test",
					Ttl:     durationpb.New(time.Hour * 24),
				}
			},
			wantErr:     true,
			errContains: "format conflicts with derived token pattern",
		},
		{
			name:   "error - duplicate key",
			rawKey: "duplicate_key_12345",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:   "duplicate_key_12345",
					Name:     "First Import",
					ActorId:  "test",
					Ttl:      durationpb.New(time.Hour * 24),
					Metadata: nil,
				}
			},
			wantErr:     true,
			errContains: "key already imported",
		},
		{
			name:   "error - empty raw key",
			rawKey: "",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:   "",
					Name:     "Empty Key",
					ActorId:  "test",
					Ttl:      durationpb.New(time.Hour * 24),
					Metadata: nil,
				}
			},
			wantErr:     true,
			errContains: "raw_key: value length must be at least 1",
		},
		{
			name:   "error - empty name",
			rawKey: "some_valid_key",
			params: func(_ string) *talosv2alpha1.ImportAPIKeyRequest {
				return &talosv2alpha1.ImportAPIKeyRequest{
					RawKey:   "some_valid_key",
					Name:     "",
					ActorId:  "test",
					Ttl:      durationpb.New(time.Hour * 24),
					Metadata: nil,
				}
			},
			wantErr:     true,
			errContains: "name: value length must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, _, ctx := setupTestService(t)

			// For duplicate test, import the key first
			if tt.name == "error - duplicate key" {
				params := tt.params("") // nid not used
				_, err := svc.ImportAPIKey(ctx, params)
				require.NoError(t, err)
			}

			// Run the test
			params := tt.params("") // nid not used
			resp, err := svc.ImportAPIKey(ctx, params)

			if tt.wantErr {
				require.Error(t, err)
				// For herodot errors, check the reason field
				var herodotErr *herodot.DefaultError
				if errors.As(err, &herodotErr) {
					assert.Contains(t, herodotErr.ReasonField, tt.errContains)
				} else {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				imported := resp
				require.NotNil(t, imported)

				// Verify response
				assert.NotEmpty(t, imported.KeyId)
				assert.Equal(t, params.Name, imported.Name)
				assert.Equal(t, params.ActorId, imported.ActorId)
				assert.NotNil(t, imported.ExpireTime)

				// Verify key ID is tenant-scoped SHA512/256 hash (default NID for OSS)
				expectedKeyID := crypto.HashImportedAPIKey(tt.rawKey, "00000000-0000-0000-0000-000000000000")
				assert.Equal(t, expectedKeyID, imported.KeyId)
			}
		})
	}
}

func TestImportAPIKey_EmptyRequest(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{})
	require.Error(t, err)
	assert.Nil(t, resp)

	var herodotErr *herodot.DefaultError
	require.True(t, errors.As(err, &herodotErr))
	assert.Equal(t, 400, herodotErr.CodeField)
}

func TestListImportedAPIKeys(t *testing.T) {
	t.Parallel()
	svc, _, ctx := setupTestService(t)

	// Note: Network is created automatically by driver.Initialize()

	// Import multiple keys with different attributes
	keys := []struct {
		rawKey  string
		name    string
		actorID string
		ttl     time.Duration
	}{
		{"stripe_key_001", "Stripe Key 1", "owner-1", time.Hour * 24 * 365},
		{"stripe_key_002", "Stripe Key 2", "owner-1", time.Hour * 24 * 365},
		{"github_key_001", "GitHub Key 1", "owner-2", time.Hour * 24 * 90},
		{"aws_key_001", "AWS Key 1", "owner-2", time.Hour * 24 * 30},
	}

	for _, k := range keys {
		params := &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:   k.rawKey,
			Name:     k.name,
			ActorId:  k.actorID,
			Ttl:      durationpb.New(k.ttl),
			Metadata: nil,
		}
		_, err := svc.ImportAPIKey(ctx, params)
		require.NoError(t, err)
	}

	tests := []struct {
		name            string
		status          talosv2alpha1.KeyStatus
		actorID         string
		pageSize        int32
		pageToken       string
		wantCount       int
		wantHasNextPage bool
	}{
		{
			name:            "list all",
			status:          talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
			actorID:         "",
			pageSize:        50,
			pageToken:       "",
			wantCount:       4,
			wantHasNextPage: false,
		},
		{
			name:            "filter by owner-1",
			status:          talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
			actorID:         "owner-1",
			pageSize:        50,
			pageToken:       "",
			wantCount:       2,
			wantHasNextPage: false,
		},
		{
			name:            "filter by owner-2",
			status:          talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
			actorID:         "owner-2",
			pageSize:        50,
			pageToken:       "",
			wantCount:       2,
			wantHasNextPage: false,
		},
		{
			name:            "filter by active status and owner",
			status:          talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE,
			actorID:         "owner-1",
			pageSize:        50,
			pageToken:       "",
			wantCount:       2,
			wantHasNextPage: false,
		},
		{
			name:            "pagination - first page",
			status:          talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
			actorID:         "",
			pageSize:        2,
			pageToken:       "",
			wantCount:       2,
			wantHasNextPage: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var filterParts []string
			if tt.actorID != "" {
				filterParts = append(filterParts, `actor_id="`+tt.actorID+`"`)
			}
			if tt.status != talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED {
				filterParts = append(filterParts, "status="+tt.status.String())
			}
			filter := strings.Join(filterParts, " AND ")
			resp, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
				Filter:    filter,
				PageSize:  tt.pageSize,
				PageToken: tt.pageToken,
			})
			require.NoError(t, err)
			assert.Len(t, resp.ImportedApiKeys, tt.wantCount)
			if tt.wantHasNextPage {
				assert.NotEmpty(t, resp.NextPageToken, "expected next page token to be present")
			} else {
				assert.Empty(t, resp.NextPageToken, "expected no next page token")
			}
		})
	}

	// Test pagination continuation (second page)
	t.Run("pagination - second page using cursor", func(t *testing.T) {
		t.Parallel()
		// Get first page
		resp1, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
			PageSize: 2,
		})
		require.NoError(t, err)
		assert.Len(t, resp1.ImportedApiKeys, 2)
		assert.NotEmpty(t, resp1.NextPageToken)

		// Get second page using the cursor
		resp2, err := svc.ListImportedAPIKeys(ctx, &talosv2alpha1.ListImportedAPIKeysRequest{
			PageSize:  2,
			PageToken: resp1.NextPageToken,
		})
		require.NoError(t, err)
		assert.Len(t, resp2.ImportedApiKeys, 2)
		assert.Empty(t, resp2.NextPageToken) // Last page - no more results (4 keys total, 2 per page = 2 pages)

		// Verify the keys are different
		assert.NotEqual(t, resp1.ImportedApiKeys[0].KeyId, resp2.ImportedApiKeys[0].KeyId)
	})

	// todo add more tests for filtering by status (active/revoked), edge cases for pagination, invalid filters, and advesarial page tokens
}

func TestGetImportedAPIKey(t *testing.T) {
	t.Parallel()
	svc, _, ctx := setupTestService(t)

	// Note: Network is created automatically by driver.Initialize()

	// Import a key
	rawKey := "test_key_for_retrieval"
	metadata, _ := structpb.NewStruct(map[string]any{
		"test": "value",
	})
	params := &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:   rawKey,
		Name:     "Test Key",
		ActorId:  "test-owner",
		Ttl:      durationpb.New(time.Hour * 24),
		Metadata: metadata,
	}
	importResp, err := svc.ImportAPIKey(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, importResp)
	imported := importResp
	require.NotNil(t, imported)

	tests := []struct {
		name    string
		keyID   string
		wantErr bool
	}{
		{
			name:    "success - retrieve existing key",
			keyID:   imported.KeyId,
			wantErr: false,
		},
		{
			name:    "error - key not found",
			keyID:   "nonexistent_hash_1234567890",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp, err := svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{
				KeyId: tt.keyID,
			})

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, imported.KeyId, resp.KeyId)
				assert.Equal(t, imported.Name, resp.Name)
			}
		})
	}
}

func TestRevokeImportedAPIKey(t *testing.T) {
	t.Parallel()
	svc, _, ctx := setupTestService(t)

	// Note: Network is created automatically by driver.Initialize()

	// Import a key
	rawKey := "test_key_for_revocation"
	params := &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:   rawKey,
		Name:     "Test Key for Revocation",
		ActorId:  "test-owner",
		Ttl:      durationpb.New(time.Hour * 24),
		Metadata: nil,
	}
	importResp, err := svc.ImportAPIKey(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, importResp)
	imported := importResp
	require.NotNil(t, imported)

	// Import a second key and pre-revoke it to test the double-revoke error path.
	preRevokedResp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:  "test_key_already_revoked",
		Name:    "Pre-revoked Key",
		ActorId: "test-owner",
		Ttl:     durationpb.New(time.Hour * 24),
	})
	require.NoError(t, err)
	preRevokedID := preRevokedResp.KeyId
	_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{
		KeyId:  preRevokedID,
		Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		keyID       string
		reason      talosv2alpha1.RevocationReason
		wantErr     bool
		errContains string
	}{
		{
			name:    "success - revoke key",
			keyID:   imported.KeyId,
			reason:  talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr: false,
		},
		{
			name:        "error - already revoked returns conflict",
			keyID:       preRevokedID,
			reason:      talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr:     true,
			errContains: "already revoked",
		},
		{
			name:        "error - key not found",
			keyID:       "nonexistent_hash_1234567890",
			reason:      talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
			wantErr:     true,
			errContains: "imported key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp, err := svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{
				KeyId:  tt.keyID,
				Reason: tt.reason,
			})

			if tt.wantErr {
				require.Error(t, err)
				// For herodot errors, check the reason field
				var herodotErr *herodot.DefaultError
				if errors.As(err, &herodotErr) {
					assert.Contains(t, herodotErr.ReasonField, tt.errContains)
				} else {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
			}
		})
	}
}

func TestDeleteImportedAPIKey(t *testing.T) {
	t.Parallel()
	svc, _, ctx := setupTestService(t)

	// Note: Network is created automatically by driver.Initialize()

	// Import keys for deletion tests
	key1Params := &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:   "test_key_for_deletion_1",
		Name:     "Test Key 1",
		ActorId:  "test-owner",
		Ttl:      durationpb.New(time.Hour * 24),
		Metadata: nil,
	}
	importResp1, err := svc.ImportAPIKey(ctx, key1Params)
	require.NoError(t, err)
	require.NotNil(t, importResp1)
	imported1 := importResp1
	require.NotNil(t, imported1)

	tests := []struct {
		name        string
		keyID       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "success - delete key",
			keyID:   imported1.KeyId,
			wantErr: false,
		},
		{
			name:        "error - key not found (already deleted)",
			keyID:       imported1.KeyId,
			wantErr:     true,
			errContains: "imported key not found",
		},
		{
			name:        "error - nonexistent key",
			keyID:       "nonexistent_hash_1234567890",
			wantErr:     true,
			errContains: "imported key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NOT parallel - subtests share state (same key, sequential dependency)
			_, err := svc.DeleteImportedAPIKey(ctx, &talosv2alpha1.DeleteImportedAPIKeyRequest{
				KeyId: tt.keyID,
			})

			if tt.wantErr {
				require.Error(t, err)
				// For herodot errors, check the reason field
				var herodotErr *herodot.DefaultError
				if errors.As(err, &herodotErr) {
					assert.Contains(t, herodotErr.ReasonField, tt.errContains)
				} else {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)

				// Verify key is actually deleted
				resp, err := svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{
					KeyId: tt.keyID,
				})
				require.Error(t, err)
				assert.Nil(t, resp)
			}
		})
	}
}

func TestVerifyAPIKey_ImportedAPIKeys(t *testing.T) {
	t.Parallel()
	svc, dpVerifier, ctx := setupTestService(t)

	// Note: Network is created automatically by driver.Initialize()

	// Import a test key
	importedRawKey := "stripe_sk_test_12345678901234567890"
	metadata, _ := structpb.NewStruct(map[string]any{
		"env": "test",
	})
	params := &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:   importedRawKey,
		Name:     "Test Imported Key",
		ActorId:  "payment-service",
		Ttl:      durationpb.New(time.Hour * 24 * 365),
		Metadata: metadata,
	}
	importResp, err := svc.ImportAPIKey(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, importResp)
	imported := importResp
	require.NotNil(t, imported)

	tests := []struct {
		name        string
		apiKey      string
		wantErr     bool
		errContains string
	}{
		{
			name:    "success - verify imported key",
			apiKey:  importedRawKey,
			wantErr: false,
		},
		{
			name:        "error - wrong key",
			apiKey:      "stripe_sk_test_wrong_key_1234567890abcdef",
			wantErr:     true,
			errContains: "API key not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbKey, _, err := dpVerifier.VerifyAPIKey(ctx, tt.apiKey)

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
				require.NotNil(t, dbKey)

				// Verify basic fields
				assert.Equal(t, imported.KeyId, dbKey.KeyID)
				assert.Equal(t, "Test Imported Key", dbKey.Name)
			}
		})
	}
}

func TestVerifyAPIKey_RevokedImportedAPIKey(t *testing.T) {
	t.Parallel()
	svc, dpVerifier, ctx := setupTestService(t)

	// Note: Network is created automatically by driver.Initialize()

	// Import and then revoke a key
	revokedRawKey := "key_to_be_revoked_1234567890abcdefghijklmnop"
	params := &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:   revokedRawKey,
		Name:     "Key to Revoke",
		ActorId:  "test-user",
		Ttl:      durationpb.New(time.Hour * 24),
		Metadata: nil,
	}
	importResp, err := svc.ImportAPIKey(ctx, params)
	require.NoError(t, err)
	require.NotNil(t, importResp)
	imported := importResp
	require.NotNil(t, imported)

	// Revoke the key
	_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{
		KeyId:  imported.KeyId,
		Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	})
	require.NoError(t, err)

	// Try to verify the revoked key
	dbKey, _, err := dpVerifier.VerifyAPIKey(ctx, revokedRawKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has been revoked")
	assert.Nil(t, dbKey)
}

// importKeyForUpdate is a helper that imports a unique key for a single update subtest.
func importKeyForUpdate(t *testing.T, svc *service.Admin, ctx context.Context, rawKeySuffix, name string, scopes []string) *talosv2alpha1.ImportedAPIKey {
	t.Helper()
	resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:  "update_test_key_" + rawKeySuffix,
		Name:    name,
		ActorId: "owner-update-test",
		Ttl:     durationpb.New(24 * time.Hour),
		Scopes:  scopes,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func TestUpdateImportedAPIKey(t *testing.T) {
	t.Parallel()
	svc, _, ctx := setupTestService(t)

	// todo ensure we emit events!

	t.Run("update name only via update_mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "name_mask", "Original Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
				Name:  "Updated Name",
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", updated.Name)
		// scopes preserved (not in mask)
		assert.Equal(t, []string{"read"}, updated.Scopes)
	})

	t.Run("mask excludes field — scopes sent but not in mask are ignored", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "mask_excl", "Excl Name", []string{"read"})
		// Send both name and scopes, but mask only contains "name"
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:  imported.KeyId,
				Name:   "Name Changed",
				Scopes: []string{"admin"},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Name Changed", updated.Name)
		assert.Equal(t, []string{"read"}, updated.Scopes) // unchanged
	})

	t.Run("update scopes via mask — name sent but not in mask is ignored", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "scopes_mask", "Scope Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:  imported.KeyId,
				Name:   "Should Not Change",
				Scopes: []string{"read", "write"},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"scopes"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Scope Name", updated.Name)                // unchanged
		assert.Equal(t, []string{"read", "write"}, updated.Scopes) // changed
	})

	t.Run("update scopes without mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "no_mask_scopes", "No Mask Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:  imported.KeyId,
				Scopes: []string{"read", "write"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"read", "write"}, updated.Scopes)
	})

	t.Run("update metadata via mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "meta_mask", "Meta Name", []string{"read"})
		meta, err := structpb.NewStruct(map[string]any{"env": "production"})
		require.NoError(t, err)
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:    imported.KeyId,
				Name:     "Should Not Change",
				Metadata: meta,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"metadata"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.Metadata)
		assert.Equal(t, "production", updated.Metadata.Fields["env"].GetStringValue())
		assert.Equal(t, "Meta Name", updated.Name) // unchanged
	})

	t.Run("set rate_limit_policy via mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "rl_set_mask", "RL Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  1000,
					Window: durationpb.New(time.Hour),
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"rate_limit_policy"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.RateLimitPolicy)
		assert.Equal(t, int64(1000), updated.RateLimitPolicy.Quota)
	})

	t.Run("clear rate_limit_policy via mask with nil policy", func(t *testing.T) {
		t.Parallel()
		// Import key that has a rate limit policy
		resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:  "update_test_key_rl_clear_mask",
			Name:    "RL Clear Name",
			ActorId: "owner-update-test",
			Ttl:     durationpb.New(24 * time.Hour),
			Scopes:  []string{"read"},
			RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(time.Hour),
			},
		})
		require.NoError(t, err)
		imported := resp
		require.NotNil(t, imported.RateLimitPolicy)

		// Clear by including rate_limit_policy in mask with nil value
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:           imported.KeyId,
				RateLimitPolicy: nil,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"rate_limit_policy"},
			},
		})
		require.NoError(t, err)
		assert.Nil(t, updated.RateLimitPolicy)
	})

	t.Run("nil rate_limit_policy without mask does not clear existing policy", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:  "update_test_key_rl_nil_no_mask",
			Name:    "RL Nil No Mask",
			ActorId: "owner-update-test",
			Ttl:     durationpb.New(24 * time.Hour),
			Scopes:  []string{"read"},
			RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(time.Hour),
			},
		})
		require.NoError(t, err)
		imported := resp
		require.NotNil(t, imported.RateLimitPolicy)

		// No mask, nil RateLimitPolicy — presence-based path skips nil fields
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:           imported.KeyId,
				Name:            "Updated Name",
				RateLimitPolicy: nil,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.RateLimitPolicy) // preserved
		assert.Equal(t, int64(500), updated.RateLimitPolicy.Quota)
	})

	t.Run("nil rate_limit_policy excluded from mask does not clear existing policy", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:  "update_test_key_rl_nil_excl_mask",
			Name:    "RL Nil Excl Mask",
			ActorId: "owner-update-test",
			Ttl:     durationpb.New(24 * time.Hour),
			Scopes:  []string{"read"},
			RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(time.Hour),
			},
		})
		require.NoError(t, err)
		imported := resp
		require.NotNil(t, imported.RateLimitPolicy)

		// rate_limit_policy is NOT in mask — nil value must not clear
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:           imported.KeyId,
				Name:            "Updated Name",
				RateLimitPolicy: nil,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.RateLimitPolicy) // preserved
		assert.Equal(t, int64(500), updated.RateLimitPolicy.Quota)
	})

	t.Run("clear rate_limit_policy alongside other fields in mask", func(t *testing.T) {
		t.Parallel()
		resp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
			RawKey:  "update_test_key_rl_clear_multi_mask",
			Name:    "RL Clear Multi Name",
			ActorId: "owner-update-test",
			Ttl:     durationpb.New(24 * time.Hour),
			Scopes:  []string{"read"},
			RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(time.Hour),
			},
		})
		require.NoError(t, err)
		imported := resp
		require.NotNil(t, imported.RateLimitPolicy)

		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:           imported.KeyId,
				Name:            "Cleared RL",
				RateLimitPolicy: nil,
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"name", "rate_limit_policy"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Cleared RL", updated.Name)
		assert.Nil(t, updated.RateLimitPolicy)
	})

	t.Run("update name without mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "name_no_mask", "Original Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
				Name:  "New Name",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "New Name", updated.Name)
		assert.Equal(t, []string{"read"}, updated.Scopes) // unchanged
	})

	t.Run("update metadata without mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "meta_no_mask", "Meta Name", []string{"read"})
		meta, err := structpb.NewStruct(map[string]any{"env": "staging"})
		require.NoError(t, err)
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:    imported.KeyId,
				Metadata: meta,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.Metadata)
		assert.Equal(t, "staging", updated.Metadata.Fields["env"].GetStringValue())
	})

	t.Run("set rate_limit_policy without mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "rl_no_mask", "RL Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  500,
					Window: durationpb.New(time.Hour),
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.RateLimitPolicy)
		assert.Equal(t, int64(500), updated.RateLimitPolicy.Quota)
	})

	t.Run("set ip_restriction via mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "ip_mask", "IP Name", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
				IpRestriction: &talosv2alpha1.IPRestriction{
					AllowedCidrs: []string{"10.0.0.0/8"},
				},
			},
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: []string{"ip_restriction"},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.IpRestriction)
		assert.Contains(t, updated.IpRestriction.AllowedCidrs, "10.0.0.0/8")
	})

	t.Run("set ip_restriction without mask", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "ip_no_mask", "IP No Mask", []string{"read"})
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
				IpRestriction: &talosv2alpha1.IPRestriction{
					AllowedCidrs: []string{"192.168.0.0/16"},
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, updated.IpRestriction)
		assert.Contains(t, updated.IpRestriction.AllowedCidrs, "192.168.0.0/16")
	})

	t.Run("rate_limit_policy excluded from mask is not applied", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "rl_excl_mask", "RL Excl Name", []string{"read"})
		// Send rate_limit_policy in request but NOT in mask — must be ignored
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
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
		assert.Equal(t, "Name Changed", updated.Name)
		assert.Nil(t, updated.RateLimitPolicy) // not applied
	})

	t.Run("ip_restriction excluded from mask is not applied", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "ip_excl_mask", "IP Excl Name", []string{"read"})
		// Send ip_restriction in request but NOT in mask — must be ignored
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: imported.KeyId,
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
		assert.Equal(t, "Name Changed", updated.Name)
		assert.Nil(t, updated.IpRestriction) // not applied
	})

	t.Run("multiple fields in mask simultaneously including rate_limit and ip_restriction", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "multi_mask", "Multi Name", []string{"read"})
		meta, err := structpb.NewStruct(map[string]any{"tier": "gold"})
		require.NoError(t, err)
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:    imported.KeyId,
				Name:     "Multi Updated",
				Scopes:   []string{"read", "write"},
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
		assert.Equal(t, "Multi Updated", updated.Name)
		assert.Equal(t, []string{"read", "write"}, updated.Scopes)
		assert.Equal(t, "gold", updated.Metadata.Fields["tier"].GetStringValue())
		require.NotNil(t, updated.RateLimitPolicy)
		assert.Equal(t, int64(100), updated.RateLimitPolicy.Quota)
		require.NotNil(t, updated.IpRestriction)
		assert.Contains(t, updated.IpRestriction.AllowedCidrs, "172.16.0.0/12")
	})

	t.Run("not found returns 404", func(t *testing.T) {
		t.Parallel()
		_, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId: "nonexistenthashvalue000000000000",
				Name:  "Does not matter",
			},
		})
		require.Error(t, err)
		var herodotErr *herodot.DefaultError
		require.True(t, errors.As(err, &herodotErr))
		assert.Equal(t, 404, herodotErr.CodeField)
	})

	// AIP-134 / google.protobuf.FieldMask only allows paths that name fields
	// of the resource. Sub-paths into a google.protobuf.Struct (such as
	// "metadata.plan") are not valid mask entries and must be rejected with
	// INVALID_ARGUMENT. Clients clear or replace metadata as a whole.
	t.Run("dotted metadata sub-path is rejected with INVALID_ARGUMENT", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "dotted_meta", "Dotted Meta", []string{"read"})
		meta, err := structpb.NewStruct(map[string]any{"plan": "premium"})
		require.NoError(t, err)
		_, err = svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:    imported.KeyId,
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

	// Server-managed fields on ImportedAPIKey (status, timestamps, revocation_*)
	// must be ignored on input even when set in the embedded resource.
	t.Run("server-managed fields in embedded resource are ignored", func(t *testing.T) {
		t.Parallel()
		imported := importKeyForUpdate(t, svc, ctx, "server_managed", "Server Managed", []string{"read"})
		futureTime := timestamppb.New(time.Now().Add(99 * 365 * 24 * time.Hour))
		updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
			ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
				KeyId:      imported.KeyId,
				Name:       "Renamed",
				Status:     talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED,
				CreateTime: futureTime,
				UpdateTime: futureTime,
				ExpireTime: futureTime,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "Renamed", updated.Name)
		assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE, updated.Status,
			"client-supplied status must be ignored")
		assert.NotEqual(t, futureTime.AsTime(), updated.CreateTime.AsTime(),
			"client-supplied create_time must be ignored")
	})
}

func TestImportedAPIKeyLifecycle(t *testing.T) {
	t.Parallel()
	svc, dpVerifier, ctx := setupTestService(t)

	rawKey := "lifecycle_test_key_abcdefghijklmnopqrstuvwxyz0123"

	// 1. Import
	importResp, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportAPIKeyRequest{
		RawKey:  rawKey,
		Name:    "Lifecycle Key",
		ActorId: "lifecycle-owner",
		Ttl:     durationpb.New(24 * time.Hour),
		Scopes:  []string{"read"},
		Metadata: func() *structpb.Struct {
			s, _ := structpb.NewStruct(map[string]any{"version": "1"})
			return s
		}(),
	})
	require.NoError(t, err)
	imported := importResp
	require.NotNil(t, imported)
	assert.Equal(t, "Lifecycle Key", imported.Name)
	assert.Equal(t, []string{"read"}, imported.Scopes)

	// 2. Get — assert fields match
	got, err := svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{KeyId: imported.KeyId})
	require.NoError(t, err)
	assert.Equal(t, imported.KeyId, got.KeyId)
	assert.Equal(t, "Lifecycle Key", got.Name)

	// 3. Update — name change + new scope
	meta, err := structpb.NewStruct(map[string]any{"version": "2"})
	require.NoError(t, err)
	updated, err := svc.UpdateImportedAPIKey(ctx, &talosv2alpha1.UpdateImportedAPIKeyRequest{
		ImportedApiKey: &talosv2alpha1.ImportedAPIKey{
			KeyId:    imported.KeyId,
			Name:     "Lifecycle Key v2",
			Scopes:   []string{"read", "write"},
			Metadata: meta,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Lifecycle Key v2", updated.Name)
	assert.Equal(t, []string{"read", "write"}, updated.Scopes)

	// 4. Get again — assert update applied
	got2, err := svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{KeyId: imported.KeyId})
	require.NoError(t, err)
	assert.Equal(t, "Lifecycle Key v2", got2.Name)
	assert.Equal(t, []string{"read", "write"}, got2.Scopes)

	// 5. Verify key works before revocation
	_, _, err = dpVerifier.VerifyAPIKey(ctx, rawKey)
	require.NoError(t, err)

	// 6. Revoke via unified endpoint (regression test for Postgres bug)
	_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{
		KeyId:  imported.KeyId,
		Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	})
	require.NoError(t, err)

	// 7. Get — key is now revoked
	revoked, err := svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{KeyId: imported.KeyId})
	require.NoError(t, err)
	assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED, revoked.Status)

	// 8. Verify fails after revocation
	_, _, err = dpVerifier.VerifyAPIKey(ctx, rawKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	// 9. Re-revocation returns conflict
	_, err = svc.RevokeAPIKey(ctx, &talosv2alpha1.RevokeAPIKeyRequest{
		KeyId:  imported.KeyId,
		Reason: talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflict")

	// 10. Delete
	_, err = svc.DeleteImportedAPIKey(ctx, &talosv2alpha1.DeleteImportedAPIKeyRequest{KeyId: imported.KeyId})
	require.NoError(t, err)

	// 11. Confirm it's gone
	_, err = svc.GetImportedAPIKey(ctx, &talosv2alpha1.GetImportedAPIKeyRequest{KeyId: imported.KeyId})
	require.Error(t, err)
	var herodotErr *herodot.DefaultError
	require.True(t, errors.As(err, &herodotErr))
	assert.Equal(t, 404, herodotErr.CodeField)
}

// reviewed - @aeneasr - 2026-03-26
