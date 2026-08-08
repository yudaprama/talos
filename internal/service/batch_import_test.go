package service_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/service/validation"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

func TestBatchImportAPIKeys_RequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		req         *talosv2alpha1.BatchCreateImportedApiKeysRequest
		errContains string
	}{
		{
			name:        "empty request",
			req:         &talosv2alpha1.BatchCreateImportedApiKeysRequest{},
			errContains: "at least one item",
		},
		{
			name: "empty batch",
			req: &talosv2alpha1.BatchCreateImportedApiKeysRequest{
				Requests: []*talosv2alpha1.ImportApiKeyRequest{},
			},
			errContains: "at least one item",
		},
		{
			name: "batch exceeds limit",
			req: &talosv2alpha1.BatchCreateImportedApiKeysRequest{
				Requests: makeImportRequests(service.MaxBatchImportSize + 1),
			},
			errContains: "maximum 1000 keys per batch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, _, ctx := setupTestService(t)

			resp, err := svc.BatchImportAPIKeys(ctx, tt.req)
			require.Error(t, err)
			assert.Nil(t, resp)

			var herodotErr *herodot.DefaultError
			require.True(t, errors.As(err, &herodotErr))
			assert.Equal(t, 400, herodotErr.CodeField)
			assert.Contains(t, herodotErr.ReasonField, tt.errContains)
		})
	}
}

func TestBatchImportAPIKeys_SuccessScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		batchSize int
	}{
		{
			name:      "single key batch success",
			batchSize: 1,
		},
		{
			name:      "multiple keys batch success",
			batchSize: 5,
		},
		{
			name:      "batch size at limit",
			batchSize: service.MaxBatchImportSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, verifier, ctx := setupTestService(t)

			keys := make([]*talosv2alpha1.ImportApiKeyRequest, tt.batchSize)
			for i := range tt.batchSize {
				keys[i] = &talosv2alpha1.ImportApiKeyRequest{
					RawKey:  fmt.Sprintf("batch-success-raw-key-%04d-abcdefghijklmnopqrstuvwxyz", i),
					Name:    fmt.Sprintf("batch-success-name-%d", i),
					ActorId: "batch-owner",
					Scopes:  []string{"read"},
				}
			}

			resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{Requests: keys})
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, int32(tt.batchSize), resp.GetSuccessCount())
			assert.Equal(t, int32(0), resp.GetFailureCount())
			require.Len(t, resp.GetResults(), tt.batchSize)

			for i, result := range resp.GetResults() {
				require.NotNil(t, result)
				assert.Equal(t, int32(i), result.GetIndex())
				require.NotNil(t, result.GetImportedApiKey())
				assert.Nil(t, result.ErrorCode)
				assert.Nil(t, result.ErrorMessage)
				assert.Equal(t, keys[i].GetName(), result.GetImportedApiKey().GetName())
				assert.Equal(t, keys[i].GetActorId(), result.GetImportedApiKey().GetActorId())
			}

			// Verify imported keys can be used for authentication.
			checkIndices := []int{0}
			if tt.batchSize > 1 {
				checkIndices = append(checkIndices, tt.batchSize-1)
			}
			for _, idx := range checkIndices {
				verifiedKey, _, verifyErr := verifier.VerifyAPIKey(ctx, keys[idx].GetRawKey())
				require.NoError(t, verifyErr)
				assert.Equal(t, resp.GetResults()[idx].GetImportedApiKey().GetKeyId(), verifiedKey.KeyID)
			}
		})
	}
}

func TestBatchImportAPIKeys_PartialFailure(t *testing.T) {
	t.Parallel()

	svc, verifier, ctx := setupTestService(t)

	_, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
		RawKey:  "already-imported-key",
		Name:    "existing",
		ActorId: "existing-owner",
	})
	require.NoError(t, err)

	batch := []*talosv2alpha1.ImportApiKeyRequest{
		{RawKey: "partial-valid-1-abcdefghijklmnopqrstuvwxyz123456", Name: "partial-name-1", ActorId: "partial-owner"},
		{RawKey: "already-imported-key", Name: "duplicate", ActorId: "partial-owner"},
		{RawKey: "", Name: "missing-raw", ActorId: "partial-owner"},
		{RawKey: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", Name: "format-conflict-derived", ActorId: "partial-owner"},
		{RawKey: "partial-valid-2-abcdefghijklmnopqrstuvwxyz123456", Name: "partial-name-2", ActorId: "partial-owner"},
	}

	resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{Requests: batch})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(2), resp.GetSuccessCount())
	assert.Equal(t, int32(3), resp.GetFailureCount())
	require.Len(t, resp.GetResults(), len(batch))

	for i, result := range resp.GetResults() {
		assert.Equal(t, int32(i), result.GetIndex())
	}

	assert.NotNil(t, resp.GetResults()[0].GetImportedApiKey())
	assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS, resp.GetResults()[1].GetErrorCode())
	assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT, resp.GetResults()[2].GetErrorCode())
	assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_FAILED_PRECONDITION, resp.GetResults()[3].GetErrorCode())
	assert.Contains(t, resp.GetResults()[3].GetErrorMessage(), "derived token pattern")
	assert.NotNil(t, resp.GetResults()[4].GetImportedApiKey())

	verified1, _, verifyErr1 := verifier.VerifyAPIKey(ctx, "partial-valid-1-abcdefghijklmnopqrstuvwxyz123456")
	require.NoError(t, verifyErr1)
	assert.Equal(t, resp.GetResults()[0].GetImportedApiKey().GetKeyId(), verified1.KeyID)

	verified2, _, verifyErr2 := verifier.VerifyAPIKey(ctx, "partial-valid-2-abcdefghijklmnopqrstuvwxyz123456")
	require.NoError(t, verifyErr2)
	assert.Equal(t, resp.GetResults()[4].GetImportedApiKey().GetKeyId(), verified2.KeyID)
}

func TestBatchImportAPIKeys_AllFailuresReturnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		keys         []*talosv2alpha1.ImportApiKeyRequest
		expectedCode int
		errContains  string
	}{
		{
			name: "all validation errors",
			keys: []*talosv2alpha1.ImportApiKeyRequest{
				{RawKey: "", Name: "", ActorId: ""},
				{RawKey: "", Name: "name-only", ActorId: "owner"},
			},
			expectedCode: 400,
			errContains:  "failed validation",
		},
		{
			name: "all duplicates",
			keys: []*talosv2alpha1.ImportApiKeyRequest{
				{RawKey: "duplicate-all-1", Name: "duplicate-all-1", ActorId: "duplicate-owner"},
				{RawKey: "duplicate-all-2", Name: "duplicate-all-2", ActorId: "duplicate-owner"},
			},
			expectedCode: 409,
			errContains:  "already exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, _, ctx := setupTestService(t)

			if tt.name == "all duplicates" {
				for _, key := range tt.keys {
					_, importErr := svc.ImportAPIKey(ctx, key)
					require.NoError(t, importErr)
				}
			}

			resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{Requests: tt.keys})
			require.Error(t, err)
			assert.Nil(t, resp)

			var herodotErr *herodot.DefaultError
			require.True(t, errors.As(err, &herodotErr))
			assert.Equal(t, tt.expectedCode, herodotErr.CodeField)
			assert.Contains(t, herodotErr.ReasonField, tt.errContains)
		})
	}
}

func TestBatchImportAPIKeys_ProtoValidationPerItem(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	overlongName := strings.Repeat("n", 256)

	batch := []*talosv2alpha1.ImportApiKeyRequest{
		{RawKey: "proto-valid-1-abcdefghijklmnopqrstuvwxyz123456", Name: "proto-valid-name-1", ActorId: "proto-owner"},
		{RawKey: "proto-overlong-name-abcdefghijklmnopqrstuvwxyz", Name: overlongName, ActorId: "proto-owner"},
		{RawKey: "proto-valid-2-abcdefghijklmnopqrstuvwxyz123456", Name: "proto-valid-name-2", ActorId: "proto-owner"},
	}

	resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{Requests: batch})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(2), resp.GetSuccessCount())
	assert.Equal(t, int32(1), resp.GetFailureCount())
	require.Len(t, resp.GetResults(), len(batch))

	assert.NotNil(t, resp.GetResults()[0].GetImportedApiKey())
	assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT, resp.GetResults()[1].GetErrorCode())
	assert.Contains(t, resp.GetResults()[1].GetErrorMessage(), "name")
	assert.NotNil(t, resp.GetResults()[2].GetImportedApiKey())

	// Guard against divergence: single import must reject the same violation.
	single, err := svc.ImportAPIKey(ctx, &talosv2alpha1.ImportApiKeyRequest{
		RawKey:  "proto-single-overlong-abcdefghijklmnopqrstuvwxyz",
		Name:    overlongName,
		ActorId: "proto-owner",
	})
	require.Error(t, err)
	assert.Nil(t, single)
	var herodotErr *herodot.DefaultError
	require.True(t, errors.As(err, &herodotErr))
	assert.Equal(t, 400, herodotErr.CodeField)
}

func TestBatchImportAPIKeys_DuplicateWithinSameBatch(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	duplicateRawKey := "duplicate-within-batch"
	resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{
		Requests: []*talosv2alpha1.ImportApiKeyRequest{
			{RawKey: duplicateRawKey, Name: "first", ActorId: "owner"},
			{RawKey: duplicateRawKey, Name: "second", ActorId: "owner"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(1), resp.GetSuccessCount())
	assert.Equal(t, int32(1), resp.GetFailureCount())
	require.Len(t, resp.GetResults(), 2)
	assert.Equal(t, int32(0), resp.GetResults()[0].GetIndex())
	assert.Equal(t, int32(1), resp.GetResults()[1].GetIndex())
	assert.NotNil(t, resp.GetResults()[0].GetImportedApiKey())
	assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS, resp.GetResults()[1].GetErrorCode())
}

func TestBatchImportAPIKeys_MetadataTooLarge(t *testing.T) {
	t.Parallel()

	svc, _, ctx := setupTestService(t)

	metadata, err := structpb.NewStruct(map[string]any{
		"payload": strings.Repeat("x", validation.MaxMetadataSize+1),
	})
	require.NoError(t, err)

	resp, err := svc.BatchImportAPIKeys(ctx, &talosv2alpha1.BatchCreateImportedApiKeysRequest{
		Requests: []*talosv2alpha1.ImportApiKeyRequest{
			{
				RawKey:   "batch-metadata-too-large-key",
				Name:     "batch-metadata-too-large-name",
				ActorId:  "batch-metadata-too-large-owner",
				Metadata: metadata,
			},
			{
				RawKey:  "batch-metadata-valid-key",
				Name:    "batch-metadata-valid-name",
				ActorId: "batch-metadata-owner",
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, int32(1), resp.GetSuccessCount())
	assert.Equal(t, int32(1), resp.GetFailureCount())
	require.Len(t, resp.GetResults(), 2)
	assert.Equal(t, talosv2alpha1.BatchCreateImportedApiKeysErrorCode_BATCH_CREATE_IMPORTED_API_KEYS_ERROR_INVALID_ARGUMENT, resp.GetResults()[0].GetErrorCode())
	assert.Contains(t, resp.GetResults()[0].GetErrorMessage(), "metadata size")
	assert.NotNil(t, resp.GetResults()[1].GetImportedApiKey())
}

func makeImportRequests(size int) []*talosv2alpha1.ImportApiKeyRequest {
	keys := make([]*talosv2alpha1.ImportApiKeyRequest, size)
	for i := range size {
		keys[i] = &talosv2alpha1.ImportApiKeyRequest{
			RawKey:  fmt.Sprintf("batch-limit-raw-key-%04d-abcdefghijklmnopqrstuvwxyz", i),
			Name:    fmt.Sprintf("batch-limit-name-%d", i),
			ActorId: "batch-limit-owner",
		}
	}
	return keys
}

// reviewed - @aeneasr - 2026-03-26
