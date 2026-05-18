package api_test

import (
	"fmt"
	"net/http"

	client "github.com/ory-corp/talos/internal/client/generated"
)

func (s *APIKeyE2ETestSuite) TestBatchImportAPIKeys() {
	ctx := s.T().Context()

	s.Run("all imports pass via HTTP with at least 3 keys", func() {
		m := s.testServer.Metrics
		beforeBatchReqs := snap(m.BatchImportRequests)
		beforeCreated := snap(m.APIKeysCreated)
		beforePartialFail := snap(m.BatchImportPartialFailures)

		keys := make([]client.ImportAPIKeyRequest, 5)
		for i := range 5 {
			keys[i] = newImportReq(
				fmt.Sprintf("e2e-batch-success-%d", i),
				fmt.Sprintf("batch-success-%d", i),
				"e2e-batch-owner",
			)
		}

		batchReq := client.NewBatchImportAPIKeysRequest()
		batchReq.SetRequests(keys)

		resp := s.sdkBatchImportAPIKeys(ctx, batchReq)
		s.Equal(int32(5), resp.GetSuccessCount())
		s.Equal(int32(0), resp.GetFailureCount())
		s.Len(resp.GetResults(), 5)

		s.Equal(1, counterDelta(m.BatchImportRequests, beforeBatchReqs), "BatchImportRequests")
		s.Equal(5, counterDelta(m.APIKeysCreated, beforeCreated), "APIKeysCreated")
		s.Equal(0, counterDelta(m.BatchImportPartialFailures, beforePartialFail), "BatchImportPartialFailures")

		for i, result := range resp.GetResults() {
			s.Equal(int32(i), result.GetIndex())
			s.True(result.HasImportedApiKey())
			s.False(result.HasErrorCode())
			s.False(result.HasErrorMessage())
			apiKey, ok := result.GetImportedApiKeyOk()
			s.True(ok)

			verifyResp := s.sdkVerify(ctx, keys[i].GetRawKey())
			s.True(verifyResp.GetIsValid())
			s.Equal(apiKey.GetKeyId(), verifyResp.GetKeyId())
		}
	})

	s.Run("some imports pass via HTTP with 2 pass and 2 fail", func() {
		m := s.testServer.Metrics
		existing := newImportReq("e2e-batch-matrix-duplicate-existing", "matrix-existing", "e2e-batch-matrix-owner")
		s.sdkImportAPIKey(ctx, &existing)

		beforeBatchReqs := snap(m.BatchImportRequests)
		beforeCreated := snap(m.APIKeysCreated)
		beforePartialFail := snap(m.BatchImportPartialFailures)

		batchReq := client.NewBatchImportAPIKeysRequest()
		batchReq.SetRequests([]client.ImportAPIKeyRequest{
			newImportReq("e2e-batch-matrix-valid-1", "matrix-valid-1", "e2e-batch-matrix-owner"),
			newImportReq("e2e-batch-matrix-duplicate-existing", "matrix-duplicate", "e2e-batch-matrix-owner"),
			func() client.ImportAPIKeyRequest {
				req := client.NewImportAPIKeyRequest()
				req.SetRawKey("e2e-batch-matrix-invalid-missing-name")
				req.SetActorId("e2e-batch-matrix-owner")
				return *req
			}(),
			newImportReq("e2e-batch-matrix-valid-2", "matrix-valid-2", "e2e-batch-matrix-owner"),
		})

		resp := s.sdkBatchImportAPIKeys(ctx, batchReq)
		s.Equal(int32(2), resp.GetSuccessCount())
		s.Equal(int32(2), resp.GetFailureCount())
		s.Len(resp.GetResults(), 4)

		s.True(resp.GetResults()[0].HasImportedApiKey())
		s.True(resp.GetResults()[1].HasErrorCode())
		s.Equal(client.BATCHIMPORTERRORCODE_BATCH_IMPORT_ERROR_ALREADY_EXISTS, resp.GetResults()[1].GetErrorCode())
		s.True(resp.GetResults()[2].HasErrorCode())
		s.Equal(client.BATCHIMPORTERRORCODE_BATCH_IMPORT_ERROR_INVALID_ARGUMENT, resp.GetResults()[2].GetErrorCode())
		s.True(resp.GetResults()[3].HasImportedApiKey())

		verifyFirst := s.sdkVerify(ctx, "e2e-batch-matrix-valid-1")
		s.True(verifyFirst.GetIsValid())
		verifySecond := s.sdkVerify(ctx, "e2e-batch-matrix-valid-2")
		s.True(verifySecond.GetIsValid())

		s.Equal(1, counterDelta(m.BatchImportRequests, beforeBatchReqs), "BatchImportRequests")
		s.Equal(2, counterDelta(m.APIKeysCreated, beforeCreated), "APIKeysCreated")
		s.Equal(1, counterDelta(m.BatchImportPartialFailures, beforePartialFail), "BatchImportPartialFailures")
	})

	s.Run("partial failure response structure", func() {
		duplicateReq := client.NewImportAPIKeyRequest()
		duplicateReq.SetRawKey("e2e-batch-duplicate-existing")
		duplicateReq.SetName("existing")
		duplicateReq.SetActorId("e2e-batch-owner")
		s.sdkImportAPIKey(ctx, duplicateReq)

		batchItems := []client.ImportAPIKeyRequest{
			newImportReq("e2e-batch-partial-valid-1", "partial-valid-1", "e2e-batch-owner"),
			newImportReq("e2e-batch-duplicate-existing", "duplicate", "e2e-batch-owner"),
			func() client.ImportAPIKeyRequest {
				req := client.NewImportAPIKeyRequest()
				req.SetRawKey("e2e-batch-invalid-missing-name")
				req.SetActorId("e2e-batch-owner")
				return *req
			}(),
			newImportReq("prod_v1_Qixc9eno7AsY9gYxGU2tAFZf36gyPhnx2nNUpNvqexZun1jq7raV7c8VkrhyqPZR_AbC3XyZ789", "format-conflict", "e2e-batch-owner"),
			newImportReq("e2e-batch-partial-valid-2", "partial-valid-2", "e2e-batch-owner"),
		}

		batchReq := client.NewBatchImportAPIKeysRequest()
		batchReq.SetRequests(batchItems)

		resp := s.sdkBatchImportAPIKeys(ctx, batchReq)
		s.Equal(int32(2), resp.GetSuccessCount())
		s.Equal(int32(3), resp.GetFailureCount())
		s.Len(resp.GetResults(), len(batchItems))

		for i, result := range resp.GetResults() {
			s.Equal(int32(i), result.GetIndex())
		}

		s.True(resp.GetResults()[0].HasImportedApiKey())
		s.True(resp.GetResults()[1].HasErrorCode())
		s.Equal(client.BATCHIMPORTERRORCODE_BATCH_IMPORT_ERROR_ALREADY_EXISTS, resp.GetResults()[1].GetErrorCode())
		s.True(resp.GetResults()[2].HasErrorCode())
		s.Equal(client.BATCHIMPORTERRORCODE_BATCH_IMPORT_ERROR_INVALID_ARGUMENT, resp.GetResults()[2].GetErrorCode())
		s.True(resp.GetResults()[3].HasErrorCode())
		s.Equal(client.BATCHIMPORTERRORCODE_BATCH_IMPORT_ERROR_FAILED_PRECONDITION, resp.GetResults()[3].GetErrorCode())
		s.True(resp.GetResults()[4].HasImportedApiKey())

		verifyFirst := s.sdkVerify(ctx, "e2e-batch-partial-valid-1")
		s.True(verifyFirst.GetIsValid())
		verifySecond := s.sdkVerify(ctx, "e2e-batch-partial-valid-2")
		s.True(verifySecond.GetIsValid())
	})

	s.Run("batch limit enforcement", func() {
		keys := make([]client.ImportAPIKeyRequest, 1001)
		for i := range 1001 {
			req := client.NewImportAPIKeyRequest()
			req.SetRawKey(fmt.Sprintf("e2e-batch-over-limit-%d", i))
			req.SetName(fmt.Sprintf("over-limit-%d", i))
			req.SetActorId("e2e-over-limit-owner")
			keys[i] = *req
		}

		batchReq := client.NewBatchImportAPIKeysRequest()
		batchReq.SetRequests(keys)

		httpResp, err := s.sdkBatchImportAPIKeysExpectError(ctx, batchReq)
		s.requireHTTPError(err, httpResp, http.StatusBadRequest)
	})

	s.Run("none pass via HTTP when all keys already exist", func() {
		m := s.testServer.Metrics
		first := client.NewImportAPIKeyRequest()
		first.SetRawKey("e2e-batch-all-dup-1")
		first.SetName("all-dup-1")
		first.SetActorId("e2e-all-dup-owner")
		s.sdkImportAPIKey(ctx, first)

		second := client.NewImportAPIKeyRequest()
		second.SetRawKey("e2e-batch-all-dup-2")
		second.SetName("all-dup-2")
		second.SetActorId("e2e-all-dup-owner")
		s.sdkImportAPIKey(ctx, second)

		third := client.NewImportAPIKeyRequest()
		third.SetRawKey("e2e-batch-all-dup-3")
		third.SetName("all-dup-3")
		third.SetActorId("e2e-all-dup-owner")
		s.sdkImportAPIKey(ctx, third)

		beforeBatchReqs := snap(m.BatchImportRequests)
		beforeCreated := snap(m.APIKeysCreated)
		beforePartialFail := snap(m.BatchImportPartialFailures)

		batchReq := client.NewBatchImportAPIKeysRequest()
		batchReq.SetRequests([]client.ImportAPIKeyRequest{*first, *second, *third})

		httpResp, err := s.sdkBatchImportAPIKeysExpectError(ctx, batchReq)
		s.requireHTTPError(err, httpResp, http.StatusConflict)

		s.Equal(1, counterDelta(m.BatchImportRequests, beforeBatchReqs), "BatchImportRequests")
		s.Equal(0, counterDelta(m.APIKeysCreated, beforeCreated), "APIKeysCreated")
		s.Equal(0, counterDelta(m.BatchImportPartialFailures, beforePartialFail), "BatchImportPartialFailures")
	})
}

// reviewed - @aeneasr - 2026-03-27
