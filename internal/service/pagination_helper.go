package service

import (
	"context"

	"github.com/cockroachdb/errors"

	"github.com/ory/talos/internal/contextx"
	"github.com/ory/talos/internal/crypto"

	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/pagination"
	"github.com/ory/talos/internal/service/validation"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// paginationHelper manages cursor-based pagination for list operations.
// It provides a centralized way to handle pagination across all list endpoints.
type paginationHelper struct {
	provider ConfigProvider
}

// trimResults removes the extra item fetched for hasMore detection.
// Returns the slice trimmed to pageSize.
// Note: Package-level function (not method) to support generic types.
func trimResults[T any](results []T, pageSize int32) []T {
	if len(results) > int(pageSize) {
		return results[:pageSize]
	}
	return results
}

// listQueryParams holds the parsed and validated parameters for a list query.
type listQueryParams struct {
	filter    validation.ListFilter
	cursorKey string
	limit     int64
	pageSize  int32
}

// prepareListQuery validates request fields and returns ready-to-use query parameters.
// This is the shared pagination setup for ListIssuedAPIKeys and ListImportedAPIKeys.
func (p *paginationHelper) prepareListQuery(ctx context.Context, filter string, reqPageSize int32, pageToken string) (listQueryParams, error) {
	f, err := validation.ParseListFilter(filter)
	if err != nil {
		return listQueryParams{}, errdef.BadRequest(err.Error())
	}
	if f.Status != talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED && f.ActorID == "" {
		return listQueryParams{}, errdef.BadRequest("status filter must be combined with actor_id: use filter='actor_id=\"<value>\" AND status=<value>'")
	}

	pageSize := pagination.ValidatePageSize(reqPageSize)

	var cursorKeyID string
	if pageToken != "" {
		keys, err := crypto.PaginationKeysForVerification(ctx, p.provider)
		if err != nil {
			return listQueryParams{}, errdef.InternalError("derive pagination keys").WithWrap(errors.WithStack(err))
		}
		cursor, err := pagination.DecodeCursor(keys, pageToken)
		if err != nil {
			return listQueryParams{}, errdef.BadRequest("invalid page token").WithWrap(errors.WithStack(err))
		}
		nid, err := contextx.RequiredNetworkIDFromContext(ctx)
		if err != nil {
			return listQueryParams{}, errdef.InternalError("extract network id from context").WithWrap(errors.WithStack(err))
		}
		if cursor.NID != nid.String() {
			return listQueryParams{}, errdef.BadRequest("page token network mismatch")
		}
		cursorKeyID = cursor.ID
	}

	return listQueryParams{
		filter:    f,
		cursorKey: cursorKeyID,
		limit:     int64(pageSize + 1),
		pageSize:  pageSize,
	}, nil
}

// nextPageToken generates the next page token from query results.
// keyID is the ID of the last item in the trimmed results.
func (p *paginationHelper) nextPageToken(ctx context.Context, originalCount int, pageSize int32, keyID string) (string, error) {
	if originalCount <= int(pageSize) {
		return "", nil
	}
	secret, err := crypto.HMACSecretForSigning(ctx, p.provider)
	if err != nil {
		return "", errdef.InternalError("derive pagination key").WithWrap(errors.WithStack(err))
	}
	key := crypto.DerivePaginationKey(secret)
	nid, err := contextx.RequiredNetworkIDFromContext(ctx)
	if err != nil {
		return "", errdef.InternalError("extract network id from context").WithWrap(errors.WithStack(err))
	}
	token, err := pagination.EncodeCursor(key, keyID, nid.String())
	if err != nil {
		return "", errdef.InternalError("encode pagination cursor").WithWrap(errors.WithStack(err))
	}
	return token, nil
}

// reviewed - @aeneasr - 2026-03-26
