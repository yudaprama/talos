package service

import (
	"context"
	"slices"

	"github.com/cockroachdb/errors"

	"github.com/ory-corp/talos/internal/contextx"

	talosconfig "github.com/ory-corp/talos/internal/config"
	"github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/errdef"
	"github.com/ory-corp/talos/internal/pagination"
	"github.com/ory-corp/talos/internal/service/validation"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
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

	secrets := paginationSecrets(ctx, p.provider)

	var cursorKeyID string
	if pageToken != "" {
		cursor, err := pagination.DecodeCursor(secrets, pageToken)
		if err != nil {
			return listQueryParams{}, errdef.BadRequest("invalid page token").WithWrap(errors.WithStack(err))
		}
		if cursor.NID != contextx.NetworkIDFromContext(ctx).String() {
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
	secrets := paginationSecrets(ctx, p.provider)
	token, err := pagination.EncodeCursor(secrets[0], keyID, contextx.NetworkIDFromContext(ctx).String())
	if err != nil {
		return "", errdef.InternalError("encode pagination cursor").WithWrap(errors.WithStack(err))
	}
	return token, nil
}

// paginationSecrets returns the current pagination secret followed by any retired secrets.
func paginationSecrets(ctx context.Context, provider ConfigProvider) []string {
	if current := provider.String(ctx, talosconfig.KeySecretsPagination); current != "" {
		retired := provider.Strings(ctx, talosconfig.KeySecretsPaginationRetired)
		return slices.Concat([]string{current}, retired)
	}
	return crypto.DefaultSecrets(ctx, provider)
}

// reviewed - @aeneasr - 2026-03-26
