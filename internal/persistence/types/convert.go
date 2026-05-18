package persistencetypes

import (
	"context"

	"github.com/ory-corp/talos/internal/contextx"

	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
)

// ImportedAPIKeyToIssuedAPIKey converts an ImportedApiKey to a db.IssuedApiKey for uniform handling.
// NID is sourced from context (never from the database record).
func ImportedAPIKeyToIssuedAPIKey(ctx context.Context, imported db.ImportedApiKey) db.IssuedApiKey {
	return db.IssuedApiKey{
		NID:                  contextx.NetworkIDFromContext(ctx),
		KeyID:                imported.KeyID,
		Name:                 imported.Name,
		TokenPrefix:          "imported",
		Version:              0,
		ActorID:              imported.ActorID,
		Scopes:               imported.Scopes,
		Status:               imported.Status,
		Metadata:             imported.Metadata,
		LastUsedAt:           imported.LastUsedAt,
		ExpiresAt:            imported.ExpiresAt,
		CreatedAt:            imported.CreatedAt,
		UpdatedAt:            imported.UpdatedAt,
		RateLimitQuota:       imported.RateLimitQuota,
		RateLimitWindow:      imported.RateLimitWindow,
		RevocationReason:     imported.RevocationReason,
		RevocationReasonText: imported.RevocationReasonText,
		AllowedCidrs:         imported.AllowedCidrs,
		RequestID:            imported.RequestID,
		Visibility:           imported.Visibility,
	}
}

// reviewed - @aeneasr - 2026-03-26
