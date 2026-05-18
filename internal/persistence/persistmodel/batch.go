// Package persistmodel defines shared persistence data structures.
package persistmodel

import (
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"

	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
)

// requestIDMaxLen is the maximum byte length of RequestID, matching the
// VARCHAR(36) column constraint in all supported database backends.
const requestIDMaxLen = 36

// BatchCreateImportedAPIKeyInput contains one imported key to create in a batch operation.
type BatchCreateImportedAPIKeyInput struct {
	KeyID           string
	ActorID         string
	Name            string
	Scopes          json.RawMessage
	Metadata        json.RawMessage
	ExpiresAt       *time.Time
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage
	Visibility      int32
	// RequestID is the AIP-133 idempotency key. When non-empty, a unique index
	// on (nid, request_id) prevents duplicate rows across retried batch imports.
	// Must not exceed 36 bytes (VARCHAR(36)).
	RequestID string
}

// Validate checks that field values satisfy the persistence-layer constraints.
// Call this before passing an input to any CreateImportedAPIKeysBatch driver.
func (b *BatchCreateImportedAPIKeyInput) Validate() error {
	if len(b.RequestID) > requestIDMaxLen {
		return errors.Errorf(
			"request_id %q exceeds maximum length of %d bytes",
			b.RequestID, requestIDMaxLen,
		)
	}
	return nil
}

// BatchCreateImportedAPIKeysResult contains inserted and pre-existing imported keys keyed by key_id.
type BatchCreateImportedAPIKeysResult struct {
	Inserted map[string]db.ImportedApiKey
	Existing map[string]struct{}
}

// reviewed - @aeneasr - 2026-03-26
