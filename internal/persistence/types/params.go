// Package persistencetypes defines the shared parameter structs and helpers used by
// the persistence layer. These helpers encapsulate normalization rules so the
// concrete database drivers can stay lean and consistent.
package persistencetypes

import (
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"

	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
)

// CreateIssuedAPIKeyParams aggregates all inputs required to create an API key.
type CreateIssuedAPIKeyParams struct {
	KeyID           string
	Name            string
	TokenPrefix     string
	ActorID         string
	Scopes          json.RawMessage // Pre-normalized JSON from validation layer
	Metadata        json.RawMessage
	ExpiresAt       *time.Time
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage // Pre-normalized JSON array of CIDR strings
	RequestID       string          // Client-controlled idempotency key (AIP-133); empty = no idempotency
	Visibility      int32           // KeyVisibility proto enum value: 1=SECRET, 2=PUBLIC
}

// RotateIssuedAPIKeyParams captures information required for atomic rotation.
type RotateIssuedAPIKeyParams struct {
	OldKeyID        string
	NewKeyID        string
	Name            string
	TokenPrefix     string
	ActorID         string
	Scopes          []string
	Metadata        json.RawMessage
	ExpiresAt       *time.Time
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage
	Visibility      int32
}

// CreateImportedKeyParams contains inputs for creating imported keys.
type CreateImportedKeyParams struct {
	KeyID           string
	ActorID         string
	Name            string
	Scopes          json.RawMessage
	Metadata        json.RawMessage
	Status          int32
	ExpiresAt       *time.Time
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage
	RequestID       string // Client-controlled idempotency key (AIP-133); empty = no idempotency
	Visibility      int32  // KeyVisibility proto enum value: 1=SECRET, 2=PUBLIC
}

// UpdateIssuedAPIKeyParams represents updates to mutable key fields.
type UpdateIssuedAPIKeyParams struct {
	KeyID           string
	Name            string
	Scopes          []string
	Metadata        json.RawMessage
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage // nil = no update, non-nil = update
}

// RevokeIssuedAPIKeyParams contains inputs for revocation operations.
type RevokeIssuedAPIKeyParams struct {
	KeyID       string
	Reason      int32
	Description string
	ExpiresAt   *time.Time // New expiration timestamp (computed by business logic)
}

// UpdateImportedKeyParams represents updates to mutable imported key fields.
type UpdateImportedKeyParams struct {
	KeyID           string
	Name            string
	Scopes          []string
	Metadata        json.RawMessage
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage // nil = no update, non-nil = update
}

// PreparedFields normalizes the optional update payloads.
func (p UpdateImportedKeyParams) PreparedFields() (UpdateFields, error) {
	return prepareUpdateFields(p.Scopes, p.Metadata, p.AllowedCIDRs)
}

// RevokeImportedKeyParams contains inputs for revoking imported keys.
type RevokeImportedKeyParams struct {
	KeyID       string
	Reason      int32
	Description string
	ExpiresAt   *time.Time // New expiration timestamp (computed by business logic)
}

// KeyFields holds normalized scopes/metadata JSON used by multiple drivers.
type KeyFields struct {
	ScopesJSON   json.RawMessage
	MetadataJSON json.RawMessage
}

// PreparedFields normalizes scopes/metadata for API key creation.
// Scopes are already normalized by the validation layer, so we just ensure metadata is normalized.
func (p CreateIssuedAPIKeyParams) PreparedFields() (KeyFields, error) {
	normalizedMetadata := sqlutil.NormalizeMetadata(p.Metadata)
	return KeyFields{
		ScopesJSON:   p.Scopes,
		MetadataJSON: normalizedMetadata,
	}, nil
}

// RotateIssuedAPIKeyResult holds both the newly created key and the old key that was
// read inside the transaction. Returning the old key eliminates the TOCTOU gap
// that existed when the read happened outside the transaction boundary.
type RotateIssuedAPIKeyResult struct {
	NewKey db.IssuedApiKey
	OldKey db.IssuedApiKey
}

// PreparedFields normalizes scopes/metadata for API key rotation.
func (p RotateIssuedAPIKeyParams) PreparedFields() (KeyFields, error) {
	scopesJSON, err := json.Marshal(p.Scopes)
	if err != nil {
		return KeyFields{}, errors.Wrap(err, "marshal scopes")
	}
	return KeyFields{
		ScopesJSON:   scopesJSON,
		MetadataJSON: sqlutil.NormalizeMetadata(p.Metadata),
	}, nil
}

// PreparedFields normalizes scopes/metadata for imported key creation.
func (p CreateImportedKeyParams) PreparedFields() KeyFields {
	return KeyFields{
		ScopesJSON:   sqlutil.NormalizeScopesJSON(p.Scopes),
		MetadataJSON: sqlutil.NormalizeMetadata(p.Metadata),
	}
}

// UpdateFields encapsulates normalized payloads for update statements.
type UpdateFields struct {
	ScopesJSON      json.RawMessage
	MetadataJSON    json.RawMessage
	AllowedCIDRs    json.RawMessage
	HasMetadata     bool
	HasAllowedCIDRs bool
}

// PreparedFields normalizes the optional update payloads.
func (p UpdateIssuedAPIKeyParams) PreparedFields() (UpdateFields, error) {
	return prepareUpdateFields(p.Scopes, p.Metadata, p.AllowedCIDRs)
}

// prepareUpdateFields normalizes optional update payloads shared by both
// UpdateIssuedAPIKeyParams and UpdateImportedKeyParams.
func prepareUpdateFields(scopes []string, metadata json.RawMessage, allowedCIDRs json.RawMessage) (UpdateFields, error) {
	var fields UpdateFields

	// Scopes are always written: both service callers (issued and imported key
	// updates) pass the full merged value (existing-or-patched), so an empty
	// slice is an explicit clear, not a "skip this column" signal. Marshal nil
	// as [] so the JSON column never receives null.
	scopesJSON, err := json.Marshal(sqlutil.NonNilSlice(scopes))
	if err != nil {
		return UpdateFields{}, errors.Wrap(err, "marshal scopes")
	}
	fields.ScopesJSON = scopesJSON

	if len(metadata) > 0 {
		fields.HasMetadata = true
		fields.MetadataJSON = sqlutil.NormalizeMetadata(metadata)
	}

	if allowedCIDRs != nil {
		fields.HasAllowedCIDRs = true
		fields.AllowedCIDRs = allowedCIDRs
	}

	return fields, nil
}

// JSONScopes returns the scopes payload. It is always non-nil because updates
// carry the full merged scopes value; an empty array clears the scopes.
func (u UpdateFields) JSONScopes() json.RawMessage {
	return u.ScopesJSON
}

// JSONMetadata returns the metadata payload or nil when untouched.
func (u UpdateFields) JSONMetadata() json.RawMessage {
	if !u.HasMetadata {
		return nil
	}
	return u.MetadataJSON
}

// JSONAllowedCIDRs returns the allowed CIDRs payload or nil when no update is requested.
func (u UpdateFields) JSONAllowedCIDRs() json.RawMessage {
	if !u.HasAllowedCIDRs {
		return nil
	}
	return u.AllowedCIDRs
}

// reviewed - @aeneasr - 2026-03-26
