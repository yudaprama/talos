// Package persistence provides database driver abstraction and interfaces.
package persistence

import (
	"context"
	"database/sql"

	"github.com/ory-corp/talos/internal/persistence/persistmodel"
	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	persistencetypes "github.com/ory-corp/talos/internal/persistence/types"
)

// Persister is the interface that all database drivers must implement.
// This provides a common abstraction over SQLite, PostgreSQL, MySQL, and CockroachDB.
//
// Network ID (NID) is extracted from context internally by each driver implementation.
// OSS uses hardcoded uuid.Nil (single-tenant); commercial drivers use contextx.NetworkIDFromContext.
type Persister interface {
	// Issued API Key operations

	// CreateIssuedAPIKey creates a new API key in the database.
	CreateIssuedAPIKey(ctx context.Context, params persistencetypes.CreateIssuedAPIKeyParams) (db.IssuedApiKey, error)

	// GetIssuedAPIKey retrieves an API key by ID regardless of status.
	GetIssuedAPIKey(ctx context.Context, keyID string) (db.IssuedApiKey, error)

	// GetIssuedAPIKeysBatch retrieves multiple issued API keys by their key_ids in a single query.
	// Returns only the rows that exist; missing key_ids produce no entry in the result.
	// The caller must handle per-item not-found logic.
	GetIssuedAPIKeysBatch(ctx context.Context, keyIDs []string) ([]db.IssuedApiKey, error)

	// GetActiveIssuedAPIKey retrieves an API key by ID only if it is active.
	GetActiveIssuedAPIKey(ctx context.Context, keyID string) (db.IssuedApiKey, error)

	// RevokeIssuedAPIKey marks an API key as revoked with a structured reason.
	RevokeIssuedAPIKey(ctx context.Context, params persistencetypes.RevokeIssuedAPIKeyParams) error

	// RotateIssuedAPIKeyAtomic atomically reads the old key, verifies it is active,
	// creates a new API key, and revokes the old one — all in one transaction.
	//
	// mergeFunc is called inside the transaction with the just-read old key. It must return
	// the fully-populated RotateIssuedAPIKeyParams used to create the new key. This eliminates
	// the TOCTOU gap that existed when merging happened outside the transaction boundary.
	RotateIssuedAPIKeyAtomic(ctx context.Context, oldKeyID string, mergeFunc func(db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error)) (persistencetypes.RotateIssuedAPIKeyResult, error)

	// DeleteIssuedAPIKey permanently removes an API key from the database.
	DeleteIssuedAPIKey(ctx context.Context, keyID string) error

	// ListIssuedAPIKeysByNetwork lists API keys with cursor-based pagination.
	// Optional actorID filter leverages idx_issued_api_keys_actor_pagination composite index.
	ListIssuedAPIKeysByNetwork(ctx context.Context, actorID string, statusFilter int32, cursorKeyID string, limit int64) ([]db.IssuedApiKey, error)

	// UpdateIssuedAPIKeyLastUsed updates the last_used_at timestamp for an API key.
	UpdateIssuedAPIKeyLastUsed(ctx context.Context, keyID string) error

	// UpdateImportedAPIKeyLastUsed updates the last_used_at timestamp for an imported key.
	UpdateImportedAPIKeyLastUsed(ctx context.Context, keyID string) error

	// BatchUpdateIssuedAPIKeyLastUsed updates last_used_at for multiple issued keys in one query.
	// Callers running outside a request (background workers) must inject NID into ctx
	// before calling.
	BatchUpdateIssuedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error

	// BatchUpdateImportedAPIKeyLastUsed updates last_used_at for multiple imported keys in one query.
	// Callers running outside a request (background workers) must inject NID into ctx
	// before calling.
	BatchUpdateImportedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error

	// UpdateIssuedAPIKeyMetadata updates mutable API key fields using aggregated parameters.
	UpdateIssuedAPIKeyMetadata(ctx context.Context, params persistencetypes.UpdateIssuedAPIKeyParams) (db.IssuedApiKey, error)

	// GetExpiredIssuedAPIKeys retrieves API keys that have passed their expiration time.
	GetExpiredIssuedAPIKeys(ctx context.Context, limit int32) ([]db.IssuedApiKey, error)

	// ExpireIssuedAPIKeys marks expired API keys as expired in batches.
	ExpireIssuedAPIKeys(ctx context.Context, limit int32) (int64, error)

	// Imported Key operations

	// CreateImportedAPIKey creates a record for an externally-issued API key.
	CreateImportedAPIKey(ctx context.Context, params persistencetypes.CreateImportedKeyParams) (db.ImportedApiKey, error)

	// CreateImportedAPIKeysBatch creates multiple imported keys in a single transaction.
	// Duplicate keys are treated as no-ops.
	CreateImportedAPIKeysBatch(ctx context.Context, keys []persistmodel.BatchCreateImportedAPIKeyInput) (persistmodel.BatchCreateImportedAPIKeysResult, error)

	// GetImportedAPIKeyByHash retrieves an imported key by its key_id hash.
	GetImportedAPIKeyByHash(ctx context.Context, keyID string) (db.ImportedApiKey, error)

	// GetImportedAPIKeysBatch retrieves multiple imported API keys by their key_id hashes in a single query.
	// Returns only the rows that exist; missing hashes produce no entry in the result.
	// The caller must handle per-item not-found logic.
	GetImportedAPIKeysBatch(ctx context.Context, hashes []string) ([]db.ImportedApiKey, error)

	// GetIssuedAPIKeyByRequestID retrieves an issued API key by its idempotency key (AIP-133).
	// Returns sql.ErrNoRows if no key was created with this request_id.
	GetIssuedAPIKeyByRequestID(ctx context.Context, requestID string) (db.IssuedApiKey, error)

	// GetImportedAPIKeyByRequestID retrieves an imported key by its idempotency key (AIP-133).
	// Returns sql.ErrNoRows if no key was created with this request_id.
	GetImportedAPIKeyByRequestID(ctx context.Context, requestID string) (db.ImportedApiKey, error)

	// ListImportedAPIKeys lists imported keys with cursor-based pagination.
	ListImportedAPIKeys(ctx context.Context, status int32, actorID, cursorKeyID string, limit int64) ([]db.ImportedApiKey, error)

	// UpdateImportedAPIKeyMetadata updates mutable fields of an imported key.
	UpdateImportedAPIKeyMetadata(ctx context.Context, params persistencetypes.UpdateImportedKeyParams) (db.ImportedApiKey, error)

	// RevokeImportedAPIKey marks an imported key as revoked with a structured reason.
	RevokeImportedAPIKey(ctx context.Context, params persistencetypes.RevokeImportedKeyParams) (db.ImportedApiKey, error)

	// DeleteImportedAPIKey permanently removes an imported key from the database.
	DeleteImportedAPIKey(ctx context.Context, keyID string) error

	// NOTE: Signing key operations removed - keys are now loaded from configuration
	// See internal/crypto/keyservice.go for config-based key loading via ory/x/fetcher and lestrrat-go/jwx/v3.

	// Initialization and lifecycle

	// Initialize performs any necessary database setup operations.
	Initialize(_ context.Context) error

	// InitializeNetwork creates a network row with the given ID if it does not already exist.
	// Used by multi-tenant test setups to create tenant networks through the driver
	// rather than raw SQL.
	InitializeNetwork(ctx context.Context, networkID string) error

	// Close cleanly shuts down the database connection and releases resources.
	Close() error

	// Ping verifies that the database connection is alive and responding.
	Ping(_ context.Context) error

	// DB returns the underlying sql.DB connection for direct access.
	DB() *sql.DB

	// DriverName returns the database driver name (e.g., "sqlite3", "postgres", "mysql", "cockroach").
	DriverName() string
}

// reviewed - @aeneasr - 2026-03-26
