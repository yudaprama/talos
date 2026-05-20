// Package sqlite provides SQLite database driver implementation.
package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/x/otelx"

	"github.com/ory/talos/internal/persistence/persistmodel"

	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlite/sqliteshared"
	"github.com/ory/talos/internal/persistence/sqlutil"

	persistencetypes "github.com/ory/talos/internal/persistence/types"
	"github.com/ory/talos/internal/tracing"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// networkID is the fixed NID for OSS — single-tenant with no network isolation.
var networkID = uuid.Nil

// Driver wraps the sqlc queries with a cleaner interface for SQLite.
type Driver struct {
	conn *sqlx.DB
	q    *db.Queries
}

// NewDriver creates a new SQLite driver.
func NewDriver(dsn string) (*Driver, error) {
	if dsn == "" {
		return nil, errors.Errorf("DSN is required")
	}

	// Strip sqlite:// or sqlite3:// prefix if present.
	// The modernc.org/sqlite driver expects a raw file path or :memory:.
	dsn = strings.TrimPrefix(dsn, "sqlite3://")
	dsn = strings.TrimPrefix(dsn, "sqlite://")

	conn, err := sqliteshared.OpenDB(dsn)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	return &Driver{
		conn: conn,
		q:    db.New(conn.DB),
	}, nil
}

func (d *Driver) withTx(ctx context.Context, fn func(*db.Queries) error) error {
	return sqliteshared.WithTx(ctx, d.conn, d.q, fn)
}

// CreateIssuedAPIKey creates a new API key (v1 format - simplified schema).
func (d *Driver) CreateIssuedAPIKey(ctx context.Context, params persistencetypes.CreateIssuedAPIKeyParams) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.CreateIssuedAPIKey",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	fields, err := params.PreparedFields()
	if err != nil {
		return db.IssuedApiKey{}, err
	}

	now := sqlutil.UTCNow()

	err = d.withTx(ctx, func(qtx *db.Queries) error {
		var txErr error
		result, txErr = qtx.CreateIssuedAPIKey(ctx, db.CreateIssuedAPIKeyParams{
			NID:             networkID,
			KeyID:           params.KeyID,
			Name:            params.Name,
			TokenPrefix:     params.TokenPrefix,
			Version:         int64(1),
			ActorID:         new(params.ActorID),
			Scopes:          fields.ScopesJSON,
			Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			Metadata:        fields.MetadataJSON,
			LastUsedAt:      nil,
			ExpiresAt:       params.ExpiresAt,
			RateLimitQuota:  params.RateLimitQuota,
			RateLimitWindow: params.RateLimitWindow,
			AllowedCidrs:    sqlutil.NormalizeScopesJSON(params.AllowedCIDRs),
			RequestID:       sqlutil.PtrOrNil(params.RequestID),
			Visibility:      params.Visibility,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
		return txErr
	})

	return result, err
}

// GetIssuedAPIKeyByRequestID retrieves an issued API key by its idempotency key (AIP-133).
func (d *Driver) GetIssuedAPIKeyByRequestID(ctx context.Context, requestID string) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetIssuedAPIKeyByRequestID",
		attribute.String("request_id", requestID),
	)
	defer otelx.End(span, &err)

	return d.q.GetIssuedAPIKeyByRequestID(ctx, networkID, sqlutil.PtrOrNil(requestID))
}

// GetIssuedAPIKey retrieves an API key (lookup by UUID).
func (d *Driver) GetIssuedAPIKey(ctx context.Context, keyID string) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetIssuedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	return d.q.GetIssuedAPIKey(ctx, networkID, keyID)
}

// GetIssuedAPIKeysBatch retrieves multiple issued API keys by their key_ids in one query.
// Returns only the rows that exist; missing key_ids produce no entry.
func (d *Driver) GetIssuedAPIKeysBatch(ctx context.Context, keyIDs []string) (result []db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetIssuedAPIKeysBatch",
		attribute.Int("batch_size", len(keyIDs)),
	)
	defer otelx.End(span, &err)

	if len(keyIDs) == 0 {
		return []db.IssuedApiKey{}, nil
	}

	query, args := sqlutil.BuildINQuery[db.IssuedApiKey](sqlutil.DialectQuestionMark, "issued_api_keys", networkID, keyIDs)
	result, err = sqlutil.QueryRows(ctx, d.conn, query, args, len(keyIDs), sqlutil.ScanRow[db.IssuedApiKey])
	if err != nil {
		return nil, errors.Wrap(err, "batch query issued keys")
	}

	return result, nil
}

// GetActiveIssuedAPIKey retrieves an active API key (hot path optimization).
func (d *Driver) GetActiveIssuedAPIKey(ctx context.Context, keyID string) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetActiveIssuedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	return d.q.GetActiveIssuedAPIKey(ctx, networkID, keyID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE))
}

// RevokeIssuedAPIKey revokes an API key with a structured reason.
func (d *Driver) RevokeIssuedAPIKey(ctx context.Context, params persistencetypes.RevokeIssuedAPIKeyParams) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.RevokeIssuedAPIKey",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	return d.withTx(ctx, func(qtx *db.Queries) error {
		return qtx.RevokeIssuedAPIKey(ctx, db.RevokeIssuedAPIKeyParams{
			RevokedStatus:        int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED),
			UpdatedAt:            now,
			ExpiresAt:            params.ExpiresAt,
			RevocationReason:     params.Reason,
			RevocationReasonText: sqlutil.PtrOrNil(params.Description),
			NID:                  networkID,
			KeyID:                params.KeyID,
		})
	})
}

// RotateIssuedAPIKeyAtomic atomically reads the old key, verifies it is active,
// creates a new API key, and revokes the old one — all in one transaction.
func (d *Driver) RotateIssuedAPIKeyAtomic(ctx context.Context, oldKeyID string, mergeFunc func(db.IssuedApiKey) (persistencetypes.RotateIssuedAPIKeyParams, error)) (result persistencetypes.RotateIssuedAPIKeyResult, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.RotateIssuedAPIKeyAtomic",
		attribute.String("old_key_id", oldKeyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()

	err = d.withTx(ctx, func(qtx *db.Queries) error {
		// Read the old key inside the transaction.
		// Two-step: first check existence (sql.ErrNoRows → 404), then check status
		// (ErrKeyNotActive → 409). This eliminates the TOCTOU race while preserving
		// precise error semantics for callers.
		oldKey, txErr := qtx.GetIssuedAPIKey(ctx, networkID, oldKeyID)
		if txErr != nil {
			return txErr
		}
		if oldKey.Status != int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE) {
			return persistencetypes.ErrKeyNotActive
		}
		result.OldKey = oldKey

		params, txErr := mergeFunc(oldKey)
		if txErr != nil {
			return txErr
		}

		fields, txErr := params.PreparedFields()
		if txErr != nil {
			return txErr
		}

		result.NewKey, txErr = qtx.CreateIssuedAPIKey(ctx, db.CreateIssuedAPIKeyParams{
			NID:             networkID,
			KeyID:           params.NewKeyID,
			Name:            params.Name,
			TokenPrefix:     params.TokenPrefix,
			Version:         int64(1),
			ActorID:         new(params.ActorID),
			Scopes:          fields.ScopesJSON,
			Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			Metadata:        fields.MetadataJSON,
			LastUsedAt:      nil,
			ExpiresAt:       params.ExpiresAt,
			RateLimitQuota:  params.RateLimitQuota,
			RateLimitWindow: params.RateLimitWindow,
			AllowedCidrs:    sqlutil.NormalizeScopesJSON(params.AllowedCIDRs),
			Visibility:      params.Visibility,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
		if txErr != nil {
			return txErr
		}

		rotatedText := "rotated: replaced by new key"
		txErr = qtx.RevokeIssuedAPIKey(ctx, db.RevokeIssuedAPIKeyParams{
			RevokedStatus:        int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED),
			UpdatedAt:            now,
			RevocationReason:     int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED),
			RevocationReasonText: &rotatedText,
			NID:                  networkID,
			KeyID:                oldKeyID,
		})
		return txErr
	})

	return result, err
}

// DeleteIssuedAPIKey deletes an API key.
func (d *Driver) DeleteIssuedAPIKey(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.DeleteIssuedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	return d.withTx(ctx, func(qtx *db.Queries) error {
		return qtx.DeleteIssuedAPIKey(ctx, networkID, keyID)
	})
}

// ListIssuedAPIKeysByNetwork lists API keys with cursor-based pagination.
// Optional actor_id filter leverages idx_issued_api_keys_actor_pagination composite index.
// Optional statusFilter: pass 0 to return all statuses.
func (d *Driver) ListIssuedAPIKeysByNetwork(ctx context.Context, actorID string, statusFilter int32, cursorKeyID string, limit int64) (result []db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.ListIssuedAPIKeysByNetwork",
		attribute.Int64("limit", limit),
	)
	defer otelx.End(span, &err)

	return d.q.ListIssuedAPIKeysByNetwork(ctx, db.ListIssuedAPIKeysByNetworkParams{
		NID:          networkID,
		ActorID:      sqlutil.ToNullString(actorID),
		StatusFilter: sqliteshared.Int32ToNullable(statusFilter),
		CursorKeyID:  sqlutil.ToNullString(cursorKeyID),
		PageLimit:    limit,
	})
}

// UpdateIssuedAPIKeyLastUsed updates the last used timestamp for an API key.
func (d *Driver) UpdateIssuedAPIKeyLastUsed(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.UpdateIssuedAPIKeyLastUsed",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	return d.withTx(ctx, func(qtx *db.Queries) error {
		return qtx.UpdateIssuedAPIKeyLastUsed(ctx, &now, networkID, keyID)
	})
}

// UpdateImportedAPIKeyLastUsed updates the last used timestamp for an imported key.
func (d *Driver) UpdateImportedAPIKeyLastUsed(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.UpdateImportedAPIKeyLastUsed",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	return d.withTx(ctx, func(qtx *db.Queries) error {
		return qtx.UpdateImportedAPIKeyLastUsed(ctx, &now, networkID, keyID)
	})
}

// BatchUpdateIssuedAPIKeyLastUsed updates last_used_at for multiple issued keys in one query.
func (d *Driver) BatchUpdateIssuedAPIKeyLastUsed(ctx context.Context, keyIDs []string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.BatchUpdateIssuedAPIKeyLastUsed",
		attribute.Int("batch_size", len(keyIDs)),
	)
	defer otelx.End(span, &err)

	if len(keyIDs) == 0 {
		return nil
	}

	now := sqlutil.UTCNow()
	query, args := sqlutil.BuildINUpdateQuery(sqlutil.DialectQuestionMark, "issued_api_keys", now, networkID, keyIDs)
	_, err = d.conn.ExecContext(ctx, query, args...)
	return err
}

// BatchUpdateImportedAPIKeyLastUsed updates last_used_at for multiple imported keys in one query.
func (d *Driver) BatchUpdateImportedAPIKeyLastUsed(ctx context.Context, keyIDs []string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.BatchUpdateImportedAPIKeyLastUsed",
		attribute.Int("batch_size", len(keyIDs)),
	)
	defer otelx.End(span, &err)

	if len(keyIDs) == 0 {
		return nil
	}

	now := sqlutil.UTCNow()
	query, args := sqlutil.BuildINUpdateQuery(sqlutil.DialectQuestionMark, "imported_api_keys", now, networkID, keyIDs)
	_, err = d.conn.ExecContext(ctx, query, args...)
	return err
}

// UpdateIssuedAPIKeyMetadata updates an API key's name, scopes, and metadata.
func (d *Driver) UpdateIssuedAPIKeyMetadata(ctx context.Context, params persistencetypes.UpdateIssuedAPIKeyParams) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.UpdateIssuedAPIKeyMetadata",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	fields, err := params.PreparedFields()
	if err != nil {
		return db.IssuedApiKey{}, err
	}
	now := sqlutil.UTCNow()
	result, err = d.q.UpdateIssuedAPIKey(ctx, db.UpdateIssuedAPIKeyParams{
		UpdateName: new(params.Name), UpdateScopes: fields.JSONScopes(), UpdateMetadata: fields.JSONMetadata(),
		UpdateRateLimitQuota: params.RateLimitQuota, UpdateRateLimitWindow: params.RateLimitWindow,
		UpdateAllowedCidrs: fields.JSONAllowedCIDRs(), UpdatedAt: now, NID: networkID, KeyID: params.KeyID,
	})
	return result, err
}

// GetExpiredIssuedAPIKeys retrieves expired API keys (batched).
func (d *Driver) GetExpiredIssuedAPIKeys(ctx context.Context, limit int32) (result []db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetExpiredIssuedAPIKeys",
		attribute.Int("batch_size", int(limit)),
	)
	defer otelx.End(span, &err)

	return d.q.GetExpiredIssuedAPIKeys(ctx, networkID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), int64(limit))
}

// CountActiveAPIKeysUpTo returns the number of non-revoked API keys
// (issued + imported combined) for the current network, capped at limit.
// Used for quota enforcement; the query is bounded so it never scans more
// than 2*limit rows. The result is min(actual_count, limit).
func (d *Driver) CountActiveAPIKeysUpTo(ctx context.Context, limit int64) (count int64, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.CountActiveAPIKeysUpTo",
		attribute.Int64("limit", limit),
	)
	defer otelx.End(span, &err)

	if limit <= 0 {
		return 0, nil
	}

	activeStatus := int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE)

	issued, err := d.q.ListActiveIssuedKeyIDsBounded(ctx, networkID, activeStatus, limit)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	issuedCount := int64(len(issued))
	if issuedCount >= limit {
		return limit, nil
	}

	imported, err := d.q.ListActiveImportedKeyIDsBounded(ctx, networkID, activeStatus, limit-issuedCount)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return issuedCount + int64(len(imported)), nil
}

// ExpireIssuedAPIKeys marks up to 'limit' expired API keys as expired (batched for scalability).
// Returns the number of keys that were expired.
func (d *Driver) ExpireIssuedAPIKeys(ctx context.Context, limit int32) (rowsAffected int64, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.ExpireIssuedAPIKeys",
		attribute.Int("batch_size", int(limit)),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	result, err := d.q.ExpireIssuedAPIKeys(ctx, db.ExpireIssuedAPIKeysParams{
		ExpiredStatus: int32(talosv2alpha1.KeyStatus_KEY_STATUS_EXPIRED),
		UpdatedAt:     now,
		NID:           networkID,
		ActiveStatus:  int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		BatchLimit:    int64(limit),
	})
	if err != nil {
		return 0, err
	}
	rowsAffected, err = result.RowsAffected()
	return rowsAffected, err
}

// CreateImportedAPIKey creates a new imported API key.
func (d *Driver) CreateImportedAPIKey(ctx context.Context, params persistencetypes.CreateImportedKeyParams) (result db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.CreateImportedAPIKey",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	fields := params.PreparedFields()

	now := sqlutil.UTCNow()

	err = d.withTx(ctx, func(qtx *db.Queries) error {
		row, txErr := qtx.CreateImportedAPIKey(ctx, db.CreateImportedAPIKeyParams{
			NID:             networkID,
			KeyID:           params.KeyID,
			ActorID:         new(params.ActorID),
			Name:            params.Name,
			Scopes:          fields.ScopesJSON,
			Metadata:        fields.MetadataJSON,
			Status:          params.Status,
			ExpiresAt:       params.ExpiresAt,
			RateLimitQuota:  params.RateLimitQuota,
			RateLimitWindow: params.RateLimitWindow,
			AllowedCidrs:    sqlutil.NormalizeScopesJSON(params.AllowedCIDRs),
			RequestID:       sqlutil.PtrOrNil(params.RequestID),
			Visibility:      params.Visibility,
			CreatedAt:       now,
			UpdatedAt:       now,
		})
		if txErr != nil {
			return txErr
		}
		result = row
		return nil
	})

	return result, err
}

// CreateImportedAPIKeysBatch creates multiple imported keys in a single transaction.
func (d *Driver) CreateImportedAPIKeysBatch(ctx context.Context, keys []persistmodel.BatchCreateImportedAPIKeyInput) (result persistmodel.BatchCreateImportedAPIKeysResult, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.CreateImportedAPIKeysBatch",
		attribute.Int("batch_size", len(keys)),
	)
	defer otelx.End(span, &err)

	if len(keys) > sqliteshared.MaxBatchKeys {
		return persistmodel.BatchCreateImportedAPIKeysResult{}, errors.Errorf(
			"batch size %d exceeds SQLite limit of %d keys (SQLITE_MAX_VARIABLE_NUMBER / 15 args per key)",
			len(keys), sqliteshared.MaxBatchKeys,
		)
	}

	result = persistmodel.BatchCreateImportedAPIKeysResult{
		Inserted: make(map[string]db.ImportedApiKey, len(keys)),
		Existing: make(map[string]struct{}, len(keys)),
	}
	if len(keys) == 0 {
		return result, nil
	}

	keyIDs := make([]string, len(keys))
	for i, key := range keys {
		keyIDs[i] = key.KeyID
	}

	// Manual transaction instead of withTx: the batch insert uses raw *sql.Tx
	// for ExecContext with a dynamically built query, which withTx's *db.Queries
	// closure cannot accommodate.
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return persistmodel.BatchCreateImportedAPIKeysResult{}, errors.Wrap(err, "begin transaction")
	}

	txErr := func() error {
		now := sqlutil.UTCNow()
		insertQuery, insertArgs := sqliteshared.BuildBatchInsertImportedKeysQuery(networkID.String(), keys, now)

		rows, err := tx.QueryContext(ctx, insertQuery, insertArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			row, err := sqlutil.ScanRow[db.ImportedApiKey](rows)
			if err != nil {
				return errors.Wrap(err, "scan inserted imported key")
			}
			result.Inserted[row.KeyID] = row
		}
		if err := rows.Err(); err != nil {
			return err
		}

		conflictIDs := make([]string, 0, len(keyIDs))
		for _, id := range keyIDs {
			if _, inserted := result.Inserted[id]; !inserted {
				conflictIDs = append(conflictIDs, id)
			}
		}

		existingRows, err := sqliteshared.QueryImportedKeysByIDs(ctx, tx, networkID.String(), conflictIDs)
		if err != nil {
			return err
		}
		for _, row := range existingRows {
			result.Existing[row.KeyID] = struct{}{}
		}
		return nil
	}()

	if txErr != nil {
		_ = tx.Rollback()
		err = txErr
	} else {
		err = errors.Wrap(tx.Commit(), "commit transaction")
	}
	if err != nil {
		return persistmodel.BatchCreateImportedAPIKeysResult{}, errors.Wrap(err, "batch create imported API keys")
	}

	return result, err
}

// GetImportedAPIKeyByHash retrieves an imported key by its SHA512/256 hash.
func (d *Driver) GetImportedAPIKeyByHash(ctx context.Context, keyID string) (result db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetImportedAPIKeyByHash",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	return d.q.GetImportedAPIKeyByHash(ctx, networkID, keyID)
}

// GetImportedAPIKeysBatch retrieves multiple imported API keys by their key_id hashes in one query.
// Returns only the rows that exist; missing hashes produce no entry.
func (d *Driver) GetImportedAPIKeysBatch(ctx context.Context, hashes []string) (result []db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetImportedAPIKeysBatch",
		attribute.Int("batch_size", len(hashes)),
	)
	defer otelx.End(span, &err)

	if len(hashes) == 0 {
		return []db.ImportedApiKey{}, nil
	}

	query, args := sqlutil.BuildINQuery[db.ImportedApiKey](sqlutil.DialectQuestionMark, "imported_api_keys", networkID, hashes)
	result, err = sqlutil.QueryRows(ctx, d.conn, query, args, len(hashes), sqlutil.ScanRow[db.ImportedApiKey])
	if err != nil {
		return nil, errors.Wrap(err, "batch query imported keys")
	}

	return result, nil
}

// GetImportedAPIKeyByRequestID retrieves an imported key by its idempotency key (AIP-133).
func (d *Driver) GetImportedAPIKeyByRequestID(ctx context.Context, requestID string) (result db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetImportedAPIKeyByRequestID",
		attribute.String("request_id", requestID),
	)
	defer otelx.End(span, &err)

	return d.q.GetImportedAPIKeyByRequestID(ctx, networkID, sqlutil.PtrOrNil(requestID))
}

// ListImportedAPIKeys lists imported keys with cursor-based pagination.
// cursorKeyID is the last key_id from previous page (empty string to start from beginning).
func (d *Driver) ListImportedAPIKeys(ctx context.Context, status int32, actorID, cursorKeyID string, limit int64) (result []db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.ListImportedAPIKeys",
		attribute.Int64("limit", limit),
	)
	defer otelx.End(span, &err)

	return d.q.ListImportedAPIKeys(ctx, db.ListImportedAPIKeysParams{
		NID:         networkID,
		ActorID:     sqlutil.ToNullString(actorID),
		Status:      sqliteshared.Int32ToNullable(status),
		CursorKeyID: sqlutil.ToNullString(cursorKeyID),
		PageLimit:   limit,
	})
}

// UpdateImportedAPIKeyMetadata updates mutable fields of an imported key.
func (d *Driver) UpdateImportedAPIKeyMetadata(ctx context.Context, params persistencetypes.UpdateImportedKeyParams) (result db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.UpdateImportedAPIKeyMetadata",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	fields, err := params.PreparedFields()
	if err != nil {
		return db.ImportedApiKey{}, err
	}
	now := sqlutil.UTCNow()
	row, err := d.q.UpdateImportedAPIKeyMetadata(ctx, db.UpdateImportedAPIKeyMetadataParams{
		UpdateName: new(params.Name), UpdateScopes: fields.JSONScopes(), UpdateMetadata: fields.JSONMetadata(),
		UpdateRateLimitQuota: params.RateLimitQuota, UpdateRateLimitWindow: params.RateLimitWindow,
		UpdateAllowedCidrs: fields.JSONAllowedCIDRs(), UpdatedAt: now, NID: networkID, KeyID: params.KeyID,
	})
	if err != nil {
		return db.ImportedApiKey{}, err
	}
	return row, nil
}

// RevokeImportedAPIKey revokes an imported key with a structured reason.
func (d *Driver) RevokeImportedAPIKey(ctx context.Context, params persistencetypes.RevokeImportedKeyParams) (result db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.RevokeImportedAPIKey",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	err = d.withTx(ctx, func(qtx *db.Queries) error {
		row, txErr := qtx.RevokeImportedAPIKey(ctx, db.RevokeImportedAPIKeyParams{
			RevokedStatus:        int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED),
			UpdatedAt:            now,
			ExpiresAt:            params.ExpiresAt,
			RevocationReason:     params.Reason,
			RevocationReasonText: sqlutil.PtrOrNil(params.Description),
			NID:                  networkID,
			KeyID:                params.KeyID,
		})
		if txErr != nil {
			return txErr
		}
		result = row
		return nil
	})
	return result, err
}

// DeleteImportedAPIKey permanently deletes an imported key.
func (d *Driver) DeleteImportedAPIKey(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.DeleteImportedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	return d.withTx(ctx, func(qtx *db.Queries) error {
		return qtx.DeleteImportedAPIKey(ctx, networkID, keyID)
	})
}

// Close closes the database connection.
func (d *Driver) Close() error {
	return d.conn.Close()
}

// Ping checks the database connection.
func (d *Driver) Ping(ctx context.Context) error {
	return d.conn.PingContext(ctx)
}

// DB returns the underlying *sql.DB for transaction support.
func (d *Driver) DB() *sql.DB {
	return d.conn.DB
}

// DriverName returns the database driver name.
func (d *Driver) DriverName() string {
	return "sqlite3"
}

// Initialize creates the default network if it doesn't exist.
func (d *Driver) Initialize(ctx context.Context) error {
	return sqliteshared.InitializeNetwork(ctx, d.conn, networkID.String())
}

// InitializeNetwork creates a network row with the given ID if it does not already exist.
func (d *Driver) InitializeNetwork(ctx context.Context, networkID string) error {
	return sqliteshared.InitializeNetwork(ctx, d.conn, networkID)
}
