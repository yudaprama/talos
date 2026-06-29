// Package postgres provides the PostgreSQL database driver implementation.
package postgres

import (
	"context"
	"database/sql"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/x/otelx"

	"github.com/ory/talos/internal/persistence/persistmodel"
	"github.com/ory/talos/internal/persistence/postgres/postgresshared"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
	persistencetypes "github.com/ory/talos/internal/persistence/types"
	"github.com/ory/talos/internal/tracing"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// networkID is the fixed NID for OSS — single-tenant with no network isolation.
var networkID = uuid.Nil

// Column lists kept in sync with the sqlc-generated row structs (db tags). The
// SELECT/RETURNING order is irrelevant — sqlx.StructScan binds by db tag — but
// listing columns explicitly keeps us off SELECT *.
const (
	issuedCols = `nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, ` +
		`last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, ` +
		`revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility`

	importedCols = `nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, ` +
		`created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, ` +
		`revocation_reason_text, allowed_cidrs, request_id, visibility`
)

// Driver is the PostgreSQL persistence.Persister implementation. Queries are
// hand-written ($N placeholders) and scan into the shared sqlc-generated db.*
// model structs via sqlx.
type Driver struct {
	conn *sqlx.DB
}

// Conn returns the underlying connection. The metering fork's DBMeter uses it to
// run usage/balance queries over the same database.
func (d *Driver) Conn() *sqlx.DB { return d.conn }

// NewDriver creates a new PostgreSQL driver. cleanedDSN is a libpq/pgx DSN with
// any talos-specific pool query parameters already stripped by ParseDSN.
func NewDriver(dsn string) (*Driver, error) {
	if dsn == "" {
		return nil, errors.Errorf("DSN is required")
	}

	conn, err := postgresshared.OpenDB(dsn)
	if err != nil {
		return nil, err
	}

	return &Driver{conn: conn}, nil
}

// nullableActor returns nil for the empty actor filter, preserving the
// "narg IS NULL OR col = narg" optional-filter semantics from queries.sql.
func nullableActor(actorID string) any {
	if actorID == "" {
		return nil
	}
	return actorID
}

// nullableStatus returns nil when the status filter is the zero value, matching
// the SQLite Int32ToNullable behavior (0 = no filter).
func nullableStatus(status int32) any {
	if status == 0 {
		return nil
	}
	return status
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
	const q = `INSERT INTO issued_api_keys (
		nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata,
		last_used_at, expires_at, rate_limit_quota, rate_limit_window, allowed_cidrs,
		request_id, visibility, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb,
		$10, $11, $12, $13, $14::jsonb,
		$15, $16, $17, $18
	) RETURNING ` + issuedCols

	err = sqlx.GetContext(ctx, d.conn, &result, q,
		networkID, params.KeyID, params.Name, params.TokenPrefix, int64(1),
		params.ActorID, postgresshared.JSONBArg(fields.ScopesJSON),
		int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), postgresshared.JSONBArg(fields.MetadataJSON),
		nil, params.ExpiresAt, params.RateLimitQuota, params.RateLimitWindow,
		postgresshared.JSONBArg(sqlutil.NormalizeScopesJSON(params.AllowedCIDRs)),
		sqlutil.PtrOrNil(params.RequestID), params.Visibility, now, now,
	)
	return result, err
}

// GetIssuedAPIKeyByRequestID retrieves an issued API key by its idempotency key (AIP-133).
func (d *Driver) GetIssuedAPIKeyByRequestID(ctx context.Context, requestID string) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetIssuedAPIKeyByRequestID",
		attribute.String("request_id", requestID),
	)
	defer otelx.End(span, &err)

	const q = `SELECT ` + issuedCols + ` FROM issued_api_keys WHERE nid = $1 AND request_id = $2 LIMIT 1`
	err = sqlx.GetContext(ctx, d.conn, &result, q, networkID, sqlutil.PtrOrNil(requestID))
	return result, err
}

// GetIssuedAPIKey retrieves an API key (lookup by UUID).
func (d *Driver) GetIssuedAPIKey(ctx context.Context, keyID string) (result db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetIssuedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	const q = `SELECT ` + issuedCols + ` FROM issued_api_keys WHERE nid = $1 AND key_id = $2 LIMIT 1`
	err = sqlx.GetContext(ctx, d.conn, &result, q, networkID, keyID)
	return result, err
}

// GetIssuedAPIKeysBatch retrieves multiple issued API keys by their key_ids in one query.
func (d *Driver) GetIssuedAPIKeysBatch(ctx context.Context, keyIDs []string) (result []db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetIssuedAPIKeysBatch",
		attribute.Int("batch_size", len(keyIDs)),
	)
	defer otelx.End(span, &err)

	if len(keyIDs) == 0 {
		return []db.IssuedApiKey{}, nil
	}

	query, args := sqlutil.BuildINQuery[db.IssuedApiKey](sqlutil.DialectNumbered, "issued_api_keys", networkID, keyIDs)
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

	const q = `SELECT ` + issuedCols + ` FROM issued_api_keys WHERE nid = $1 AND key_id = $2 AND status = $3 LIMIT 1`
	err = sqlx.GetContext(ctx, d.conn, &result, q, networkID, keyID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE))
	return result, err
}

// RevokeIssuedAPIKey revokes an API key with a structured reason.
func (d *Driver) RevokeIssuedAPIKey(ctx context.Context, params persistencetypes.RevokeIssuedAPIKeyParams) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.RevokeIssuedAPIKey",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	const q = `UPDATE issued_api_keys
		SET status = $1, updated_at = $2, expires_at = $3, revocation_reason = $4, revocation_reason_text = $5
		WHERE nid = $6 AND key_id = $7`
	_, err = d.conn.ExecContext(ctx, q,
		int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), now, params.ExpiresAt,
		params.Reason, sqlutil.PtrOrNil(params.Description), networkID, params.KeyID,
	)
	return err
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

	tx, err := d.conn.BeginTxx(ctx, nil)
	if err != nil {
		return result, errors.Wrap(err, "begin transaction")
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Read the old key inside the transaction. Two-step: existence (sql.ErrNoRows
	// → 404) then status (ErrKeyNotActive → 409). Eliminates the TOCTOU race.
	var oldKey db.IssuedApiKey
	const getQ = `SELECT ` + issuedCols + ` FROM issued_api_keys WHERE nid = $1 AND key_id = $2 LIMIT 1`
	if err = sqlx.GetContext(ctx, tx, &oldKey, getQ, networkID, oldKeyID); err != nil {
		return result, err
	}
	if oldKey.Status != int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE) {
		err = persistencetypes.ErrKeyNotActive
		return result, err
	}
	result.OldKey = oldKey

	params, mErr := mergeFunc(oldKey)
	if mErr != nil {
		err = mErr
		return result, err
	}

	fields, fErr := params.PreparedFields()
	if fErr != nil {
		err = fErr
		return result, err
	}

	const insertQ = `INSERT INTO issued_api_keys (
		nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata,
		last_used_at, expires_at, rate_limit_quota, rate_limit_window, allowed_cidrs, visibility, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb, $10, $11, $12, $13, $14::jsonb, $15, $16, $17
	) RETURNING ` + issuedCols
	if err = sqlx.GetContext(ctx, tx, &result.NewKey, insertQ,
		networkID, params.NewKeyID, params.Name, params.TokenPrefix, int64(1),
		params.ActorID, postgresshared.JSONBArg(fields.ScopesJSON),
		int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), postgresshared.JSONBArg(fields.MetadataJSON),
		nil, params.ExpiresAt, params.RateLimitQuota, params.RateLimitWindow,
		postgresshared.JSONBArg(sqlutil.NormalizeScopesJSON(params.AllowedCIDRs)),
		params.Visibility, now, now,
	); err != nil {
		return result, err
	}

	rotatedText := "rotated: replaced by new key"
	const revokeQ = `UPDATE issued_api_keys
		SET status = $1, updated_at = $2, revocation_reason = $3, revocation_reason_text = $4
		WHERE nid = $5 AND key_id = $6`
	if _, err = tx.ExecContext(ctx, revokeQ,
		int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), now,
		int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_SUPERSEDED), &rotatedText,
		networkID, oldKeyID,
	); err != nil {
		return result, err
	}

	err = errors.Wrap(tx.Commit(), "commit transaction")
	return result, err
}

// DeleteIssuedAPIKey deletes an API key.
func (d *Driver) DeleteIssuedAPIKey(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.DeleteIssuedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	_, err = d.conn.ExecContext(ctx, `DELETE FROM issued_api_keys WHERE nid = $1 AND key_id = $2`, networkID, keyID)
	return err
}

// ListIssuedAPIKeysByNetwork lists API keys with cursor-based pagination.
func (d *Driver) ListIssuedAPIKeysByNetwork(ctx context.Context, actorID string, statusFilter int32, cursorKeyID string, limit int64) (result []db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.ListIssuedAPIKeysByNetwork",
		attribute.Int64("limit", limit),
	)
	defer otelx.End(span, &err)

	const q = `SELECT ` + issuedCols + ` FROM issued_api_keys
		WHERE nid = $1
		  AND ($2::text IS NULL OR actor_id = $2)
		  AND ($3::int IS NULL OR status = $3)
		  AND ($4::text IS NULL OR key_id < $4)
		ORDER BY key_id DESC
		LIMIT $5`
	result = []db.IssuedApiKey{}
	err = sqlx.SelectContext(ctx, d.conn, &result, q,
		networkID, nullableActor(actorID), nullableStatus(statusFilter), nullableActor(cursorKeyID), limit,
	)
	return result, err
}

// UpdateIssuedAPIKeyLastUsed updates the last used timestamp for an API key.
func (d *Driver) UpdateIssuedAPIKeyLastUsed(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.UpdateIssuedAPIKeyLastUsed",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	_, err = d.conn.ExecContext(ctx,
		`UPDATE issued_api_keys SET last_used_at = $1 WHERE nid = $2 AND key_id = $3`,
		now, networkID, keyID,
	)
	return err
}

// UpdateImportedAPIKeyLastUsed updates the last used timestamp for an imported key.
func (d *Driver) UpdateImportedAPIKeyLastUsed(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.UpdateImportedAPIKeyLastUsed",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	_, err = d.conn.ExecContext(ctx,
		`UPDATE imported_api_keys SET last_used_at = $1 WHERE nid = $2 AND key_id = $3`,
		now, networkID, keyID,
	)
	return err
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
	query, args := sqlutil.BuildINUpdateQuery(sqlutil.DialectNumbered, "issued_api_keys", now, networkID, keyIDs)
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
	query, args := sqlutil.BuildINUpdateQuery(sqlutil.DialectNumbered, "imported_api_keys", now, networkID, keyIDs)
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
	const q = `UPDATE issued_api_keys SET
		name = COALESCE($1, name),
		scopes = COALESCE($2::jsonb, scopes),
		metadata = COALESCE($3::jsonb, metadata),
		rate_limit_quota = $4,
		rate_limit_window = $5,
		allowed_cidrs = COALESCE($6::jsonb, allowed_cidrs),
		updated_at = $7
	WHERE nid = $8 AND key_id = $9
	RETURNING ` + issuedCols
	err = sqlx.GetContext(ctx, d.conn, &result, q,
		params.Name, postgresshared.JSONBArg(fields.JSONScopes()), postgresshared.JSONBArg(fields.JSONMetadata()),
		params.RateLimitQuota, params.RateLimitWindow, postgresshared.JSONBArg(fields.JSONAllowedCIDRs()),
		now, networkID, params.KeyID,
	)
	return result, err
}

// GetExpiredIssuedAPIKeys retrieves expired API keys (batched).
func (d *Driver) GetExpiredIssuedAPIKeys(ctx context.Context, limit int32) (result []db.IssuedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetExpiredIssuedAPIKeys",
		attribute.Int("batch_size", int(limit)),
	)
	defer otelx.End(span, &err)

	const q = `SELECT ` + issuedCols + ` FROM issued_api_keys
		WHERE nid = $1 AND status = $2 AND expires_at < now()
		LIMIT $3`
	result = []db.IssuedApiKey{}
	err = sqlx.SelectContext(ctx, d.conn, &result, q,
		networkID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), int64(limit),
	)
	return result, err
}

// CountActiveAPIKeysUpTo returns the number of non-revoked API keys
// (issued + imported combined) for the current network, capped at limit.
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

	var issued []string
	const issuedQ = `SELECT key_id FROM issued_api_keys WHERE nid = $1 AND status = $2 ORDER BY key_id LIMIT $3`
	if err = sqlx.SelectContext(ctx, d.conn, &issued, issuedQ, networkID, activeStatus, limit); err != nil {
		return 0, errors.WithStack(err)
	}
	issuedCount := int64(len(issued))
	if issuedCount >= limit {
		return limit, nil
	}

	var imported []string
	const importedQ = `SELECT key_id FROM imported_api_keys WHERE nid = $1 AND status = $2 ORDER BY key_id LIMIT $3`
	if err = sqlx.SelectContext(ctx, d.conn, &imported, importedQ, networkID, activeStatus, limit-issuedCount); err != nil {
		return 0, errors.WithStack(err)
	}
	return issuedCount + int64(len(imported)), nil
}

// ExpireIssuedAPIKeys marks up to 'limit' expired API keys as expired (batched).
// Returns the number of keys that were expired. The (nid, key_id) subselect
// replaces the SQLite ROWID trick (Postgres has no ROWID and supports the
// composite-PK IN form directly).
func (d *Driver) ExpireIssuedAPIKeys(ctx context.Context, limit int32) (rowsAffected int64, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.ExpireIssuedAPIKeys",
		attribute.Int("batch_size", int(limit)),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	const q = `UPDATE issued_api_keys
		SET status = $1, updated_at = $2
		WHERE (nid, key_id) IN (
			SELECT nid, key_id FROM issued_api_keys
			WHERE nid = $3 AND status = $4 AND expires_at < now()
			LIMIT $5
		)`
	res, err := d.conn.ExecContext(ctx, q,
		int32(talosv2alpha1.KeyStatus_KEY_STATUS_EXPIRED), now,
		networkID, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), int64(limit),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

	const q = `INSERT INTO imported_api_keys (
		nid, key_id, actor_id, name, scopes, metadata, status, expires_at,
		rate_limit_quota, rate_limit_window, allowed_cidrs, request_id, visibility, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8,
		$9, $10, $11::jsonb, $12, $13, $14, $15
	) RETURNING ` + importedCols
	err = sqlx.GetContext(ctx, d.conn, &result, q,
		networkID, params.KeyID, params.ActorID, params.Name,
		postgresshared.JSONBArg(fields.ScopesJSON), postgresshared.JSONBArg(fields.MetadataJSON),
		params.Status, params.ExpiresAt, params.RateLimitQuota, params.RateLimitWindow,
		postgresshared.JSONBArg(sqlutil.NormalizeScopesJSON(params.AllowedCIDRs)),
		sqlutil.PtrOrNil(params.RequestID), params.Visibility, now, now,
	)
	return result, err
}

// CreateImportedAPIKeysBatch creates multiple imported keys in a single transaction.
func (d *Driver) CreateImportedAPIKeysBatch(ctx context.Context, keys []persistmodel.BatchCreateImportedAPIKeyInput) (result persistmodel.BatchCreateImportedAPIKeysResult, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.CreateImportedAPIKeysBatch",
		attribute.Int("batch_size", len(keys)),
	)
	defer otelx.End(span, &err)

	if len(keys) > postgresshared.MaxBatchKeys {
		return persistmodel.BatchCreateImportedAPIKeysResult{}, errors.Errorf(
			"batch size %d exceeds PostgreSQL limit of %d keys (65535 bind params / 15 args per key)",
			len(keys), postgresshared.MaxBatchKeys,
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

	tx, err := d.conn.BeginTxx(ctx, nil)
	if err != nil {
		return persistmodel.BatchCreateImportedAPIKeysResult{}, errors.Wrap(err, "begin transaction")
	}

	txErr := func() error {
		now := sqlutil.UTCNow()
		insertQuery, insertArgs := postgresshared.BuildBatchInsertImportedKeysQuery(networkID.String(), keys, now)

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
		_ = rows.Close()

		conflictIDs := make([]string, 0, len(keyIDs))
		for _, id := range keyIDs {
			if _, inserted := result.Inserted[id]; !inserted {
				conflictIDs = append(conflictIDs, id)
			}
		}

		existingRows, err := postgresshared.QueryImportedKeysByIDs(ctx, tx, networkID.String(), conflictIDs)
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

	const q = `SELECT ` + importedCols + ` FROM imported_api_keys WHERE nid = $1 AND key_id = $2 LIMIT 1`
	err = sqlx.GetContext(ctx, d.conn, &result, q, networkID, keyID)
	return result, err
}

// GetImportedAPIKeysBatch retrieves multiple imported API keys by their key_id hashes in one query.
func (d *Driver) GetImportedAPIKeysBatch(ctx context.Context, hashes []string) (result []db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.GetImportedAPIKeysBatch",
		attribute.Int("batch_size", len(hashes)),
	)
	defer otelx.End(span, &err)

	if len(hashes) == 0 {
		return []db.ImportedApiKey{}, nil
	}

	query, args := sqlutil.BuildINQuery[db.ImportedApiKey](sqlutil.DialectNumbered, "imported_api_keys", networkID, hashes)
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

	const q = `SELECT ` + importedCols + ` FROM imported_api_keys WHERE nid = $1 AND request_id = $2 LIMIT 1`
	err = sqlx.GetContext(ctx, d.conn, &result, q, networkID, sqlutil.PtrOrNil(requestID))
	return result, err
}

// ListImportedAPIKeys lists imported keys with cursor-based pagination.
func (d *Driver) ListImportedAPIKeys(ctx context.Context, status int32, actorID, cursorKeyID string, limit int64) (result []db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.ListImportedAPIKeys",
		attribute.Int64("limit", limit),
	)
	defer otelx.End(span, &err)

	const q = `SELECT ` + importedCols + ` FROM imported_api_keys
		WHERE nid = $1
		  AND ($2::text IS NULL OR actor_id = $2)
		  AND ($3::int IS NULL OR status = $3)
		  AND ($4::text IS NULL OR key_id < $4)
		ORDER BY key_id DESC
		LIMIT $5`
	result = []db.ImportedApiKey{}
	err = sqlx.SelectContext(ctx, d.conn, &result, q,
		networkID, nullableActor(actorID), nullableStatus(status), nullableActor(cursorKeyID), limit,
	)
	return result, err
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
	const q = `UPDATE imported_api_keys SET
		name = COALESCE($1, name),
		scopes = COALESCE($2::jsonb, scopes),
		metadata = COALESCE($3::jsonb, metadata),
		rate_limit_quota = $4,
		rate_limit_window = $5,
		allowed_cidrs = COALESCE($6::jsonb, allowed_cidrs),
		updated_at = $7
	WHERE nid = $8 AND key_id = $9
	RETURNING ` + importedCols
	err = sqlx.GetContext(ctx, d.conn, &result, q,
		params.Name, postgresshared.JSONBArg(fields.JSONScopes()), postgresshared.JSONBArg(fields.JSONMetadata()),
		params.RateLimitQuota, params.RateLimitWindow, postgresshared.JSONBArg(fields.JSONAllowedCIDRs()),
		now, networkID, params.KeyID,
	)
	return result, err
}

// RevokeImportedAPIKey revokes an imported key with a structured reason.
func (d *Driver) RevokeImportedAPIKey(ctx context.Context, params persistencetypes.RevokeImportedKeyParams) (result db.ImportedApiKey, err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.RevokeImportedAPIKey",
		attribute.String("key_id", params.KeyID),
	)
	defer otelx.End(span, &err)

	now := sqlutil.UTCNow()
	const q = `UPDATE imported_api_keys
		SET status = $1, updated_at = $2, expires_at = $3, revocation_reason = $4, revocation_reason_text = $5
		WHERE nid = $6 AND key_id = $7
		RETURNING ` + importedCols
	err = sqlx.GetContext(ctx, d.conn, &result, q,
		int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), now, params.ExpiresAt,
		params.Reason, sqlutil.PtrOrNil(params.Description), networkID, params.KeyID,
	)
	return result, err
}

// DeleteImportedAPIKey permanently deletes an imported key.
func (d *Driver) DeleteImportedAPIKey(ctx context.Context, keyID string) (err error) {
	ctx, span := tracing.Start(
		ctx, "persistence.DeleteImportedAPIKey",
		attribute.String("key_id", keyID),
	)
	defer otelx.End(span, &err)

	_, err = d.conn.ExecContext(ctx, `DELETE FROM imported_api_keys WHERE nid = $1 AND key_id = $2`, networkID, keyID)
	return err
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
	return "postgres"
}

// Initialize creates the default network if it doesn't exist.
func (d *Driver) Initialize(ctx context.Context) error {
	return postgresshared.InitializeNetwork(ctx, d.conn, networkID.String())
}

// InitializeNetwork creates a network row with the given ID if it does not already exist.
func (d *Driver) InitializeNetwork(ctx context.Context, networkID string) error {
	return postgresshared.InitializeNetwork(ctx, d.conn, networkID)
}
