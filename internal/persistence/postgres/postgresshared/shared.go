// Package postgresshared contains PostgreSQL helpers shared by the OSS and
// commercial drivers. Centralizing them here prevents silent behavioral drift
// between editions: the byte-identical helpers must stay byte-identical.
package postgresshared

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/XSAM/otelsql"
	"github.com/cockroachdb/errors"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/reflectx"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver registered as "pgx"

	"github.com/ory/talos/internal/persistence/persistmodel"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// MaxBatchKeys is the maximum number of imported keys per batch insert.
// PostgreSQL's bind-parameter limit is 65535; each key uses 15 bind parameters,
// so the hard limit is 65535 / 15 = 4369 keys per statement.
const MaxBatchKeys = 4369

// dbTagMapper reads the `db:"…"` tags emitted by sqlc (emit_db_tags) without
// lowercasing field names, so sqlx.StructScan binds against the exact column
// names. Set as the *sqlx.DB Mapper in OpenDB.
//
//nolint:gochecknoglobals // sqlx mapper is read-only after init.
var dbTagMapper = reflectx.NewMapperFunc("db", func(s string) string { return s })

// JSONBArg adapts a json.RawMessage for binding to a JSONB column. It returns a
// string (so pgx sends a text value the `$n::jsonb` cast can coerce) or nil for
// an absent value (NULL). Never returns a []byte, which pgx would encode as
// bytea and Postgres would refuse to cast to jsonb.
func JSONBArg(v json.RawMessage) any {
	if v == nil {
		return nil
	}
	return string(v)
}

// OpenDB opens a PostgreSQL database with OTEL instrumentation and DB stats
// metrics. The caller owns the returned *sqlx.DB and is responsible for closing
// it and applying any pool configuration.
func OpenDB(dsn string) (*sqlx.DB, error) {
	sqlDB, err := otelsql.Open("pgx", dsn, otelsql.WithAttributes(
		semconv.DBSystemNamePostgreSQL,
	), otelsql.WithSpanOptions(otelsql.SpanOptions{
		OmitConnResetSession: true,
		OmitConnectorConnect: true,
	}))
	if err != nil {
		return nil, errors.Wrap(err, "open database")
	}

	if _, err := otelsql.RegisterDBStatsMetrics(sqlDB, otelsql.WithAttributes(
		semconv.DBSystemNamePostgreSQL,
	)); err != nil {
		_ = sqlDB.Close()
		return nil, errors.Wrap(err, "register DB stats metrics")
	}

	conn := sqlx.NewDb(sqlDB, "pgx")
	conn.Mapper = dbTagMapper
	return conn, nil
}

// InitializeNetwork creates a network row with the given ID if it does not
// already exist.
func InitializeNetwork(ctx context.Context, conn *sqlx.DB, nid string) error {
	now := sqlutil.UTCNow()
	_, err := conn.ExecContext(
		ctx,
		`INSERT INTO networks (id, created_at, updated_at) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
		nid, now, now,
	)
	if err != nil {
		return errors.Wrap(err, "create network")
	}
	return nil
}

// BuildBatchInsertImportedKeysQuery builds a single INSERT ... ON CONFLICT DO
// NOTHING RETURNING statement for imported keys using $N placeholders. The
// RETURNING clause yields only actually-inserted rows so callers can derive the
// conflict set without a post-INSERT SELECT.
func BuildBatchInsertImportedKeysQuery(nid string, keys []persistmodel.BatchCreateImportedAPIKeyInput, now time.Time) (string, []any) {
	var builder strings.Builder
	builder.Grow(len(keys) * 90)
	builder.WriteString("INSERT INTO imported_api_keys (")
	builder.WriteString("nid, key_id, actor_id, name, scopes, metadata, status, expires_at, rate_limit_quota, rate_limit_window, allowed_cidrs, visibility, request_id, created_at, updated_at")
	builder.WriteString(") VALUES ")

	args := make([]any, 0, len(keys)*15)
	p := 1
	for i, key := range keys {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString("(")
		for j := range 15 {
			if j > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString("$")
			builder.WriteString(strconv.Itoa(p))
			// scopes (5th), metadata (6th), allowed_cidrs (11th) are JSONB.
			switch j {
			case 4, 5, 10:
				builder.WriteString("::jsonb")
			}
			p++
		}
		builder.WriteString(")")

		args = append(
			args,
			nid,
			key.KeyID,
			sqlutil.PtrOrNil(key.ActorID),
			key.Name,
			JSONBArg(sqlutil.NormalizeScopesJSON(key.Scopes)),
			JSONBArg(sqlutil.NormalizeMetadata(key.Metadata)),
			int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
			key.ExpiresAt,
			key.RateLimitQuota,
			key.RateLimitWindow,
			JSONBArg(sqlutil.NormalizeScopesJSON(key.AllowedCIDRs)),
			key.Visibility,
			sqlutil.PtrOrNil(key.RequestID),
			now,
			now,
		)
	}
	builder.WriteString(" ON CONFLICT (nid, key_id) DO NOTHING")
	builder.WriteString(" RETURNING nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility")

	return builder.String(), args
}

// QueryImportedKeysByIDs fetches imported_api_keys rows for the given (nid, keyIDs).
// Used by batch-insert paths to populate the conflict (existing) set.
func QueryImportedKeysByIDs(ctx context.Context, q sqlutil.QueryContexter, nid string, keyIDs []string) ([]db.ImportedApiKey, error) {
	if len(keyIDs) == 0 {
		return []db.ImportedApiKey{}, nil
	}

	query, args := sqlutil.BuildINQuery[db.ImportedApiKey](sqlutil.DialectNumbered, "imported_api_keys", nid, keyIDs)
	result, err := sqlutil.QueryRows(ctx, q, query, args, len(keyIDs), sqlutil.ScanRow[db.ImportedApiKey])
	if err != nil {
		return nil, errors.Wrap(err, "query imported keys by id")
	}

	return result, nil
}
