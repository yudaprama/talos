package sqlutil

import (
	"database/sql"
	"reflect"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/reflectx"
)

// scanRowMapper is a package-level sqlx mapper that reads `db:"…"` tags
// emitted by sqlc (`emit_db_tags: true`) without lowercasing field names.
//
//nolint:gochecknoglobals // sqlx mapper is read-only after init.
var scanRowMapper = reflectx.NewMapperFunc("db", func(s string) string { return s })

// ScanRow scans the next row from rows into a fresh value of T using the
// `db:"…"` tags emitted by sqlc on the generated row types. Replaces the
// hand-written scan*APIKey helpers across SQLite, Postgres, and MySQL.
//
// Strict mode: by default sqlx returns an error when a selected column has no
// matching struct field. The corresponding direction (struct field with no
// column) is covered by lint-sql (forbids SELECT *) and the cross-backend
// TestStructEquivalence_* tests.
func ScanRow[T any](rows *sql.Rows) (T, error) {
	var out T
	sx := &sqlx.Rows{Rows: rows, Mapper: scanRowMapper}
	if err := sx.StructScan(&out); err != nil {
		return out, err
	}
	return out, nil
}

// scanRowColumns returns a comma-separated list of `db:"…"` tag names declared
// on T, in field-declaration order. Used by BuildINQuery to derive the SELECT
// column list automatically from the row type.
//
// Only top-level fields are emitted. Reflectx descends into nested types like
// sql.NullString and exposes paths such as "actor_id.String" / "actor_id.Valid"
// in tm.Index, but those subfields are not real DB columns — the parent is.
// Filtering on Path containing a dot keeps the SELECT list aligned with the
// columns sqlx.StructScan binds against (sql.Scanner types are scanned whole).
func scanRowColumns[T any]() string {
	tm := scanRowMapper.TypeMap(reflect.TypeFor[T]())
	names := make([]string, 0, len(tm.Index))
	for _, fi := range tm.Index {
		if fi.Field.Anonymous {
			continue
		}
		if strings.Contains(fi.Path, ".") {
			continue
		}
		names = append(names, fi.Path)
	}
	return strings.Join(names, ", ")
}
