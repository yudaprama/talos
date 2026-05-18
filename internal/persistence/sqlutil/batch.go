package sqlutil

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// Dialect controls placeholder style for batch IN queries.
type Dialect int

const (
	// DialectQuestionMark uses ? placeholders (SQLite, MySQL).
	DialectQuestionMark Dialect = iota
	// DialectNumbered uses $N placeholders (PostgreSQL, CockroachDB).
	DialectNumbered
)

// QueryContexter abstracts *sql.DB and *sql.Tx for query execution.
type QueryContexter interface {
	QueryContext(ctx context.Context, query string, _ ...any) (*sql.Rows, error)
}

// ExecContexter abstracts *sql.DB and *sql.Tx for exec operations.
type ExecContexter interface {
	ExecContext(ctx context.Context, query string, _ ...any) (sql.Result, error)
}

// BuildINQuery constructs a SELECT col_a, col_b, ... FROM table
// WHERE nid = ? AND key_id IN (?, ...) query using the given dialect's
// placeholder style. The column list is derived from the `db:"…"` tags on T
// (the sqlc-generated row type) in field-declaration order, so adding a
// column to the sqlc model automatically updates the SELECT list.
//
// The filter column is hardcoded to key_id. The table parameter must be a
// hardcoded string literal — never user input.
func BuildINQuery[T any, ID any](dialect Dialect, table string, nid any, ids []ID) (string, []any) {
	args := make([]any, 0, len(ids)+1)
	args = append(args, nid)

	var qb strings.Builder
	qb.WriteString("SELECT ")
	qb.WriteString(scanRowColumns[T]())
	qb.WriteString(" FROM ")
	qb.WriteString(table)

	switch dialect {
	case DialectQuestionMark:
		qb.WriteString(" WHERE nid = ? AND key_id IN (")
		for i, id := range ids {
			if i > 0 {
				qb.WriteString(", ")
			}
			qb.WriteString("?")
			args = append(args, id)
		}
	case DialectNumbered:
		qb.WriteString(" WHERE nid = $1 AND key_id IN (")
		for i, id := range ids {
			if i > 0 {
				qb.WriteString(", ")
			}
			qb.WriteString("$")
			qb.WriteString(strconv.Itoa(i + 2))
			args = append(args, id)
		}
	}
	qb.WriteString(")")

	return qb.String(), args
}

// BuildINUpdateQuery constructs an UPDATE ... SET last_used_at = ? WHERE nid = ? AND key_id IN (?, ...) query
// using the given dialect's placeholder style. It returns the query string and args.
// The timestamp argument comes first, then nid, then the IDs.
// The table parameter must be a hardcoded string literal — never user input.
func BuildINUpdateQuery[ID any](dialect Dialect, table string, timestamp any, nid any, ids []ID) (string, []any) {
	args := make([]any, 0, len(ids)+2)
	args = append(args, timestamp, nid)

	var qb strings.Builder
	qb.WriteString("UPDATE ")
	qb.WriteString(table)

	switch dialect {
	case DialectQuestionMark:
		qb.WriteString(" SET last_used_at = ? WHERE nid = ? AND key_id IN (")
		for i, id := range ids {
			if i > 0 {
				qb.WriteString(", ")
			}
			qb.WriteString("?")
			args = append(args, id)
		}
	case DialectNumbered:
		qb.WriteString(" SET last_used_at = $1 WHERE nid = $2 AND key_id IN (")
		for i, id := range ids {
			if i > 0 {
				qb.WriteString(", ")
			}
			qb.WriteString("$")
			qb.WriteString(strconv.Itoa(i + 3))
			args = append(args, id)
		}
	}
	qb.WriteString(")")

	return qb.String(), args
}

// QueryRows executes a query and scans each row using scanFn into a slice of T.
// It handles row iteration, closing, and error propagation.
func QueryRows[T any](ctx context.Context, q QueryContexter, query string, args []any, capacity int, scanFn func(*sql.Rows) (T, error)) (result []T, err error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); err == nil {
			err = closeErr
		}
	}()

	result = make([]T, 0, capacity)
	for rows.Next() {
		row, scanErr := scanFn(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	if iterErr := rows.Err(); iterErr != nil {
		return nil, iterErr
	}

	return result, nil
}
