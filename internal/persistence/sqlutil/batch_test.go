package sqlutil

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

type testRowThreeCols struct {
	NID   string `db:"nid"`
	KeyID string `db:"key_id"`
	Name  string `db:"name"`
}

type testRowTwoCols struct {
	NID   string `db:"nid"`
	KeyID string `db:"key_id"`
}

type testRowOneCol struct {
	C string `db:"c"`
}

func TestBuildINQuery_QuestionMark(t *testing.T) {
	t.Parallel()

	query, args := BuildINQuery[testRowThreeCols](DialectQuestionMark, "issued_api_keys", "tenant-1", []string{"a", "b", "c"})

	assert.Equal(t, "SELECT nid, key_id, name FROM issued_api_keys WHERE nid = ? AND key_id IN (?, ?, ?)", query)
	assert.Equal(t, []any{"tenant-1", "a", "b", "c"}, args)
}

func TestBuildINQuery_Numbered(t *testing.T) {
	t.Parallel()

	query, args := BuildINQuery[testRowTwoCols](DialectNumbered, "imported_api_keys", "tenant-1", []string{"x", "y"})

	assert.Equal(t, "SELECT nid, key_id FROM imported_api_keys WHERE nid = $1 AND key_id IN ($2, $3)", query)
	assert.Equal(t, []any{"tenant-1", "x", "y"}, args)
}

func TestBuildINQuery_SingleID(t *testing.T) {
	t.Parallel()

	query, args := BuildINQuery[testRowOneCol](DialectQuestionMark, "t", "n", []string{"only"})

	assert.Equal(t, "SELECT c FROM t WHERE nid = ? AND key_id IN (?)", query)
	assert.Equal(t, []any{"n", "only"}, args)
}

// TestBuildINQuery_ColumnsFromDBTags locks the contract that BuildINQuery
// derives its SELECT column list from the `db:"…"` tags on T in declaration
// order, skipping fields tagged `db:"-"`.
func TestBuildINQuery_ColumnsFromDBTags(t *testing.T) {
	t.Parallel()

	type row struct {
		NID         string `db:"nid"`
		KeyID       string `db:"key_id"`
		Computed    string `db:"-"`
		TokenPrefix string `db:"token_prefix"`
	}

	query, _ := BuildINQuery[row](DialectQuestionMark, "tbl", "n", []string{"a"})

	assert.Equal(t, "SELECT nid, key_id, token_prefix FROM tbl WHERE nid = ? AND key_id IN (?)", query,
		"column list must come from db tags in declaration order; db:\"-\" fields excluded")
}

// TestBuildINQuery_NullableScannerColumns guards against the SELECT list
// expanding into the inner fields of sql.Null* types. The MySQL row types use
// sql.NullString / sql.NullInt64 for nullable columns; reflectx descends into
// their String/Valid/Int64 fields, but the DB columns are the outer names.
func TestBuildINQuery_NullableScannerColumns(t *testing.T) {
	t.Parallel()

	type row struct {
		NID     string         `db:"nid"`
		KeyID   string         `db:"key_id"`
		ActorID sql.NullString `db:"actor_id"`
		Quota   sql.NullInt64  `db:"rate_limit_quota"`
	}

	query, _ := BuildINQuery[row](DialectQuestionMark, "imported_api_keys", "n", []string{"a"})

	assert.Equal(t, "SELECT nid, key_id, actor_id, rate_limit_quota FROM imported_api_keys WHERE nid = ? AND key_id IN (?)", query,
		"sql.Null* fields must appear by their outer column name, not actor_id.String / .Valid")
}

func TestQueryRows_Integration(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.ExecContext(t.Context(), "CREATE TABLE items (id TEXT, val TEXT)")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO items (id, val) VALUES ('a', 'alpha'), ('b', 'beta'), ('c', 'gamma')")
	require.NoError(t, err)

	type row struct{ ID, Val string }
	scanFn := func(rows *sql.Rows) (row, error) {
		var r row
		err := rows.Scan(&r.ID, &r.Val)
		return r, err
	}

	result, err := QueryRows(t.Context(), db, "SELECT id, val FROM items ORDER BY id", nil, 3, scanFn)
	require.NoError(t, err)

	assert.Equal(t, []row{{"a", "alpha"}, {"b", "beta"}, {"c", "gamma"}}, result)
}

func TestQueryRows_Empty(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.ExecContext(t.Context(), "CREATE TABLE items (id TEXT)")
	require.NoError(t, err)

	type row struct{ ID string }
	result, err := QueryRows(t.Context(), db, "SELECT id FROM items", nil, 0, func(rows *sql.Rows) (row, error) {
		var r row
		err := rows.Scan(&r.ID)
		return r, err
	})
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestQueryRows_QueryError(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = QueryRows(context.Background(), db, "SELECT * FROM nonexistent", nil, 0, func(_ *sql.Rows) (struct{}, error) { //nolint:unqueryvet // test queries a nonexistent table to assert error propagation
		return struct{}{}, nil
	})
	require.Error(t, err)
}

func TestBuildINUpdateQuery_QuestionMark(t *testing.T) {
	t.Parallel()

	query, args := BuildINUpdateQuery(DialectQuestionMark, "issued_api_keys", "2025-01-01", "tenant-1", []string{"a", "b", "c"})

	assert.Equal(t, "UPDATE issued_api_keys SET last_used_at = ? WHERE nid = ? AND key_id IN (?, ?, ?)", query)
	assert.Equal(t, []any{"2025-01-01", "tenant-1", "a", "b", "c"}, args)
}

func TestBuildINUpdateQuery_Numbered(t *testing.T) {
	t.Parallel()

	query, args := BuildINUpdateQuery(DialectNumbered, "imported_api_keys", "2025-01-01", "tenant-1", []string{"x", "y"})

	assert.Equal(t, "UPDATE imported_api_keys SET last_used_at = $1 WHERE nid = $2 AND key_id IN ($3, $4)", query)
	assert.Equal(t, []any{"2025-01-01", "tenant-1", "x", "y"}, args)
}

func TestBuildINUpdateQuery_SingleID(t *testing.T) {
	t.Parallel()

	query, args := BuildINUpdateQuery(DialectQuestionMark, "t", "ts", "n", []string{"only"})

	assert.Equal(t, "UPDATE t SET last_used_at = ? WHERE nid = ? AND key_id IN (?)", query)
	assert.Equal(t, []any{"ts", "n", "only"}, args)
}

func TestBuildINUpdateQuery_Integration(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.ExecContext(t.Context(), "CREATE TABLE keys (nid TEXT, key_id TEXT, last_used_at TEXT)")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO keys (nid, key_id, last_used_at) VALUES ('n1', 'a', NULL), ('n1', 'b', NULL), ('n1', 'c', NULL)")
	require.NoError(t, err)

	query, args := BuildINUpdateQuery(DialectQuestionMark, "keys", "2025-04-07", "n1", []string{"a", "c"})
	_, err = db.ExecContext(t.Context(), query, args...)
	require.NoError(t, err)

	// Verify only a and c were updated
	rows, err := db.QueryContext(t.Context(), "SELECT key_id, last_used_at FROM keys ORDER BY key_id")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rows.Close() })

	type row struct {
		keyID      string
		lastUsedAt sql.NullString
	}
	var results []row
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.keyID, &r.lastUsedAt))
		results = append(results, r)
	}
	require.NoError(t, rows.Err())

	assert.Equal(t, []row{
		{keyID: "a", lastUsedAt: sql.NullString{String: "2025-04-07", Valid: true}},
		{keyID: "b", lastUsedAt: sql.NullString{}},
		{keyID: "c", lastUsedAt: sql.NullString{String: "2025-04-07", Valid: true}},
	}, results)
}
