package sqlutil

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

type scanFixture struct {
	ID    int64   `db:"id"`
	Name  string  `db:"name"`
	Score *int64  `db:"score"`
	Note  *string `db:"note"`
	// Unexported fields must be skipped.
	skipped int //nolint:unused
}

func openScanFixtureDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	// :memory: SQLite is per-connection; pin to a single physical connection so
	// the schema and rows seen by the test stay consistent across queries.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.ExecContext(t.Context(), `CREATE TABLE scan_fixture (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		score INTEGER,
		note TEXT
	)`)
	require.NoError(t, err)
	return db
}

func TestScanRow_AllFieldsPopulated(t *testing.T) {
	t.Parallel()
	db := openScanFixtureDB(t)
	score := int64(42)
	note := "hello"
	_, err := db.ExecContext(t.Context(), `INSERT INTO scan_fixture (id, name, score, note) VALUES (1, 'a', ?, ?)`, score, note)
	require.NoError(t, err)

	rows, err := db.QueryContext(t.Context(), `SELECT id, name, score, note FROM scan_fixture WHERE id = 1`)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next())

	got, err := ScanRow[scanFixture](rows)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.ID)
	assert.Equal(t, "a", got.Name)
	require.NotNil(t, got.Score)
	assert.Equal(t, int64(42), *got.Score)
	require.NotNil(t, got.Note)
	assert.Equal(t, "hello", *got.Note)
}

func TestScanRow_NullableFieldsNil(t *testing.T) {
	t.Parallel()
	db := openScanFixtureDB(t)
	_, err := db.ExecContext(t.Context(), `INSERT INTO scan_fixture (id, name) VALUES (2, 'b')`)
	require.NoError(t, err)

	rows, err := db.QueryContext(t.Context(), `SELECT id, name, score, note FROM scan_fixture WHERE id = 2`)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next())

	got, err := ScanRow[scanFixture](rows)
	require.NoError(t, err)
	assert.Nil(t, got.Score)
	assert.Nil(t, got.Note)
}

// TestScanRow_FieldOrderIndependent proves struct declaration order does not
// have to match SELECT column order. Mapping is by db tag, not by position.
func TestScanRow_FieldOrderIndependent(t *testing.T) {
	t.Parallel()
	db := openScanFixtureDB(t)
	score := int64(99)
	note := "ordered"
	_, err := db.ExecContext(t.Context(), `INSERT INTO scan_fixture (id, name, score, note) VALUES (10, 'reversed', ?, ?)`, score, note)
	require.NoError(t, err)

	type reversedFixture struct {
		Note  *string `db:"note"`
		Score *int64  `db:"score"`
		Name  string  `db:"name"`
		ID    int64   `db:"id"`
	}

	rows, err := db.QueryContext(t.Context(), `SELECT id, name, score, note FROM scan_fixture WHERE id = 10`)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next())

	got, err := ScanRow[reversedFixture](rows)
	require.NoError(t, err)
	assert.Equal(t, int64(10), got.ID, "ID must be populated from the id column, not by position")
	assert.Equal(t, "reversed", got.Name, "Name must be populated from the name column, not by position")
	require.NotNil(t, got.Score)
	assert.Equal(t, int64(99), *got.Score)
	require.NotNil(t, got.Note)
	assert.Equal(t, "ordered", *got.Note)
}

// TestScanRow_SwappedSameTypedColumns proves that swapping two same-typed
// columns in the SELECT does NOT silently corrupt values — Name and Note are
// both string-based, but must be routed by tag, not by position.
func TestScanRow_SwappedSameTypedColumns(t *testing.T) {
	t.Parallel()
	db := openScanFixtureDB(t)
	_, err := db.ExecContext(t.Context(), `INSERT INTO scan_fixture (id, name, note) VALUES (11, 'real-name', 'real-note')`)
	require.NoError(t, err)

	// Swap two same-typed columns (name, note). Positional scanning would
	// silently produce got.Name == "real-note" and got.Note == "real-name".
	rows, err := db.QueryContext(t.Context(), `SELECT id, note, score, name FROM scan_fixture WHERE id = 11`)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next())

	got, err := ScanRow[scanFixture](rows)
	require.NoError(t, err)
	assert.Equal(t, "real-name", got.Name, "Name must come from the name column, not the position of name in SELECT")
	require.NotNil(t, got.Note)
	assert.Equal(t, "real-note", *got.Note, "Note must come from the note column, not the position of note in SELECT")
}

// TestScanRow_UnknownColumnReturnsError proves that a SELECT returning a column
// with no matching db tag fails loudly instead of silently dropping data.
func TestScanRow_UnknownColumnReturnsError(t *testing.T) {
	t.Parallel()
	db := openScanFixtureDB(t)
	_, err := db.ExecContext(t.Context(), `INSERT INTO scan_fixture (id, name) VALUES (12, 'd')`)
	require.NoError(t, err)

	rows, err := db.QueryContext(t.Context(), `SELECT id, name, score, note, id AS extra FROM scan_fixture WHERE id = 12`)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next())

	_, err = ScanRow[scanFixture](rows)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extra", "error must name the unmapped column")
}

// TestScanRow_DashTagSkipsField proves fields with `db:"-"` are intentionally
// excluded from scanning and do not trigger missing-column errors.
func TestScanRow_DashTagSkipsField(t *testing.T) {
	t.Parallel()
	db := openScanFixtureDB(t)
	_, err := db.ExecContext(t.Context(), `INSERT INTO scan_fixture (id, name, score, note) VALUES (15, 'g', 7, 'world')`)
	require.NoError(t, err)

	type withDash struct {
		ID       int64   `db:"id"`
		Name     string  `db:"name"`
		Score    *int64  `db:"score"`
		Note     *string `db:"note"`
		Computed string  `db:"-"`
	}

	rows, err := db.QueryContext(t.Context(), `SELECT id, name, score, note FROM scan_fixture WHERE id = 15`)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next())

	got, err := ScanRow[withDash](rows)
	require.NoError(t, err)
	assert.Equal(t, int64(15), got.ID)
	assert.Equal(t, "g", got.Name)
	assert.Empty(t, got.Computed, "fields tagged db:\"-\" must be left at zero value")
}

func benchScanFixtureRows(b *testing.B, query string) *sql.DB {
	b.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(b, err)
	// :memory: SQLite is per-connection; pin to a single physical connection so
	// the schema and rows are visible across queries from the same *sql.DB.
	db.SetMaxOpenConns(1)
	b.Cleanup(func() { _ = db.Close() })
	_, err = db.ExecContext(context.Background(), `CREATE TABLE scan_fixture (id INTEGER PRIMARY KEY, name TEXT NOT NULL, score INTEGER, note TEXT)`)
	require.NoError(b, err)
	for i := range 100 {
		_, err = db.ExecContext(context.Background(), `INSERT INTO scan_fixture (id, name, score, note) VALUES (?, 'n', ?, 'x')`, i+1, i)
		require.NoError(b, err)
	}
	_ = query
	return db
}

func BenchmarkScanRow_Manual(b *testing.B) {
	db := benchScanFixtureRows(b, "")
	for b.Loop() {
		benchScanRowManual(b, db)
	}
}

func benchScanRowManual(b *testing.B, db *sql.DB) {
	b.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT id, name, score, note FROM scan_fixture`)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			b.Fatal(err)
		}
	}()
	for rows.Next() {
		var f scanFixture
		if err := rows.Scan(&f.ID, &f.Name, &f.Score, &f.Note); err != nil {
			b.Fatal(err)
		}
	}
	if err := rows.Err(); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkScanRow_Reflective(b *testing.B) {
	db := benchScanFixtureRows(b, "")
	for b.Loop() {
		benchScanRowReflective(b, db)
	}
}

func benchScanRowReflective(b *testing.B, db *sql.DB) {
	b.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT id, name, score, note FROM scan_fixture`)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			b.Fatal(err)
		}
	}()
	for rows.Next() {
		if _, err := ScanRow[scanFixture](rows); err != nil {
			b.Fatal(err)
		}
	}
	if err := rows.Err(); err != nil {
		b.Fatal(err)
	}
}
