package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence/migrations"
	"github.com/ory-corp/talos/internal/persistence/persistmodel"
	"github.com/ory-corp/talos/internal/persistence/sqlite/sqliteshared"
)

func TestNewDriver_StripsSQLitePrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dsn  string
	}{
		{"plain file", "test.db"},
		{"sqlite://file", "sqlite://file.db"},
		{"sqlite3://file", "sqlite3://file.db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dsn string
			switch {
			case strings.HasPrefix(tt.dsn, "sqlite3://"):
				dsn = "sqlite3://" + t.TempDir() + "/" + tt.dsn[len("sqlite3://"):]
			case strings.HasPrefix(tt.dsn, "sqlite://"):
				dsn = "sqlite://" + t.TempDir() + "/" + tt.dsn[len("sqlite://"):]
			default:
				dsn = t.TempDir() + "/" + tt.dsn
			}

			driver, err := NewDriver(dsn)
			require.NoError(t, err)
			t.Cleanup(func() { _ = driver.Close() })
		})
	}
}

func TestNewDriver_PinsPoolToOne(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsn  string
	}{
		{name: "file", dsn: "sqlite://" + t.TempDir() + "/pool.db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			driver, err := NewDriver(tt.dsn)
			require.NoError(t, err)
			t.Cleanup(func() { _ = driver.Close() })

			stats := driver.conn.Stats()
			assert.Equal(t, 1, stats.MaxOpenConnections)
		})
	}
}

func TestNewDriver_ForeignKeysEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsn  string
	}{
		{name: "file", dsn: "sqlite://" + t.TempDir() + "/fk.db?mode=rwc"},
		{name: "memory", dsn: "sqlite://:memory:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			driver, err := NewDriver(tt.dsn)
			require.NoError(t, err)
			t.Cleanup(func() { _ = driver.Close() })

			var foreignKeys int
			require.NoError(t, driver.conn.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&foreignKeys))
			assert.Equal(t, 1, foreignKeys)
		})
	}
}

func TestNewDriver_FileDBWorks(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	dsn := t.TempDir() + "/test.db"
	driver, err := NewDriver(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	_, err = driver.conn.ExecContext(ctx, `
		CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);
		INSERT INTO test (name) VALUES ('test1');
		INSERT INTO test (name) VALUES ('test2');
	`)
	require.NoError(t, err)

	var count int
	err = driver.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM test").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

// applyMigrations runs all SQLite migrations against driver's underlying DB.
func applyMigrations(t *testing.T, d *Driver) {
	t.Helper()
	fsys, driverName, err := migrations.GetMigrationsFSForDriver("sqlite")
	require.NoError(t, err)

	src, err := iofs.New(fsys, driverName)
	require.NoError(t, err)

	dbDriver, err := migratesqlite.WithInstance(d.conn.DB, &migratesqlite.Config{})
	require.NoError(t, err)

	m, err := migrate.NewWithInstance("iofs", src, "sqlite", dbDriver)
	require.NoError(t, err)

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("apply migrations: %v", err)
	}

	if err := d.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize driver: %v", err)
	}
}

func TestCreateImportedAPIKeysBatch_SizeLimit(t *testing.T) {
	t.Parallel()

	makeKeys := func(n int) []persistmodel.BatchCreateImportedAPIKeyInput {
		keys := make([]persistmodel.BatchCreateImportedAPIKeyInput, n)
		for i := range keys {
			keys[i] = persistmodel.BatchCreateImportedAPIKeyInput{KeyID: strings.Repeat("a", i%63+1)}
		}
		return keys
	}

	ctx := t.Context()

	t.Run("over limit returns clear error without touching DB", func(t *testing.T) {
		t.Parallel()
		// conn/q are nil; the limit check fires before any DB access.
		driver := &Driver{}
		_, err := driver.CreateImportedAPIKeysBatch(ctx, makeKeys(sqliteshared.MaxBatchKeys+1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds SQLite limit")
	})

	t.Run("at limit uses a real driver", func(t *testing.T) {
		t.Parallel()
		dsn := t.TempDir() + "/batch_limit_test.db"
		driver, err := NewDriver(dsn)
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		applyMigrations(t, driver)

		_, err = driver.CreateImportedAPIKeysBatch(ctx, makeKeys(sqliteshared.MaxBatchKeys))
		require.NoError(t, err, "exactly %d keys must not exceed the batch limit", sqliteshared.MaxBatchKeys)
	})
}
