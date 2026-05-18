package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"

	"github.com/ory-corp/talos/internal/persistence/migrations/testhelper"
	"github.com/ory-corp/talos/internal/persistence/sqlite"

	_ "modernc.org/sqlite" // SQLite driver
)

// Test helpers for SQLite (OSS edition)

// createTestDB creates a file-based SQLite database for testing.
func createTestDB(ctx context.Context, t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_fk=1")
	require.NoError(t, err, "open sqlite database")

	err = db.PingContext(ctx)
	require.NoError(t, err, "ping database")

	return db
}

// cleanupTestDB closes the database.
func cleanupTestDB(t *testing.T, db *sql.DB) {
	t.Helper()
	if db != nil {
		err := db.Close()
		require.NoError(t, err, "close database")
	}
}

// newSQLiteMigrate builds a *migrate.Migrate for the SQLite migrations FS.
func newSQLiteMigrate(t *testing.T, db *sql.DB) *migrate.Migrate {
	t.Helper()
	fsys, driverName, err := GetMigrationsFSForDriver("sqlite")
	require.NoError(t, err, "get migrations filesystem")

	sourceDriver, err := iofs.New(fsys, driverName)
	require.NoError(t, err, "create source driver")
	t.Cleanup(func() { _ = sourceDriver.Close() })

	dbDriver, err := migratesqlite.WithInstance(db, &migratesqlite.Config{})
	require.NoError(t, err, "create database driver")

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
	require.NoError(t, err, "create migrate instance")
	return m
}

// applyAllMigrations applies all SQLite migrations.
func applyAllMigrations(_ context.Context, t *testing.T, db *sql.DB) error {
	t.Helper()
	return newSQLiteMigrate(t, db).Up()
}

// applyMigrationsUpTo applies migrations up to a specific version.
func applyMigrationsUpTo(_ context.Context, t *testing.T, db *sql.DB, version int) error {
	t.Helper()
	// #nosec G115 - version is from test input, overflow acceptable
	return newSQLiteMigrate(t, db).Migrate(uint(version))
}

// rollbackMigrations rolls back N migration steps.
func rollbackMigrations(_ context.Context, t *testing.T, db *sql.DB, steps int) error {
	t.Helper()
	return newSQLiteMigrate(t, db).Steps(-steps)
}

// getCurrentMigrationVersion returns the current migration version.
func getCurrentMigrationVersion(_ context.Context, t *testing.T, db *sql.DB) (uint, bool, error) {
	t.Helper()
	return testhelper.Version(t, newSQLiteMigrate(t, db))
}

// tableExists checks if a table exists in SQLite
func tableExists(ctx context.Context, db *sql.DB, tableName string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`
	var exists bool
	err := db.QueryRowContext(ctx, query, tableName).Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "check if table exists")
	}
	return exists, nil
}

// columnExists checks if a column exists in a SQLite table
func columnExists(ctx context.Context, db *sql.DB, tableName, columnName string) (bool, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return false, errors.Wrap(err, "get table info")
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dfltValue *string

		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return false, errors.Wrap(err, "scan column info")
		}

		if name == columnName {
			return true, nil
		}
	}
	return false, rows.Err()
}

// TestSQLiteMigrations tests migrations for SQLite (OSS edition)
func TestSQLiteMigrations(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping migration tests in short mode")
	}

	ctx := t.Context()

	t.Run("migrations_apply_successfully", func(t *testing.T) {
		t.Parallel()
		db := createTestDB(ctx, t)
		t.Cleanup(func() { cleanupTestDB(t, db) })

		// Apply all migrations
		err := applyAllMigrations(ctx, t, db)
		require.NoError(t, err)

		// Verify expected tables exist
		expectedTables := []string{"issued_api_keys", "imported_api_keys", "networks"}
		for _, table := range expectedTables {
			exists, err := tableExists(ctx, db, table)
			require.NoError(t, err)
			assert.True(t, exists, "table %s should exist", table)
		}
	})

	t.Run("tables_exist_after_migration", func(t *testing.T) {
		t.Parallel()
		db := createTestDB(ctx, t)
		t.Cleanup(func() { cleanupTestDB(t, db) })

		// Apply all migrations
		err := applyAllMigrations(ctx, t, db)
		require.NoError(t, err)

		// Verify expected tables exist
		expectedTables := []string{"issued_api_keys", "imported_api_keys", "networks"}
		for _, table := range expectedTables {
			exists, err := tableExists(ctx, db, table)
			require.NoError(t, err)
			assert.True(t, exists, "table %s should exist", table)
		}

		// Verify issued_api_keys table has expected columns using PRAGMA directly
		rows, err := db.QueryContext(ctx, "PRAGMA table_info(issued_api_keys)")
		require.NoError(t, err)
		defer func() { _ = rows.Close() }()

		columnNames := make(map[string]bool)
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var dflt *string
			err = rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk)
			require.NoError(t, err)
			columnNames[name] = true
		}
		require.NoError(t, rows.Err())

		expectedColumns := []string{"nid", "key_id", "name", "token_prefix", "version", "actor_id", "scopes", "status", "metadata", "created_at", "updated_at", "rate_limit_quota", "rate_limit_window"}
		for _, colName := range expectedColumns {
			assert.True(t, columnNames[colName], "column %s should exist in issued_api_keys table", colName)
		}
	})

	t.Run("idempotency", func(t *testing.T) {
		t.Parallel()
		db := createTestDB(ctx, t)
		t.Cleanup(func() { cleanupTestDB(t, db) })

		// Apply all migrations first time
		err := applyAllMigrations(ctx, t, db)
		require.NoError(t, err)

		// Try to apply again - should get ErrNoChange
		err = applyAllMigrations(ctx, t, db)
		assert.ErrorIs(t, err, migrate.ErrNoChange, "applying migrations twice should return ErrNoChange")
	})

	t.Run("migration_version_tracking", func(t *testing.T) {
		t.Parallel()
		db := createTestDB(ctx, t)
		t.Cleanup(func() { cleanupTestDB(t, db) })

		// Check initial version (should be 0/nil)
		version, dirty, err := getCurrentMigrationVersion(ctx, t, db)
		require.NoError(t, err)
		assert.Equal(t, uint(0), version, "initial version should be 0")
		assert.False(t, dirty, "initial state should not be dirty")

		// Apply migrations up to version 1 (the only migration)
		err = applyMigrationsUpTo(ctx, t, db, 1)
		require.NoError(t, err)

		// Check version is now 1 (OSS has 1 squashed migration)
		version, dirty, err = getCurrentMigrationVersion(ctx, t, db)
		require.NoError(t, err)
		assert.Equal(t, uint(1), version, "version should be 1")
		assert.False(t, dirty, "state should not be dirty")
	})

	t.Run("forward_backward_compatibility", func(t *testing.T) {
		t.Parallel()
		db := createTestDB(ctx, t)
		t.Cleanup(func() { cleanupTestDB(t, db) })

		// Test squashed migration: Full schema with all columns
		t.Run("migration_1_full_schema", func(t *testing.T) {
			// Apply migration 1 (squashed - includes all tables and columns)
			err := applyMigrationsUpTo(ctx, t, db, 1)
			require.NoError(t, err)

			// Verify all tables exist
			expectedTables := []string{"issued_api_keys", "imported_api_keys", "networks"}
			for _, table := range expectedTables {
				exists, err := tableExists(ctx, db, table)
				require.NoError(t, err)
				assert.True(t, exists, "table %s should exist after migration 1", table)
			}

			// Verify rate_limit columns exist in issued_api_keys table
			exists, err := columnExists(ctx, db, "issued_api_keys", "rate_limit_quota")
			require.NoError(t, err)
			assert.True(t, exists, "rate_limit_quota column should exist")

			exists, err = columnExists(ctx, db, "issued_api_keys", "rate_limit_window")
			require.NoError(t, err)
			assert.True(t, exists, "rate_limit_window column should exist")

			// Insert test data
			_, err = db.ExecContext(ctx, `
				INSERT INTO networks (id, created_at, updated_at)
				VALUES ('test-network', '2024-01-15 10:00:00', '2024-01-15 10:00:00')
			`)
			require.NoError(t, err)

			_, err = db.ExecContext(ctx, `
				INSERT INTO issued_api_keys (nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, created_at, updated_at, rate_limit_quota, rate_limit_window)
				VALUES ('test-network', 'test-key-1', 'Test Key', 'phx_test', 1, 'user-1', CAST('["read"]' AS BLOB), 1, CAST('{}' AS BLOB), '2024-01-15 10:00:00', '2024-01-15 10:00:00', 100, 30)
			`)
			require.NoError(t, err)

			// Verify data exists
			err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM issued_api_keys WHERE key_id = 'test-key-1')").Scan(&exists)
			require.NoError(t, err)
			assert.True(t, exists, "issued_api_key test-key-1 should exist")

			// Verify rate limit data
			var quota, window *int64
			err = db.QueryRowContext(ctx, `
				SELECT rate_limit_quota, rate_limit_window
				FROM issued_api_keys
				WHERE key_id = 'test-key-1'
			`).Scan(&quota, &window)
			require.NoError(t, err)
			assert.NotNil(t, quota)
			assert.NotNil(t, window)
			assert.Equal(t, int64(100), *quota)
			assert.Equal(t, int64(30), *window)
		})
	})

	t.Run("complete_up_down_cycle", func(t *testing.T) {
		t.Parallel()
		db := createTestDB(ctx, t)
		t.Cleanup(func() { cleanupTestDB(t, db) })

		// Apply all migrations
		err := applyAllMigrations(ctx, t, db)
		require.NoError(t, err)

		// Insert test data at fully migrated state
		_, err = db.ExecContext(ctx, `
			INSERT INTO networks (id, created_at, updated_at)
			VALUES ('full-test', datetime('now'), datetime('now'))
		`)
		require.NoError(t, err)

		// Roll back all migrations (tables are dropped, data is gone)
		err = rollbackMigrations(ctx, t, db, len(listMigrationVersions(t)))
		require.NoError(t, err)

		// Verify tables don't exist
		exists, err := tableExists(ctx, db, "issued_api_keys")
		require.NoError(t, err)
		assert.False(t, exists, "issued_api_keys table should not exist after full rollback")

		// Reapply all migrations
		err = applyAllMigrations(ctx, t, db)
		require.NoError(t, err)

		// Verify tables exist again
		exists, err = tableExists(ctx, db, "issued_api_keys")
		require.NoError(t, err)
		assert.True(t, exists, "issued_api_keys table should exist after reapplying migrations")

		// Data from before won't exist (full rollback dropped tables)
		// But we can insert new data
		_, err = db.ExecContext(ctx, `
			INSERT INTO networks (id, created_at, updated_at)
			VALUES ('new-test', datetime('now'), datetime('now'))
		`)
		require.NoError(t, err)

		var count int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "should have 1 network after cycle")
	})
}

// TestGetMigrationsFS tests the migration filesystem factory function
func TestGetMigrationsFS(t *testing.T) {
	t.Parallel()
	t.Run("sqlite_url", func(t *testing.T) {
		t.Parallel()
		fsys, driver, err := GetMigrationsFS("sqlite3://test.db")
		require.NoError(t, err)
		assert.NotNil(t, fsys)
		assert.Equal(t, "sqlite", driver)
	})

	t.Run("memory_url", func(t *testing.T) {
		t.Parallel()
		fsys, driver, err := GetMigrationsFS(":memory:")
		require.NoError(t, err)
		assert.NotNil(t, fsys)
		assert.Equal(t, "sqlite", driver)
	})

	t.Run("unsupported_database_oss", func(t *testing.T) {
		t.Parallel()
		_, _, err := GetMigrationsFS("postgres://localhost/test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "oss edition only supports SQLite")
	})
}

// TestGetMigrationsFSForDriver tests the driver-specific filesystem function
func TestGetMigrationsFSForDriver(t *testing.T) {
	t.Parallel()
	t.Run("sqlite_supported", func(t *testing.T) {
		t.Parallel()
		fsys, driver, err := GetMigrationsFSForDriver("sqlite")
		require.NoError(t, err)
		assert.NotNil(t, fsys)
		assert.Equal(t, "sqlite", driver)

		// Verify it's a valid filesystem with migrations in sqlite directory
		_, err = fs.ReadDir(fsys, "sqlite")
		assert.NoError(t, err, "should be able to read migration directory")
	})

	t.Run("commercial_databases_not_supported_in_oss", func(t *testing.T) {
		t.Parallel()
		commercialDrivers := []string{"postgres", "mysql", "cockroach"}
		for _, driver := range commercialDrivers {
			t.Run(driver, func(t *testing.T) {
				t.Parallel()
				_, _, err := GetMigrationsFSForDriver(driver)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "oss edition only supports SQLite")
			})
		}
	})

	t.Run("unsupported_driver", func(t *testing.T) {
		t.Parallel()
		_, _, err := GetMigrationsFSForDriver("oracle")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "oss edition only supports SQLite")
	})
}

// listMigrationVersions returns the sorted slice of migration version numbers
// derived from *.up.sql files in the SQLite migrations FS.
func listMigrationVersions(t *testing.T) []uint {
	t.Helper()
	fsys, driverName, err := GetMigrationsFSForDriver("sqlite")
	require.NoError(t, err)

	entries, err := fs.ReadDir(fsys, driverName)
	require.NoError(t, err)

	seen := make(map[uint]bool)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		v, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			t.Fatalf("malformed migration filename %q: numeric prefix required", e.Name())
		}
		if seen[uint(v)] {
			continue
		}
		seen[uint(v)] = true
	}

	versions := make([]uint, 0, len(seen))
	for v := range seen {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	return versions
}

// stepMigrationsAndLoadFixtures applies each migration one at a time and loads
// fixture data immediately after each step. The test fails if a fixture file is
// missing for any version — add an empty file with a comment to explicitly mark
// versions that add no test data.
func stepMigrationsAndLoadFixtures(ctx context.Context, t *testing.T, db *sql.DB, dialect, nid string) {
	t.Helper()
	for _, v := range listMigrationVersions(t) {
		err := applyMigrationsUpTo(ctx, t, db, int(v))
		if !errors.Is(err, migrate.ErrNoChange) {
			require.NoError(t, err, "apply migration %d", v)
		}
		loadFixtures(t, db, fmt.Sprintf("%06d", v), dialect, nid)
	}
}

// snapshotFor returns a cupaloy config that stores snapshots under
// testdata/snapshots/{version}/{dialect}/{table}/
func compareWithFixture(t *testing.T, actual any, version, dialect, table, id, nid string) {
	t.Helper()
	testhelper.CompareWithFixture(t, "testdata", actual, version, dialect, table, id, nid)
}

func loadFixtures(t *testing.T, db *sql.DB, version, dialect, nid string) {
	t.Helper()
	testhelper.LoadFixtures(t, db, "testdata", version, dialect, nid)
}

// TestSQLiteMigratest verifies that fixture data inserted at migration v1 survives
// the full migration lifecycle and round-trips correctly through the SQLite driver.
// This mirrors the migratest pattern used in keto and kratos, adapted for golang-migrate.
func TestSQLiteMigratest(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping migration tests in short mode")
	}

	ctx := t.Context()

	// ossNID is the hardcoded single-tenant network ID used by the OSS SQLite driver.
	const ossNID = "00000000-0000-0000-0000-000000000000"
	// fixedKeyIDs are the UUIDs written to the fixture file.
	const (
		activeKeyID  = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		revokedKeyID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		expiredKeyID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
		importedHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	)

	t.Run("round_trip", func(t *testing.T) {
		t.Parallel()

		dbPath := filepath.Join(t.TempDir(), "migratest.db")

		driver, err := sqlite.NewDriver(dbPath)
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		stepMigrationsAndLoadFixtures(ctx, t, driver.DB(), "sqlite", ossNID)

		t.Run("active_issued_key", func(t *testing.T) {
			t.Parallel()
			key, err := driver.GetIssuedAPIKey(ctx, activeKeyID)
			require.NoError(t, err)
			compareWithFixture(t, key, "000001", "sqlite", "issued_api_keys", activeKeyID, ossNID)
		})

		t.Run("revoked_issued_key", func(t *testing.T) {
			t.Parallel()
			key, err := driver.GetIssuedAPIKey(ctx, revokedKeyID)
			require.NoError(t, err)
			compareWithFixture(t, key, "000001", "sqlite", "issued_api_keys", revokedKeyID, ossNID)
		})

		t.Run("expired_issued_key", func(t *testing.T) {
			t.Parallel()
			key, err := driver.GetIssuedAPIKey(ctx, expiredKeyID)
			require.NoError(t, err)
			compareWithFixture(t, key, "000001", "sqlite", "issued_api_keys", expiredKeyID, ossNID)
		})

		t.Run("imported_key", func(t *testing.T) {
			t.Parallel()
			key, err := driver.GetImportedAPIKeyByHash(ctx, importedHash)
			require.NoError(t, err)
			compareWithFixture(t, key, "000001", "sqlite", "imported_api_keys", importedHash, ossNID)
		})

		t.Run("list_returns_all_issued_keys", func(t *testing.T) {
			t.Parallel()
			keys, err := driver.ListIssuedAPIKeysByNetwork(ctx, "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED), "", 50)
			require.NoError(t, err)
			assert.Len(t, keys, 3, "expected 3 issued keys from v1 fixture")

			activeKeys, err := driver.ListIssuedAPIKeysByNetwork(ctx, "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), "", 50)
			require.NoError(t, err)
			assert.Len(t, activeKeys, 1, "expected 1 active key")

			revokedKeys, err := driver.ListIssuedAPIKeysByNetwork(ctx, "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED), "", 50)
			require.NoError(t, err)
			assert.Len(t, revokedKeys, 1, "expected 1 revoked key from v1 fixture")
		})

		t.Run("list_imported_keys", func(t *testing.T) {
			t.Parallel()
			keys, err := driver.ListImportedAPIKeys(ctx, int32(talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED), "", "", 50)
			require.NoError(t, err)
			assert.Len(t, keys, 1, "expected 1 imported key from v1 fixture")
		})
	})

	t.Run("up_down_up_cycle", func(t *testing.T) {
		t.Parallel()

		dbPath := filepath.Join(t.TempDir(), "migratest-cycle.db")

		driver, err := sqlite.NewDriver(dbPath)
		require.NoError(t, err)
		t.Cleanup(func() { _ = driver.Close() })

		applyAndLoad := func() {
			stepMigrationsAndLoadFixtures(ctx, t, driver.DB(), "sqlite", ossNID)
		}

		applyAndLoad()

		// Roll back all migrations — tables are dropped, data is gone.
		require.NoError(t, rollbackMigrations(ctx, t, driver.DB(), len(listMigrationVersions(t))))

		// Re-apply migrations — schema is restored but empty.
		applyAndLoad()

		// Fixture data was re-inserted; snapshots must match the round_trip baseline.
		for _, keyID := range []string{activeKeyID, revokedKeyID, expiredKeyID} {
			key, err := driver.GetIssuedAPIKey(ctx, keyID)
			require.NoError(t, err)
			compareWithFixture(t, key, "000001", "sqlite", "issued_api_keys", keyID, ossNID)
		}
		imp, err := driver.GetImportedAPIKeyByHash(ctx, importedHash)
		require.NoError(t, err)
		compareWithFixture(t, imp, "000001", "sqlite", "imported_api_keys", importedHash, ossNID)

		all, err := driver.ListIssuedAPIKeysByNetwork(ctx, "", int32(talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED), "", 50)
		require.NoError(t, err)
		assert.Len(t, all, 3, "expected 3 issued keys from v1 fixture")

		imported, err := driver.ListImportedAPIKeys(ctx, int32(talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED), "", "", 50)
		require.NoError(t, err)
		assert.Len(t, imported, 1, "expected 1 imported key from v1 fixture")
	})
}
