package migrations_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence/migrations"
	"github.com/ory-corp/talos/internal/persistence/sqlite"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"

	_ "modernc.org/sqlite" // SQLite driver
)

// newE2ESQLiteMigrate builds a *migrate.Migrate for the given sql.DB.
func newE2ESQLiteMigrate(t *testing.T, db *sql.DB) *migrate.Migrate {
	t.Helper()
	fsys, driverName, err := migrations.GetMigrationsFSForDriver("sqlite")
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

// createE2ETestDB creates a file-based SQLite database and returns both the open
// connection and the file path so callers can open additional connections.
func createE2ETestDB(t *testing.T) (db *sql.DB, dbPath string) {
	t.Helper()
	dbPath = filepath.Join(t.TempDir(), "e2e.db")
	db, err := sql.Open("sqlite", dbPath+"?_fk=1")
	require.NoError(t, err, "open sqlite database")
	require.NoError(t, db.PingContext(t.Context()), "ping database")
	t.Cleanup(func() { _ = db.Close() })
	return db, dbPath
}

// TestSQLiteMigrationE2E verifies that after running all migrations the database is
// fully functional: a SQLite driver can issue, read back, and revoke API keys.
func TestSQLiteMigrationE2E(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping E2E migration tests in short mode")
	}

	ctx := t.Context()

	// Apply all migrations through the public migration API.
	rawDB, dbPath := createE2ETestDB(t)
	m := newE2ESQLiteMigrate(t, rawDB)
	require.NoError(t, m.Up(), "all migrations must apply cleanly")

	// Open the driver against the migrated file so we exercise the production
	// code path (NewDriver + Initialize) rather than raw SQL alone.
	driver, err := sqlite.NewDriver(dbPath)
	require.NoError(t, err, "NewDriver must succeed after migrations")
	t.Cleanup(func() { _ = driver.Close() })
	require.NoError(t, driver.Initialize(ctx), "Initialize must succeed after migrations")

	const (
		// ossNID is the hardcoded single-tenant network ID used by the OSS SQLite driver.
		ossNID  = "00000000-0000-0000-0000-000000000000"
		keyID   = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
		keyName = "e2e-migration-key"
	)
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	activeStatus := int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE)
	revokedStatus := int32(talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED)

	// Issue — insert a key directly via SQL against the migrated schema.
	// JSON columns (scopes, metadata, allowed_cidrs) must be CAST AS BLOB to match
	// the storage format the sqlite driver uses when writing json.RawMessage ([]byte).
	_, err = rawDB.ExecContext(ctx, `
		INSERT INTO issued_api_keys
			(nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata,
			 revocation_reason, visibility, allowed_cidrs, created_at, updated_at)
		VALUES
			(?, ?, ?, 'talos', 1, 'user-e2e',
			 CAST('["read"]' AS BLOB), ?, CAST('{}' AS BLOB),
			 0, 1, CAST('[]' AS BLOB), ?, ?)
	`, ossNID, keyID, keyName, activeStatus, now, now)
	require.NoError(t, err, "INSERT issued_api_key must succeed on migrated schema")

	// Read back — confirm the row round-trips through the driver.
	key, err := driver.GetIssuedAPIKey(ctx, keyID)
	require.NoError(t, err, "GetIssuedAPIKey must find the inserted key")
	assert.Equal(t, keyID, key.KeyID, "key ID must match")
	assert.Equal(t, keyName, key.Name, "key name must match")
	assert.Equal(t, activeStatus, key.Status, "key status must be active")

	// Revoke — update the status column.
	_, err = rawDB.ExecContext(ctx, `
		UPDATE issued_api_keys SET status = ?, updated_at = ? WHERE key_id = ?
	`, revokedStatus, now, keyID)
	require.NoError(t, err, "UPDATE issued_api_key status must succeed")

	// Verify revocation through the driver.
	revoked, err := driver.GetIssuedAPIKey(ctx, keyID)
	require.NoError(t, err, "GetIssuedAPIKey must find the revoked key")
	assert.Equal(t, revokedStatus, revoked.Status, "key status must be revoked")
}

// TestSQLiteMigrationDownE2E verifies that rolling back all migrations leaves the
// database in a state where the driver cannot initialise. This ensures the down
// migrations are consistent with the schema expectations of the application.
func TestSQLiteMigrationDownE2E(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping E2E migration tests in short mode")
	}

	ctx := t.Context()

	rawDB, dbPath := createE2ETestDB(t)
	m := newE2ESQLiteMigrate(t, rawDB)

	require.NoError(t, m.Up(), "all migrations must apply cleanly")

	// Roll back all migrations.
	require.NoError(t, m.Down(), "down migration must succeed")

	// Open a Driver against the same file — NewDriver does not touch the schema.
	driver, err := sqlite.NewDriver(dbPath)
	require.NoError(t, err, "NewDriver must succeed regardless of schema state")
	t.Cleanup(func() { _ = driver.Close() })

	// Initialize queries the networks table, which no longer exists after rollback.
	err = driver.Initialize(ctx)
	require.Error(t, err, "Initialize must fail when schema has been rolled back")
}
