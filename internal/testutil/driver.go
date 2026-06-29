// Package testutil provides basic testing utilities for database initialization and mocking.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/golang-migrate/migrate/v4"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"

	"github.com/ory/talos/internal/persistence/migrations"
	"github.com/ory/talos/internal/persistence/postgres"
)

// TestDatabaseURLEnv is the environment variable holding the base PostgreSQL DSN
// used by the test suite. Each test gets an isolated schema created within that
// database, so the URL should point at a throwaway/test database.
const TestDatabaseURLEnv = "TALOS_TEST_DATABASE_URL"

// contextGetter is an interface for testing.TB implementations that support Context().
// This is satisfied by *testing.T and *testing.B in Go 1.24+.
type contextGetter interface {
	Context() context.Context
}

// InitDriver initializes a PostgreSQL driver with migrations for testing,
// isolated in a freshly created schema that is dropped on test cleanup.
//
// dsn may be empty (or a legacy sqlite/":memory:" value), in which case the base
// DSN is read from TALOS_TEST_DATABASE_URL. The test is skipped when no DSN is
// available so the suite degrades gracefully on machines without a Postgres.
func InitDriver(tb testing.TB, dsn string) (*postgres.Driver, error) {
	driver, _, err := InitDriverWithDSN(tb, dsn)
	return driver, err
}

// InitDriverWithDSN is like InitDriver but also returns the schema-qualified DSN
// the driver is bound to. Callers that must open the same isolated schema from a
// second connection (e.g. exercising server bootstrap from a config DSN) pass
// this DSN through their config provider.
func InitDriverWithDSN(tb testing.TB, dsn string) (*postgres.Driver, string, error) {
	tb.Helper()

	ctxProvider, ok := tb.(contextGetter)
	if !ok {
		return nil, "", errors.New("testing.TB does not support Context() - requires Go 1.18+")
	}
	ctx := ctxProvider.Context()

	// Ignore empty and legacy sqlite-style DSNs: the source of truth is the env.
	base := dsn
	if base == "" || strings.HasPrefix(base, "sqlite") || strings.Contains(base, ":memory:") {
		base = os.Getenv(TestDatabaseURLEnv)
	}
	if base == "" {
		tb.Skipf("%s not set; skipping Postgres-backed test", TestDatabaseURLEnv)
		return nil, "", nil
	}

	schema := fmt.Sprintf("talos_test_%d", time.Now().UnixNano())

	// Create the isolated schema using a short-lived admin connection.
	admin, err := sql.Open("pgx", base)
	if err != nil {
		return nil, "", errors.Wrap(err, "open admin connection")
	}
	if _, err := admin.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %q", schema)); err != nil {
		_ = admin.Close()
		return nil, "", errors.Wrap(err, "create test schema")
	}
	_ = admin.Close()

	driverDSN := appendSearchPath(base, schema)

	driver, err := postgres.NewDriver(driverDSN)
	if err != nil {
		dropSchema(ctx, base, schema)
		return nil, "", errors.Wrap(err, "create driver")
	}

	tb.Cleanup(func() {
		_ = driver.Close()
		dropSchema(context.WithoutCancel(ctx), base, schema)
	})

	if err := runMigrations(driver.DB(), schema); err != nil {
		return nil, "", errors.Wrap(err, "run migrations")
	}

	if err := driver.Initialize(ctx); err != nil {
		return nil, "", errors.Wrap(err, "initialize default network")
	}

	return driver, driverDSN, nil
}

// appendSearchPath appends the search_path runtime parameter to a DSN so every
// pooled connection operates inside the isolated schema. pgx forwards unknown
// query parameters as server runtime parameters.
func appendSearchPath(dsn, schema string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + url.QueryEscape(schema)
}

// runMigrations runs all up migrations into the given schema.
func runMigrations(db *sql.DB, schema string) error {
	migrationsFS, driverName, err := migrations.GetMigrationsFSForDriver("postgres")
	if err != nil {
		return errors.Wrap(err, "get migrations filesystem")
	}

	sourceDriver, err := iofs.New(migrationsFS, driverName)
	if err != nil {
		return errors.Wrap(err, "create migration source")
	}

	dbDriver, err := migratepostgres.WithInstance(db, &migratepostgres.Config{SchemaName: schema})
	if err != nil {
		return errors.Wrap(err, "create database driver")
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", dbDriver)
	if err != nil {
		return errors.Wrap(err, "create migrator")
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return errors.Wrap(err, "run migrations")
	}

	return nil
}

// dropSchema removes the isolated test schema (best effort).
func dropSchema(ctx context.Context, base, schema string) {
	admin, err := sql.Open("pgx", base)
	if err != nil {
		return
	}
	defer func() { _ = admin.Close() }()
	_, _ = admin.ExecContext(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %q CASCADE", schema))
}
