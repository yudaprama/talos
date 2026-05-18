// Package testutil provides basic testing utilities for database initialization and mocking.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/ory-corp/talos/internal/persistence/sqlite"

	"github.com/ory-corp/talos/internal/persistence/migrations"
)

// contextGetter is an interface for testing.TB implementations that support Context().
// This is satisfied by *testing.T and *testing.B in Go 1.24+.
type contextGetter interface {
	Context() context.Context
}

// InitDriver initializes a new SQLite driver with migrations for testing.
// Creates a file-based database in a temporary directory.
func InitDriver(tb testing.TB, dsn string) (*sqlite.Driver, error) {
	tb.Helper()

	// Get context from testing.T (all callers use testing.T, not Benchmark)
	ctxProvider, ok := tb.(contextGetter)
	if !ok {
		return nil, errors.New("testing.TB does not support Context() - requires Go 1.18+")
	}
	ctx := ctxProvider.Context()

	// If DSN is empty or ":memory:", create file-based temp database
	if dsn == "" || dsn == ":memory:" || strings.Contains(dsn, ":memory:") {
		tempDir := tb.TempDir()

		dsn = fmt.Sprintf("sqlite://%s/test-%d.db?mode=rwc", tempDir, time.Now().UnixNano())
	}

	// Create driver
	driver, err := sqlite.NewDriver(dsn)
	if err != nil {
		return nil, errors.Wrap(err, "create driver")
	}

	// Run migrations
	if err := runMigrations(driver.DB()); err != nil {
		_ = driver.Close()

		return nil, errors.Wrap(err, "run migrations")
	}

	// Initialize default network and signing keys
	if err := driver.Initialize(ctx); err != nil {
		_ = driver.Close()

		return nil, errors.Wrap(err, "initialize default network")
	}

	return driver, nil
}

// runMigrations runs all up migrations
func runMigrations(db *sql.DB) error {
	// Get migrations filesystem for SQLite
	migrationsFS, driverName, err := migrations.GetMigrationsFSForDriver("sqlite")
	if err != nil {
		return errors.Wrap(err, "get migrations filesystem")
	}

	// Create migration source from embedded FS
	sourceDriver, err := iofs.New(migrationsFS, driverName)
	if err != nil {
		return errors.Wrap(err, "create migration source")
	}

	// Create database driver
	dbDriver, err := migratesqlite.WithInstance(db, &migratesqlite.Config{})
	if err != nil {
		return errors.Wrap(err, "create database driver")
	}

	// Create migrator
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
	if err != nil {
		return errors.Wrap(err, "create migrator")
	}

	// Run all migrations
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return errors.Wrap(err, "run migrations")
	}

	return nil
}
