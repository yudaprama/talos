// Package migrations provides embedded SQL migration files for SQLite (OSS edition).
package migrations

import (
	"embed"
	"io/fs"
	"strings"

	"github.com/cockroachdb/errors"
)

// Database driver names (constants for goconst linter)
const (
	DriverSQLite      = "sqlite"
	DriverSQLite3     = "sqlite3"
	DriverPostgres    = "postgres"
	DriverPostgreSQL  = "postgresql"
	DriverMySQL       = "mysql"
	DriverCockroach   = "cockroach"
	DriverCockroachDB = "cockroachdb"
)

// SQLite migrations (OSS edition)
//
//go:embed sqlite/*.sql
var sqliteFS embed.FS

// GetMigrationsFS returns the migrations filesystem for SQLite based on database URL.
// OSS edition only supports SQLite.
func GetMigrationsFS(databaseURL string) (fs.FS, string, error) {
	// OSS only supports SQLite
	if !strings.HasPrefix(databaseURL, "sqlite3://") &&
		!strings.HasPrefix(databaseURL, "sqlite://") &&
		!strings.Contains(databaseURL, ".db") &&
		databaseURL != ":memory:" {
		return nil, "", errors.Errorf("oss edition only supports SQLite databases (got: %s), for PostgreSQL, MySQL, or CockroachDB, use the commercial edition", databaseURL)
	}

	// Return SQLite filesystem
	return sqliteFS, DriverSQLite, nil
}

// GetMigrationsFSForDriver returns migrations for a specific database driver.
// This is used internally by test helpers.
// OSS only supports SQLite; commercial databases handled by commercial package.
func GetMigrationsFSForDriver(driver string) (fs.FS, string, error) {
	switch driver {
	case DriverSQLite, DriverSQLite3:
		return sqliteFS, DriverSQLite, nil
	default:
		return nil, "", errors.Errorf("oss edition only supports SQLite driver (got: %s)", driver)
	}
}

// reviewed - @aeneasr - 2026-03-26
