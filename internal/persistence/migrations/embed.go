// Package migrations provides embedded SQL migration files for PostgreSQL.
package migrations

import (
	"embed"
	"io/fs"

	"github.com/cockroachdb/errors"
)

// Database driver names (constants for goconst linter)
const (
	DriverPostgres    = "postgres"
	DriverPostgreSQL  = "postgresql"
	DriverCockroach   = "cockroach"
	DriverCockroachDB = "cockroachdb"
)

// PostgreSQL migrations
//
//go:embed postgres/*.sql
var postgresFS embed.FS

// GetMigrationsFS returns the migrations filesystem for the given database URL.
// Talos is PostgreSQL-only; any non-postgres DSN is rejected.
//
// The returned string is the subdirectory within the embedded FS (also used as
// the iofs source path in cmd/migrate.go), not a driver identifier.
func GetMigrationsFS(databaseURL string) (fs.FS, string, error) {
	return GetMigrationsFSForDriver(driverFromDSN(databaseURL))
}

// GetMigrationsFSForDriver returns migrations for a specific database driver.
// This is used internally by test helpers. PostgreSQL-only.
func GetMigrationsFSForDriver(driver string) (fs.FS, string, error) {
	switch driver {
	case DriverPostgres, DriverPostgreSQL, DriverCockroach, DriverCockroachDB:
		return postgresFS, DriverPostgres, nil
	default:
		return nil, "", errors.Errorf("talos only supports PostgreSQL databases (got driver: %s)", driver)
	}
}

// driverFromDSN extracts the scheme of a DSN (the part before "://") so callers
// can pass a full DSN to GetMigrationsFS. Returns the raw input when no scheme
// is present so GetMigrationsFSForDriver can produce a clear error.
func driverFromDSN(dsn string) string {
	if i := indexScheme(dsn); i >= 0 {
		return dsn[:i]
	}
	return dsn
}

func indexScheme(dsn string) int {
	for i := 0; i+2 < len(dsn); i++ {
		if dsn[i] == ':' && dsn[i+1] == '/' && dsn[i+2] == '/' {
			return i
		}
	}
	return -1
}
