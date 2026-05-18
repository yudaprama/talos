// Package dbutil provides database utility functions for driver detection and configuration.
package dbutil

import "strings"

const (
	// DriverPgx is the driver name for PostgreSQL and CockroachDB
	DriverPgx = "pgx"
)

// GetDriverName detects the SQL driver name from a DSN string.
// Returns "pgx" for PostgreSQL/CockroachDB, "mysql" for MySQL, or "sqlite3" as default.
func GetDriverName(dsn string) string {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return DriverPgx
	case strings.HasPrefix(dsn, "mysql://"):
		return "mysql"
	case strings.HasPrefix(dsn, "cockroach://"), strings.HasPrefix(dsn, "cockroachdb://"):
		return DriverPgx
	default:
		return "sqlite3"
	}
}

// ShouldRetry determines if a database connection should use retry logic.
// Returns false for file-based SQLite databases, true for network databases.
func ShouldRetry(dsn string) bool {
	// SQLite databases don't need retry logic
	if strings.HasPrefix(dsn, "sqlite3://") ||
		strings.HasPrefix(dsn, "sqlite://") ||
		strings.HasPrefix(dsn, ":memory:") {
		return false
	}
	// All network databases (Postgres, MySQL, CockroachDB) benefit from retry
	return true
}

// reviewed - @aeneasr - 2026-03-25
