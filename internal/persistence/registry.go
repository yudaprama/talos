package persistence

import (
	"context"
	"database/sql"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/ory/x/logrusx"
	"github.com/ory/x/sqlcon"

	"github.com/ory/talos/internal/persistence/postgres"
)

// Persister name constants
const (
	DriverSQLite    = "sqlite"
	DriverPostgres  = "postgres"
	DriverCockroach = "cockroach"
)

// Factory is a function that creates a database driver instance from a DSN string.
// DSN format: <scheme>://<connection_string>?<query_params>
// The scheme determines the driver type (sqlite://, postgres://, cockroach://)
// Query parameters control connection pool settings (max_conns, max_idle_conns, etc.)
// Context is used for connection establishment and initialization.
type Factory func(context.Context, string) (Persister, error)

// ConnectionOptions contains parsed connection pool settings from DSN query parameters
type ConnectionOptions struct {
	MaxConns        int
	MaxIdleConns    int
	MaxConnLifetime time.Duration
	MaxIdleConnTime time.Duration
	CleanedDSN      string
}

// ParseDSN parses a DSN string and extracts driver name and connection options.
// The driver type is determined from the DSN scheme:
//   - sqlite:// or sqlite3:// -> "sqlite"
//   - postgres:// or postgresql:// -> "postgres"
//   - cockroach:// or cockroachdb:// -> "cockroach"
//
// Connection pool settings are parsed from query parameters:
//   - max_conns=N
//   - max_idle_conns=N
//   - max_conn_lifetime=5m
//   - max_conn_idle_time=1m
//   - pool_* (for pgxpool compatibility)
func ParseDSN(dsn string) (driverName string, opts ConnectionOptions, err error) {
	if dsn == "" {
		return "", ConnectionOptions{}, errors.New("DSN cannot be empty")
	}

	// Use ory/x to get driver name from scheme
	driverName = sqlcon.GetDriverName(dsn)

	// Normalize driver names
	switch driverName {
	case "sqlite3", DriverSQLite:
		driverName = DriverSQLite
	case "postgresql":
		driverName = DriverPostgres
	case "cockroachdb":
		driverName = DriverCockroach
	}

	// Use ory/x to parse connection options from query parameters
	// Create a no-op logger since we use slog, not logrus
	logger := logrusx.New("", "")
	maxConns, maxIdleConns, maxConnLifetime, maxIdleConnTime, cleanedDSN := sqlcon.ParseConnectionOptions(logger, dsn)

	// Finalize the DSN
	cleanedDSN = sqlcon.FinalizeDSN(logger, cleanedDSN)

	opts = ConnectionOptions{
		MaxConns:        maxConns,
		MaxIdleConns:    maxIdleConns,
		MaxConnLifetime: maxConnLifetime,
		MaxIdleConnTime: maxIdleConnTime,
		CleanedDSN:      cleanedDSN,
	}

	return driverName, opts, nil
}

// NewDriver creates a new database driver based on the DSN.
// The driver type is determined from the DSN scheme (sqlite://, postgres://, cockroach://).
// It accepts proprietary factories which will be checked first before falling back to OSS types.
//
// Error handling:
//   - DSN parsing errors: fail immediately (permanent error)
//   - Unknown driver type: fail immediately (permanent error)
//   - Persister initialization errors: fail immediately (permanent error - bad config, missing deps)
//
// Note: Connection retry logic is handled by individual driver implementations using dbutil.ConnectWithRetry.
//
// DSN format examples:
//   - sqlite://./data.db
//   - postgres://user:pass@host:5432/db?max_conns=50
//   - cockroach://user@host:26257/db?pool_max_conns=100
func NewDriver(ctx context.Context, dsn string, proprietaryFactories map[string]Factory) (Persister, error) {
	// Parse DSN to determine driver type (permanent error if invalid) and to
	// extract connection-pool settings from query parameters.
	driverName, opts, err := ParseDSN(dsn)
	if err != nil {
		return nil, errors.Wrap(err, "parse DSN")
	}

	// Create driver instance (permanent error if fails - bad config, missing deps, etc.)
	var driver Persister

	// Check proprietary factories first (only available in Enterprise builds)
	switch {
	case proprietaryFactories[driverName] != nil:
		driver, err = proprietaryFactories[driverName](ctx, dsn)
		if err != nil {
			return nil, errors.Wrapf(err, "initialize %s database driver", driverName)
		}
	case driverName == DriverPostgres || driverName == DriverCockroach:
		// CockroachDB speaks the PostgreSQL wire protocol, so the same driver
		// serves both. CleanedDSN has the talos pool query params stripped so
		// pgx does not choke on them.
		driver, err = postgres.NewDriver(opts.CleanedDSN)
		if err != nil {
			return nil, errors.Wrapf(err, "initialize %s database driver", driverName)
		}
		applyPoolSettings(driver.DB(), opts)
	default:
		return nil, errors.Errorf("unknown database driver: %s. Talos supports: postgres, cockroach", driverName)
	}

	return driver, nil
}

// applyPoolSettings applies the connection-pool options parsed from the DSN
// query string to the underlying *sql.DB. Zero values are left at the driver
// default. PostgreSQL (unlike the old single-writer SQLite path) benefits from
// a real pool, so callers should size max_conns for their concurrency.
func applyPoolSettings(sqlDB *sql.DB, opts ConnectionOptions) {
	if sqlDB == nil {
		return
	}
	if opts.MaxConns > 0 {
		sqlDB.SetMaxOpenConns(opts.MaxConns)
	}
	if opts.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(opts.MaxIdleConns)
	}
	if opts.MaxConnLifetime > 0 {
		sqlDB.SetConnMaxLifetime(opts.MaxConnLifetime)
	}
	if opts.MaxIdleConnTime > 0 {
		sqlDB.SetConnMaxIdleTime(opts.MaxIdleConnTime)
	}
}

// reviewed - @aeneasr - 2026-03-26
