package cmd

import (
	"cmp"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/golang-migrate/migrate/v4"

	// Import database drivers for side effects (registers drivers with migrate)
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/spf13/cobra"

	"github.com/ory/x/cmdx"
)

// newMigrateCmd creates the migrate command with all subcommands
func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration tools",
		Long:  `Run database migrations for the API Key service`,
	}

	// Add subcommands using factory functions
	cmd.AddCommand(newMigrateUpCmd())
	cmd.AddCommand(newMigrateDownCmd())
	cmd.AddCommand(newMigrateStatusCmd())
	cmd.AddCommand(newMigrateForceCmd())

	return cmd
}

// newMigrateUpCmd creates the migrate up command with bound flag variables
func newMigrateUpCmd() *cobra.Command {
	var database string

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Run all pending migrations",
		Long: `Apply all pending migrations to the database.

The database connection string can be provided via:
  - DB_DSN environment variable
  - --database flag (overrides DB_DSN)`,
		Example: `  # SQLite
  {{ .CommandPath }} --database "sqlite3://./data/talos.db"

  # PostgreSQL (commercial)
  export DB_DSN="postgres://user:pass@localhost:5432/talos?sslmode=disable"
  {{ .CommandPath }}

  # MySQL (commercial)
  {{ .CommandPath }} --database "mysql://user:pass@tcp(localhost:3306)/talos"

  # CockroachDB (commercial)
  {{ .CommandPath }} --database "cockroach://user:pass@localhost:5432/talos?sslmode=disable"`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dbDSN, err := getDatabaseDSN(database)
			if err != nil {
				return err
			}

			m, err := newMigrate(dbDSN)
			if err != nil {
				return errors.Wrap(err, "initialize migrations")
			}
			defer m.Close()

			// Get current version before migration
			version, dirty, err := m.Version()
			if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
				return errors.Wrap(err, "get current version")
			}

			// Check if database is dirty
			if dirty {
				_, _ = fmt.Fprintf(os.Stderr, "Error: Database is in dirty state at version %d\n", version)
				_, _ = fmt.Fprintf(os.Stderr, "Run 'talos migrate force <version>' to resolve this\n")
				return cmdx.FailSilently(cmd)
			}

			// Run migrations
			if err := m.Up(); err != nil {
				if errors.Is(err, migrate.ErrNoChange) {
					_, _ = fmt.Fprintf(os.Stderr, "No migrations to run (current version: %d)\n", version)
					return nil
				}
				return errors.Wrap(err, "migration failed")
			}

			// Get new version
			newVersion, _, err := m.Version()
			if err != nil {
				return errors.Wrap(err, "get new version")
			}

			_, _ = fmt.Fprintf(os.Stderr, "Successfully migrated from version %d to %d\n", version, newVersion)
			return nil
		},
	}

	cmd.Flags().StringVar(&database, "database", "", "database DSN (overrides DB_DSN)")

	return cmd
}

// newMigrateDownCmd creates the migrate down command with bound flag variables
func newMigrateDownCmd() *cobra.Command {
	var database string
	var steps int

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Rollback migrations",
		Long: `Roll back the last N migrations (default: 1).

This is useful for reverting recent migrations in development.
In production, use this carefully and ensure you have backups.`,
		Example: `  # Roll back last migration
  {{ .CommandPath }}

  # Roll back last 3 migrations
  {{ .CommandPath }} --steps 3`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Guard against non-positive steps. --steps is a signed int, and the
			// rollback below calls m.Steps(-steps); a negative value would
			// double-negate into a positive count and silently apply UP
			// migrations instead of rolling back.
			if steps <= 0 {
				return errors.Errorf("--steps must be a positive number, got %d", steps)
			}

			dbDSN, err := getDatabaseDSN(database)
			if err != nil {
				return err
			}

			m, err := newMigrate(dbDSN)
			if err != nil {
				return errors.Wrap(err, "initialize migrations")
			}
			defer m.Close()

			// Get current version
			version, dirty, err := m.Version()
			if err != nil {
				if errors.Is(err, migrate.ErrNilVersion) {
					_, _ = fmt.Fprintf(os.Stderr, "No migrations to roll back (database not initialized)\n")
					return nil
				}
				return errors.Wrap(err, "get current version")
			}

			// Check if database is dirty
			if dirty {
				_, _ = fmt.Fprintf(os.Stderr, "Error: Database is in dirty state at version %d\n", version)
				_, _ = fmt.Fprintf(os.Stderr, "Run 'talos migrate force <version>' to resolve this\n")
				return cmdx.FailSilently(cmd)
			}

			// Roll back steps
			if err := m.Steps(-steps); err != nil {
				if errors.Is(err, migrate.ErrNoChange) {
					_, _ = fmt.Fprintf(os.Stderr, "No migrations to roll back (current version: %d)\n", version)
					return nil
				}
				return errors.Wrap(err, "migration rollback failed")
			}

			// Get new version
			newVersion, _, err := m.Version()
			if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
				return errors.Wrap(err, "get new version")
			}

			if errors.Is(err, migrate.ErrNilVersion) {
				_, _ = fmt.Fprintf(os.Stderr, "Successfully rolled back all migrations (database empty)\n")
			} else {
				_, _ = fmt.Fprintf(os.Stderr, "Successfully rolled back from version %d to %d\n", version, newVersion)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&database, "database", "", "database DSN (overrides DB_DSN)")
	cmd.Flags().IntVar(&steps, "steps", 1, "number of migrations to roll back")

	return cmd
}

// newMigrateStatusCmd creates the migrate status command
func newMigrateStatusCmd() *cobra.Command {
	var database string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		Long: `Display the current database migration status.

Shows:
  - Current migration version
  - Whether the database is in a dirty state
  - Database connection info`,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			dbDSN, err := getDatabaseDSN(database)
			if err != nil {
				return err
			}

			m, err := newMigrate(dbDSN)
			if err != nil {
				return errors.Wrap(err, "initialize migrations")
			}
			defer m.Close()

			// Get current version
			version, dirty, err := m.Version()
			if err != nil {
				if errors.Is(err, migrate.ErrNilVersion) {
					_, _ = fmt.Fprintf(os.Stderr, "Database Status: Not initialized (no migrations applied)\n")
					return nil
				}
				return errors.Wrap(err, "get version")
			}

			// Display status
			status := "clean"
			if dirty {
				status = "DIRTY"
			}

			_, _ = fmt.Fprintf(os.Stderr, "Database Status: %s\n", status)
			_, _ = fmt.Fprintf(os.Stderr, "Current Version: %d\n", version)

			if dirty {
				_, _ = fmt.Fprintf(os.Stderr, "\nWARNING: Database is in dirty state!\n")
				_, _ = fmt.Fprintf(os.Stderr, "This usually means a migration failed mid-execution.\n")
				_, _ = fmt.Fprintf(os.Stderr, "Run 'talos migrate force %d' to mark it as resolved.\n", version)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&database, "database", "", "database DSN (overrides DB_DSN)")

	return cmd
}

// newMigrateForceCmd creates the migrate force command
func newMigrateForceCmd() *cobra.Command {
	var database string

	cmd := &cobra.Command{
		Use:   "force VERSION",
		Short: "Force set migration version (use with caution)",
		Long: `Force the migration version to a specific value.

This is useful when:
  - A migration failed and left the database in a dirty state
  - You need to manually fix the database state
  - You want to mark a migration as applied without running it

WARNING: This command should be used carefully as it can lead to
inconsistent database state if used incorrectly.`,
		Example: `  # Mark database as clean at version 5
  {{ .CommandPath }} 5`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			var targetVersion int
			if _, err := fmt.Sscanf(args[0], "%d", &targetVersion); err != nil {
				return errors.Errorf("invalid version: %s (must be an integer)", args[0])
			}

			dbDSN, err := getDatabaseDSN(database)
			if err != nil {
				return err
			}

			m, err := newMigrate(dbDSN)
			if err != nil {
				return errors.Wrap(err, "initialize migrations")
			}
			defer m.Close()

			// Force version
			if err := m.Force(targetVersion); err != nil {
				return errors.Wrap(err, "force version")
			}

			_, _ = fmt.Fprintf(os.Stderr, "Successfully forced migration version to %d\n", targetVersion)
			_, _ = fmt.Fprintf(os.Stderr, "Database is now marked as clean\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&database, "database", "", "database DSN (overrides DB_DSN)")

	return cmd
}

// newMigrate creates a new migrate instance for the given database DSN
func newMigrate(dbDSN string) (*migrate.Migrate, error) {
	// Get the appropriate migrations filesystem for this database type
	// getMigrationsFS is defined in migrate_imports_*.go based on build tags
	migrationsFS, driverName, err := getMigrationsFS(dbDSN)
	if err != nil {
		return nil, errors.Wrap(err, "get migrations filesystem")
	}

	// Create migration source from embedded FS
	sourceDriver, err := iofs.New(migrationsFS, driverName)
	if err != nil {
		return nil, errors.Wrap(err, "create migration source")
	}

	// Clean the DSN for the database driver
	// golang-migrate expects slightly different DSN formats
	cleanedDSN := dbDSN
	// Check original DSN to determine database type (driverName from GetMigrationsFS is just "." for directory)
	isSQLite := strings.HasPrefix(dbDSN, "sqlite://") || strings.HasPrefix(dbDSN, "sqlite3://") || strings.HasSuffix(dbDSN, ".db") || dbDSN == ":memory:"

	var databaseURL string
	if isSQLite {
		// For sqlite, remove the scheme prefix
		cleanedDSN = strings.TrimPrefix(cleanedDSN, "sqlite3://")
		cleanedDSN = strings.TrimPrefix(cleanedDSN, "sqlite://")

		// Normalize relative paths to start with ./
		// This prevents URL parsing issues where .db/file is interpreted as hostname
		if !strings.HasPrefix(cleanedDSN, "/") && !strings.HasPrefix(cleanedDSN, "./") && cleanedDSN != ":memory:" {
			cleanedDSN = "./" + cleanedDSN
		}

		// SQLite absolute path: sqlite3:///path (three slashes total)
		// SQLite relative path: sqlite3://./path (two slashes + ./ prefix)
		databaseURL = fmt.Sprintf("sqlite://%s", cleanedDSN)
	} else {
		// For other databases (postgres, mysql, cockroach), use the DSN as-is
		// golang-migrate accepts the standard URL format
		databaseURL = dbDSN
	}

	m, err := migrate.NewWithSourceInstance(
		"iofs",
		sourceDriver,
		databaseURL,
	)
	if err != nil {
		return nil, errors.Wrap(err, "create migrate instance")
	}

	return m, nil
}

// getDatabaseDSN gets the database DSN from the flag or environment variable.
func getDatabaseDSN(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}

	if dsn := cmp.Or(os.Getenv("DB_DSN"), os.Getenv("DSN")); dsn != "" {
		return dsn, nil
	}

	return "", errors.New("database DSN not provided (use --database flag or DB_DSN environment variable)")
}

// reviewed - @aeneasr - 2026-03-25
