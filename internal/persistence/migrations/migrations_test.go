package migrations

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMigrationsFS(t *testing.T) {
	t.Run("postgres_url", func(t *testing.T) {
		fsys, name, err := GetMigrationsFS("postgres://user:pass@localhost:5432/talos?sslmode=disable")
		require.NoError(t, err)
		assert.Equal(t, DriverPostgres, name)
		require.NotNil(t, fsys)

		entries, err := fs.ReadDir(fsys, "postgres")
		require.NoError(t, err)
		assert.NotEmpty(t, entries, "embedded postgres migrations must be present")
	})

	t.Run("cockroach_url", func(t *testing.T) {
		_, name, err := GetMigrationsFS("cockroach://user@localhost:26257/talos")
		require.NoError(t, err)
		assert.Equal(t, DriverPostgres, name)
	})

	t.Run("unsupported_sqlite", func(t *testing.T) {
		_, _, err := GetMigrationsFS("sqlite:///tmp/talos.db")
		require.Error(t, err)
	})

	t.Run("unsupported_mysql", func(t *testing.T) {
		_, _, err := GetMigrationsFS("mysql://user:pass@tcp(localhost:3306)/talos")
		require.Error(t, err)
	})
}

func TestGetMigrationsFSForDriver(t *testing.T) {
	for _, driver := range []string{DriverPostgres, DriverPostgreSQL, DriverCockroach, DriverCockroachDB} {
		t.Run(driver+"_supported", func(t *testing.T) {
			fsys, name, err := GetMigrationsFSForDriver(driver)
			require.NoError(t, err)
			assert.Equal(t, DriverPostgres, name)
			assert.NotNil(t, fsys)
		})
	}

	for _, driver := range []string{"sqlite", "sqlite3", "mysql", "oracle", ""} {
		t.Run(driver+"_unsupported", func(t *testing.T) {
			_, _, err := GetMigrationsFSForDriver(driver)
			require.Error(t, err)
		})
	}
}
