package sqlite_test

import (
	"testing"

	"github.com/gofrs/uuid"

	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence/persistencetest"
	"github.com/ory-corp/talos/internal/testutil"
)

// TestDriverSuite runs the shared driver test suite against the SQLite driver.
// This ensures that the SQLite driver correctly implements the persistence.Driver interface
// and behaves consistently with other drivers (Postgres, etc.).
// This test significantly increases coverage for internal/persistence/sqlite package.
func TestDriverSuite(t *testing.T) {
	t.Parallel()
	// Use a file-based temp database for production parity.
	// InitDriver handles migrations and default network creation.
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = driver.Close()
	})

	// Run the shared test suite
	// Use uuid.Nil network ID as SQLite driver is single-tenant (OSS)
	// The driver internally uses a hardcoded nil UUID
	persistencetest.RunDriverTestSuite(t, driver, uuid.Nil)
}

// reviewed - @aeneasr - 2026-03-26
