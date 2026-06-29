package persistence_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/persistence"
)

// TestNewDriver_SupportedSchemes verifies driver selection by DSN scheme. Talos
// is PostgreSQL-only; CockroachDB shares the PostgreSQL wire protocol. Other
// schemes are rejected. PostgreSQL/CockroachDB DSNs construct successfully
// without a live database because pgx connects lazily.
func TestNewDriver_SupportedSchemes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		dsn            string
		expectError    bool
		errorSubstring string
	}{
		{
			name:        "PostgreSQL driver is supported",
			dsn:         "postgres://user:pass@localhost:5432/test",
			expectError: false,
		},
		{
			name:        "CockroachDB driver is supported",
			dsn:         "cockroach://root@localhost:26257/test?sslmode=disable",
			expectError: false,
		},
		{
			name:           "SQLite is rejected",
			dsn:            "sqlite://" + t.TempDir() + "/test.db",
			expectError:    true,
			errorSubstring: "postgres",
		},
		{
			name:           "MySQL is rejected",
			dsn:            "mysql://root@localhost:3306/test",
			expectError:    true,
			errorSubstring: "postgres",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			driver, err := persistence.NewDriver(t.Context(), tt.dsn, nil)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
				assert.Nil(t, driver)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, driver)
			require.NoError(t, driver.Close())
		})
	}
}
