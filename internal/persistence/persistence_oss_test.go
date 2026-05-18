package persistence_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence"
)

func TestOSSEdition_OnlySQLiteAvailable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		dsn            string
		expectError    bool
		errorSubstring string
	}{
		{
			name:        "SQLite driver works in OSS",
			dsn:         "sqlite://" + t.TempDir() + "/test.db",
			expectError: false,
		},
		{
			name:           "PostgreSQL returns Enterprise edition error",
			dsn:            "postgres://localhost/test",
			expectError:    true,
			errorSubstring: "Enterprise edition",
		},
		{
			name:           "MySQL returns Enterprise edition error",
			dsn:            "mysql://root@localhost:3306/test",
			expectError:    true,
			errorSubstring: "Enterprise edition",
		},
		{
			name:           "CockroachDB returns Enterprise edition error",
			dsn:            "cockroach://root@localhost:26257/test?sslmode=disable",
			expectError:    true,
			errorSubstring: "Enterprise edition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// OSS build: pass nil for proprietary factories
			driver, err := persistence.NewDriver(t.Context(), tt.dsn, nil)

			if tt.expectError {
				require.Error(t, err)
				// Check that error mentions OSS or Enterprise limitation
				assert.Contains(t, err.Error(), "OSS",
					"OSS build should mention OSS edition limitation for non-SQLite drivers")
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
				assert.Nil(t, driver)
			} else {
				require.NoError(t, err)
				require.NotNil(t, driver)
				// Clean up
				require.NoError(t, driver.Close())
			}
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
