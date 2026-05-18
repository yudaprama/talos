package health

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestChecker_DatabaseReady(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		closeDB       bool
		expectError   bool
		errorContains string
	}{
		{
			name:        "success",
			expectError: false,
		},
		{
			name:          "ping fails",
			closeDB:       true,
			expectError:   true,
			errorContains: "database ping failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db := openTestDB(t)

			writer := herodot.NewJSONWriter(nil)
			checker := NewChecker(writer)
			checker.AddDatabaseCheck(db)

			if tt.closeDB {
				require.NoError(t, db.Close())
			}

			req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			checkers := checker.ReadyCheckers()
			err := checkers["database"](req)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestChecker_AddDatabaseCheck_NilPanics(t *testing.T) {
	t.Parallel()

	writer := herodot.NewJSONWriter(nil)
	checker := NewChecker(writer)
	checker.AddDatabaseCheck(nil)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	checkers := checker.ReadyCheckers()
	assert.Panics(t, func() {
		_ = checkers["database"](req)
	})
}

func TestChecker_CustomChecks(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)

	writer := herodot.NewJSONWriter(nil)
	checker := NewChecker(writer)
	checker.AddDatabaseCheck(db)

	// Add multiple custom checks
	var redisChecked, cacheChecked bool
	checker.AddReadyCheck("redis", func(_ *http.Request) error {
		redisChecked = true
		return nil
	})
	checker.AddReadyCheck("cache", func(_ *http.Request) error {
		cacheChecked = true
		return nil
	})

	// Verify checks are registered
	checkers := checker.ReadyCheckers()
	assert.Len(t, checkers, 3) // database + redis + cache
	assert.Contains(t, checkers, "database")
	assert.Contains(t, checkers, "redis")
	assert.Contains(t, checkers, "cache")

	// Execute custom checks
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	require.NoError(t, checkers["redis"](req))
	require.NoError(t, checkers["cache"](req))

	assert.True(t, redisChecked, "redis check should have been called")
	assert.True(t, cacheChecked, "cache check should have been called")
}

func TestChecker_Handler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		closeDB         bool
		addFailingCheck bool
		expectStatus    int
	}{
		{
			name:         "all checks pass",
			expectStatus: http.StatusOK,
		},
		{
			name:         "database check fails",
			closeDB:      true,
			expectStatus: http.StatusServiceUnavailable,
		},
		{
			name:            "custom check fails",
			addFailingCheck: true,
			expectStatus:    http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db := openTestDB(t)

			writer := herodot.NewJSONWriter(nil)
			checker := NewChecker(writer)
			checker.AddDatabaseCheck(db)

			if tt.addFailingCheck {
				checker.AddReadyCheck("failing", func(_ *http.Request) error {
					return assert.AnError
				})
			}

			if tt.closeDB {
				require.NoError(t, db.Close())
			}

			handler := checker.Handler()

			req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			rec := httptest.NewRecorder()

			handler.Ready(true).ServeHTTP(rec, req)

			assert.Equal(t, tt.expectStatus, rec.Code)
		})
	}
}

// reviewed - @aeneasr - 2026-03-27
