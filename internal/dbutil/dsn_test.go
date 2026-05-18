// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dbutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripPoolParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes pool_mode",
			input:    "postgres://user:pass@localhost:5432/db?pool_mode=advanced&sslmode=disable",
			expected: "postgres://user:pass@localhost:5432/db?sslmode=disable",
		},
		{
			name:     "removes max_conns",
			input:    "postgres://user:pass@localhost:5432/db?max_conns=100&sslmode=disable",
			expected: "postgres://user:pass@localhost:5432/db?sslmode=disable",
		},
		{
			name:     "removes multiple pool params",
			input:    "postgres://user:pass@localhost:5432/db?pool_mode=advanced&max_conns=100&max_idle_conns=10&max_conn_lifetime=3600&max_conn_idle_time=600&conn_max_idle_time=300&sslmode=disable",
			expected: "postgres://user:pass@localhost:5432/db?sslmode=disable",
		},
		{
			name:     "removes pgxpool params with pool_ prefix",
			input:    "postgres://user:pass@localhost:5432/db?pool_max_conns=50&pool_min_conns=5&pool_health_check_period=30&sslmode=disable",
			expected: "postgres://user:pass@localhost:5432/db?sslmode=disable",
		},
		{
			name:     "preserves non-pool params",
			input:    "postgres://user:pass@localhost:5432/db?sslmode=disable&connect_timeout=10&application_name=talos",
			expected: "postgres://user:pass@localhost:5432/db?application_name=talos&connect_timeout=10&sslmode=disable",
		},
		{
			name:     "handles malformed DSN with parse error",
			input:    "://invalid",
			expected: "://invalid",
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "handles DSN without query params",
			input:    "postgres://user:pass@localhost:5432/db",
			expected: "postgres://user:pass@localhost:5432/db",
		},
		{
			name:     "removes only pool params when mixed",
			input:    "postgres://user:pass@localhost:5432/db?pool_mode=standard&max_conns=20&sslmode=require&pool_max_conns=30",
			expected: "postgres://user:pass@localhost:5432/db?sslmode=require",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := StripPoolParams(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPrepareMySQLDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strips mysql:// prefix",
			input:    "mysql://user:pass@tcp(localhost:3306)/db",
			expected: "user:pass@tcp(localhost:3306)/db",
		},
		{
			name:     "preserves DSN without mysql:// prefix",
			input:    "user:pass@tcp(localhost:3306)/db",
			expected: "user:pass@tcp(localhost:3306)/db",
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "strips mysql:// with query params",
			input:    "mysql://user:pass@tcp(localhost:3306)/db?parseTime=true&charset=utf8mb4",
			expected: "user:pass@tcp(localhost:3306)/db?parseTime=true&charset=utf8mb4",
		},
		{
			name:     "does not strip other schemes",
			input:    "postgres://user:pass@localhost:5432/db",
			expected: "postgres://user:pass@localhost:5432/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := PrepareMySQLDSN(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStripPoolParamsIntegration(t *testing.T) {
	t.Parallel()

	// Real-world DSNs from production and test code
	t.Run("postgres production DSN", func(t *testing.T) {
		t.Parallel()

		input := "postgres://talos:secret@localhost:5432/talos?pool_mode=advanced&max_conns=50&max_idle_conns=10&sslmode=disable"
		result := StripPoolParams(input)

		// Should preserve actual postgres params
		assert.Contains(t, result, "sslmode=disable")
		// Should remove pool params
		assert.NotContains(t, result, "pool_mode")
		assert.NotContains(t, result, "max_conns")
		assert.NotContains(t, result, "max_idle_conns")
	})

	t.Run("cockroachdb production DSN", func(t *testing.T) {
		t.Parallel()

		input := "cockroach://root@localhost:26257/defaultdb?pool_mode=standard&max_conns=25&sslmode=disable"
		result := StripPoolParams(input)

		// Should preserve actual cockroach params
		assert.Contains(t, result, "sslmode=disable")
		// Should remove pool params
		assert.NotContains(t, result, "pool_mode")
		assert.NotContains(t, result, "max_conns")
	})

	t.Run("mysql production DSN with pool params", func(t *testing.T) {
		t.Parallel()

		// MySQL DSN with tcp() notation can't be parsed by url.Parse
		// This is expected behavior - these DSNs should be handled at the driver level
		input := "mysql://user:pass@tcp(localhost:3306)/talos?max_conns=100&parseTime=true"
		stripped := StripPoolParams(input)

		// url.Parse fails on tcp() notation, so original DSN is returned
		assert.Equal(t, input, stripped, "MySQL DSN with tcp() notation should be returned unchanged")

		// PrepareMySQLDSN should still work
		result := PrepareMySQLDSN(stripped)
		assert.NotContains(t, result, "mysql://")
		assert.Contains(t, result, "tcp(localhost:3306)")
	})

	t.Run("mysql standard URL format with pool params", func(t *testing.T) {
		t.Parallel()

		// Use standard URL format (without tcp notation) for pool param stripping
		input := "mysql://user:pass@localhost:3306/talos?max_conns=100&parseTime=true"
		stripped := StripPoolParams(input)

		// Should successfully strip pool params from standard URL format
		assert.NotContains(t, stripped, "max_conns")
		assert.Contains(t, stripped, "parseTime=true")

		// PrepareMySQLDSN should work on both
		result := PrepareMySQLDSN(stripped)
		assert.NotContains(t, result, "mysql://")
		assert.Contains(t, result, "user:pass@localhost:3306")
	})
}

func TestStripPoolParamsEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("preserves URL encoding", func(t *testing.T) {
		t.Parallel()

		input := "postgres://user:p%40ss@localhost:5432/db?pool_mode=advanced&application_name=test%20app"
		result := StripPoolParams(input)

		// Should preserve URL-encoded values
		assert.Contains(t, result, "p%40ss")
		assert.Contains(t, result, "application_name=test+app") // url.Parse may normalize encoding
		assert.NotContains(t, result, "pool_mode")
	})

	t.Run("handles DSN with fragment", func(t *testing.T) {
		t.Parallel()

		input := "postgres://user:pass@localhost:5432/db?pool_mode=standard&sslmode=disable#fragment"
		result := StripPoolParams(input)

		// Should preserve fragment
		assert.Contains(t, result, "#fragment")
		assert.NotContains(t, result, "pool_mode")
	})

	t.Run("handles DSN with only pool params", func(t *testing.T) {
		t.Parallel()

		input := "postgres://user:pass@localhost:5432/db?pool_mode=standard&max_conns=10"
		result := StripPoolParams(input)

		// Should return DSN without query string
		expected := "postgres://user:pass@localhost:5432/db"
		assert.Equal(t, expected, result)
	})
}

func TestStripPoolParamsReturnValue(t *testing.T) {
	t.Parallel()

	t.Run("returns different string when params removed", func(t *testing.T) {
		t.Parallel()

		input := "postgres://user:pass@localhost:5432/db?pool_mode=standard"
		result := StripPoolParams(input)

		assert.NotEqual(t, input, result)
		assert.NotContains(t, result, "pool_mode")
	})

	t.Run("returns same string when no params to remove", func(t *testing.T) {
		t.Parallel()

		input := "postgres://user:pass@localhost:5432/db?sslmode=disable"
		result := StripPoolParams(input)

		// Should be functionally equivalent (may differ in query param order)
		assert.Contains(t, result, "sslmode=disable")
		assert.NotContains(t, result, "pool_mode")
	})

	t.Run("returns original on parse error", func(t *testing.T) {
		t.Parallel()

		input := "://invalid"
		result := StripPoolParams(input)

		require.Equal(t, input, result)
	})
}

// reviewed - @aeneasr - 2026-03-25
