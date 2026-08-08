package crypto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFilterExpiredStrings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	t.Run("bare strings are always kept", func(t *testing.T) {
		t.Parallel()
		input := []string{"secret1", "secret2", "secret3"}
		result := filterExpiredStrings(input, now)
		assert.Equal(t, []string{"secret1", "secret2", "secret3"}, result)
	})

	t.Run("expired entries are dropped", func(t *testing.T) {
		t.Parallel()
		input := []string{
			"secret1|2026-01-01T00:00:00Z", // expired
			"secret2",                       // bare, kept
			"secret3|2027-01-01T00:00:00Z", // future, kept
		}
		result := filterExpiredStrings(input, now)
		assert.Equal(t, []string{"secret2", "secret3"}, result)
	})

	t.Run("expiry suffix is stripped from active entries", func(t *testing.T) {
		t.Parallel()
		input := []string{"secret|2027-01-01T00:00:00Z"}
		result := filterExpiredStrings(input, now)
		assert.Equal(t, []string{"secret"}, result)
	})

	t.Run("entries with malformed timestamp are kept", func(t *testing.T) {
		t.Parallel()
		input := []string{"secret|not-a-timestamp"}
		result := filterExpiredStrings(input, now)
		assert.Equal(t, []string{"secret|not-a-timestamp"}, result)
	})

	t.Run("empty input returns empty", func(t *testing.T) {
		t.Parallel()
		result := filterExpiredStrings(nil, now)
		assert.Empty(t, result)
	})

	t.Run("pipe in secret value is handled correctly", func(t *testing.T) {
		t.Parallel()
		// LastIndex finds the rightmost pipe, so "secret|extra|2027-..." is
		// treated as secret="secret|extra" with expiry "2027-..."
		input := []string{"secret|extra|2027-01-01T00:00:00Z"}
		result := filterExpiredStrings(input, now)
		assert.Equal(t, []string{"secret|extra"}, result)
	})

	t.Run("all expired returns only current", func(t *testing.T) {
		t.Parallel()
		input := []string{
			"old1|2025-01-01T00:00:00Z",
			"old2|2025-06-01T00:00:00Z",
		}
		result := filterExpiredStrings(input, now)
		assert.Empty(t, result)
	})
}
