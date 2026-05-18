package crypto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateKeyTimestamp(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	t.Run("accepts keys within max age", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			timestamp int64
			maxAge    time.Duration
		}{
			{
				name:      "current timestamp",
				timestamp: now.Unix(),
				maxAge:    24 * time.Hour,
			},
			{
				name:      "1 hour old",
				timestamp: now.Add(-1 * time.Hour).Unix(),
				maxAge:    24 * time.Hour,
			},
			{
				name:      "23 hours old (just within limit)",
				timestamp: now.Add(-23 * time.Hour).Unix(),
				maxAge:    24 * time.Hour,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				err := ValidateKeyTimestamp(tt.timestamp, tt.maxAge, DefaultClockSkew)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("rejects keys exceeding max age", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			timestamp int64
			maxAge    time.Duration
		}{
			{
				name:      "25 hours old",
				timestamp: now.Add(-25 * time.Hour).Unix(),
				maxAge:    24 * time.Hour,
			},
			{
				name:      "7 days old",
				timestamp: now.Add(-7 * 24 * time.Hour).Unix(),
				maxAge:    24 * time.Hour,
			},
			{
				name:      "1 year old",
				timestamp: now.Add(-365 * 24 * time.Hour).Unix(),
				maxAge:    30 * 24 * time.Hour,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				err := ValidateKeyTimestamp(tt.timestamp, tt.maxAge, DefaultClockSkew)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "timestamp too old")
			})
		}
	})

	t.Run("rejects future timestamps", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			timestamp int64
		}{
			{
				name:      "1 hour in future",
				timestamp: now.Add(1 * time.Hour).Unix(),
			},
			{
				name:      "1 day in future",
				timestamp: now.Add(24 * time.Hour).Unix(),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				err := ValidateKeyTimestamp(tt.timestamp, 24*time.Hour, DefaultClockSkew)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "timestamp in future")
			})
		}
	})

	t.Run("allows small clock skew (5 minutes)", func(t *testing.T) {
		t.Parallel()

		// 4 minutes in future (within 5 min skew tolerance)
		timestamp := now.Add(4 * time.Minute).Unix()

		err := ValidateKeyTimestamp(timestamp, 24*time.Hour, DefaultClockSkew)
		assert.NoError(t, err, "should accept timestamps within 5 min clock skew")
	})

	t.Run("rejects excessive future timestamps beyond skew", func(t *testing.T) {
		t.Parallel()

		// 10 minutes in future (exceeds 5 min skew tolerance)
		timestamp := now.Add(10 * time.Minute).Unix()

		err := ValidateKeyTimestamp(timestamp, 24*time.Hour, DefaultClockSkew)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timestamp in future")
	})

	t.Run("clamps clock skew exceeding MaxClockSkew", func(t *testing.T) {
		t.Parallel()

		// 2 hours in the future should be rejected even with a 10-hour clock skew,
		// because MaxClockSkew clamps the effective tolerance to 600 seconds (10 minutes).
		timestamp := now.Add(20 * time.Minute).Unix()

		err := ValidateKeyTimestamp(timestamp, 0, 10*time.Hour)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timestamp in future")

		// 5 minutes in the future should be accepted (within clamped 10-minute tolerance).
		timestamp = now.Add(5 * time.Minute).Unix()

		err = ValidateKeyTimestamp(timestamp, 0, 10*time.Hour)
		assert.NoError(t, err, "should accept timestamps within clamped MaxClockSkew")
	})
}

// reviewed - @aeneasr - 2026-03-26
