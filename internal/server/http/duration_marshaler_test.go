package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertDurationStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "24 hours",
			input:    `{"ttl": "24h"}`,
			expected: `{"ttl": "86400s"}`,
		},
		{
			name:     "1 hour",
			input:    `{"ttl": "1h"}`,
			expected: `{"ttl": "3600s"}`,
		},
		{
			name:     "30 minutes",
			input:    `{"ttl": "30m"}`,
			expected: `{"ttl": "1800s"}`,
		},
		{
			name:     "1 hour 30 minutes",
			input:    `{"ttl": "1h30m"}`,
			expected: `{"ttl": "5400s"}`,
		},
		{
			name:     "complex duration",
			input:    `{"ttl": "24h30m45s"}`,
			expected: `{"ttl": "88245s"}`,
		},
		{
			// "86400s" now matches the updated regex and is parsed then re-emitted as "86400s" — same value.
			name:     "protobuf seconds format re-emitted unchanged",
			input:    `{"ttl": "86400s"}`,
			expected: `{"ttl": "86400s"}`,
		},
		{
			name:     "fractional seconds unchanged",
			input:    `{"ttl": "3.5s"}`,
			expected: `{"ttl": "3.5s"}`,
		},
		{
			name:     "multiple fields",
			input:    `{"name": "test", "ttl": "24h", "actor_id": "user-1"}`,
			expected: `{"name": "test", "ttl": "86400s", "actor_id": "user-1"}`,
		},
		{
			name:     "no duration field",
			input:    `{"name": "test", "actor_id": "user-1"}`,
			expected: `{"name": "test", "actor_id": "user-1"}`,
		},
		{
			name:     "7 days",
			input:    `{"ttl": "168h"}`,
			expected: `{"ttl": "604800s"}`,
		},
		{
			name:     "30 days",
			input:    `{"ttl": "720h"}`,
			expected: `{"ttl": "2592000s"}`,
		},
		// Extended single units
		{name: "1 day", input: `{"ttl": "1d"}`, expected: `{"ttl": "86400s"}`},
		{name: "7 days via d unit", input: `{"ttl": "7d"}`, expected: `{"ttl": "604800s"}`},
		{name: "1 week", input: `{"ttl": "1w"}`, expected: `{"ttl": "604800s"}`},
		{name: "1 month", input: `{"ttl": "1mo"}`, expected: `{"ttl": "2592000s"}`},
		{name: "1 year", input: `{"ttl": "1y"}`, expected: `{"ttl": "31536000s"}`},
		// Mixed extended + standard
		{name: "1 day 12 hours", input: `{"ttl": "1d12h"}`, expected: `{"ttl": "129600s"}`},
		{name: "1 year 6 months", input: `{"ttl": "1y6mo"}`, expected: `{"ttl": "47088000s"}`},
		{name: "2 weeks 3 days", input: `{"ttl": "2w3d"}`, expected: `{"ttl": "1468800s"}`},
		// Standard units now handled by duration.Parse (same output as before)
		{name: "60 seconds", input: `{"ttl": "60s"}`, expected: `{"ttl": "60s"}`},
		// Sub-second: 500ms = 0.5s — must not truncate to "0s"
		{name: "500 milliseconds", input: `{"ttl": "500ms"}`, expected: `{"ttl": "0.5s"}`},
		// Non-duration string field is unchanged
		{name: "string value unchanged", input: `{"name": "mykey"}`, expected: `{"name": "mykey"}`},
		// Non-ttl fields with duration-like values must not be converted
		{name: "non-ttl duration-like value not converted", input: `{"unit": "1m"}`, expected: `{"unit": "1m"}`},
		{name: "only ttl field converted in mixed object", input: `{"unit": "1m", "ttl": "1d"}`, expected: `{"unit": "1m", "ttl": "86400s"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := convertDurationStrings([]byte(tt.input))
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
