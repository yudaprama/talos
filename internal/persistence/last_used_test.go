package persistence

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldUpdateLastUsed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 4, 15, 4, 5, 0, time.UTC)

	tests := []struct {
		name       string
		lastUsedAt *time.Time
		want       bool
	}{
		{
			name:       "nil lastUsedAt returns true",
			lastUsedAt: nil,
			want:       true,
		},
		{
			name:       "yesterday returns true",
			lastUsedAt: new(now.Add(-24 * time.Hour)),
			want:       true,
		},
		{
			name:       "one week ago returns true",
			lastUsedAt: new(now.Add(-7 * 24 * time.Hour)),
			want:       true,
		},
		{
			name:       "today at midnight returns false",
			lastUsedAt: new(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)),
			want:       false,
		},
		{
			name:       "today at noon returns false",
			lastUsedAt: new(time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)),
			want:       false,
		},
		{
			name:       "today one second ago returns false",
			lastUsedAt: new(now.Add(-1 * time.Second)),
			want:       false,
		},
		{
			name:       "today in different timezone (UTC+5) returns false",
			lastUsedAt: new(time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.FixedZone("UTC+5", 5*60*60))),
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ShouldUpdateLastUsed(tt.lastUsedAt, now)
			assert.Equal(t, tt.want, got)
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
