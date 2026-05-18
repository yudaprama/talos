package sqlutil_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ory-corp/talos/internal/persistence/sqlutil"
)

func TestCalculateRevocationExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	thirtyDays := 30 * 24 * time.Hour

	tests := []struct {
		name      string
		expiresAt *time.Time
		want      time.Time
	}{
		{
			name:      "nil expiresAt returns now plus 30 days",
			expiresAt: nil,
			want:      now.Add(thirtyDays),
		},
		{
			name:      "expiresAt before 30d returns now plus 30 days",
			expiresAt: new(now.Add(10 * 24 * time.Hour)),
			want:      now.Add(thirtyDays),
		},
		{
			name:      "expiresAt after 30d returns original",
			expiresAt: new(now.Add(60 * 24 * time.Hour)),
			want:      now.Add(60 * 24 * time.Hour),
		},
		{
			name:      "expiresAt exactly 30d boundary returns now plus 30 days",
			expiresAt: new(now.Add(thirtyDays)),
			want:      now.Add(thirtyDays),
		},
		{
			name:      "expiresAt slightly past 30d returns original",
			expiresAt: new(now.Add(thirtyDays + time.Second)),
			want:      now.Add(thirtyDays + time.Second),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sqlutil.CalculateRevocationExpiry(now, tt.expiresAt)
			assert.Equal(t, tt.want, *got)
		})
	}
}
