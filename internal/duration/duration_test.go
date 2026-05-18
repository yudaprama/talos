package duration_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/duration"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		// --- Extended single units ---
		{name: "1 day", input: "1d", want: 24 * time.Hour},
		{name: "7 days", input: "7d", want: 7 * 24 * time.Hour},
		{name: "1 week", input: "1w", want: 7 * 24 * time.Hour},
		{name: "2 weeks", input: "2w", want: 14 * 24 * time.Hour},
		{name: "1 month", input: "1mo", want: 30 * 24 * time.Hour},
		{name: "6 months", input: "6mo", want: 6 * 30 * 24 * time.Hour},
		{name: "12 months", input: "12mo", want: 12 * 30 * 24 * time.Hour},
		{name: "1 year", input: "1y", want: 365 * 24 * time.Hour},
		{name: "2 years", input: "2y", want: 2 * 365 * 24 * time.Hour},

		// --- Standard single units (must not regress) ---
		{name: "1 hour", input: "1h", want: time.Hour},
		{name: "30 minutes", input: "30m", want: 30 * time.Minute},
		{name: "60 seconds", input: "60s", want: 60 * time.Second},
		{name: "500 milliseconds", input: "500ms", want: 500 * time.Millisecond},
		{name: "100 microseconds", input: "100us", want: 100 * time.Microsecond},
		{name: "1000 nanoseconds", input: "1000ns", want: 1000 * time.Nanosecond},

		// --- Standard Go compound (must not regress) ---
		{name: "1 hour 30 minutes", input: "1h30m", want: 90 * time.Minute},
		{name: "1 hour 2 seconds", input: "1h2s", want: time.Hour + 2*time.Second},
		{name: "24 hours 30 minutes 45 seconds", input: "24h30m45s", want: 24*time.Hour + 30*time.Minute + 45*time.Second},

		// --- Mixed extended + standard ---
		{name: "1 day 12 hours", input: "1d12h", want: 36 * time.Hour},
		{name: "1 day 12 hours 30 minutes", input: "1d12h30m", want: 36*time.Hour + 30*time.Minute},
		{name: "1 year 6 months", input: "1y6mo", want: 365*24*time.Hour + 6*30*24*time.Hour},
		{name: "2 years 3 months 4 days", input: "2y3mo4d", want: 2*365*24*time.Hour + 3*30*24*time.Hour + 4*24*time.Hour},
		{name: "2 weeks 3 days", input: "2w3d", want: 2*7*24*time.Hour + 3*24*time.Hour},
		{
			name: "1 year 2 months 3 days 4 hours 5 minutes 6 seconds", input: "1y2mo3d4h5m6s",
			want: 365*24*time.Hour + 2*30*24*time.Hour + 3*24*time.Hour + 4*time.Hour + 5*time.Minute + 6*time.Second,
		},

		// --- Go serialization round-trip ---
		// time.Duration.String() produces "8760h0m0s" for 1 year — must parse correctly.
		{name: "go string for 1 year", input: "8760h0m0s", want: 365 * 24 * time.Hour},
		{name: "go string for 30 days", input: "720h0m0s", want: 30 * 24 * time.Hour},

		// --- Error cases ---
		{name: "empty string", input: "", wantErr: true},
		// "0" is valid in time.ParseDuration but Parse requires a unit — document this deliberate difference.
		{name: "bare zero no unit", input: "0", wantErr: true},
		{name: "no unit", input: "42", wantErr: true},
		{name: "unknown unit", input: "1x", wantErr: true},
		// Capital M is ambiguous between minutes and months — reject it; use "1m" or "1mo".
		{name: "capital M ambiguous", input: "1M", wantErr: true},
		{name: "trailing junk", input: "1h!", wantErr: true},
		// Integer overflow: very large coefficient must return an error, not silently wrap to 0.
		{name: "overflow coefficient", input: "99999999999999999999y", wantErr: true},
		// Multiplication overflow: coefficient fits int64 but the result exceeds max Duration (~292 years).
		{name: "overflow multiplication", input: "300y", wantErr: true},
		{name: "overflow compound sum", input: "290y3y", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := duration.Parse(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
