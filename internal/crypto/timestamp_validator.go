package crypto

import (
	"time"

	"github.com/cockroachdb/errors"
)

const (
	// DefaultClockSkew is the default maximum clock skew tolerance.
	// Allows for minor time sync differences between client and server.
	// Override per-tenant via the credentials.clock_skew config key.
	// Console/UI surface for tenant clock-skew configuration is a separate product task.
	DefaultClockSkew = 5 * time.Minute

	// MaxClockSkew is the upper bound for clock skew tolerance.
	// Values above this are clamped to prevent misconfiguration from
	// disabling freshness checks entirely. Maximum 10 minutes (600 seconds).
	MaxClockSkew = 600 * time.Second
)

// ValidateKeyTimestamp validates an API key timestamp against age constraints.
// Future timestamps are rejected if beyond clockSkew ahead of current time.
// Past timestamps are rejected if older than maxAge (zero maxAge skips age check).
// Use DefaultClockSkew when no per-tenant override is configured.
func ValidateKeyTimestamp(timestamp int64, maxAge, clockSkew time.Duration) error {
	if clockSkew > MaxClockSkew {
		clockSkew = MaxClockSkew
	}

	now := time.Now().UTC()
	keyTime := time.Unix(timestamp, 0).UTC()

	// Check for future timestamps (with clock skew tolerance)
	if keyTime.After(now.Add(clockSkew)) {
		return errors.Errorf("timestamp in future: key created at %s, current time %s",
			keyTime.Format(time.RFC3339),
			now.Format(time.RFC3339))
	}

	// If maxAge is zero or negative (not configured), skip age check
	if maxAge <= 0 {
		return nil
	}

	// Check for timestamps exceeding max age
	age := now.Sub(keyTime)
	if age > maxAge {
		return errors.Errorf("timestamp too old: key age %s exceeds max age %s",
			age.Round(time.Second),
			maxAge.Round(time.Second))
	}

	return nil
}

// reviewed - @aeneasr - 2026-03-26
