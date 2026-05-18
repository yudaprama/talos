package sqlutil

import (
	"testing"
	"time"
)

func TestUtcNow(t *testing.T) {
	t.Parallel()

	t.Run("returns UTC time", func(t *testing.T) {
		now := UTCNow()

		// Verify it's in UTC location
		if now.Location() != time.UTC {
			t.Errorf("UTCNow() location = %v, want %v", now.Location(), time.UTC)
		}

		// Verify it's reasonably close to current time
		systemNow := time.Now().UTC()
		diff := systemNow.Sub(now)
		if diff < 0 {
			diff = -diff
		}

		// Should be within 1 second (generous for CI environments)
		if diff > time.Second {
			t.Errorf("UTCNow() time difference = %v, want < 1s", diff)
		}
	})
}

// reviewed - @aeneasr - 2026-03-26
