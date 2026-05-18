package sqlutil

import "time"

// UTCNow returns the current time in UTC for database operations.
// This ensures all database timestamps are explicit and consistent,
// following the AGENTS.md principle: "ALWAYS use explicit UTC timestamps -
// Never rely on database DEFAULT for timestamps".
func UTCNow() time.Time {
	return time.Now().UTC()
}

// reviewed - @aeneasr - 2026-03-26
