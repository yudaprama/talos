package persistence

import "time"

// ShouldUpdateLastUsed checks if the last_used_at timestamp needs to be updated.
// Returns true if lastUsedAt is nil or from a previous day (in UTC).
// This optimization avoids unnecessary database writes since we only track
// day-level granularity for last_used_at.
func ShouldUpdateLastUsed(lastUsedAt *time.Time, now time.Time) bool {
	if lastUsedAt == nil {
		return true
	}

	nowUTC := now.UTC()
	lastUsedUTC := lastUsedAt.UTC()
	return lastUsedUTC.Year() != nowUTC.Year() ||
		lastUsedUTC.Month() != nowUTC.Month() ||
		lastUsedUTC.Day() != nowUTC.Day()
}

// reviewed - @aeneasr - 2026-03-26
