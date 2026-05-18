// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sqlutil

import "time"

// CalculateRevocationExpiry computes the expiration timestamp to set when revoking a key.
// Returns max(now + 30 days, originalExpiresAt if set).
func CalculateRevocationExpiry(now time.Time, originalExpiresAt *time.Time) *time.Time {
	thirtyDaysFromNow := now.Add(30 * 24 * time.Hour)

	if originalExpiresAt == nil {
		return &thirtyDaysFromNow
	}

	if originalExpiresAt.After(thirtyDaysFromNow) {
		return originalExpiresAt
	}
	return &thirtyDaysFromNow
}

// reviewed - @aeneasr - 2026-03-26
