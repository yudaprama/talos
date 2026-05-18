package sqlutil

import (
	"database/sql"
	"time"
)

// NullStringPtr converts sql.NullString to *string
// Returns nil if not valid, pointer to string otherwise
func NullStringPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

// NullTimePtr converts sql.NullTime to *time.Time in UTC.
// Returns nil if not valid, pointer to UTC time otherwise.
func NullTimePtr(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return new(nt.Time.UTC())
}

// NullInt64Ptr converts sql.NullInt64 to *int64
// Returns nil if not valid, pointer to int64 otherwise
func NullInt64Ptr(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int64
}

// ToNullString converts string to sql.NullString
// Empty string becomes invalid/null
func ToNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ToNullTime converts *time.Time to sql.NullTime
// nil becomes invalid/null
func ToNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// ToNullInt64 converts *int64 to sql.NullInt64
// nil becomes invalid/null
func ToNullInt64(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}

// reviewed - @aeneasr - 2026-03-26
