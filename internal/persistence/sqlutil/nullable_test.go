package sqlutil

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNullStringPtr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    sql.NullString
		expected *string
	}{
		{
			name:     "valid string",
			input:    sql.NullString{String: "test", Valid: true},
			expected: new("test"),
		},
		{
			name:     "invalid/null",
			input:    sql.NullString{Valid: false},
			expected: nil,
		},
		{
			name:     "empty string but valid",
			input:    sql.NullString{String: "", Valid: true},
			expected: new(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NullStringPtr(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestNullTimePtr(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	tests := []struct {
		name     string
		input    sql.NullTime
		expected *time.Time
	}{
		{
			name:     "valid time",
			input:    sql.NullTime{Time: now, Valid: true},
			expected: &now,
		},
		{
			name:     "invalid/null",
			input:    sql.NullTime{Valid: false},
			expected: nil,
		},
		{
			name:     "zero time but valid",
			input:    sql.NullTime{Time: time.Time{}, Valid: true},
			expected: new(time.Time{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NullTimePtr(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestNullInt64Ptr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    sql.NullInt64
		expected *int64
	}{
		{
			name:     "valid positive int",
			input:    sql.NullInt64{Int64: 42, Valid: true},
			expected: new(int64(42)),
		},
		{
			name:     "valid zero",
			input:    sql.NullInt64{Int64: 0, Valid: true},
			expected: new(int64(0)),
		},
		{
			name:     "valid negative int",
			input:    sql.NullInt64{Int64: -100, Valid: true},
			expected: new(int64(-100)),
		},
		{
			name:     "invalid/null",
			input:    sql.NullInt64{Valid: false},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NullInt64Ptr(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestToNullString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected sql.NullString
	}{
		{
			name:     "non-empty string",
			input:    "test",
			expected: sql.NullString{String: "test", Valid: true},
		},
		{
			name:     "empty string becomes null",
			input:    "",
			expected: sql.NullString{Valid: false},
		},
		{
			name:     "whitespace is not empty",
			input:    "   ",
			expected: sql.NullString{String: "   ", Valid: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ToNullString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToNullTime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	tests := []struct {
		name     string
		input    *time.Time
		expected sql.NullTime
	}{
		{
			name:     "non-nil pointer",
			input:    &now,
			expected: sql.NullTime{Time: now, Valid: true},
		},
		{
			name:     "nil pointer becomes null",
			input:    nil,
			expected: sql.NullTime{Valid: false},
		},
		{
			name:     "zero time pointer",
			input:    new(time.Time{}),
			expected: sql.NullTime{Time: time.Time{}, Valid: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ToNullTime(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
