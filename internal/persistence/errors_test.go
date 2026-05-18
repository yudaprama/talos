package persistence

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsConnectionError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"connection refused", errors.New("connection refused"), true},
		{"connection reset", errors.New("connection reset by peer"), true},
		{"no such host", errors.New("no such host"), true},
		{"network unreachable", errors.New("network is unreachable"), true},
		{"connection closed", errors.New("connection closed"), true},
		{"dial tcp error", errors.New("dial tcp: timeout"), true},
		{"other error", errors.New("some other error"), false},
		{"empty error", errors.New(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsConnectionError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"UNIQUE constraint", errors.New("UNIQUE constraint failed: api_keys.id"), true},
		{"unique constraint lowercase", errors.New("unique constraint failed"), true},
		{"duplicate key", errors.New("duplicate key value violates unique constraint"), true},
		{"MySQL duplicate entry", errors.New("Duplicate entry 'key' for key 'PRIMARY'"), true},
		{"other error", errors.New("some other error"), false},
		{"empty error", errors.New(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsUniqueViolation(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
