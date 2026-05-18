package sqlutil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeJSONBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    json.RawMessage
		fallback json.RawMessage
		expected string
	}{
		{
			name:     "nil input returns fallback",
			input:    nil,
			fallback: json.RawMessage(`{}`),
			expected: `{}`,
		},
		{
			name:     "empty input returns fallback",
			input:    json.RawMessage{},
			fallback: json.RawMessage(`[]`),
			expected: `[]`,
		},
		{
			name:     "non-empty input returned as-is",
			input:    json.RawMessage(`{"key":"value"}`),
			fallback: json.RawMessage(`{}`),
			expected: `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NormalizeJSONBytes(tt.input, tt.fallback)
			assert.JSONEq(t, tt.expected, string(result))
		})
	}
}

func TestNormalizeMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    json.RawMessage
		expected string
	}{
		{
			name:     "nil becomes empty object",
			input:    nil,
			expected: `{}`,
		},
		{
			name:     "empty slice becomes empty object",
			input:    json.RawMessage{},
			expected: `{}`,
		},
		{
			name:     "empty JSON object stays empty object",
			input:    json.RawMessage(`{}`),
			expected: `{}`,
		},
		{
			name:     "populated object stays unchanged",
			input:    json.RawMessage(`{"key":"value"}`),
			expected: `{"key":"value"}`,
		},
		{
			name:     "complex nested object stays unchanged",
			input:    json.RawMessage(`{"user":{"id":123,"name":"test"},"tags":["a","b"]}`),
			expected: `{"user":{"id":123,"name":"test"},"tags":["a","b"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NormalizeMetadata(tt.input)
			assert.JSONEq(t, tt.expected, string(result))
		})
	}
}

func TestNormalizeScopesJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    json.RawMessage
		expected string
	}{
		{
			name:     "nil becomes empty array",
			input:    nil,
			expected: `[]`,
		},
		{
			name:     "empty slice becomes empty array",
			input:    json.RawMessage{},
			expected: `[]`,
		},
		{
			name:     "empty JSON array stays empty array",
			input:    json.RawMessage(`[]`),
			expected: `[]`,
		},
		{
			name:     "populated array stays unchanged",
			input:    json.RawMessage(`["read","write"]`),
			expected: `["read","write"]`,
		},
		{
			name:     "single item array stays unchanged",
			input:    json.RawMessage(`["admin"]`),
			expected: `["admin"]`,
		},
		{
			name:     "array with special characters stays unchanged",
			input:    json.RawMessage(`["api:read","user:*"]`),
			expected: `["api:read","user:*"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := NormalizeScopesJSON(tt.input)
			assert.JSONEq(t, tt.expected, string(result))
		})
	}
}

func TestUnmarshalScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    json.RawMessage
		wantErr  bool
		expected []string
	}{
		{
			name:     "nil returns empty non-nil slice",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "empty bytes returns empty non-nil slice",
			input:    json.RawMessage{},
			expected: []string{},
		},
		{
			name:    "invalid JSON returns error",
			input:   json.RawMessage(`{not json`),
			wantErr: true,
		},
		{
			name:     "JSON null returns empty non-nil slice",
			input:    json.RawMessage(`null`),
			expected: []string{},
		},
		{
			name:     "empty JSON array returns empty non-nil slice",
			input:    json.RawMessage(`[]`),
			expected: []string{},
		},
		{
			name:     "single scope",
			input:    json.RawMessage(`["read"]`),
			expected: []string{"read"},
		},
		{
			name:     "multiple scopes",
			input:    json.RawMessage(`["read","write","admin"]`),
			expected: []string{"read", "write", "admin"},
		},
		{
			name:     "scopes with special characters",
			input:    json.RawMessage(`["api:read","user:*","scope.with.dots"]`),
			expected: []string{"api:read", "user:*", "scope.with.dots"},
		},
		{
			name:    "wrong JSON type (object) returns error",
			input:   json.RawMessage(`{"key":"value"}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := UnmarshalScopes(tt.input)
			if tt.wantErr {
				require.Error(t, err, "malformed input must surface an error")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
			assert.NotNil(t, result, "result must never be nil on success")
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
