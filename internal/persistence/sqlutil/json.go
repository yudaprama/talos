// Package sqlutil provides common utilities for database drivers.
// It includes helpers for pointer conversions, nullable type handling,
// JSON field normalization, and transaction error handling.
package sqlutil

import (
	"encoding/json"

	"github.com/cockroachdb/errors"
)

// NormalizeJSONBytes returns v if non-empty, otherwise returns fallback.
// Use this to guarantee JSON columns never store NULL.
func NormalizeJSONBytes(v json.RawMessage, fallback json.RawMessage) json.RawMessage {
	if len(v) == 0 {
		return fallback
	}
	return v
}

// NormalizeMetadata returns v if non-empty, otherwise returns `{}`.
func NormalizeMetadata(v json.RawMessage) json.RawMessage {
	return NormalizeJSONBytes(v, json.RawMessage(`{}`))
}

// NormalizeScopesJSON returns v if non-empty, otherwise returns `[]`.
func NormalizeScopesJSON(v json.RawMessage) json.RawMessage {
	return NormalizeJSONBytes(v, json.RawMessage(`[]`))
}

// UnmarshalScopes parses a JSON-encoded scopes value into a string slice.
// Returns an empty non-nil slice when the input is empty or JSON null. Surfaces
// an error for malformed JSON or a non-array type so callers can decide how to
// handle corrupt persisted data instead of silently treating it as empty.
func UnmarshalScopes(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return nil, errors.Wrap(err, "unmarshal scopes")
	}
	if scopes == nil {
		return []string{}, nil
	}
	return scopes, nil
}

// reviewed - @aeneasr - 2026-03-26
