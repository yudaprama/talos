// Package service implements the business logic layer for API key management.
package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ory-corp/talos/internal/errdef"
	"github.com/ory-corp/talos/internal/service/validation"
)

// fieldMask wraps AIP-134 update_mask semantics.
// It encapsulates the useMask/pathSet construction that is repeated across
// every Update method, providing a single predicate instead of branching
// on useMask + pathSet at every field.
type fieldMask struct {
	useMask bool
	pathSet map[string]bool
}

// newFieldMask builds a fieldMask from protobuf update_mask paths.
// When paths is empty (no mask provided), legacy presence-based behavior applies.
func newFieldMask(paths []string) fieldMask {
	useMask := len(paths) > 0
	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}
	return fieldMask{useMask: useMask, pathSet: pathSet}
}

// newFieldMaskValidated builds a fieldMask from protobuf update_mask paths and
// rejects unknown paths with InvalidArgument. AIP-134 requires that unknown
// fields in update_mask cause an explicit error rather than being silently
// dropped — otherwise typos in paths produce no-op updates. The error message
// lists the allowed paths so clients can correct the request without external
// reference material.
func newFieldMaskValidated(paths, allowed []string) (fieldMask, error) {
	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = true
	}
	for _, p := range paths {
		if !allowedSet[p] {
			return fieldMask{}, errdef.BadRequest(fmt.Sprintf(
				"unknown update_mask path: %q (allowed: %s)",
				p, strings.Join(allowed, ", "),
			))
		}
	}
	return newFieldMask(paths), nil
}

// has reports whether the mask covers the named top-level field. A field is
// covered when the mask contains the field name itself or any sub-path under
// it (e.g. `rate_limit_policy` is covered by `rate_limit_policy.window`).
func (m fieldMask) has(field string) bool {
	if m.pathSet[field] {
		return true
	}
	prefix := field + "."
	for p := range m.pathSet {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// applyString returns reqVal if the field should be updated (per mask or
// legacy presence-based semantics), otherwise returns existing.
//
// AIP-134 semantics:
//   - mask provided, field in mask  → reqVal (even if empty — explicit clear)
//   - mask provided, field not in mask → existing (preserve)
//   - no mask, reqVal != ""         → reqVal (legacy presence-based)
//   - no mask, reqVal == ""         → existing (preserve)
func (m fieldMask) applyString(field, reqVal, existing string) string {
	if m.useMask {
		if m.has(field) {
			return reqVal
		}
		return existing
	}
	if reqVal != "" {
		return reqVal
	}
	return existing
}

// applySlice returns reqVal if the field should be updated, otherwise existing.
// For slices, the legacy "non-zero" check is len > 0.
func applySlice[T any](m fieldMask, field string, reqVal, existing []T) []T {
	if m.useMask {
		if m.has(field) {
			return reqVal
		}
		return existing
	}
	if len(reqVal) > 0 {
		return reqVal
	}
	return existing
}

// applyMetadata applies AIP-134 mask semantics to a structpb.Struct metadata
// field. It handles JSON marshaling, nil-to-empty-object normalization, and
// size validation.
func (m fieldMask) applyMetadata(reqMetadata *structpb.Struct, existing json.RawMessage) (json.RawMessage, error) {
	if m.useMask {
		if !m.has("metadata") {
			return existing, nil
		}
		if reqMetadata != nil {
			metadataBytes, err := reqMetadata.MarshalJSON()
			if err != nil {
				return nil, errdef.BadRequest("invalid metadata format").WithWrap(errors.WithStack(err))
			}
			if err := validation.ValidateMetadataSize(metadataBytes); err != nil {
				return nil, err
			}
			return metadataBytes, nil
		}
		result := json.RawMessage(`{}`)
		if err := validation.ValidateMetadataSize(result); err != nil {
			return nil, err
		}
		return result, nil
	}
	// Legacy presence-based: only update if request provides metadata.
	if reqMetadata != nil {
		metadataBytes, err := reqMetadata.MarshalJSON()
		if err != nil {
			return nil, errdef.BadRequest("invalid metadata format").WithWrap(errors.WithStack(err))
		}
		if err := validation.ValidateMetadataSize(metadataBytes); err != nil {
			return nil, err
		}
		return metadataBytes, nil
	}
	return existing, nil
}
