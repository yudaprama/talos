// Package validation provides request validation and normalization for the service layer.
// It consolidates all business rules, field normalization, and security constraints
// to ensure consistent validation across all API endpoints.
package validation

import (
	"encoding/json"

	"github.com/cockroachdb/errors"

	"github.com/ory-corp/talos/internal/errdef"
)

const (
	// MaxMetadataSize is the maximum allowed size for metadata JSON (64KB)
	MaxMetadataSize = 65536
)

// ValidateMetadataSize ensures metadata doesn't exceed 64KB.
func ValidateMetadataSize(metadata json.RawMessage) error {
	if len(metadata) > MaxMetadataSize {
		return errors.WithStack(errdef.ErrBadRequest().WithReasonf(
			"metadata size (%d bytes) exceeds maximum of %d bytes",
			len(metadata), MaxMetadataSize,
		))
	}
	return nil
}

// reviewed - @aeneasr - 2026-03-26
