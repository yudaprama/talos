package validation

import (
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ory-corp/talos/internal/clientip"
	"github.com/ory-corp/talos/internal/errdef"
	"github.com/ory-corp/talos/internal/persistence/sqlutil"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// NormalizedFields holds normalized request fields ready for persistence.
type NormalizedFields struct {
	Scopes          json.RawMessage
	Metadata        json.RawMessage
	RateLimitQuota  *int64
	RateLimitWindow *int64
	AllowedCIDRs    json.RawMessage // JSON array of CIDR strings
}

// NormalizeCreateFields normalizes fields from IssueAPIKeyRequest or ImportAPIKeyRequest.
// Returns normalized JSON-encoded fields ready for persistence.
func NormalizeCreateFields(
	scopes []string,
	metadata *structpb.Struct,
	rateLimitPolicy *talosv2alpha1.RateLimitPolicy,
	ipRestriction *talosv2alpha1.IPRestriction,
) (NormalizedFields, error) {
	// Marshal scopes - ensure we get [] not null for nil slices
	var scopesJSON json.RawMessage
	if len(scopes) > 0 {
		bytes, err := json.Marshal(scopes)
		if err != nil {
			return NormalizedFields{}, errdef.BadRequest("invalid scopes").WithWrap(errors.WithStack(err))
		}
		scopesJSON = bytes
	}
	scopesJSON = sqlutil.NormalizeScopesJSON(scopesJSON)

	// Normalize metadata
	var metadataJSON json.RawMessage
	if metadata != nil {
		bytes, err := metadata.MarshalJSON()
		if err != nil {
			return NormalizedFields{}, errdef.BadRequest("invalid metadata").WithWrap(errors.WithStack(err))
		}
		metadataJSON = bytes
	}
	metadataJSON = sqlutil.NormalizeMetadata(metadataJSON)

	// Extract rate limit
	var quota, window *int64
	if rateLimitPolicy != nil {
		q := rateLimitPolicy.Quota
		quota = &q
		if rateLimitPolicy.Window != nil {
			if rateLimitPolicy.Window.AsDuration() < time.Second {
				return NormalizedFields{}, errdef.BadRequest("rate limit window must be at least 1 second")
			}
			w := int64(rateLimitPolicy.Window.AsDuration().Seconds())
			window = &w
		}
	}

	// Normalize IP restriction
	allowedCIDRs, err := NormalizeIPRestriction(ipRestriction)
	if err != nil {
		return NormalizedFields{}, err
	}

	return NormalizedFields{
		Scopes:          scopesJSON,
		Metadata:        metadataJSON,
		RateLimitQuota:  quota,
		RateLimitWindow: window,
		AllowedCIDRs:    allowedCIDRs,
	}, nil
}

// NormalizeIPRestriction validates and normalizes an IPRestriction proto message.
// Returns the normalized JSON CIDR array. Returns "[]" when no restriction is set.
func NormalizeIPRestriction(r *talosv2alpha1.IPRestriction) (json.RawMessage, error) {
	if r == nil {
		return json.RawMessage("[]"), nil
	}
	if err := clientip.ValidateCIDRs(r.GetAllowedCidrs()); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}
	cidrsJSON, err := json.Marshal(sqlutil.NonNilSlice(r.GetAllowedCidrs()))
	if err != nil {
		return nil, errdef.BadRequest("invalid allowed CIDRs").WithWrap(errors.WithStack(err))
	}
	return cidrsJSON, nil
}

// ConvertTTL converts protobuf Duration to time.Duration with default fallback.
// A nil duration uses defaultTTL. An explicitly-zero duration (0s) means no
// expiry and returns 0. A negative duration falls back to defaultTTL.
func ConvertTTL(pbDuration *durationpb.Duration, defaultTTL time.Duration) time.Duration {
	if pbDuration != nil {
		ttl := pbDuration.AsDuration()
		if ttl > 0 {
			return ttl
		}
		if ttl == 0 {
			return 0
		}
	}
	return defaultTTL
}

// reviewed - @aeneasr - 2026-03-26
