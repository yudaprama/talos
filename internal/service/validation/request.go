package validation

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ory/talos/internal/errdef"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// CreateKeyRequest represents normalized/validated inputs for creating a key.
type CreateKeyRequest struct {
	Name      string
	ActorID   string
	Fields    NormalizedFields
	TTL       time.Duration
	ExpiresAt *time.Time
}

// ValidateAndNormalizeIssueRequest validates and normalizes an IssueApiKeyRequest.
// Returns a CreateKeyRequest ready for service layer processing.
func ValidateAndNormalizeIssueRequest(
	req *talosv2alpha1.IssueApiKeyRequest,
	defaultTTL time.Duration,
	maxTTL time.Duration,
) (CreateKeyRequest, error) {
	// Normalize fields
	fields, err := NormalizeCreateFields(
		req.GetScopes(),
		req.GetMetadata(),
		req.GetRateLimitPolicy(),
		req.GetIpRestriction(),
	)
	if err != nil {
		return CreateKeyRequest{}, err
	}

	// IssueApiKey does not require name or actor_id because the service generates
	// the key secret automatically — these are optional labels. ImportApiKey
	// requires both because the caller registers an existing external credential
	// and must explicitly declare its identity.

	// Validate metadata size
	if err := ValidateMetadataSize(fields.Metadata); err != nil {
		return CreateKeyRequest{}, err
	}

	// Convert TTL, falling back to the project default when caller omits it.
	ttl, err := resolveTTL(req.GetTtl(), defaultTTL, maxTTL)
	if err != nil {
		return CreateKeyRequest{}, err
	}

	// Calculate expiration
	exp := time.Now().UTC().Add(ttl)

	return CreateKeyRequest{
		Name:      req.Name,
		ActorID:   req.ActorId,
		Fields:    fields,
		TTL:       ttl,
		ExpiresAt: &exp,
	}, nil
}

// ImportKeyRequest represents normalized/validated inputs for importing a key.
type ImportKeyRequest struct {
	RawKey    string
	Name      string
	ActorID   string
	Fields    NormalizedFields
	ExpiresAt *time.Time
}

// ValidateAndNormalizeImportRequest validates and normalizes an ImportApiKeyRequest.
// defaultTTL is applied when the caller provides no TTL; maxTTL caps the final TTL
// (0 means no cap). These follow the same semantics as ValidateAndNormalizeIssueRequest.
func ValidateAndNormalizeImportRequest(
	req *talosv2alpha1.ImportApiKeyRequest,
	defaultTTL time.Duration,
	maxTTL time.Duration,
) (ImportKeyRequest, error) {
	// Validate required fields
	if req.GetRawKey() == "" {
		return ImportKeyRequest{}, errdef.BadRequest("raw_key is required")
	}
	if req.GetName() == "" {
		return ImportKeyRequest{}, errdef.BadRequest("name is required")
	}
	// actor_id emptiness is also enforced by the proto min_len: 1 constraint (buf.validate).
	// This Go check is defense-in-depth for callers that bypass proto validation.
	if req.GetActorId() == "" {
		return ImportKeyRequest{}, errdef.BadRequest("actor_id is required")
	}

	// Normalize fields
	fields, err := NormalizeCreateFields(
		req.GetScopes(),
		req.GetMetadata(),
		req.GetRateLimitPolicy(),
		req.GetIpRestriction(),
	)
	if err != nil {
		return ImportKeyRequest{}, err
	}

	// Validate metadata size
	if err := ValidateMetadataSize(fields.Metadata); err != nil {
		return ImportKeyRequest{}, err
	}

	// Convert TTL, falling back to the project default when caller omits it.
	ttl, err := resolveTTL(req.GetTtl(), defaultTTL, maxTTL)
	if err != nil {
		return ImportKeyRequest{}, err
	}

	// Calculate expiration
	exp := time.Now().UTC().Add(ttl)

	return ImportKeyRequest{
		RawKey:    req.GetRawKey(),
		Name:      req.GetName(),
		ActorID:   req.GetActorId(),
		Fields:    fields,
		ExpiresAt: &exp,
	}, nil
}

// resolveTTL produces a concrete, positive TTL from the proto request. Callers
// that omit TTL get the project default; zero or over-max TTLs are rejected so
// users see a clear error instead of silent clamping. Talos does not support
// non-expiring API keys.
func resolveTTL(
	pbDuration *durationpb.Duration,
	defaultTTL, maxTTL time.Duration,
) (time.Duration, error) {
	ttl := ConvertTTL(pbDuration, defaultTTL)
	if ttl <= 0 {
		return 0, errdef.BadRequest("ttl must be greater than 0; non-expiring API keys are not supported")
	}
	if maxTTL > 0 && ttl > maxTTL {
		return 0, errdef.BadRequest(fmt.Sprintf("ttl %s exceeds the project maximum of %s", ttl, maxTTL))
	}
	return ttl, nil
}

// reviewed - @aeneasr - 2026-03-26
