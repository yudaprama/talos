// Package service — self-service operations authenticated by a trusted X-User-Id
// HTTP header.
//
// The Self* RPCs (SelfIssueApiKey, SelfListIssuedApiKeys, SelfRevokeIssuedApiKey)
// are the X-User-Id-authenticated counterpart to the admin issue/list/revoke
// RPCs. They exist so a single-user-facing edge proxy (Ory Oathkeeper with a
// Kratos cookie_session authenticator) can offer key self-management without
// a per-application BFF holding an admin token.
//
// Trust model: Talos has no built-in identity provider, so it trusts the
// network boundary for the admin surface. The self-service surface extends
// that same trust to the X-User-Id header: the edge MUST inject it from an
// authoritative source (e.g. a verified Kratos session), and MUST overwrite
// any client-supplied value. A request that reaches Talos without the header
// (or with an empty value) is rejected with Unauthenticated.
//
// actor_id is ALWAYS taken from the header — it is conspicuously absent from
// every request message in talos.proto so a client cannot mint keys for
// another actor by setting a body field. Self-list hard-codes the actor_id
// filter server-side; self-revoke does an ownership check before revoking.
// Scopes, rate limits, IP restrictions, and visibility are NOT exposed here —
// they are admin-only knobs and would create an escalation path if a self-
// issued key could carry them.
package service

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/tracing"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"

	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/attribute"
)

// actorIDFromHeader extracts the X-User-Id header from the gRPC metadata
// (populated by the gateway's extractMetadata from the HTTP request). Returns
// an Unauthenticated error when the header is absent or empty — this is the
// single trust check that gates every Self* RPC, so it lives here rather than
// being duplicated across methods.
func actorIDFromHeader(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing trust header: X-User-Id is required (deploy behind an edge that injects it from a Kratos session)")
	}
	values := md.Get("x-user-id")
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", status.Error(codes.Unauthenticated, "missing trust header: X-User-Id is required (deploy behind an edge that injects it from a Kratos session)")
	}
	return strings.TrimSpace(values[0]), nil
}

// requireAdmin returns the embedded *Admin reference or an Unimplemented error.
// In a deployment that did not construct the Admin service (e.g. ModePublic
// before buildAdapters was updated to always create one), the self-service
// surface is unavailable. This guards against nil-deref if Public is ever
// constructed without an admin ref (e.g. in a test).
func (s *Public) requireAdmin() (*Admin, error) {
	if s.admin == nil {
		return nil, status.Error(codes.Unimplemented, "self-service surface not configured: admin service is not wired")
	}
	return s.admin, nil
}

// SelfIssueApiKey creates a new API key bound to the caller's actor_id (from
// the X-User-Id header). Self-issued keys inherit the default visibility
// (SECRET) and an empty scope set; the caller cannot escalate either. The
// request's name, ttl, and request_id fields are forwarded to the underlying
// Admin.IssueApiKey implementation.
func (s *Public) SelfIssueApiKey(ctx context.Context, req *talosv2alpha1.SelfIssueApiKeyRequest) (_ *talosv2alpha1.IssueApiKeyResponse, err error) {
	ctx, span := tracing.Start(ctx, "public.SelfIssueApiKey")
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	actorID, err := actorIDFromHeader(ctx)
	if err != nil {
		return nil, err
	}
	span.SetAttributes(attribute.String("actor_id", actorID))

	admin, err := s.requireAdmin()
	if err != nil {
		return nil, err
	}

	// Build an admin IssueApiKeyRequest with actor_id from the header and
	// every escalation knob (scopes, rate_limit_policy, ip_restriction,
	// visibility, metadata) defaulted. The admin service validates + fills
	// TTL/name defaults; we pass them through unchanged.
	adminReq := &talosv2alpha1.IssueApiKeyRequest{
		ActorId:   actorID,
		Name:      req.GetName(),
		RequestId: req.GetRequestId(),
	}
	// Forward TTL only when the caller set it (admin treats zero as "use
	// default"). Pass the proto-duration pointer directly — no copy needed
	// because the admin path consumes it read-only.
	if req.GetTtl() != nil {
		adminReq.Ttl = req.GetTtl()
	}
	// Default name to a stable sentinel so the resulting key is identifiable
	// as self-issued in audit logs. Empty name is allowed by the proto (max_len
	// 255, no min) so admin validation will accept it; we substitute here only
	// for readability.
	if adminReq.Name == "" {
		adminReq.Name = "self-issued"
	}

	resp, err := admin.IssueApiKey(ctx, adminReq)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// SelfListIssuedApiKeys lists the caller's API keys. The actor_id filter is
// hard-coded server-side from the X-User-Id header — the request's filter
// field does not exist on the self-service message (it would be ignored
// anyway), and a caller cannot enumerate other actors' keys.
func (s *Public) SelfListIssuedApiKeys(ctx context.Context, req *talosv2alpha1.SelfListIssuedApiKeysRequest) (_ *talosv2alpha1.ListIssuedApiKeysResponse, err error) {
	ctx, span := tracing.Start(ctx, "public.SelfListIssuedApiKeys")
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	actorID, err := actorIDFromHeader(ctx)
	if err != nil {
		return nil, err
	}
	span.SetAttributes(attribute.String("actor_id", actorID))

	admin, err := s.requireAdmin()
	if err != nil {
		return nil, err
	}

	// Force the actor_id filter server-side. An AIP-160 expression that
	// happens to match actor_id is also acceptable; we substitute our own
	// to guarantee isolation regardless of any future request shape change.
	adminReq := &talosv2alpha1.ListIssuedApiKeysRequest{
		PageSize:  req.GetPageSize(),
		PageToken: req.GetPageToken(),
		Filter:    "actor_id=\"" + actorID + "\"",
	}
	return admin.ListIssuedAPIKeys(ctx, adminReq)
}

// SelfRevokeIssuedApiKey revokes an issued key owned by the caller. Ownership
// is verified before revocation: the key's actor_id must match the X-User-Id
// header. On mismatch (or not-found) we return 404 — never 403 — so a caller
// cannot enumerate other actors' key ids by probing.
//
// PRIVILEGE_WITHDRAWN is rejected here (admin-only reason), mirroring the
// proof-of-possession self-revoke. Self-revocation uses KEY_COMPROMISE,
// AFFILIATION_CHANGED, SUPERSEDED, or UNSPECIFIED.
func (s *Public) SelfRevokeIssuedApiKey(ctx context.Context, req *talosv2alpha1.SelfRevokeIssuedApiKeyRequest) (_ *emptypb.Empty, err error) {
	ctx, span := tracing.Start(
		ctx, "public.SelfRevokeIssuedApiKey",
		attribute.String("key_id", req.GetKeyId()),
	)
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	actorID, err := actorIDFromHeader(ctx)
	if err != nil {
		return nil, err
	}

	admin, err := s.requireAdmin()
	if err != nil {
		return nil, err
	}

	// Ownership check before revocation. GetIssuedAPIKey returns NotFound on
	// a missing key, which we surface as 404 directly. A key that exists but
	// belongs to a different actor is also surfaced as 404 (not 403) to avoid
	// leaking which key ids exist across actors.
	key, err := admin.GetIssuedAPIKey(ctx, &talosv2alpha1.GetIssuedApiKeyRequest{KeyId: req.GetKeyId()})
	if err != nil {
		return nil, err
	}
	if key.GetActorId() != actorID {
		// Treat as not-found so a caller probing key ids learns nothing.
		return nil, errdef.ErrAPIKeyNotFound().WithReasonf("API key not found")
	}

	// Reject PRIVILEGE_WITHDRAWN (admin-only reason) — same rule as the
	// proof-of-possession self-revoke in RevokeApiKey above.
	if req.GetReason() == talosv2alpha1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN {
		return nil, errdef.BadRequest("PRIVILEGE_WITHDRAWN is not allowed for self-revocation")
	}

	return admin.RevokeIssuedApiKey(ctx, &talosv2alpha1.RevokeIssuedApiKeyRequest{
		KeyId:       req.GetKeyId(),
		Reason:      req.GetReason(),
		Description: req.GetDescription(),
	})
}
