package service

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"log/slog"

	"buf.build/go/protovalidate"
	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ory/talos/internal/cachecontrol"
	"github.com/ory/talos/internal/clientip"
	"github.com/ory/talos/internal/errdef"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
	"github.com/ory/talos/internal/ratelimit"
	"github.com/ory/talos/internal/tracing"
	"github.com/ory/talos/internal/verifier"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"

	"github.com/ory/herodot"
	"github.com/ory/x/otelx"
)

// Public implements proof-of-possession self-revocation and credential
// verification. Verification helpers (VerifyAPIKey, BatchVerifyAPIKeys) are
// admin-only and are reached through the admin adapter, which delegates to
// this type.
type Public struct {
	apiKeyVerifier *verifier.Verifier
	protoValidator protovalidate.Validator
	rateLimiter    ratelimit.Limiter
}

// NewPublic creates a new Public server.
func NewPublic(v *verifier.Verifier, pv protovalidate.Validator, rl ratelimit.Limiter) *Public {
	return &Public{
		apiKeyVerifier: v,
		protoValidator: pv,
		rateLimiter:    rl,
	}
}

// Response Building

// verificationErrorToResponse maps verification errors to proto error responses.
// For recognized herodot errors the reason field is used as the message.
// For all other errors a generic message is returned to avoid leaking internal
// error details (driver messages, stack traces, library internals) to callers.
func verificationErrorToResponse(err error) *talosv2alpha1.VerifyApiKeyResponse {
	code := mapErrorToVerificationCode(err)
	msg := "An internal server error occurred."
	// stderrors.AsType is a generic type-assertion helper from the Go stdlib errors package.
	// It is the correct idiomatic approach for extracting a typed error from an error chain.
	if herodotErr, ok := stderrors.AsType[*herodot.DefaultError](err); ok {
		if herodotErr.ReasonField != "" {
			msg = herodotErr.ReasonField
		} else {
			msg = herodotErr.ErrorField
		}
	}
	return &talosv2alpha1.VerifyApiKeyResponse{
		IsValid:      false,
		ErrorCode:    &code,
		ErrorMessage: &msg,
	}
}

func cacheStatusMetadata(status cachecontrol.CacheStatus) metadata.MD {
	return metadata.Pairs("ory-talos-cache", string(status))
}

// mapErrorToVerificationCode maps verifier errors to proto error codes.
func mapErrorToVerificationCode(err error) talosv2alpha1.VerificationErrorCode {
	switch {
	case errors.Is(err, errdef.ErrAPIKeyExpired()):
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_EXPIRED
	case errors.Is(err, errdef.ErrAPIKeyRevoked()):
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_REVOKED
	case errors.Is(err, errdef.ErrAPIKeyNotFound()),
		errors.Is(err, errdef.ErrParentKeyInvalid()):
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_NOT_FOUND
	case errors.Is(err, errdef.ErrSignatureInvalid()):
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_SIGNATURE_INVALID
	case errors.Is(err, errdef.ErrCredentialRequired()),
		errors.Is(err, errdef.ErrInvalidAPIKeyFormat()),
		errors.Is(err, errdef.ErrUnknownCredential()),
		errors.Is(err, errdef.ErrInvalidTokenType()):
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT
	case errors.Is(err, errdef.ErrIPNotAllowed()):
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_IP_NOT_ALLOWED
	default:
		return talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INTERNAL
	}
}

// dbKeyToVerifyResponse converts a db.IssuedApiKey to a proto VerifyApiKeyResponse.
// Note: DB column uses ExpiresAt, proto uses ExpireTime
func dbKeyToVerifyResponse(_ context.Context, dbKey *db.IssuedApiKey) (*talosv2alpha1.VerifyApiKeyResponse, error) {
	metadata := metadataToStructpb(dbKey.Metadata)
	rateLimitPolicy := buildRateLimitPolicy(dbKey.RateLimitQuota, dbKey.RateLimitWindow)

	var actorID string
	if dbKey.ActorID != nil {
		actorID = *dbKey.ActorID
	}

	scopes, err := sqlutil.UnmarshalScopes(dbKey.Scopes)
	if err != nil {
		return nil, err
	}

	return &talosv2alpha1.VerifyApiKeyResponse{
		IsValid:         true,
		Status:          talosv2alpha1.KeyStatus(dbKey.Status),
		KeyId:           dbKey.KeyID,
		ActorId:         actorID,
		Scopes:          scopes,
		ExpireTime:      maybeProtoTimestamp(dbKey.ExpiresAt),
		Metadata:        metadata,
		RateLimitPolicy: rateLimitPolicy,
		Visibility:      talosv2alpha1.KeyVisibility(dbKey.Visibility),
	}, nil
}

// applyRateLimiting enforces rate limiting on a verification response.
// It is a no-op when the key has no rate limit policy.
// On limiter error, it fails open (records the error on the span but does not block).
func (s *Public) applyRateLimiting(ctx context.Context, keyID string, response *talosv2alpha1.VerifyApiKeyResponse, span trace.Span) {
	if response.RateLimitPolicy == nil {
		return
	}

	rlResult, rlErr := s.rateLimiter.Allow(ctx, keyID, response.RateLimitPolicy)
	if rlErr != nil {
		// Fail-open: log error but don't block verification
		span.RecordError(rlErr)
		return
	}

	response.RateLimitRemaining = &rlResult.Remaining
	resetTs := timestamppb.New(rlResult.ResetAt)
	response.RateLimitResetTime = resetTs
	if !rlResult.Allowed {
		response.IsValid = false
		errCode := talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_RATE_LIMITED
		response.ErrorCode = &errCode
		errMsg := "rate limit exceeded"
		response.ErrorMessage = &errMsg
	}
}

// VerifyAPIKey verifies a single credential (API key or derived token)
func (s *Public) VerifyAPIKey(ctx context.Context, req *talosv2alpha1.VerifyApiKeyRequest) (resp *talosv2alpha1.VerifyApiKeyResponse, err error) {
	ctx, span := tracing.Start(ctx, "public.VerifyAPIKey")
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	dbKey, cacheStatus, verifyErr := s.apiKeyVerifier.VerifyAPIKey(ctx, req.GetCredential())
	switch cacheStatus {
	case cachecontrol.CacheHit:
		err = grpc.SetHeader(ctx, cacheStatusMetadata(cachecontrol.CacheHit))
	case cachecontrol.CacheMiss:
		err = grpc.SetHeader(ctx, cacheStatusMetadata(cachecontrol.CacheMiss))
	case cachecontrol.CacheSkip:
		err = grpc.SetHeader(ctx, cacheStatusMetadata(cachecontrol.CacheSkip))
	}
	if err != nil {
		slog.WarnContext(ctx, "failed to set cache status header", slog.Any("error", err))
	}
	if verifyErr != nil {
		if mapErrorToVerificationCode(verifyErr) == talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INTERNAL {
			span.RecordError(verifyErr)
		}
		return verificationErrorToResponse(verifyErr), nil
	}

	response, convErr := dbKeyToVerifyResponse(ctx, dbKey)
	if convErr != nil {
		err := wrapDecodePersistedScopesError(convErr)
		span.RecordError(err)
		return verificationErrorToResponse(err), nil
	}
	response.Issuer = s.apiKeyVerifier.GetTokenIssuer(ctx)
	s.applyRateLimiting(ctx, dbKey.KeyID, response, span)

	// The edge proxy caches verification responses on host+credential only.
	// A cached "valid" response would bypass two per-request checks:
	//   - IP allowlist enforcement (allowed_cidrs), keyed to the caller's IP, and
	//   - rate limit enforcement, which must decrement quota on every request.
	// Signal the proxy not to store these responses, keeping enforcement upstream.
	// Rate limiting only enforces in commercial builds; the OSS no-op limiter
	// reports Enabled() == false, so OSS emits no spurious header (and has no edge
	// proxy anyway).
	ipRestricted := clientip.HasRestriction(dbKey.AllowedCidrs)
	rateLimited := s.rateLimiter.Enabled() && response.RateLimitPolicy != nil
	if ipRestricted || rateLimited {
		if err := grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store")); err != nil {
			slog.WarnContext(ctx, "failed to set cache-control header", slog.Any("error", err))
		}
	}

	return response, nil
}

// BatchVerifyAPIKeys verifies multiple credentials in one DB round-trip for issued keys.
// Issued keys are pre-validated (parse, timestamp, prefix, checksum) then fetched via
// a single WHERE key_id IN (...) query. Non-issued types (imported, derived) fall through
// to individual verification.
func (s *Public) BatchVerifyAPIKeys(ctx context.Context, req *talosv2alpha1.BatchVerifyApiKeysRequest) (resp *talosv2alpha1.BatchVerifyApiKeysResponse, err error) {
	ctx, span := tracing.Start(
		ctx, "public.BatchVerifyAPIKeys",
		attribute.Int("batch_size", len(req.GetRequests())),
	)
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	keys := req.GetRequests()
	results := make([]*talosv2alpha1.VerifyApiKeyResponse, len(keys))

	// Collect non-empty credentials while pre-filling errors for nil/empty entries.
	credentials := make([]string, 0, len(keys))
	credIdx := make([]int, 0, len(keys)) // maps credentials[j] → keys[i]

	for i, credReq := range keys {
		if credReq == nil {
			code := talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT
			msg := "empty credential in request"
			results[i] = &talosv2alpha1.VerifyApiKeyResponse{
				IsValid:      false,
				ErrorCode:    &code,
				ErrorMessage: &msg,
			}
			continue
		}

		cred := credReq.GetCredential()
		if cred == "" {
			msg := "credential is required"
			results[i] = &talosv2alpha1.VerifyApiKeyResponse{
				IsValid:      false,
				ErrorCode:    talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INVALID_FORMAT.Enum(),
				ErrorMessage: &msg,
			}
			continue
		}

		credentials = append(credentials, cred)
		credIdx = append(credIdx, i)
	}

	if len(credentials) > 0 {
		batchResults, batchErr := s.apiKeyVerifier.BatchVerifyAPIKeys(ctx, credentials)
		if batchErr != nil {
			return nil, batchErr
		}

		for j, res := range batchResults {
			origIdx := credIdx[j]
			if res.Err != nil {
				results[origIdx] = verificationErrorToResponse(res.Err)
				continue
			}
			response, convErr := dbKeyToVerifyResponse(ctx, res.Key)
			if convErr != nil {
				err := wrapDecodePersistedScopesError(convErr)
				span.RecordError(err)
				results[origIdx] = verificationErrorToResponse(err)
				continue
			}
			response.Issuer = s.apiKeyVerifier.GetTokenIssuer(ctx)
			s.applyRateLimiting(ctx, res.Key.KeyID, response, span)
			results[origIdx] = response
		}
	}

	// Unlike VerifyApiKey, we emit no Cache-Control: no-store here because the
	// edge proxy does not cache batch responses (isVerifyEndpoint matches only
	// apiKeys:verify, and TestProxyHandler_BatchVerifyProxiedWithoutCaching pins
	// that). If batch ever becomes edge-cacheable, the per-request IP allowlist
	// and rate-limit checks would be bypassed silently. A single response carries
	// many results, so the fix is response-level: emit no-store when ANY result
	// is IP-restricted or rate-limited (Cache-Control is per response, not per
	// result).
	return &talosv2alpha1.BatchVerifyApiKeysResponse{
		Results: results,
	}, nil
}

// RevokeApiKey allows an API key holder to revoke their own key by providing the full secret.
func (s *Public) RevokeApiKey(ctx context.Context, req *talosv2alpha1.SelfRevokeApiKeyRequest) (resp *talosv2alpha1.SelfRevokeApiKeyResponse, err error) {
	ctx, span := tracing.Start(ctx, "public.RevokeApiKey")
	defer otelx.End(span, &err)

	if err := s.protoValidator.Validate(req); err != nil {
		return nil, errdef.BadRequest(err.Error())
	}

	// Reject PRIVILEGE_WITHDRAWN for self-revocation (admin-only reason)
	if req.GetReason() == talosv2alpha1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN {
		return nil, errdef.BadRequest("PRIVILEGE_WITHDRAWN is not allowed for self-revocation")
	}

	if err := s.apiKeyVerifier.SelfRevokeAPIKey(ctx, req.GetCredential(), int32(req.GetReason())); err != nil {
		return nil, err
	}

	return &talosv2alpha1.SelfRevokeApiKeyResponse{}, nil
}

// GetJwks returns the JSON Web Key Set for token verification. The set is
// sourced from the configured signing keys via the shared KeyService and
// is suitable for publishing on the public verification surface (RFC 7517).
// Symmetric keys are filtered out and private key material is stripped.
func (s *Public) GetJwks(ctx context.Context, _ *talosv2alpha1.GetJWKSRequest) (_ *talosv2alpha1.GetJWKSResponse, err error) {
	ctx, span := tracing.Start(ctx, "public.GetJwks")
	defer otelx.End(span, &err)

	keySet, err := s.apiKeyVerifier.ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, errdef.InternalError("list signing keys").WithWrap(errors.WithStack(err))
	}

	if keySet.Len() == 0 {
		return nil, errdef.InternalError("no active signing keys found")
	}

	jwks := make([]any, 0, keySet.Len())
	for i := range keySet.Len() {
		jwkKey, ok := keySet.Key(i)
		if !ok {
			continue
		}

		// Symmetric keys (HMAC) must never appear in the public JWKS endpoint
		// because they have no public/private distinction — exposing them leaks
		// the secret material.
		if jwkKey.KeyType() == jwa.OctetSeq() {
			continue
		}

		publicJWK, err := jwkKey.PublicKey()
		if err != nil {
			continue
		}

		// Marshal to JSON and unmarshal to normalize types (jwa.KeyType -> string, etc.)
		jsonBytes, err := json.Marshal(publicJWK)
		if err != nil {
			continue
		}

		var jwkMap map[string]any
		if err := json.Unmarshal(jsonBytes, &jwkMap); err != nil {
			continue
		}

		jwks = append(jwks, jwkMap)
	}

	jwksStruct, err := structpb.NewStruct(map[string]any{"keys": jwks})
	if err != nil {
		return nil, errdef.InternalError("convert JWKS to struct").WithWrap(errors.WithStack(err))
	}

	span.SetAttributes(attribute.Int("key_count", len(jwks)))

	return &talosv2alpha1.GetJWKSResponse{
		Jwks: jwksStruct,
	}, nil
}

// reviewed - @aeneasr - 2026-03-26
