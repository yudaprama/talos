// Package http provides gRPC-Gateway HTTP/REST server functionality.
package http

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ory/talos/internal/cachecontrol"
	"github.com/ory/talos/internal/clientip"
	"github.com/ory/talos/internal/config"
	"github.com/ory/talos/internal/errdef"
	"github.com/ory/talos/internal/health"
	"github.com/ory/talos/internal/metering"
	"github.com/ory/talos/internal/tracing"

	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/herodot"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// GatewayServer handles HTTP/REST requests using grpc-gateway
type GatewayServer struct {
	mux           *http.ServeMux
	healthChecker *health.Checker
	adminAdapter  talosv2alpha1.ApiKeysServer
	meter         metering.Meter
	writer        herodot.Writer
	config        config.ProviderInterface
}

// NewGatewayServer creates a new HTTP gateway server with direct service integration
func NewGatewayServer(
	healthChecker *health.Checker,
	adminAdapter talosv2alpha1.ApiKeysServer,
	writer herodot.Writer,
	provider config.ProviderInterface,
) *GatewayServer {
	return &GatewayServer{
		mux:           http.NewServeMux(),
		healthChecker: healthChecker,
		adminAdapter:  adminAdapter,
		writer:        writer,
		config:        provider,
	}
}

// WithMeter attaches a usage meter to the gateway so it can serve
// GET /v2alpha1/self/usageHistory. If not set, the handler returns 501.
func (s *GatewayServer) WithMeter(m metering.Meter) *GatewayServer {
	s.meter = m
	return s
}

// Setup initializes the gateway routes
func (s *GatewayServer) Setup(ctx context.Context) error {
	// Create gRPC-Gateway mux with custom settings
	// Use DurationAwareJSONPb to support Go duration format (e.g., "24h", "1h30m")
	// in addition to protobuf format ("86400s")
	gwmux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, NewDurationAwareJSONPb()),
		runtime.WithMetadata(s.extractMetadata),
		runtime.WithErrorHandler(s.customErrorHandler),
		runtime.WithForwardResponseOption(forwardRateLimitHeaders),
		runtime.WithForwardResponseOption(forwardHTTPStatusCode),
		runtime.WithOutgoingHeaderMatcher(verifyResponseHeaderMatcher),
		runtime.WithMiddlewares(GetDefaultMetrics().GatewayMiddleware()),
	)

	err := talosv2alpha1.RegisterApiKeysHandlerServer(ctx, gwmux, s.adminAdapter)
	if err != nil {
		return errors.Wrap(err, "register API keys handler")
	}

	s.setupRoutes(gwmux)

	return nil
}

// setupRoutes configures HTTP routes. gRPC-Gateway routes get per-endpoint metrics automatically
// via the GatewayMiddleware registered on gwmux. Only non-gateway routes are registered here.
func (s *GatewayServer) setupRoutes(gwmux *runtime.ServeMux) {
	metrics := GetDefaultMetrics()

	// Health check endpoints with instrumentation
	healthxHandler := s.healthChecker.Handler()
	s.mux.Handle("/health/alive", metrics.Instrument(healthxHandler.Alive(), "/health/alive"))
	s.mux.Handle("/health/ready", metrics.Instrument(healthxHandler.Ready(true), "/health/ready"))

	// Metrics endpoint — only registered in commercial builds. Not instrumented to avoid recursion.
	s.setupMetricsRoute()

	// Version endpoint - returns binary version info and config hash
	s.mux.Handle("/version", metrics.Instrument(http.HandlerFunc(s.handleVersion), "/version"))

	// Gateway-friendly verify: returns 401 on invalid credentials (unlike the
	// standard /v2alpha1/admin/apiKeys:verify which always returns 200). Used by
	// an Ory Oathkeeper remote_json authenticator as its verification backend.
	s.mux.Handle(GatewayVerifyPath, metrics.Instrument(http.HandlerFunc(s.handleGatewayVerify), GatewayVerifyPath))

	// Self-service usage history: returns the caller's recent api_key_usage rows.
	// Requires X-User-Id injected by the edge (Oathkeeper cookie_session).
	const usageHistoryPath = "/v2alpha1/self/usageHistory"
	s.mux.Handle(usageHistoryPath, metrics.Instrument(http.HandlerFunc(s.handleSelfUsageHistory), usageHistoryPath))

	// Edition-specific routes (e.g. /revisions/talos in commercial builds).
	s.registerEditionRoutes(metrics, gwmux)

	// All /v2alpha1/ routes are handled by gwmux; per-endpoint metrics come from GatewayMiddleware.
	s.mux.Handle("/", gwmux)
}

// ServeHTTP implements http.Handler with tracing and cache control extraction
func (s *GatewayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.Start(r.Context(), "http.gateway.serve")
	defer span.End()

	d := cachecontrol.ParseHeader(r.Header.Get("Cache-Control"))
	ctx = cachecontrol.WithCacheControl(ctx, cachecontrol.CacheControl{
		NoCache: d.NoCache || strings.EqualFold(r.Header.Get("Pragma"), "no-cache"),
		NoStore: d.NoStore,
	})
	ctx = clientip.WithRequestInfo(ctx, r)

	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	s.mux.ServeHTTP(rw, r.WithContext(ctx))

	if rw.statusCode >= http.StatusBadRequest {
		span.SetStatus(otelcodes.Error, http.StatusText(rw.statusCode))
	}
}

// extractMetadata extracts metadata from HTTP headers for gRPC-Gateway.
// X-Forwarded-Host is only trusted when serve.http.trust_forwarded_host is true;
// otherwise the Host header is used for multi-tenancy routing.
func (s *GatewayServer) extractMetadata(ctx context.Context, r *http.Request) metadata.MD {
	md := metadata.MD{}

	if auth := r.Header.Get("Authorization"); auth != "" {
		md["authorization"] = []string{auth}
	}

	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		md["x-request-id"] = []string{reqID}
	}

	// X-User-Id is the trust-bound identity header for the self-service surface
	// (SelfIssueApiKey / SelfListIssuedApiKeys / SelfRevokeIssuedApiKey). It MUST
	// be injected by a trusted edge proxy (e.g. Ory Oathkeeper from a Kratos
	// session); service methods that read it reject the request when it is
	// absent. We forward it unconditionally so a misconfigured edge (one that
	// forwards a client-supplied X-User-Id without overwriting it) fails closed
	// at the service layer with Unauthenticated, not silently here.
	if uid := r.Header.Get("X-User-Id"); uid != "" {
		md["x-user-id"] = []string{uid}
	}

	// X-Forwarded-Host drives multi-tenancy routing (commercial edition).
	// Only trust it when explicitly configured to prevent header-injection attacks.
	if host := s.effectiveHost(ctx, r); host != "" {
		md["x-forwarded-host"] = []string{host}
	}

	if cc := r.Header.Get("Cache-Control"); cc != "" {
		md["cache-control"] = []string{cc}
	}
	if pragma := r.Header.Get("Pragma"); pragma != "" {
		md["pragma"] = []string{pragma}
	}

	return md
}

// effectiveHost returns the host to use for multi-tenancy routing. When
// trust_forwarded_host is enabled, X-Forwarded-Host takes precedence over
// the Host header; otherwise the Host header is always used.
func (s *GatewayServer) effectiveHost(ctx context.Context, r *http.Request) string {
	if s.config.Bool(ctx, config.KeyServeHTTPTrustForwardedHost) {
		return cmp.Or(r.Header.Get("X-Forwarded-Host"), r.Host)
	}
	return r.Host
}

// verifyResponseHeaderMatcher forwards gRPC response metadata set by the
// VerifyAPIKey handler as standard HTTP response headers. Without it the
// default matcher would prefix these as Grpc-Metadata-* headers.
//
//   - ory-talos-cache → Ory-Talos-Cache (cache HIT/MISS/SKIP status)
//   - cache-control   → Cache-Control (no-store for IP-restricted keys, so the
//     edge proxy does not cache and replay responses past allowed_cidrs)
func verifyResponseHeaderMatcher(key string) (string, bool) {
	switch textproto.CanonicalMIMEHeaderKey(key) {
	case "Ory-Talos-Cache":
		return "Ory-Talos-Cache", true
	case "Cache-Control":
		return "Cache-Control", true
	}
	return runtime.DefaultHeaderMatcher(key)
}

// forwardRateLimitHeaders intercepts gRPC responses and adds rate limit headers
// Compliant with draft-ietf-httpapi-ratelimit-headers-10
func forwardRateLimitHeaders(_ context.Context, w http.ResponseWriter, resp proto.Message) error {
	verifyResp, ok := resp.(*talosv2alpha1.VerifyApiKeyResponse)
	if !ok {
		return nil
	}

	if policy := verifyResp.GetRateLimitPolicy(); policy != nil && policy.Quota > 0 {
		rateLimitPolicyHeader := formatRateLimitPolicyHeader(policy)
		w.Header().Set(textproto.CanonicalMIMEHeaderKey("RateLimit-Policy"), rateLimitPolicyHeader)
	}

	if verifyResp.RateLimitRemaining != nil {
		remaining := verifyResp.GetRateLimitRemaining()
		w.Header().Set(textproto.CanonicalMIMEHeaderKey("RateLimit"), fmt.Sprintf(`"default";r=%d`, remaining))
	}

	if verifyResp.RateLimitResetTime != nil && verifyResp.GetErrorCode() == talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_RATE_LIMITED {
		resetTime := verifyResp.GetRateLimitResetTime().AsTime()
		retryAfter := max(int(time.Until(resetTime).Seconds()), 1)
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}

	return nil
}

// forwardHTTPStatusCode sets the correct HTTP status code based on the response message type.
// gRPC only has one success code (OK → 200), but REST conventions require 201 for creates
// and 204 for deletes/revokes. This type-switch centralizes the mapping, making it
// compile-time safe — adding a new response type without a case here is a conscious choice
// (defaults to 200), and renaming a type produces a compiler error.
//
// AIP-133 requires Create responses to set a Location header pointing at the
// newly created resource. Rotate is a custom method that creates a new key
// resource on success, so it follows the same convention.
func forwardHTTPStatusCode(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
	switch r := resp.(type) {
	case *talosv2alpha1.IssueApiKeyResponse:
		// Location depends on which surface issued the key: the admin
		// surface (/v2alpha1/admin/issuedApiKeys) for AdminIssueApiKey,
		// the self-service surface (/v2alpha1/self/issuedApiKeys) for
		// SelfIssueApiKey. Both produce the same IssueApiKeyResponse, so
		// disambiguate via the gRPC method name annotated by grpc-gateway.
		if r.GetIssuedApiKey() != nil && r.GetIssuedApiKey().GetKeyId() != "" {
			location := "/v2alpha1/admin/issuedApiKeys/" + r.GetIssuedApiKey().GetKeyId()
			if method, ok := runtime.RPCMethod(ctx); ok && strings.HasSuffix(method, "/SelfIssueApiKey") {
				location = "/v2alpha1/self/issuedApiKeys/" + r.GetIssuedApiKey().GetKeyId()
			}
			w.Header().Set("Location", location)
		}
		w.WriteHeader(http.StatusCreated)
	case *talosv2alpha1.RotateIssuedApiKeyResponse:
		if r.GetIssuedApiKey() != nil && r.GetIssuedApiKey().GetKeyId() != "" {
			w.Header().Set("Location", "/v2alpha1/admin/issuedApiKeys/"+r.GetIssuedApiKey().GetKeyId())
		}
		w.WriteHeader(http.StatusCreated)
	case *talosv2alpha1.ImportedApiKey:
		// ImportedApiKey is returned by Import (Create), Get, and Update.
		// Only Create gets 201 + Location per AIP-133; Get/Update default to 200.
		if method, ok := runtime.RPCMethod(ctx); ok && strings.HasSuffix(method, "/AdminImportApiKey") {
			if r.GetKeyId() != "" {
				w.Header().Set("Location", "/v2alpha1/admin/importedApiKeys/"+r.GetKeyId())
			}
			w.WriteHeader(http.StatusCreated)
		}
	case *emptypb.Empty:
		// RevokeApiKey and DeleteImportedAPIKey both return Empty → 204
		w.WriteHeader(http.StatusNoContent)
	}
	return nil
}

// formatRateLimitPolicyHeader formats the RateLimitPolicy as an IETF structured field
// Example output: "default";q=1000;w=3600
func formatRateLimitPolicyHeader(policy *talosv2alpha1.RateLimitPolicy) string {
	// Use "default" as the policy name per IETF spec recommendations
	// q = quota (number of requests)
	// w = window (in seconds)
	unit := cmp.Or(policy.Unit, "requests") // Default per IETF spec

	windowSecs := int64(0)
	if policy.Window != nil {
		windowSecs = int64(policy.Window.AsDuration().Seconds())
	}

	// Basic format without explicit unit (defaults to "requests")
	if unit == "requests" {
		return fmt.Sprintf(`"default";q=%d;w=%d`, policy.Quota, windowSecs)
	}

	// Format with explicit unit for non-request quotas

	return fmt.Sprintf(`"default";q=%d;w=%d;qu="%s"`, policy.Quota, windowSecs, unit)
}

// customErrorHandler handles errors and converts them to RFC-compliant HTTP responses
func (s *GatewayServer) customErrorHandler(ctx context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		s.writer.WriteError(w, r, errdef.ErrInternalServerError().WithReason("Error handler called without error."))
		return
	}

	// Record the error on the current span (http.gateway.serve) so validation failures
	// and body-parsing errors appear as span events in Grafana Tempo traces.
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.RecordError(err)
	}

	reqID := cmp.Or(r.Header.Get("X-Request-ID"), uuid.Must(uuid.NewV4()).String())
	w.Header().Set("X-Request-ID", reqID)

	// Preserve original herodot errors to avoid lossy gRPC status code mapping.
	var herodotErr *herodot.DefaultError
	if errors.As(err, &herodotErr) {
		s.writer.WriteError(w, r, herodotErr)
		return
	}

	if stErr, ok := status.FromError(err); ok {
		reason := stErr.Message()
		for _, detail := range stErr.Details() {
			if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetReason() != "" {
				reason = info.GetReason()
				break
			}
		}
		switch stErr.Code() {
		case codes.OK:
			// No error, shouldn't reach here
			return
		case codes.InvalidArgument:
			herodotErr = errdef.ErrBadRequest()
		case codes.NotFound:
			herodotErr = errdef.ErrNotFound()
		case codes.AlreadyExists:
			herodotErr = errdef.ErrConflict()
		case codes.Unauthenticated:
			herodotErr = errdef.ErrUnauthorized()
		case codes.PermissionDenied:
			herodotErr = errdef.ErrForbidden()
		case codes.Unavailable:
			herodotErr = errdef.ErrServiceUnavailable()
		case codes.DeadlineExceeded:
			herodotErr = errdef.ErrGatewayTimeout()
		case codes.FailedPrecondition:
			herodotErr = errdef.ErrFailedPrecondition()
		case codes.ResourceExhausted:
			herodotErr = errdef.ErrTooManyRequests()
		case codes.Unimplemented:
			// gRPC-Gateway converts HTTP method-not-allowed to Unimplemented.
			// Return 404 so clients receive a consistent "not found" response
			// rather than a misleading 500.
			herodotErr = errdef.ErrNotFound()
		case codes.Canceled, codes.Unknown,
			codes.Aborted, codes.OutOfRange, codes.Internal, codes.DataLoss:
			herodotErr = errdef.ErrInternalServerError()
			// Sanitize internal error details to prevent leaking server internals
			slog.ErrorContext(ctx, "internal error", "error", err, "grpc_code", stErr.Code().String())
			reason = "an internal error occurred"
		default:
			herodotErr = errdef.ErrInternalServerError()
			slog.ErrorContext(ctx, "internal error", "error", err, "grpc_code", stErr.Code().String())
			reason = "an internal error occurred"
		}
		herodotErr = herodotErr.WithReason(reason).WithTrace(err)
	} else {
		slog.ErrorContext(ctx, "internal error", "error", err)
		herodotErr = errdef.ErrInternalServerError().WithReason("an internal error occurred").WithTrace(err)
	}

	s.writer.WriteError(w, r, herodotErr)
}

// reviewed - @aeneasr - 2026-03-26
