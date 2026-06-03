package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

type testGatewayErrorWriter struct{}

func (testGatewayErrorWriter) ReportError(_ *http.Request, _ int, _ error, _ ...any) {}

func TestFormatRateLimitPolicyHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   *talosv2alpha1.RateLimitPolicy
		expected string
	}{
		{
			name: "basic requests policy",
			policy: &talosv2alpha1.RateLimitPolicy{
				Quota:  1000,
				Window: durationpb.New(3600 * time.Second),
				Unit:   "requests",
			},
			expected: `"default";q=1000;w=3600`,
		},
		{
			name: "requests policy with empty unit (defaults to requests)",
			policy: &talosv2alpha1.RateLimitPolicy{
				Quota:  500,
				Window: durationpb.New(60 * time.Second),
				Unit:   "",
			},
			expected: `"default";q=500;w=60`,
		},
		{
			name: "hourly policy",
			policy: &talosv2alpha1.RateLimitPolicy{
				Quota:  10000,
				Window: durationpb.New(3600 * time.Second),
				Unit:   "requests",
			},
			expected: `"default";q=10000;w=3600`,
		},
		{
			name: "daily policy",
			policy: &talosv2alpha1.RateLimitPolicy{
				Quota:  100000,
				Window: durationpb.New(86400 * time.Second),
				Unit:   "requests",
			},
			expected: `"default";q=100000;w=86400`,
		},
		{
			name: "content-bytes policy",
			policy: &talosv2alpha1.RateLimitPolicy{
				Quota:  10485760, // 10MB
				Window: durationpb.New(3600 * time.Second),
				Unit:   "content-bytes",
			},
			expected: `"default";q=10485760;w=3600;qu="content-bytes"`,
		},
		{
			name: "concurrent-requests policy",
			policy: &talosv2alpha1.RateLimitPolicy{
				Quota:  100,
				Window: durationpb.New(0), // Not applicable for concurrent
				Unit:   "concurrent-requests",
			},
			expected: `"default";q=100;w=0;qu="concurrent-requests"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := formatRateLimitPolicyHeader(tt.policy)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatRateLimitPolicyHeader_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("zero quota", func(t *testing.T) {
		t.Parallel()
		policy := &talosv2alpha1.RateLimitPolicy{
			Quota:  0,
			Window: durationpb.New(3600 * time.Second),
			Unit:   "requests",
		}
		result := formatRateLimitPolicyHeader(policy)
		assert.Equal(t, `"default";q=0;w=3600`, result)
	})

	t.Run("very large quota", func(t *testing.T) {
		t.Parallel()
		policy := &talosv2alpha1.RateLimitPolicy{
			Quota:  9999999999,
			Window: durationpb.New(86400 * time.Second),
			Unit:   "requests",
		}
		result := formatRateLimitPolicyHeader(policy)
		assert.Equal(t, `"default";q=9999999999;w=86400`, result)
	})

	t.Run("one second window", func(t *testing.T) {
		t.Parallel()
		policy := &talosv2alpha1.RateLimitPolicy{
			Quota:  10,
			Window: durationpb.New(1 * time.Second),
			Unit:   "requests",
		}
		result := formatRateLimitPolicyHeader(policy)
		assert.Equal(t, `"default";q=10;w=1`, result)
	})
}

// rateLimitHeaderSnapshot returns a deterministic, sorted snapshot of rate limit headers,
// excluding Retry-After (which is time-dependent and asserted separately).
func rateLimitHeaderSnapshot(h http.Header) string {
	var lines []string
	for _, key := range []string{"Ratelimit-Policy", "Ratelimit"} {
		if v := h.Get(key); v != "" {
			lines = append(lines, key+": "+v)
		}
	}
	if len(lines) == 0 {
		return "(no rate limit headers)"
	}
	return strings.Join(lines, "\n")
}

func TestForwardRateLimitHeaders(t *testing.T) {
	t.Parallel()

	snapshotter := cupaloy.New(cupaloy.SnapshotSubdirectory(".snapshots"))
	ctx := context.Background()

	tests := []struct {
		name               string
		resp               *talosv2alpha1.VerifyApiKeyResponse
		expectPolicyHeader bool
		expectRateLimit    bool
		expectRetryAfter   bool
	}{
		{
			name: "verify_with_rate_limit_policy",
			resp: &talosv2alpha1.VerifyApiKeyResponse{
				IsValid: true,
				KeyId:   "key-123",
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  10,
					Window: durationpb.New(60 * time.Second),
					Unit:   "requests",
				},
			},
			expectPolicyHeader: true,
		},
		{
			name: "verify_with_enforcement_active",
			resp: &talosv2alpha1.VerifyApiKeyResponse{
				IsValid: true,
				KeyId:   "key-456",
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  10,
					Window: durationpb.New(60 * time.Second),
					Unit:   "requests",
				},
				RateLimitRemaining: func() *int64 { v := int64(7); return &v }(),
			},
			expectPolicyHeader: true,
			expectRateLimit:    true,
		},
		{
			name: "verify_rate_limited",
			resp: func() *talosv2alpha1.VerifyApiKeyResponse {
				remaining := int64(0)
				errorCode := talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_RATE_LIMITED
				return &talosv2alpha1.VerifyApiKeyResponse{
					IsValid: false,
					KeyId:   "key-789",
					RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
						Quota:  10,
						Window: durationpb.New(60 * time.Second),
						Unit:   "requests",
					},
					RateLimitRemaining: &remaining,
					RateLimitResetTime: timestamppb.New(time.Now().Add(30 * time.Second)),
					ErrorCode:          &errorCode,
				}
			}(),
			expectPolicyHeader: true,
			expectRateLimit:    true,
			expectRetryAfter:   true,
		},
		{
			name: "verify_no_policy",
			resp: &talosv2alpha1.VerifyApiKeyResponse{
				IsValid: true,
				KeyId:   "key-no-policy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			err := forwardRateLimitHeaders(ctx, rec, tt.resp)
			require.NoError(t, err)

			h := rec.Header()

			// Snapshot the deterministic headers
			snapshotter.SnapshotT(t, rateLimitHeaderSnapshot(h))

			// Explicit presence/absence assertions
			if tt.expectPolicyHeader {
				assert.NotEmpty(t, h.Get("Ratelimit-Policy"), "expected Ratelimit-Policy header")
			} else {
				assert.Empty(t, h.Get("Ratelimit-Policy"), "unexpected Ratelimit-Policy header")
			}

			if tt.expectRateLimit {
				assert.NotEmpty(t, h.Get("Ratelimit"), "expected Ratelimit header")
			} else {
				assert.Empty(t, h.Get("Ratelimit"), "unexpected Ratelimit header")
			}

			if tt.expectRetryAfter {
				retryAfter := h.Get("Retry-After")
				assert.NotEmpty(t, retryAfter, "expected Retry-After header")
				// Retry-After should be a positive integer (seconds until reset)
				assert.Regexp(t, `^\d+$`, retryAfter, "Retry-After should be a number")
			} else {
				assert.Empty(t, h.Get("Retry-After"), "unexpected Retry-After header")
			}
		})
	}

	t.Run("non_verify_response", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		resp := &talosv2alpha1.IssueApiKeyResponse{}
		err := forwardRateLimitHeaders(ctx, rec, resp)
		require.NoError(t, err)

		snapshotter.SnapshotT(t, rateLimitHeaderSnapshot(rec.Header()))
		assert.Empty(t, rec.Header().Get("Ratelimit-Policy"))
		assert.Empty(t, rec.Header().Get("Ratelimit"))
		assert.Empty(t, rec.Header().Get("Retry-After"))
	})

	t.Run("nil_response", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		err := forwardRateLimitHeaders(ctx, rec, nil)
		require.NoError(t, err)

		snapshotter.SnapshotT(t, rateLimitHeaderSnapshot(rec.Header()))
		assert.Empty(t, rec.Header().Get("Ratelimit-Policy"))
	})
}

func TestCacheStatusHeaderMatcher(t *testing.T) {
	t.Parallel()

	// Verify all case variants of ory-talos-cache are forwarded as Ory-Talos-Cache.
	for _, key := range []string{"ory-talos-cache", "Ory-Talos-Cache", "ORY-TALOS-CACHE"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			out, match := cacheStatusHeaderMatcher(key)
			assert.True(t, match)
			assert.Equal(t, "Ory-Talos-Cache", out)
		})
	}

	// Non-cache headers are not matched by the cache-specific path.
	for _, key := range []string{"x-custom-internal", "unrelated-header"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			out, match := cacheStatusHeaderMatcher(key)
			assert.NotEqual(t, "Ory-Talos-Cache", out)
			_ = match // delegated to DefaultHeaderMatcher; not our concern to test here
		})
	}
}

func TestCustomErrorHandler_ResourceExhaustedMapsToTooManyRequests(t *testing.T) {
	t.Parallel()

	gw := &GatewayServer{writer: NewAIPWriter(testGatewayErrorWriter{}, "talos.ory.com")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v2alpha1/admin/apiKeys:verify", nil)

	gw.customErrorHandler(t.Context(), nil, nil, rec, req, status.Error(codes.ResourceExhausted, "request body too large"))

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	var resp struct {
		Error struct {
			Code   int    `json:"code"`
			Status string `json:"status"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, http.StatusTooManyRequests, resp.Error.Code)
	assert.Equal(t, "RESOURCE_EXHAUSTED", resp.Error.Status)
}

// reviewed - @aeneasr - 2026-03-26
