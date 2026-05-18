package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/x/configx"

	"github.com/ory-corp/talos/internal/cachecontrol"
	"github.com/ory-corp/talos/internal/testutil"
)

func TestCacheControlContextPropagation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cacheControl string
		pragma       string
		expectBypass bool
	}{
		{
			name:         "no cache control - uses cache",
			cacheControl: "",
			pragma:       "",
			expectBypass: false,
		},
		{
			name:         "Cache-Control: no-cache - bypasses cache",
			cacheControl: "no-cache",
			pragma:       "",
			expectBypass: true,
		},
		{
			name:         "Cache-Control: no-store - bypasses cache",
			cacheControl: "no-store",
			pragma:       "",
			expectBypass: true,
		},
		{
			name:         "Pragma: no-cache - bypasses cache",
			cacheControl: "",
			pragma:       "no-cache",
			expectBypass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create a test handler that checks context directly
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check cache control in context directly
				shouldBypass := cachecontrol.ShouldBypassCache(r.Context())
				assert.Equal(t, tt.expectBypass, shouldBypass, "cache bypass mismatch")
				w.WriteHeader(http.StatusOK)
			})

			// Create gateway server with test handler
			server := &GatewayServer{
				mux: http.NewServeMux(),
			}
			server.mux.Handle("/test", testHandler)

			// Create request with cache control headers
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.cacheControl != "" {
				req.Header.Set("Cache-Control", tt.cacheControl)
			}
			if tt.pragma != "" {
				req.Header.Set("Pragma", tt.pragma)
			}

			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestExtractMetadata(t *testing.T) {
	t.Parallel()

	newSrv := func(trustForwardedHost bool) *GatewayServer {
		t.Helper()
		opts := []configx.OptionModifier{}
		if trustForwardedHost {
			opts = append(opts, configx.WithValues(map[string]any{
				"serve.http.trust_forwarded_host": true,
			}))
		}
		provider := testutil.NewTestProvider(t, opts...)
		return &GatewayServer{config: provider}
	}

	t.Run("forwards authorization header", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(false)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		md := srv.extractMetadata(context.Background(), req)
		assert.Equal(t, []string{"Bearer test-token"}, md["authorization"])
	})

	t.Run("forwards cache control headers", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(false)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")

		md := srv.extractMetadata(context.Background(), req)
		assert.Equal(t, []string{"no-cache"}, md["cache-control"])
		assert.Equal(t, []string{"no-cache"}, md["pragma"])
	})

	t.Run("forwards X-Forwarded-Host header when trusted", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(true)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-Host", "tenant-a.example.com")

		md := srv.extractMetadata(context.Background(), req)
		assert.Equal(t, []string{"tenant-a.example.com"}, md["x-forwarded-host"])
	})

	t.Run("ignores X-Forwarded-Host when not trusted", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(false)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Host = "real-host.example.com"
		req.Header.Set("X-Forwarded-Host", "attacker.example.com")

		md := srv.extractMetadata(context.Background(), req)
		// Should use the Host header, not the attacker's X-Forwarded-Host.
		assert.Equal(t, []string{"real-host.example.com"}, md["x-forwarded-host"])
	})

	t.Run("falls back to Host header", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(false)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Host = "example.com"

		md := srv.extractMetadata(context.Background(), req)
		assert.Equal(t, []string{"example.com"}, md["x-forwarded-host"])
	})

	t.Run("falls back to Host header when trusted but XFH absent", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(true)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Host = "example.com"

		md := srv.extractMetadata(context.Background(), req)
		assert.Equal(t, []string{"example.com"}, md["x-forwarded-host"])
	})

	t.Run("forwards request ID", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(false)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "req-12345")

		md := srv.extractMetadata(context.Background(), req)
		assert.Equal(t, []string{"req-12345"}, md["x-request-id"])
	})
}

// reviewed - @aeneasr - 2026-03-26
