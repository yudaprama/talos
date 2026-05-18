package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"

	"github.com/ory-corp/talos/internal/contextx"

	"github.com/ory-corp/talos/internal/health"
	"github.com/ory-corp/talos/internal/testutil"
	"github.com/ory-corp/talos/internal/version"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

const exampleHost = "example.com"

func newTestGatewayServer(t *testing.T) *GatewayServer {
	t.Helper()
	writer := herodot.NewJSONWriter(nil)
	provider := testutil.NewTestProvider(t)
	healthChecker := health.NewChecker(writer)
	return NewGatewayServer(healthChecker, &talosv2alpha1.UnimplementedAPIKeysServer{}, writer, provider)
}

func TestHandleVersion_ResponseStructure(t *testing.T) {
	t.Parallel()

	srv := newTestGatewayServer(t)

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	srv.handleVersion(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp versionResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	assert.Equal(t, version.Version, resp.Version)
	assert.Equal(t, version.Commit, resp.Commit)
	assert.Equal(t, version.BuildTime, resp.BuildTime)
	assert.Len(t, resp.ConfigHash, 64, "SHA256 hex digest should be 64 characters")
}

func TestHandleVersion_Determinism(t *testing.T) {
	t.Parallel()

	srv := newTestGatewayServer(t)

	var firstHash string
	for i := range 10 {
		req := httptest.NewRequest(http.MethodGet, "/version", nil)
		req.Host = exampleHost
		rec := httptest.NewRecorder()

		srv.handleVersion(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)

		var resp versionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		if i == 0 {
			firstHash = resp.ConfigHash
		}
		assert.Equal(t, firstHash, resp.ConfigHash, "request %d should return the same hash", i)
	}
}

func TestHandleVersion_HostnameAffectsHash(t *testing.T) {
	t.Parallel()

	srv := newTestGatewayServer(t)

	getHash := func(host string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/version", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		srv.handleVersion(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp versionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.ConfigHash
	}

	hashA := getHash("host-a.example.com")
	hashB := getHash("host-b.example.com")

	assert.NotEqual(t, hashA, hashB, "different hostnames should produce different hashes")
}

func TestHandleVersion_XForwardedHostIgnoredWhenNotTrusted(t *testing.T) {
	t.Parallel()

	// Default test provider does NOT set trust_forwarded_host=true.
	srv := newTestGatewayServer(t)

	getHash := func(host, forwardedHost string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/version", nil)
		req.Host = host
		if forwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", forwardedHost)
		}
		rec := httptest.NewRecorder()
		srv.handleVersion(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp versionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.ConfigHash
	}

	// Without trust_forwarded_host=true, X-Forwarded-Host should be ignored.
	hashWithForwarded := getHash("host-a.example.com", "forwarded.example.com")
	hashWithoutForwarded := getHash("host-a.example.com", "")

	assert.Equal(t, hashWithForwarded, hashWithoutForwarded,
		"X-Forwarded-Host should be ignored when trust_forwarded_host is false")
}

func TestHandleVersion_XForwardedHostTrustedWhenConfigured(t *testing.T) {
	t.Parallel()

	// Create a server with trust_forwarded_host=true.
	writer := herodot.NewJSONWriter(nil)
	provider := testutil.NewTestProvider(t, configx.WithValues(map[string]any{
		"serve.http.trust_forwarded_host": true,
	}))
	healthChecker := health.NewChecker(writer)
	srv := NewGatewayServer(healthChecker, &talosv2alpha1.UnimplementedAPIKeysServer{}, writer, provider)

	getHash := func(host, forwardedHost string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/version", nil)
		req.Host = host
		if forwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", forwardedHost)
		}
		rec := httptest.NewRecorder()
		srv.handleVersion(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp versionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.ConfigHash
	}

	// With trust_forwarded_host=true, X-Forwarded-Host should override Host.
	hashWithForwarded := getHash("host-a.example.com", "forwarded.example.com")
	hashWithoutForwarded := getHash("host-a.example.com", "")

	assert.NotEqual(t, hashWithForwarded, hashWithoutForwarded,
		"X-Forwarded-Host should change the hash when trust_forwarded_host is true")

	// Two requests with same X-Forwarded-Host but different Host should produce the same hash.
	hashSameForwarded1 := getHash("host-a.example.com", "forwarded.example.com")
	hashSameForwarded2 := getHash("host-b.example.com", "forwarded.example.com")

	assert.Equal(t, hashSameForwarded1, hashSameForwarded2,
		"same X-Forwarded-Host should produce the same hash regardless of Host header")
}

func TestHandleVersion_TenantContextAffectsHash(t *testing.T) {
	t.Parallel()

	srv := newTestGatewayServer(t)

	getHash := func(nid uuid.UUID) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/version", nil)
		req.Host = "same-host.example.com"
		ctx := context.WithValue(req.Context(), contextx.NIDKey{}, nid)
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		srv.handleVersion(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var resp versionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.ConfigHash
	}

	hashDefault := getHash(uuid.Nil)
	hashTenant := getHash(uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111")))

	assert.NotEqual(t, hashDefault, hashTenant,
		"different tenant contexts should produce different hashes")
}

// reviewed - @aeneasr - 2026-03-26
