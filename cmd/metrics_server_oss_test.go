//go:build !commercial

package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"

	"github.com/ory/talos/internal/health"
)

// TestOSSMetricsServerExposesPrometheus verifies that the metrics HTTP server
// exposes the Prometheus scrape endpoint (/metrics/prometheus) in OSS builds.
func TestOSSMetricsServerExposesPrometheus(t *testing.T) {
	t.Parallel()

	writer := herodot.NewJSONWriter(nil)
	healthChecker := health.NewChecker(writer)

	srv := createMetricsHTTPServer("unused-addr", healthChecker)
	require.NotNil(t, srv)

	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/metrics/prometheus", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "/metrics/prometheus should be exposed in OSS builds")
	assert.Contains(t, string(body), "# HELP", "response should contain Prometheus-formatted metrics")
}
