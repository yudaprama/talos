package testserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfrastructureSetup(t *testing.T) {
	t.Parallel()

	t.Run("security headers applied", func(t *testing.T) {
		t.Parallel()

		ts := NewTestServer(t)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.HTTPURL+"/health/alive", nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.NotEmpty(t, resp.Header.Get("Strict-Transport-Security"))
		assert.NotEmpty(t, resp.Header.Get("Content-Security-Policy"))
	})
}
