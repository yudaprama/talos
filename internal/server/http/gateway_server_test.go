package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGatewayServer_MultipleInstances verifies that multiple gateway server
// instances can be created without Prometheus metric registration conflicts.
// This was previously failing due to global registry usage.
func TestGatewayServer_MultipleInstances(t *testing.T) {
	t.Parallel()

	t.Run("Create multiple servers with isolated registries", func(t *testing.T) {
		t.Parallel()
		server1 := newTestGatewayServer(t)
		require.NotNil(t, server1)

		server2 := newTestGatewayServer(t)
		require.NotNil(t, server2)

		server3 := newTestGatewayServer(t)
		require.NotNil(t, server3)

		// Verify all servers are independent
		assert.NotSame(t, server1, server2)
		assert.NotSame(t, server2, server3)
		assert.NotSame(t, server1, server3)
	})

	t.Run("Server configuration is correct", func(t *testing.T) {
		t.Parallel()
		server := newTestGatewayServer(t)

		assert.NotNil(t, server.mux)
		assert.NotNil(t, server.healthChecker)
		assert.NotNil(t, server.writer)
		assert.NotNil(t, server.config)
	})
}

// reviewed - @aeneasr - 2026-03-26
