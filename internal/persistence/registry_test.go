package persistence

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/persistence/postgres"
)

func TestNewDriver_InjectedFactoryTakesPrecedence(t *testing.T) {
	t.Parallel()

	var called bool

	// The DSN is never opened (pgx connects lazily) so this exercises only the
	// factory-precedence branch, not a live database.
	driver, err := NewDriver(
		t.Context(),
		"postgres://user:pass@localhost:5432/should-not-be-opened",
		map[string]Factory{
			"postgres": func(_ context.Context, _ string) (Persister, error) {
				called = true
				return postgres.NewDriver("postgres://user:pass@localhost:5432/factory")
			},
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	assert.True(t, called)
}
