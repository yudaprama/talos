package persistence

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence/sqlite"
)

func TestNewDriver_InjectedFactoryTakesPrecedence(t *testing.T) {
	t.Parallel()

	var called bool

	driver, err := NewDriver(
		t.Context(),
		"sqlite://"+t.TempDir()+"/should-not-be-opened.db?mode=ro",
		map[string]Factory{
			"sqlite": func(_ context.Context, _ string) (Persister, error) {
				called = true
				return sqlite.NewDriver(t.TempDir() + "/factory.db")
			},
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })

	assert.True(t, called)
}
