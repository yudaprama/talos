package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO Aren't we missing a test here? That this command actually works and doesn't expose any unintended endpoints?

func TestServePublicCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newServePublicCmd()

	t.Run("has correct use and description", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "public", cmd.Use)
		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)
	})

	t.Run("has RunE set", func(t *testing.T) {
		t.Parallel()

		require.NotNil(t, cmd.RunE, "public command must have RunE handler")
	})

	t.Run("creates independent instances", func(t *testing.T) {
		t.Parallel()

		cmd1 := newServePublicCmd()
		cmd2 := newServePublicCmd()
		assert.NotSame(t, cmd1, cmd2)
	})
}
