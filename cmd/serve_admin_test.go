package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO Aren't we missing a test here? That this command actually works and doesnt expose any unintended endpoints?

func TestServeAdminCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newServeAdminCmd()

	t.Run("has correct use and description", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "admin", cmd.Use)
		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)
	})

	t.Run("has RunE set", func(t *testing.T) {
		t.Parallel()

		require.NotNil(t, cmd.RunE, "admin command must have RunE handler")
	})

	t.Run("creates independent instances", func(t *testing.T) {
		t.Parallel()

		cmd1 := newServeAdminCmd()
		cmd2 := newServeAdminCmd()
		assert.NotSame(t, cmd1, cmd2)
	})
}

// reviewed - @aeneasr - 2026-03-25
