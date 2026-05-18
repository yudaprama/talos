package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO Aren't we missing a test here? That this command actually works and the ports are open etc

func TestNewServeRootCmd_HasSubcommands(t *testing.T) {
	t.Parallel()

	cmd := newServeRootCmd()
	require.NotNil(t, cmd)

	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 2)
	assert.Equal(t, "admin", subcommands[0].Name())
	assert.Equal(t, "public", subcommands[1].Name())
}

func TestServeCmd_MissingConfigFileReturnsError(t *testing.T) {
	t.Parallel()

	cmd := NewRoot()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"serve", "--config", filepath.Join(t.TempDir(), "missing.yaml")})

	err := cmd.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "create config provider")
}

func TestServeCmd_InvalidConfigReturnsError(t *testing.T) {
	t.Parallel()

	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(configFile, []byte("http:\n  addr: 42\n"), 0o600)
	require.NoError(t, err)

	cmd := NewRoot()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"serve", "--config", configFile})

	err = cmd.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "create config provider")
}
