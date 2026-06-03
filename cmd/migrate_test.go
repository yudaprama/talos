package cmd

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO We are missing migration tests for oss and commercial that actually test the migration e2e (migrate first, then run
// the test server for exmample and make one request.

// TestNewMigrateCmd_Structure tests the structure of the migrate command
func TestNewMigrateCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newMigrateCmd()

	t.Run("has correct use and short description", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "migrate", cmd.Use)
		assert.NotEmpty(t, cmd.Short)
		assert.Contains(t, strings.ToLower(cmd.Short), "migration")
	})

	t.Run("has long description", func(t *testing.T) {
		t.Parallel()

		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, strings.ToLower(cmd.Long), "migration")
	})

	t.Run("has all subcommands", func(t *testing.T) {
		t.Parallel()

		subcommands := make(map[string]bool)
		for _, subCmd := range cmd.Commands() {
			subcommands[subCmd.Use] = true
		}

		assert.True(t, subcommands["up"], "should have 'up' subcommand")
		assert.True(t, subcommands["down"], "should have 'down' subcommand")
		assert.True(t, subcommands["status"], "should have 'status' subcommand")
		assert.True(t, subcommands["force VERSION"], "should have 'force' subcommand")
		assert.Len(t, subcommands, 4, "should have exactly 4 subcommands")
	})

	t.Run("does not have a RunE function", func(t *testing.T) {
		t.Parallel()

		// Parent command should not be runnable, only subcommands
		assert.Nil(t, cmd.RunE)
		assert.Nil(t, cmd.Run)
	})
}

// TestNewMigrateUpCmd_Structure tests the structure of the migrate up command
func TestNewMigrateUpCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newMigrateUpCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "up", cmd.Use)
	})

	t.Run("has short and long descriptions", func(t *testing.T) {
		t.Parallel()

		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, strings.ToLower(cmd.Short), "migration")
		assert.Contains(t, strings.ToLower(cmd.Long), "migration")
	})

	t.Run("has database flag", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("database")
		require.NotNil(t, flag, "should have --database flag")
		assert.Empty(t, flag.DefValue, "database flag should have empty default")
		assert.NotEmpty(t, flag.Usage, "database flag should have usage text")
	})

	t.Run("has RunE function", func(t *testing.T) {
		assert.NotNil(t, cmd.RunE, "up command should be runnable")
	})
}

// TestNewMigrateDownCmd_Structure tests the structure of the migrate down command
func TestNewMigrateDownCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newMigrateDownCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "down", cmd.Use)
	})

	t.Run("has short and long descriptions", func(t *testing.T) {
		t.Parallel()

		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, strings.ToLower(cmd.Short), "rollback")
	})

	t.Run("has database flag", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("database")
		require.NotNil(t, flag, "should have --database flag")
		assert.Empty(t, flag.DefValue, "database flag should have empty default")
	})

	t.Run("has steps flag with default", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("steps")
		require.NotNil(t, flag, "should have --steps flag")
		assert.Equal(t, "1", flag.DefValue, "steps flag should default to 1")
		assert.NotEmpty(t, flag.Usage, "steps flag should have usage text")
	})

	t.Run("has RunE function", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, cmd.RunE, "down command should be runnable")
	})

	t.Run("warns about production usage", func(t *testing.T) {
		t.Parallel()

		longLower := strings.ToLower(cmd.Long)
		// Should warn users about careful production usage
		assert.True(
			t,
			strings.Contains(longLower, "careful") || strings.Contains(longLower, "production"),
			"should warn about careful production usage",
		)
	})
}

// TestNewMigrateStatusCmd_Structure tests the structure of the migrate status command
func TestNewMigrateStatusCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newMigrateStatusCmd()

	t.Run("has correct use", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "status", cmd.Use)
	})

	t.Run("has short and long descriptions", func(t *testing.T) {
		t.Parallel()

		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, strings.ToLower(cmd.Short), "status")
	})

	t.Run("has database flag", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("database")
		require.NotNil(t, flag, "should have --database flag")
	})

	t.Run("has RunE function", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, cmd.RunE, "status command should be runnable")
	})

	t.Run("describes output information", func(t *testing.T) {
		t.Parallel()

		longLower := strings.ToLower(cmd.Long)
		assert.Contains(t, longLower, "version", "should mention version information")
		assert.Contains(t, longLower, "dirty", "should mention dirty state")
	})
}

// TestNewMigrateForceCmd_Structure tests the structure of the migrate force command
func TestNewMigrateForceCmd_Structure(t *testing.T) {
	t.Parallel()

	cmd := newMigrateForceCmd()

	t.Run("has correct use with argument placeholder", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "force VERSION", cmd.Use)
	})

	t.Run("has short and long descriptions", func(t *testing.T) {
		t.Parallel()

		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, strings.ToLower(cmd.Short), "force")
	})

	t.Run("has database flag", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("database")
		require.NotNil(t, flag, "should have --database flag")
	})

	t.Run("requires exactly one argument", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, cmd.Args, "should have argument validator")
		// cobra.ExactArgs(1) validates at runtime, we just check it's set
	})

	t.Run("has RunE function", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, cmd.RunE, "force command should be runnable")
	})

	t.Run("includes warning about careful usage", func(t *testing.T) {
		t.Parallel()

		longLower := strings.ToLower(cmd.Long)
		assert.Contains(t, longLower, "warning", "should have warning")
		assert.True(
			t,
			strings.Contains(longLower, "careful") || strings.Contains(longLower, "caution"),
			"should warn about careful usage",
		)
	})

	t.Run("describes use cases", func(t *testing.T) {
		t.Parallel()

		longLower := strings.ToLower(cmd.Long)
		assert.Contains(t, longLower, "dirty", "should mention dirty state use case")
	})
}

// TestGetDatabaseDSN_FromFlag tests DSN retrieval from flag
func TestGetDatabaseDSN_FromFlag(t *testing.T) {
	// Do NOT call t.Parallel() - test uses t.Setenv() which modifies environment
	// and is incompatible with parallel execution

	// Clear environment to ensure we're testing flag-only behavior
	t.Setenv("DB_DSN", "")

	flagValue := "sqlite3://test.db"
	dsn, err := getDatabaseDSN(flagValue)

	require.NoError(t, err)
	assert.Equal(t, flagValue, dsn)
}

// TestGetDatabaseDSN_FromEnv tests DSN retrieval from environment variable
func TestGetDatabaseDSN_FromEnv(t *testing.T) {
	// Do NOT call t.Parallel() - test uses t.Setenv() which modifies environment
	// and is incompatible with parallel execution

	envDSN := "postgres://localhost/testdb"
	t.Setenv("DB_DSN", envDSN)

	// Pass empty flag value to test environment fallback
	dsn, err := getDatabaseDSN("")

	require.NoError(t, err)
	assert.Equal(t, envDSN, dsn)
}

// TestGetDatabaseDSN_MissingBoth tests error when neither flag nor env is set
func TestGetDatabaseDSN_MissingBoth(t *testing.T) {
	// Do NOT call t.Parallel() - test uses t.Setenv() which modifies environment
	// and is incompatible with parallel execution

	// Clear environment
	t.Setenv("DB_DSN", "")

	dsn, err := getDatabaseDSN("")

	require.Error(t, err)
	assert.Empty(t, dsn)
	assert.Contains(t, err.Error(), "database DSN not provided")
	assert.Contains(t, err.Error(), "--database")
	assert.Contains(t, err.Error(), "DB_DSN")
}

// TestGetDatabaseDSN_FlagOverridesEnv tests that flag takes precedence over environment
func TestGetDatabaseDSN_FlagOverridesEnv(t *testing.T) {
	// Do NOT call t.Parallel() - test uses t.Setenv() which modifies environment
	// and is incompatible with parallel execution

	flagValue := "sqlite3://flag.db"
	envValue := "sqlite3://env.db"

	t.Setenv("DB_DSN", envValue)

	dsn, err := getDatabaseDSN(flagValue)

	require.NoError(t, err)
	assert.Equal(t, flagValue, dsn, "flag should override environment variable")
	assert.NotEqual(t, envValue, dsn)
}

// TestMigrateCommands_HelpText validates help text for all migrate commands
func TestMigrateCommands_HelpText(t *testing.T) {
	t.Parallel()

	commands := map[string]*cobra.Command{
		"migrate":        newMigrateCmd(),
		"migrate up":     newMigrateUpCmd(),
		"migrate down":   newMigrateDownCmd(),
		"migrate status": newMigrateStatusCmd(),
		"migrate force":  newMigrateForceCmd(),
	}

	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.NotEmpty(t, cmd.Use, "Use should be set")
			assert.NotEmpty(t, cmd.Short, "Short description should be set")
			assert.NotEmpty(t, cmd.Long, "Long description should be set")

			// Long should be more detailed than short
			assert.Greater(t, len(cmd.Long), len(cmd.Short),
				"Long description should be more detailed than short")
		})
	}
}

// TestMigrateUpCmd_DSNSources tests different DSN source configurations
func TestMigrateUpCmd_DSNSources(t *testing.T) {
	t.Parallel()

	t.Run("accepts various DSN formats", func(t *testing.T) {
		t.Parallel()

		validDSNs := []string{
			"sqlite3://./data/test.db",
			"sqlite3://:memory:",
			"postgres://user:pass@localhost:5432/db",
			"mysql://user:pass@tcp(localhost:3306)/db",
		}

		for _, dsn := range validDSNs {
			t.Run(dsn, func(t *testing.T) {
				t.Parallel()

				result, err := getDatabaseDSN(dsn)
				require.NoError(t, err)
				assert.Equal(t, dsn, result)
			})
		}
	})
}

// TestMigrateDownCmd_StepsFlag tests the steps flag behavior
func TestMigrateDownCmd_StepsFlag(t *testing.T) {
	t.Parallel()

	cmd := newMigrateDownCmd()

	t.Run("default steps value is 1", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("steps")
		require.NotNil(t, flag)
		assert.Equal(t, "1", flag.DefValue)
	})

	t.Run("steps flag is integer type", func(t *testing.T) {
		t.Parallel()

		flag := cmd.Flags().Lookup("steps")
		require.NotNil(t, flag)
		assert.Equal(t, "int", flag.Value.Type())
	})
}

// TestMigrateDownCmd_RejectsNonPositiveSteps verifies the down command refuses
// non-positive --steps values. Without the guard, m.Steps(-steps) would
// double-negate a negative value and silently apply UP migrations. The guard
// runs before any database connection, so no DSN is required.
func TestMigrateDownCmd_RejectsNonPositiveSteps(t *testing.T) {
	t.Parallel()

	for _, steps := range []string{"-1", "0", "-5"} {
		t.Run("steps="+steps, func(t *testing.T) {
			t.Parallel()

			cmd := newMigrateDownCmd()
			cmd.SetArgs([]string{"--steps=" + steps})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--steps must be a positive number")
		})
	}
}

// TestMigrateForceCmd_ArgumentValidation tests force command argument requirements
func TestMigrateForceCmd_ArgumentValidation(t *testing.T) {
	t.Parallel()

	cmd := newMigrateForceCmd()

	t.Run("requires VERSION argument", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, cmd.Args, "should have argument validation")
		// The actual validation happens at runtime via cobra.ExactArgs(1)
		// We verify the command structure requires it
		assert.Contains(t, cmd.Use, "VERSION", "Use should indicate VERSION argument required")
	})
}

// TestMigrateCommands_DatabaseFlag tests database flag consistency across commands
func TestMigrateCommands_DatabaseFlag(t *testing.T) {
	t.Parallel()

	commands := []*cobra.Command{
		newMigrateUpCmd(),
		newMigrateDownCmd(),
		newMigrateStatusCmd(),
		newMigrateForceCmd(),
	}

	for i, cmd := range commands {
		t.Run(cmd.Use, func(t *testing.T) {
			t.Parallel()

			flag := cmd.Flags().Lookup("database")
			require.NotNil(t, flag, "command %d should have database flag", i)
			assert.Empty(t, flag.DefValue, "database flag should default to empty")
			assert.Equal(t, "string", flag.Value.Type(), "database flag should be string type")
		})
	}
}

// TestMigrateCommands_NoGlobalState tests that commands don't rely on global state
func TestMigrateCommands_NoGlobalState(t *testing.T) {
	t.Parallel()

	t.Run("commands can be created multiple times independently", func(t *testing.T) {
		t.Parallel()

		// Create multiple instances to ensure no shared state
		cmd1 := newMigrateCmd()
		cmd2 := newMigrateCmd()

		assert.NotSame(t, cmd1, cmd2, "should create independent instances")
		assert.Len(t, cmd1.Commands(), len(cmd2.Commands()),
			"both instances should have same subcommands")
	})

	t.Run("subcommands can be created independently", func(t *testing.T) {
		t.Parallel()

		up1 := newMigrateUpCmd()
		up2 := newMigrateUpCmd()

		assert.NotSame(t, up1, up2, "should create independent instances")

		// Modify one instance's flags shouldn't affect the other
		err := up1.Flags().Set("database", "test1")
		require.NoError(t, err)

		flag1 := up1.Flags().Lookup("database")
		flag2 := up2.Flags().Lookup("database")

		assert.Equal(t, "test1", flag1.Value.String())
		assert.Empty(t, flag2.Value.String(), "second instance should be unaffected")
	})
}

// reviewed - @aeneasr - 2026-03-25
