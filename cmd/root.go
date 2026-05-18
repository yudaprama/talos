package cmd

import (
	"fmt"
	"sync"

	"github.com/spf13/cobra"

	_ "github.com/ory-corp/talos/internal/metrics" // Register Prometheus metrics
	"github.com/ory-corp/talos/internal/version"

	"github.com/ory/x/cmdx"
)

var templatingOnce sync.Once

// NewRoot creates and returns the root command with all subcommands
func NewRoot() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "talos",
		Short: "High-performance multi-network API key service",
		Long: `API Key Service is a high-performance, multi-network service for managing
API keys with support for JWT tokens, JWKS, and various cryptographic algorithms.

It provides both admin and public APIs for comprehensive key management.`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version.Version, version.Commit, version.BuildTime),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Enable usage templating for Example fields (only once to avoid data race)
	templatingOnce.Do(func() {
		cmdx.EnableUsageTemplating(rootCmd)
	})

	// Setup persistent flags
	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.talos.yaml or ./config.yaml)")
	rootCmd.PersistentFlags().StringP("endpoint", "e", "http://localhost:4420", "HTTP server base URL including scheme, e.g. http://host:port (for client commands)")

	// Add all subcommands
	rootCmd.AddCommand(newKeysCmd())
	rootCmd.AddCommand(newMigrateCmd())
	rootCmd.AddCommand(newServeRootCmd())
	rootCmd.AddCommand(newJWKCmd())
	rootCmd.AddCommand(newProxyCmd())

	return rootCmd
}

// reviewed - @aeneasr - 2026-03-25
