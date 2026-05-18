package cmd

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"

	"github.com/ory-corp/talos/commercial/config"

	"github.com/ory-corp/talos/internal/boot"
	talosconfig "github.com/ory-corp/talos/internal/config"
	_ "github.com/ory-corp/talos/internal/metrics" // Register Prometheus metrics
)

const exampleCommandPath = `  {{ .CommandPath }}`

// newServeCmd creates the serve command with bound flag variables
func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Ory Talos server (all-in-one mode)",
		Long: `Starts the HTTP server for the API key service in all-in-one mode.

This mode runs both admin (management) and public endpoints in a single process.

For production deployments where admin and public surfaces should be
isolated (different network boundaries, different scaling profiles, etc.),
consider running them as separate processes:
- 'serve public' for public-facing endpoints only (no admin privileges)
- 'serve admin' for admin endpoints only (management and verification)`,
		Example:      exampleCommandPath,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read config flag at execution time (after flag parsing)
			configFile, _ := cmd.Flags().GetString("config")
			provider, err := config.NewProvider(cmd.Context(), configFile)
			if err != nil {
				return err
			}
			return runServe(cmd.Context(), provider, boot.ModeAllInOne)
		},
	}

	return cmd
}

// newServeRootCmd creates the serve command with all subcommands
func newServeRootCmd() *cobra.Command {
	serveCmd := newServeCmd()

	serveCmd.AddCommand(newServeAdminCmd())
	serveCmd.AddCommand(newServePublicCmd())

	return serveCmd
}

func runServe(ctx context.Context, provider talosconfig.ProviderInterface, mode boot.ServerMode) error {
	// Create context that cancels on signal (with cause set to the signal).
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Initialize server dependencies (NO config caching!)
	deps, cleanup, err := initializeServerDependencies(ctx, provider, mode)
	defer cleanup()
	if err != nil {
		return err
	}

	// Read server addresses dynamically from provider with context
	httpHost := provider.String(ctx, talosconfig.KeyServeHTTPHost)
	httpPort := provider.Int(ctx, talosconfig.KeyServeHTTPPort)
	metricsHost := provider.String(ctx, talosconfig.KeyServeMetricsHost)
	metricsPort := provider.Int(ctx, talosconfig.KeyServeMetricsPort)

	httpAddr := formatAddr(httpHost, httpPort)
	metricsAddr := formatAddr(metricsHost, metricsPort)

	httpServer, err := createHTTPServerWithMiddleware(ctx, httpAddr, deps)
	if err != nil {
		return errors.Wrap(err, "create HTTP server")
	}
	metricsServer := createMetricsHTTPServer(metricsAddr, deps.HealthChecker)

	// Start all servers using errgroup
	if err := runServersWithErrGroup(ctx, deps, httpServer, metricsServer); err != nil {
		// Only return error if it's not from context cancellation
		if !errors.Is(err, context.Canceled) {
			return err
		}
	}

	return nil
}

// reviewed - @aeneasr - 2026-03-25
