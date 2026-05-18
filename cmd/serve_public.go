package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ory-corp/talos/commercial/config"
	"github.com/ory-corp/talos/internal/boot"
)

// newServePublicCmd creates the serve public command.
func newServePublicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "public",
		Short: "Run only the public-facing endpoints",
		Long: `Runs only the public-facing endpoints (currently: proof-of-possession self-revocation).

This mode is designed to sit on the public network with no admin privileges.
It does not expose any verification, issuance, or admin lifecycle endpoints.
Verification is admin-only and must be reached through 'talos serve admin'.

Cache configuration is read from the config file (cache.type, cache.ttl, etc.).`,
		Example:      exampleCommandPath,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read config flag at execution time (after flag parsing)
			configFile, _ := cmd.Flags().GetString("config")
			provider, err := config.NewProvider(cmd.Context(), configFile)
			if err != nil {
				return err
			}
			return runServe(cmd.Context(), provider, boot.ModePublic)
		},
	}

	return cmd
}

// reviewed - @aeneasr - 2026-03-25
