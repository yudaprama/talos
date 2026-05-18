package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/ory-corp/talos/commercial/config"
	"github.com/ory-corp/talos/internal/boot"
)

// newServeAdminCmd creates the serve admin command.
func newServeAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Run only the admin endpoints",
		Long: `WARNING: this command serves unauthenticated admin endpoints.
You are responsible for placing it behind a trusted network boundary that
authenticates and authorizes every admin request (for example, an IAM proxy,
mTLS gateway, or a reverse proxy with internal-only routing). Talos itself
adds no authN or authZ middleware on the admin surface.

Runs only the admin endpoints for API key and network management.

This mode is designed for internal tools, CI/CD, and operator workflows. It
exposes the full read/write management surface: API key creation, rotation,
revocation, verification, network management, and signing-key management.

Deploy this server behind a trusted network boundary (private VPC, admin
VLAN, or authenticating reverse proxy) — never expose it to the public
internet without an external authZ layer in front.`,
		Example:      exampleCommandPath,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			slog.WarnContext(cmd.Context(),
				"admin endpoints are exposed without built-in authentication; "+
					"ensure a trusted proxy or network boundary enforces authN and authZ before any traffic reaches this server")

			// Read config flag at execution time (after flag parsing)
			configFile, _ := cmd.Flags().GetString("config")
			provider, err := config.NewProvider(cmd.Context(), configFile)
			if err != nil {
				return err
			}
			return runServe(cmd.Context(), provider, boot.ModeAdmin)
		},
	}

	return cmd
}

// reviewed - @aeneasr - 2026-03-25
