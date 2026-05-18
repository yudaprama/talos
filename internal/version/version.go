// Package version provides build-time version information for the entire application.
// These values are set at build time via -ldflags and can be referenced from anywhere,
// including CLI commands, server startup logs, and Prometheus metrics.
package version

//nolint:gochecknoglobals // These variables are intentionally global and set by -ldflags at build time
var (
	// Version is the semantic version of the build (e.g., "1.0.0", "dev")
	Version = "dev"

	// Commit is the git commit hash of the build
	Commit = "unknown"

	// BuildTime is the timestamp when the binary was built
	BuildTime = "unknown"
)

// reviewed - @aeneasr - 2026-03-25
