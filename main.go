// Package main provides the entry point for Ory Talos.
// See talos/AGENTS.md for development guidelines.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ory/x/cmdx"

	"github.com/ory-corp/talos/cmd"
)

func main() {
	// Create and execute root command
	// Version info comes from internal/version package (set by build flags)
	rootCmd := cmd.NewRoot()

	if err := rootCmd.Execute(); err != nil {
		// ErrNoPrintButFail means the command already communicated the failure
		// to the user via stderr; suppress the error message and just exit non-zero.
		if !errors.Is(err, cmdx.ErrNoPrintButFail) {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
