// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package main provides CLI documentation generation tool.
package main

import (
	"fmt"
	"os"

	"github.com/ory/x/clidoc"

	"github.com/ory-corp/talos/cmd"
)

func main() {
	// Create root command for documentation generation
	// Version info comes from internal/version package
	rootCmd := cmd.NewRoot()

	if err := clidoc.Generate(rootCmd, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %+v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stderr, "All files have been generated and updated.")
}

// reviewed - @aeneasr - 2026-03-25
