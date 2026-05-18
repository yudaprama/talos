//go:build !commercial

package cmd

import (
	"github.com/ory-corp/talos/internal/persistence/migrations"
)

var getMigrationsFS = migrations.GetMigrationsFS

// reviewed - @aeneasr - 2026-03-25
