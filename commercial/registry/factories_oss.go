//go:build !commercial

package registry

import (
	"github.com/ory/talos/internal/persistence"
)

// DatabaseDriverFactories returns database driver factories for initialization.
// The base build returns an empty map; the PostgreSQL driver is wired directly
// in persistence.NewDriver. Proprietary factories (e.g. multi-tenant variants)
// are injected by commercial builds.
func DatabaseDriverFactories() map[string]persistence.Factory {
	return make(map[string]persistence.Factory)
}

// reviewed - @aeneasr - 2026-03-25
