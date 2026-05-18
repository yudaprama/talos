// Package health provides health check functionality for database connections.
package health

import (
	"database/sql"
	"net/http"

	"github.com/cockroachdb/errors"

	"github.com/ory/herodot"
	"github.com/ory/x/healthx"
)

// Checker aggregates readiness checks for health endpoints.
type Checker struct {
	readyCheckers map[string]healthx.ReadyChecker
	writer        herodot.Writer
}

// NewChecker returns a new Checker.
func NewChecker(writer herodot.Writer) *Checker {
	return &Checker{
		readyCheckers: make(map[string]healthx.ReadyChecker),
		writer:        writer,
	}
}

// AddReadyCheck registers a named readiness check.
func (c *Checker) AddReadyCheck(name string, checkFunc healthx.ReadyChecker) {
	c.readyCheckers[name] = checkFunc
}

// AddDatabaseCheck registers a database ping readiness check.
func (c *Checker) AddDatabaseCheck(db *sql.DB) {
	c.AddReadyCheck("database", func(r *http.Request) error {
		if err := db.PingContext(r.Context()); err != nil {
			return errors.Wrap(err, "database ping failed")
		}

		return nil
	})
}

// ReadyCheckers returns the registered readiness checks.
func (c *Checker) ReadyCheckers() healthx.ReadyCheckers {
	return c.readyCheckers
}

// Handler returns an HTTP handler serving health endpoints.
func (c *Checker) Handler() *healthx.Handler {
	return healthx.NewHandler(c.writer, "ory-talos", c.ReadyCheckers())
}

// reviewed - @aeneasr - 2026-03-25
