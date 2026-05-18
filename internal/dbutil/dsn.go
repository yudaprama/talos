// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dbutil

import (
	"net/url"
	"strings"
)

// StripPoolParams removes all application-level connection pool parameters from a DSN.
// These parameters are used by the application layer (database/sql, pgxpool) and should
// not be passed to the actual database connection, as the database won't recognize them.
//
// Removes:
//   - pool_mode: Custom parameter for pool type selection
//   - max_conns: database/sql max open connections
//   - max_idle_conns: database/sql max idle connections
//   - max_conn_lifetime: database/sql connection max lifetime
//   - max_conn_idle_time: database/sql connection max idle time
//   - conn_max_idle_time: Alternative spelling that ory/x might use
//   - pool_*: All pgxpool-specific parameters
//
// Returns the original DSN if it cannot be parsed or is empty.
func StripPoolParams(dsn string) string {
	if dsn == "" {
		return dsn
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return dsn // Return original if can't parse
	}

	query := u.Query()

	// Remove application-level pool parameters
	query.Del("pool_mode")          // Our custom parameter for pool type selection
	query.Del("max_conns")          // database/sql max open connections
	query.Del("max_idle_conns")     // database/sql max idle connections
	query.Del("max_conn_lifetime")  // database/sql connection max lifetime
	query.Del("max_conn_idle_time") // database/sql connection max idle time
	query.Del("conn_max_idle_time") // Alternative spelling that ory/x might use

	// Remove pgxpool-specific parameters (pool_*)
	for key := range query {
		if strings.HasPrefix(key, "pool_") {
			query.Del(key)
		}
	}

	u.RawQuery = query.Encode()
	return u.String()
}

// PrepareMySQLDSN removes the "mysql://" scheme prefix from a MySQL DSN.
// The Go MySQL driver expects DSN without the scheme prefix.
//
// Example:
//   - Input: "mysql://user:pass@tcp(localhost:3306)/db"
//   - Output: "user:pass@tcp(localhost:3306)/db"
//
// Returns the original DSN if it doesn't have the mysql:// prefix.
func PrepareMySQLDSN(dsn string) string {
	return strings.TrimPrefix(dsn, "mysql://")
}

// reviewed - @aeneasr - 2026-03-25
