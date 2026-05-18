// Package testhelper provides shared migration lifecycle helpers usable by both
// OSS (SQLite) and commercial (Postgres/MySQL/CockroachDB) edition tests.
//
// The listMigrationVersions, applyAllMigrations, applyMigrationsUpTo, and
// rollbackMigrations helpers remain per-edition because they are thin wrappers
// over golang-migrate with different migration FS sources. The introspection
// helpers (tableExists, columnExists) remain per-driver because they use
// driver-specific SQL (PRAGMA for SQLite, information_schema for Postgres/MySQL).
package testhelper

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/cockroachdb/errors"
	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Version returns the current migration version. Returns (0, false, nil) if no
// migrations have been applied yet.
func Version(t *testing.T, m *migrate.Migrate) (uint, bool, error) {
	t.Helper()

	version, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, errors.Wrap(err, "get migration version")
	}

	return version, dirty, nil
}

// SnapshotFor returns a cupaloy config that stores snapshots under
// testdataRoot/snapshots/version/dialect/table/.
func SnapshotFor(testdataRoot, version, dialect, table string) *cupaloy.Config {
	return cupaloy.New(
		cupaloy.CreateNewAutomatically(true),
		cupaloy.FailOnUpdate(true),
		cupaloy.SnapshotFileExtension(".json"),
		cupaloy.SnapshotSubdirectory(filepath.Join(testdataRoot, "snapshots", version, dialect, table)),
	)
}

// CompareWithFixture snapshots the JSON representation of actual under the
// given table and id. The nid string is replaced with "<test-nid>" so
// snapshots remain stable across test runs that use random NIDs.
func CompareWithFixture(t *testing.T, testdataRoot string, actual any, version, dialect, table, id, nid string) {
	t.Helper()
	data, err := json.MarshalIndent(actual, "", "  ")
	require.NoError(t, err)
	normalized := strings.ReplaceAll(string(data), nid, "<test-nid>")
	assert.NoErrorf(
		t,
		SnapshotFor(testdataRoot, version, dialect, table).SnapshotWithName(id, []byte(normalized)),
		"snapshot mismatch: %s/%s/%s/%s", version, dialect, table, id,
	)
}

// LoadFixtures reads the SQL fixture file for the given migration version and dialect,
// substitutes the {{.NID}} placeholder, and executes each statement against db.
// Falls back to the generic (no dialect suffix) file when a dialect-specific one is absent.
func LoadFixtures(t *testing.T, db *sql.DB, testdataRoot, version, dialect, nid string) {
	t.Helper()

	candidates := []string{
		filepath.Join(testdataRoot, fmt.Sprintf("%s_testdata.%s.sql", version, dialect)),
		filepath.Join(testdataRoot, fmt.Sprintf("%s_testdata.sql", version)),
	}

	var content []byte
	for _, path := range candidates {
		b, err := os.ReadFile(path) //nolint:gosec // test helper reads migration fixtures from a fixed testdata root

		if err == nil {
			content = b
			break
		}
	}
	require.NotNil(t, content, "no fixture file found for version %s dialect %s", version, dialect)

	sqlStr := strings.ReplaceAll(string(content), "{{.NID}}", nid)
	sqlStr = strings.ReplaceAll(sqlStr, "\r\n", "\n")

	for stmt := range strings.SplitSeq(strings.TrimRight(sqlStr, "\n\r "), ";\n") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		_, err := db.ExecContext(t.Context(), stmt)
		require.NoError(t, err, "execute fixture statement: %.80s", stmt)
	}
}
