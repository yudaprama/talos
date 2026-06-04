# Database Migrations

This directory contains database migration files for the Ory Talos.

## Architecture

The migration system supports both OSS and Enterprise editions with an extensible architecture:

### OSS Edition

- **Location**: `internal/persistence/migrations/sqlite/`
- **Database**: SQLite only
- **Usage**: Base migrations that work for all deployments

### Enterprise Edition

- **OSS Base**: Imports from `internal/persistence/migrations/`
- **Enterprise Extensions**: `proprietary/persistence/migrations/{db}/`
- **Databases**: SQLite, PostgreSQL, MySQL, CockroachDB

## Migration Merging

The Enterprise edition can optionally merge migrations from both OSS and proprietary sources:

```
Enterprise SQLite = OSS SQLite migrations + Proprietary SQLite migrations (if any)
```

This allows enterprise features to be additive without duplicating the base schema.

## Usage

### Running Migrations

```bash
# OSS (SQLite only)
./.bin/talos migrate up --database "sqlite3://app.db"

# Commercial (PostgreSQL)
./.bin/talos-commercial migrate up --database "postgres://user:pass@localhost/dbname"
```

## Best Practices

1. **One statement per schema-change file** - Every schema change must live in
   its own migration file containing exactly one statement. Talos applies
   migrations with `golang-migrate`, and backends differ in whether a migration
   file runs in a transaction: MySQL auto-commits each DDL statement, and
   CockroachDB restricts multiple schema changes per transaction. So a file with
   multiple statements that fails partway can leave the earlier statements
   applied while `golang-migrate` marks the version dirty without completing it.
   Re-running then replays the file, the already-applied statements error, and
   the migration is stuck until someone intervenes manually. One statement per
   file keeps each change atomic and safely re-runnable.
2. **Keep migrations small and focused** - One logical change per migration
3. **Always provide down migrations** - Enable rollback capability
4. **Test both up and down** - Ensure migrations are reversible
5. **Use transactions** - Wrap DDL in BEGIN/COMMIT where supported
6. **Document breaking changes** - Add comments explaining complex migrations
