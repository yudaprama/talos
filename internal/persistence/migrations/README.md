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

1. **Keep migrations small and focused** - One logical change per migration
2. **Always provide down migrations** - Enable rollback capability
3. **Test both up and down** - Ensure migrations are reversible
4. **Use transactions** - Wrap DDL in BEGIN/COMMIT where supported
5. **Document breaking changes** - Add comments explaining complex migrations
