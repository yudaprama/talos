# Migrating existing Talos data: SQLite → PostgreSQL

Talos is now **PostgreSQL-only**. For a **fresh deployment** you do not need this
document — `talos migrate up --database $TALOS_DSN` creates the empty schema and
you are done.

This runbook is **only** for operators who have a live SQLite `talos.db` (e.g.
`~/.plano/run/talos/talos.db` or `<project>/data/talos.db`) holding API keys /
balances they must preserve.

## Tables to copy

| Table | Notes |
|---|---|
| `networks` | Single OSS row, id = `00000000-0000-0000-0000-000000000000`. Copy first (FK parent). |
| `issued_api_keys` | `scopes`, `metadata`, `allowed_cidrs` are JSON text → Postgres `JSONB`. |
| `imported_api_keys` | Same JSON columns; `key_id` is a SHA512/256 hash (not a UUID). |
| `actor_balances` | Metering balance cache (`quota`, `remaining` micros). |
| `api_key_usage` | Append-only ledger; `id` is an identity column in Postgres — **do not** copy the SQLite `id`, let Postgres regenerate, OR copy and re-sync the identity sequence (see below). |

Type differences handled by the new Postgres schema
(`internal/persistence/migrations/postgres/`):
- SQLite `DATETIME` text → Postgres `TIMESTAMPTZ`
- SQLite `JSON` text → Postgres `JSONB`
- SQLite `INTEGER PRIMARY KEY AUTOINCREMENT` → Postgres `BIGINT GENERATED ALWAYS AS IDENTITY`
- `nid` / `id` stay `VARCHAR(36)` (UUID stored as text) in both.

## Recommended: pgloader

[`pgloader`](https://pgloader.io/) converts SQLite types automatically and is the
least error-prone path.

```bash
# 1. Create the target schema first (so types/identity match the app exactly).
talos migrate up --database "$TALOS_DSN"

# 2. Load data only (skip pgloader's own DDL so it does not fight the migrations).
cat > talos.load <<'EOF'
LOAD DATABASE
  FROM   sqlite:///absolute/path/to/talos.db
  INTO   postgresql://user:pass@host:5432/talos

WITH    data only,
        include no drop,
        reset sequences

SET     search_path TO 'public';
EOF

pgloader talos.load
```

`reset sequences` re-syncs the `api_key_usage` identity so the next insert does
not collide with copied ids.

## Alternative: manual COPY / INSERT

If pgloader is unavailable, dump each table and reinsert. Key points:
- Insert `networks` **before** the keyed tables (FK `ON DELETE CASCADE`).
- Cast JSON columns explicitly on insert: `... $n::jsonb ...`.
- Parse SQLite datetime text into a real timestamp (e.g. `to_timestamp` or load
  via a script that scans into Go `time.Time`).
- For `api_key_usage`, either omit `id` (let the identity column assign) or copy
  it and then run:
  ```sql
  SELECT setval(
    pg_get_serial_sequence('api_key_usage','id'),
    (SELECT COALESCE(MAX(id),0) FROM api_key_usage)
  );
  ```

## Verify after migration

```sql
SELECT count(*) FROM issued_api_keys;
SELECT count(*) FROM imported_api_keys;
SELECT count(*) FROM actor_balances;
SELECT count(*) FROM api_key_usage;
```

Then start Talos against `TALOS_DSN` and confirm a known key verifies and that
`actor_balances.remaining` matches the pre-migration value for a sampled actor.
