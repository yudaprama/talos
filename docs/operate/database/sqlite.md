---
title: SQLite
---

# SQLite

SQLite is the default database for the OSS edition. It requires no external dependencies.

## Editions

Talos ships two SQLite drivers with different runtime behavior:

- **OSS** — single-tenant. The driver serializes all database access, so it does not support
  parallel requests. Suitable for development, prototypes, and low-traffic single-node deployments.
- **Commercial** — multi-tenant. The driver enables WAL so readers do not block writers and isolates
  data per tenant network. SQLite still serializes writes under a single-writer lock, but read
  throughput improves substantially.

Both editions use the `sqlite://` DSN scheme and share the same migrations.

## Configuration

```yaml
db:
  dsn: "sqlite:///var/lib/talos/data.db"
```

## Migrations

```bash
talos migrate up --database "sqlite:///var/lib/talos/data.db"
```

## Limitations

The points below describe SQLite as deployed by the OSS edition. The commercial SQLite driver
relaxes the read concurrency limits via WAL but keeps SQLite's single-writer lock and stays
single-node.

- Single-node only (no multi-instance deployments)
- OSS driver processes requests sequentially; no parallel reads or writes
- Write throughput limited by disk I/O
- Not suitable for [split admin and self-service deployments](../deploy/deployment-modes.md) unless
  co-located

For multi-tenant workloads or sustained concurrent traffic on SQLite, use the commercial edition.
