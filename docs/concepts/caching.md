---
title: Caching and consistency
---

# Caching and consistency

Talos can cache verification results to reduce database load and improve latency.

## How it works

When caching is enabled, the first verification request for a key hits the database. Subsequent
requests within the cache TTL are served from cache without a database lookup.

## Cache types

| Type   | Scope       | Use case                            |
| ------ | ----------- | ----------------------------------- |
| Memory | Per-process | Single node or per-instance caching |
| Redis  | Shared      | Multi-instance deployments          |

## Invalidation on admin changes

Admin mutations invalidate the cached verification result for the affected key immediately, so a
change takes effect without waiting for the cache TTL. This covers revoke, update, rotate, and
delete of both issued and imported keys.

How immediate the change is depends on the cache backend:

| Backend  | Invalidation scope                                                                     |
| -------- | -------------------------------------------------------------------------------------- |
| `redis`  | Cluster-wide and immediate — every instance shares the same store.                     |
| `memory` | Immediate on the instance that processed the change; other instances wait for the TTL. |

For a multi-instance deployment that needs immediate admin revocation across all instances, use the
shared `redis` backend. With the per-process `memory` backend, a revoked key can still verify on
other instances until their cached entry expires (bounded by `cache.ttl`).

Self-service revocation uses the same invalidation path as admin changes: the cached entry is
evicted by `key_id`, so the same backend scope applies — immediate on the instance that handles it
and cluster-wide with `redis`, bounded by the TTL on other instances with the `memory` backend.

## Eventual consistency with the memory backend

With the `memory` backend across multiple instances, revocation is still bounded by the cache TTL on
instances other than the one that processed the change:

1. Admin revokes a key via `POST /v2alpha1/admin/issuedApiKeys/{id}:revoke` (or
   `POST /v2alpha1/admin/importedApiKeys/{id}:revoke` for imported keys)
2. The revocation takes effect in the database immediately
3. The instance that processed the request evicts its cached entry immediately
4. Other instances keep their own cached result until the entry expires
5. After TTL expiry, the next verification hits the database and returns `active: false`

## Cache bypass

To force a database lookup (bypassing cache), include the `Cache-Control: no-cache` header:

```bash
curl -X POST http://localhost:4420/v2alpha1/admin/apiKeys:verify \
  -H "Content-Type: application/json" \
  -H "Cache-Control: no-cache" \
  -d '{"credential": "..."}'
```

See the [quickstart revocation check](../quickstart/index.md) and the
[curl SDK reference](../integrate/sdk/curl.md) for tested examples using cache bypass.

## TTL guidelines

| TTL   | Trade-off                                         |
| ----- | ------------------------------------------------- |
| `1m`  | Fast revocation propagation, higher database load |
| `5m`  | Balanced (recommended default)                    |
| `30m` | Low database load, slower revocation propagation  |

See [Cache operations guide](../operate/cache/index.md) for configuration details.
