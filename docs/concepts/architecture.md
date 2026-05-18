---
title: Architecture
---

# Architecture

Talos splits API key handling into two surfaces: an **admin** surface for management and
verification, and a **self-service** surface for actions a credential holder can perform on their
own credential. Both surfaces ship in the same single binary; you choose which to expose by
selecting a server mode (see [Deployment modes](../operate/deploy/deployment-modes.md)).

## Admin surface

The admin surface handles every management operation: issuance, import, list, get, update, rotate,
revoke, derivation of tokens, JWKS, and credential **verification** (single and batch). The admin
surface has no built-in authentication — operators must place a trusted proxy or network boundary in
front of it (see [Admin protection](../operate/security/admin-protection.md)).

Endpoints: `/v2alpha1/admin/*`

## Self-service surface

The self-service surface exposes only **proof-of-possession self-revocation**. A credential holder
presenting their own credential can revoke it without admin involvement. The self-service surface is
designed to sit on the public network.

Endpoints: `/v2alpha1/apiKeys:selfRevoke`

## Request flow

```
Client --> Server (admin or self-service)
              |
              v
          Verifier --> Cache (hit?) --> Database --> Response
                         |                            ^
                         +-- cache hit ---------------+
```

1. Client sends a credential to the appropriate endpoint.
2. Talos identifies the credential type (issued, imported, JWT, macaroon).
3. For issued keys, the UUID is extracted from the token identifier.
4. For imported keys, a tenant-scoped SHA-512/256 hash is computed.
5. Database lookup (or cache hit) returns key metadata.
6. Response includes key status, owner, scopes, and metadata.

## Deployment topologies

| Topology             | Edition    | Description                                      |
| -------------------- | ---------- | ------------------------------------------------ |
| Single-node          | OSS        | One process serves both surfaces (`talos serve`) |
| Split admin / public | Commercial | Admin and self-service as separate deployments   |
| Edge proxy           | Commercial | Self-service at the edge with a local cache      |

Both modes share the same database. Caching (memory or Redis) minimizes database load on the
verification hot path.

## Ports

| Port | Purpose            |
| ---- | ------------------ |
| 4420 | HTTP API (default) |
| 4422 | Prometheus metrics |

## Design philosophy

### Separation of concerns

The system is divided into distinct layers:

- **Admin surface**: management operations and verification (CRUD for keys, rotation, import, token
  derivation, single and batch verify).
- **Self-service surface**: proof-of-possession self-revocation only.
- **Persistence layer**: database abstraction with pluggable drivers.
- **Cache layer**: performance optimization with multiple backends.

Splitting admin from self-service allows independent scaling and clear network boundaries.
Verification has its own SLO (\<3ms p99) regardless of which surface drives it.

### Production-first design

Inspired by proven systems like SpiceDB and Kubernetes:

- Hard isolation between admin and self-service surfaces.
- Comprehensive observability (metrics, traces, logs) built in from the start.
- Graceful degradation and failure handling.
- Zero-downtime deployments.

### Performance by default

- Self-contained tokens (JWT/macaroon) enable stateless verification.
- HMAC-SHA256 for fast revocation checks — not bcrypt, which would limit throughput to ~10 req/sec
  per core.
- LRU caching for hot paths.
- Minimal allocations in the verification path.

## System architecture

```
Clients (CLI, SDK, HTTP)
         |
         v
+----------------------------------+
|  HTTP Server (grpc-gateway)      |
|  Port: 4420                      |
+----------------------------------+
         |
         v
+----------------------------------+
|  Middleware                      |
|  Logging, Metrics, Tracing       |
+----------------------------------+
         |
   +-----+----------+
   |                 |
   v                 v
+-----------+  +---------------+
| Admin     |  | Self-service  |
| (mgmt +   |  | (self-revoke  |
|  verify)  |  |  only)        |
+-----------+  +---------------+
   |                 |
   v                 v
+----------------------------------+
|  Service Layer                   |
|  Business logic, Validation      |
+----------------------------------+
         |
   +-----+----------+
   |                 |
   v                 v
+-----------+  +-----------+
| Persist.  |  | Cache     |
| SQLite    |  | Memory    |
| PG/MySQL  |  | LRU       |
| CRDB      |  | Redis     |
+-----------+  +-----------+
```

All requests enter through a single HTTP server built on grpc-gateway (port 4420) and pass through
middleware for logging, metrics, and tracing before being routed to the admin or self-service
surface.

## Component overview

### HTTP server

The API layer uses grpc-gateway for HTTP/JSON routing with protobuf-based schemas. It serves both
surfaces through a single port, handles CORS and compression, and exposes OpenAPI documentation.

### Service layer

Business logic is split between the admin service (key lifecycle, import, verification, token
derivation, input validation) and the self-service type (proof-of-possession self-revocation). Both
share the same verifier implementation, which is optimized for the hot path with minimal
allocations.

### Persistence

Database access uses sqlc-generated type-safe queries with pluggable drivers:

- **SQLite** — OSS edition, zero-config, suitable for millions of keys.
- **PostgreSQL** — production workloads.
- **MySQL** — production workloads.
- **CockroachDB** — distributed deployments.

Schema changes are managed through versioned migrations using golang-migrate.

### Cache

The cache layer reduces database load on the verification path:

- **Memory LRU** (OSS) — local to each instance, configurable size limits.
- **Redis** (Commercial) — distributed, supports cluster and sentinel modes.
- **Hierarchical L1+L2** (Commercial) — memory for speed, Redis for shared state.

### Crypto

Talos supports multiple signing algorithms:

- **Ed25519 (EdDSA)** — default, fastest signing and smallest keys.
- **RSA-2048/4096 (RS256)** — legacy compatibility.
- **HMAC-SHA256** — used for API key revocation checks (\<1ms with constant-time comparison).

### Observability

Built-in instrumentation across three pillars:

- **Metrics** — Prometheus exposition on port 4422 with request latency histograms and error rate
  counters.
- **Tracing** — OpenTelemetry with W3C Trace Context propagation, configurable sampling, OTLP and
  Jaeger exporters.
- **Logging** — structured JSON logging via slog with correlation IDs and contextual fields.

## Scalability

### Small (\<1k RPS)

A single Talos instance handles both surfaces with SQLite and an in-memory LRU cache. No external
dependencies required.

- OSS edition sufficient.
- 1 CPU, 512MB RAM.
- Cost: $5-10/month.

### Medium (10-50k RPS)

Separate admin and self-service deployments behind a load balancer. PostgreSQL replaces SQLite for
durability. Redis provides shared caching across self-service instances.

- Commercial edition.
- Auto-scaling for the public-facing self-service fleet.
- Cost: $100-500/month.

### Large (200k+ RPS)

A cluster of stateless self-service instances with auto-scaling, backed by a distributed Redis cache
and PostgreSQL with read replicas and connection pooling. Supports multi-region deployment.

- Commercial edition.
- Regional self-service deployment.
- Cost: $1-5k/month.
