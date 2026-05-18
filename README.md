# Ory Talos

API key management for high-throughput systems. Issue, verify, and revoke API keys at scale.

**[Documentation](./docs/index.md)** | **[Getting started](./docs/tutorials/getting-started.md)** |
**[CLI reference](./docs/reference/cli-reference.md)**

## Install

```bash
go install github.com/ory-corp/talos@latest
```

Or build from source:

```bash
git clone https://github.com/ory-corp/talos.git
cd talos
make build
```

## Quick start

Start the server:

```bash
.bin/talos serve
```

Create an API key:

```bash
curl -X POST http://localhost:4420/v2alpha1/admin/issuedApiKeys \
  -H "Content-Type: application/json" \
  -d '{"name": "my-key", "actor_id": "user-123", "scopes": ["read", "write"]}'
```

Verify a key:

```bash
curl -X POST http://localhost:4420/v2alpha1/admin/apiKeys:verify \
  -H "Content-Type: application/json" \
  -d '{"credential": "your-api-key-here"}'
```

## Docker quickstart

Run a complete demo environment with the Admin UI using Docker Compose. Both editions default to
demo mode (credentials-based login, no OAuth setup required).

**OSS edition** (SQLite, single-tenant):

```bash
docker-compose -f docker-compose.oss.yaml up --build
```

**Commercial edition** (Postgres, multi-tenant):

```bash
docker-compose -f docker-compose.commercial.yaml up --build
```

Access points:

- Admin UI: http://localhost:3001
- Backend API: http://localhost:8080
- Grafana: http://localhost:3005/

For commercial multi-tenant testing, add to `/etc/hosts`:

```
127.0.0.1 default.talos.local tenant1.talos.local tenant2.talos.local
```

## Architecture

Ory Talos is designed for systems that verify API keys across distributed infrastructure.

**API key verification is stateful.** API keys use a checksummed format that allows fast tampering
rejection before database lookup. Verification checks can be cached.

**Derived tokens are stateless.** You can mint short-lived JWT or macaroon tokens for intranet
authorization. Verify the API key at the edge or gateway, then use derived tokens for internal calls
without a database lookup. See [Token Derivation](./docs/token-derivation.md).

**Separate admin and self-service surfaces.** Key creation, revocation, derivation, and verification
run on the admin surface. The self-service surface exposes only proof-of-possession self-revocation
for credential holders. You can run them as one process or split them onto separate hosts so each
surface scales and is secured independently.

**Caching and eventual revocation.** Verification uses caches for speed. Revocation uses eventual
consistency because cached results expire on TTL or invalidation. Shorter TTLs reduce the window but
increase load. See [Caching Architecture](./docs/caching-architecture.md).

**Offline token derivation.** Long-lived API keys can derive short-lived tokens with reduced scope.
Agents and services mint their own restricted credentials without calling an auth server. Useful for
AI agents, CI/CD pipelines, and microservice-to-microservice auth.

**Code Stack.** This project uses SQLc for type-safe database access, Protocol Buffers for API
definitions, and Google AIP for API design. All APIs are exposed on a single port unless run as
separate commands (e.g., `talos serve`, `talos serve admin`).

**Versatile.** Ory Talos does not authorize requests to its admin API; you must place it behind an
API gateway or reverse proxy that handles authentication and authorization.

## Editions

Ory Talos ships in two editions with different architectural constraints.

### Open source

The open source edition runs as a **single instance** with an **embedded SQLite database**. This
architecture works well for:

- Local development and testing
- Hobby projects and prototypes
- Low-traffic applications with a handful of concurrent clients
- Self-contained deployments where you manage your own SQLite backups

The OSS edition includes the full API key lifecycle, JWT/macaroon derivation, and structured
logging. You get the complete feature set for credential management.

### Commercial

The commercial edition runs **multiple instances** against **external databases** (Postgres, MySQL,
CockroachDB). This architecture is required when you need:

- Horizontal scaling across multiple Ory Talos nodes
- High availability with database failover
- Production workloads where Ory Talos is in the critical path
- Multi-tenancy for SaaS platforms
- Distributed caching (Redis L2) for edge verification
- Zero-downtime schema migrations
- Prometheus metrics for request, latency, and cache observability
- OpenTelemetry tracing for distributed request traces

If your use case requires a "real" database with low latency and sustained concurrent load, the
commercial edition is not optional. The open source architecture cannot support this.

The commercial edition also includes an admin UI for key management.

```bash
# OSS
make build

# Commercial
make build-commercial
```

See [open core architecture](./docs/open-core-architecture.md) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `make verify` (all tests must pass)
5. Submit a pull request

## Next-generation Ory Stack

- SQLc for type-safe database access
- Protocol buffers for API definitions
- Google AIP for API design
- Expose all APIs on one port unless run as separate commands (e.g., `talos serve`,
  `talos serve admin`)
