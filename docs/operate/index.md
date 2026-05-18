---
title: Operate
description: Install, configure, and deploy Ory Talos
---

# Operate Ory Talos

This section covers everything platform engineers need to run Talos in production.

## Getting started

1. **[Install](install.md)** — build from source or download a binary
2. **[Configure](configure.md)** — set up the config file, environment variables, and secrets
3. **[Database](database/index.md)** — choose and configure a database backend
4. **[Deploy](deploy/index.md)** — run Talos with Docker, Kubernetes, or as a systemd service

## Production checklist

Before going to production, review these guides:

- **[Secrets management](secrets.md)** — configure HMAC secrets and JWKS signing keys
- **[TLS](tls.md)** — enable TLS termination or configure a reverse proxy
- **[Monitoring](monitoring/index.md)** — set up Prometheus metrics, OpenTelemetry tracing, and
  health checks
- **[Security hardening](security-hardening.md)** — production security checklist
- **[Benchmarks](benchmarks.md)** — performance baselines and load testing

## Commercial features

These features require the Commercial edition:

- **[PostgreSQL](database/postgresql.md)**, **[MySQL](database/mysql.md)**,
  **[CockroachDB](database/cockroachdb.md)** — production-grade SQL backends
- **[Caching](cache/index.md)** — in-memory and Redis caching for sub-millisecond verification
- **[Edge proxy](deploy/edge-proxy.md)** — deploy self-service at the edge
- **[Multi-tenancy](multi-tenancy.md)** — serve multiple tenants from a single cluster

## Architecture

Talos exposes two surfaces in a single binary:

- **Admin** — manages the key lifecycle and serves verification. Has no built-in authentication;
  must run behind a trusted proxy or internal-only network. See
  [Admin protection](security/admin-protection.md).
- **Self-service** — exposes proof-of-possession self-revocation to credential holders. Designed to
  sit on the public network.

You can run both surfaces in a single process (`talos serve`) or split them for production
(`talos serve admin`, `talos serve public`). See [Deployment modes](deploy/deployment-modes.md) for
details.
