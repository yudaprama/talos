---
title: Monitoring
---

# Monitoring

Talos provides built-in observability through Prometheus metrics, OpenTelemetry tracing, and health
endpoints.

:::note

Prometheus metrics and OpenTelemetry tracing require the **Commercial edition**. OSS builds do not
start the metrics server and do not emit traces. Health checks are available in both editions.

:::

- [Prometheus metrics](metrics.md) (Commercial) — request counts, latencies, and pool sizes
- [OpenTelemetry tracing](tracing.md) (Commercial) — distributed request traces
- [Health checks](health-checks.md) — liveness and readiness probes
