---
title: Deploy
---

# Deploy

Talos can be deployed as a standalone binary, Docker container, or Kubernetes workload.

## Deployment options

| Method                      | Best for                            |
| --------------------------- | ----------------------------------- |
| [Docker](docker.md)         | Development, small-scale production |
| [Kubernetes](kubernetes.md) | Production with orchestration       |
| Binary                      | Custom deployments                  |

## Architecture options

| Topology                                | Edition    | Description                                             |
| --------------------------------------- | ---------- | ------------------------------------------------------- |
| Single-node                             | OSS        | One process serves both admin and self-service surfaces |
| [Deployment modes](deployment-modes.md) | Commercial | Independent admin and self-service deployments          |
| [Edge proxy](edge-proxy.md)             | Commercial | Self-service at the edge, admin in core                 |
