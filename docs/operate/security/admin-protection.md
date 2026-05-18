---
title: Admin protection
---

# Admin protection

Talos exposes its admin surface (`/v2alpha1/admin/*`) **without any built-in authentication or
authorization**. You are responsible for placing the admin server behind a trusted proxy or network
boundary that authenticates and authorizes every request before it reaches Talos.

This page documents the supported deployment patterns. Pick one before sending admin traffic to a
Talos instance.

:::warning

Never expose `talos serve admin` directly to the public internet. Any request that reaches the admin
endpoints is treated as authorized.

:::

## Why Talos has no built-in admin authN

Talos is designed to compose with the identity, access, and gateway tooling you already run.
Embedding an authentication layer would force every operator to either:

- Adopt Talos's choice of identity provider, token format, and policy engine, or
- Bypass the embedded layer with another proxy in front, doubling the attack surface.

Instead, Talos accepts a hard contract: **the admin server trusts every incoming request.**
Operators enforce identity and policy in the layer they already operate.

## Deployment patterns

### Ory Network

Place Talos behind an Ory Network deployment configured with API token policies or session-based
authorization for the admin paths. The Ory Network gateway authenticates the caller and forwards a
verified principal header to Talos. No extra infrastructure is required.

### Reverse proxy with mTLS

Run a reverse proxy (Envoy, NGINX, HAProxy, Caddy) in front of `talos serve admin` and require
client certificates from every caller.

- Issue a private CA-signed client certificate to each operator and CI/CD identity that needs admin
  access.
- Terminate TLS and validate the client certificate at the proxy.
- Reject any request that does not present a valid certificate.

This pattern works well for internal-only admin access where every caller is known and certificate
distribution is automated.

### Cloud API gateway

Use a managed API gateway (AWS API Gateway, Google Cloud API Gateway, Azure API Management)
configured with an authorizer (IAM, OIDC, JWT) on the admin route prefix. Run Talos in a private
subnet so the gateway is the only public ingress.

- Configure the authorizer for `/v2alpha1/admin/*` to require a valid IAM principal, OIDC token, or
  signed JWT.
- Restrict the gateway -> Talos network path to a private interface (VPC link, private service
  connect, or equivalent).

### Internal-only network

For deployments where Talos serves only internal traffic, network controls can be sufficient on
their own:

- Bind `talos serve admin` to a private interface (no public listener).
- Restrict the network path with security groups, firewall rules, or a service mesh policy so only
  known internal services can reach the admin port.
- Pair this with an internal authenticating proxy if internal traffic itself is not implicitly
  trusted.

## Combining admin and self-service

If you also run `talos serve public` for proof-of-possession self-revocation, place that server
behind your **public** edge — it is designed to receive untrusted traffic and validates credentials
inline.

The two surfaces should be reachable on different hostnames, ports, or ingresses so that admin paths
cannot be reached from the public side even if configuration is misapplied.

## Verifying your boundary

Before sending production traffic, verify that the admin endpoints are unreachable from outside your
trusted boundary:

```bash
# From an unauthenticated network, this must be rejected at your proxy:
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://talos-admin.example.com/v2alpha1/admin/issuedApiKeys
# Expect: 401, 403, or a connection refused/network unreachable error.
```

A `200`, `404`, or `501` response from the admin endpoint without authentication is a
misconfiguration and must be fixed before going live.

## See also

- [Deployment modes](../deploy/deployment-modes.md) — admin-only, self-service-only, and all-in-one
  process layouts.
- [Security hardening](../security-hardening.md) — broader hardening guidance.
