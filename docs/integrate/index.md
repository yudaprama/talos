---
title: Integrate
description: Add API key authentication to your application
---

# Integrate Ory Talos

Ory Talos exposes two HTTP surfaces that map to distinct responsibilities:

- **Admin** (`/v2alpha1/admin/...`) — issue, import, list, get, update, rotate, revoke, derive
  tokens, JWKS, and verify credentials (single and batch). Has no built-in authentication; deploy
  behind a trusted proxy or internal-only network. See
  [Admin protection](../operate/security/admin-protection.md).
- **Self-service** (`/v2alpha1/apiKeys:selfRevoke`) — proof-of-possession self-revocation. A
  credential holder can revoke their own credential without admin involvement. Designed to sit on
  the public network.

Most integrations follow a simple pattern: issue keys on the admin surface, verify them on the admin
surface every time a request arrives, and let credential holders self-revoke through the
self-service surface when needed.

## Common workflows

| Task                                    | Endpoint                                                                    | Guide                                   |
| --------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------- |
| Issue a key and verify it               | `POST /v2alpha1/admin/issuedApiKeys`, `POST /v2alpha1/admin/apiKeys:verify` | [Issue and verify](issue-and-verify.md) |
| Import keys from another system         | `POST /v2alpha1/admin/importedApiKeys`                                      | [Import keys](import-keys.md)           |
| Mint short-lived JWT or macaroon tokens | `POST /v2alpha1/admin/apiKeys:derive`                                       | [Derive tokens](derive-tokens.md)       |
| Verify many credentials at once         | `POST /v2alpha1/admin/apiKeys:batchVerify`                                  | [Batch operations](batch-operations.md) |
| Update, rotate, or revoke a key         | `PATCH`, `:rotate`, `:revoke`                                               | [Key lifecycle](key-lifecycle.md)       |
| Enforce per-key rate limits             | `rate_limit_policy` on issue/update                                         | [Rate limiting](rate-limiting.md)       |
| Let key holders revoke their own key    | `POST /v2alpha1/apiKeys:selfRevoke`                                         | [Self-revocation](self-revocation.md)   |
| Handle errors and retries               | All endpoints                                                               | [Error handling](error-handling.md)     |

## Authentication

The admin surface does not enforce authentication. You must protect it at the infrastructure level
(VPN, service mesh, reverse proxy with mTLS, IAM gateway) — see
[Admin protection](../operate/security/admin-protection.md). The self-service surface is
public-facing and requires no authentication; callers supply the credential they want to revoke.

## Request format

All endpoints accept and return JSON with `Content-Type: application/json`. Field names use
`snake_case` (for example `actor_id`, `key_id`, `expire_time`).

Durations accept both Go format (`168h`, `30m`, `1h30m`) and protobuf format (`604800s`).

Timestamps follow RFC 3339 in UTC (`2025-06-15T10:30:00Z`).

## SDK and examples

- [curl cheat sheet](sdk/curl.md) — every endpoint as a copy-paste curl command
- [Go SDK](sdk/go.md) — using the generated Go client
