---
title: Error handling
description: Error response format, error codes, and retry logic
---

import Tabs from '@theme/Tabs'; import TabItem from '@theme/TabItem';

# Error handling

All Talos API errors follow a consistent JSON format. This guide covers the error response
structure, common error codes, and retry strategies.

<!-- doctest:setup:file tools/doctest/setup.sh -->
<!-- doctest:teardown:file tools/doctest/teardown.sh -->

## Error response format

Error responses follow the [Google AIP-193](https://google.aip.dev/193) format:

```json
{
  "error": {
    "code": 400,
    "message": "The API key format is invalid.",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "INVALID_API_KEY_FORMAT",
        "domain": "talos.ory.com"
      }
    ]
  }
}
```

| Field                    | Description                                                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| `error.code`             | HTTP status code                                                                                        |
| `error.message`          | Human-readable error description                                                                        |
| `error.status`           | Canonical status name from the gRPC status code (for example `INVALID_ARGUMENT`, `FAILED_PRECONDITION`) |
| `error.details[].reason` | Machine-readable error identifier (`google.rpc.ErrorInfo`)                                              |
| `error.details[].domain` | Service that produced the error                                                                         |

The `status` reflects the canonical gRPC status, so two errors that share an HTTP code remain
distinguishable — for example a state conflict returns `FAILED_PRECONDITION` while a duplicate
resource returns `ALREADY_EXISTS`, even though both use HTTP `409`.

## Verification errors

The verify endpoint (`POST /v2alpha1/admin/apiKeys:verify`) returns errors differently from admin
endpoints. Instead of an HTTP error, it returns `200 OK` with `is_valid: false` and a structured
error code:

```json
{
  "is_valid": false,
  "error_code": "VERIFICATION_ERROR_REVOKED",
  "error_message": "The API key has been revoked."
}
```

For the complete list of verification error codes (`VERIFICATION_ERROR_*`), see the
[error codes reference](../reference/error-codes.md#verification-error-codes).

## HTTP status codes

For the complete list of HTTP status codes and error IDs, see the
[error codes reference](../reference/error-codes.md).

Key categories:

- **4xx errors**: Client errors (bad request, not found, conflict). Fix the request before retrying.
- **5xx errors**: Server errors. Retry with exponential backoff.

## Retry strategy

### Safe to retry

- **503 Service Unavailable** — the server is temporarily overloaded. Retry with exponential
  backoff.
- **504 Gateway Timeout** — the request timed out. Retry with backoff.
- **Network errors** — connection refused, DNS failure, etc. Retry with backoff.

### Not safe to retry (without idempotency key)

- **409 Conflict** — the resource already exists. Check the response and adjust.
- **400 Bad Request** — fix the request before retrying.

### Idempotency key

When issuing API keys, you can include a `request_id` in the request body. This field is stored with
the key for client-side deduplication:

<!-- doctest:exec -->

<Tabs groupId="sdk" defaultValue="cli">
<TabItem value="cli" label="CLI">

```bash
# Note: request_id is only available via the HTTP API.
talos keys issue "my-service" --actor user_1 -e "$TALOS_URL"
```

</TabItem>
<TabItem value="curl" label="curl">

```bash
curl -s -X POST "$TALOS_URL/v2alpha1/admin/issuedApiKeys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-service",
    "actor_id": "user_1",
    "request_id": "unique-request-id-123"
  }' | jq .
```

</TabItem>
</Tabs>

The `request_id` is recorded in the key's metadata. The server does not enforce server-side
idempotent replay (sending the same `request_id` twice creates two keys).

## Recommended backoff

```
attempt 1: wait 100ms
attempt 2: wait 200ms
attempt 3: wait 400ms
attempt 4: wait 800ms
attempt 5: wait 1600ms (give up after this)
```

Add jitter (random 0-50% of the wait time) to avoid thundering herd effects.

## Next steps

- [Issue and verify](issue-and-verify.md) — verification response format
- [Batch operations](batch-operations.md) — partial failure handling
