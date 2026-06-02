# Talos Load Tests

k6 load tests for the Talos API key service. Tests cover the full API lifecycle: key creation,
verification, rotation, revocation, import, token derivation, and multi-tenant isolation.

## Prerequisites

- [k6](https://k6.io/docs/get-started/installation/)
- Docker (for local PostgreSQL) or an existing PostgreSQL instance
- Go toolchain

## Quick start

```bash
# Run smoke test (default)
bash test/load/run.sh

# Run load test
TEST_PROFILE=load bash test/load/run.sh

# Run stress test
TEST_PROFILE=stress bash test/load/run.sh
```

The `run.sh` script builds the commercial binary, starts PostgreSQL in Docker, runs migrations,
seeds multi-tenant data, starts the server, and executes k6. Cleanup is automatic on exit.

## Profiles

| Profile  | Read VUs        | Write VUs      | Duration | Purpose                          |
| -------- | --------------- | -------------- | -------- | -------------------------------- |
| `smoke`  | 1               | 1              | 15s      | Quick post-change validation     |
| `load`   | 15              | 5              | 2min     | Sustained regression detection   |
| `stress` | 0→105 (ramping) | 0→45 (ramping) | 5min     | Peak capacity and breaking point |

Select a profile with the `TEST_PROFILE` environment variable (default: `smoke`).

## Environment variables

| Variable                                              | Default                                                            | Description                              |
| ----------------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------- |
| `TEST_PROFILE`                                        | `smoke`                                                            | Profile: `smoke`, `load`, or `stress`    |
| `BASE_URL`                                            | `http://localhost:4420`                                            | Server URL                               |
| `AUTH_TOKEN`                                          | `test-token`                                                       | Bearer token for admin API               |
| `DB_DSN`                                              | `postgres://talos:talos@localhost:5432/talos_test?sslmode=disable` | Database URL                             |
| `SKIP_DOCKER`                                         | `false`                                                            | Skip Docker setup, use existing Postgres |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` | see `run.sh`                                                       | Individual DB connection params          |

## Test scenarios

Tests are split into concurrent read and write scenarios that run simultaneously.

### Read scenarios (~70% of VUs)

- **Verify API key** — single key verification via the admin verify endpoint
- **Batch verify** — batch verification (up to 100 keys per request)
- **Get key** — fetch key details by ID
- **List keys** — paginated key listing
- **JWKS** — fetch `derivedKeys/jwks.json`
- **Derive token** — JWT and macaroon derivation

### Write scenarios (~30% of VUs)

- **Create + rotate + revoke** — full key lifecycle
- **Import + self-revoke** — imported key lifecycle
- **Update key** — metadata updates

### Specialized scenarios (1 VU each)

- **NID isolation** — verifies cross-tenant isolation (tenant-a key must not verify on tenant-b)
- **Batch boundary** — tests batch size limits (101 keys → 400 error)

## Thresholds

### Smoke and load

| Metric      | Threshold |
| ----------- | --------- |
| Checks      | 100%      |
| HTTP errors | 0%        |
| Overall p99 | < 500ms   |
| Verify p95  | < 25ms    |
| Verify p99  | < 100ms   |

### Stress

| Metric      | Threshold |
| ----------- | --------- |
| Checks      | 100%      |
| HTTP errors | < 1%      |
| Overall p99 | < 400ms   |
| Verify p95  | < 100ms   |
| Verify p99  | < 200ms   |

## API coverage

All endpoints use v2alpha1 API paths:

### Admin

- `POST /v2alpha1/admin/issuedApiKeys` — create key
- `GET /v2alpha1/admin/issuedApiKeys/{id}` — get key
- `GET /v2alpha1/admin/issuedApiKeys` — list keys
- `PATCH /v2alpha1/admin/issuedApiKeys/{id}` — update key
- `POST /v2alpha1/admin/issuedApiKeys/{id}:rotate` — rotate key
- `POST /v2alpha1/admin/issuedApiKeys/{id}:revoke` — revoke issued key
- `POST /v2alpha1/admin/importedApiKeys` — import key
- `POST /v2alpha1/admin/importedApiKeys/{id}:revoke` — revoke imported key
- `POST /v2alpha1/admin/importedApiKeys:batchImport` — batch import
- `POST /v2alpha1/admin/apiKeys:verify` — verify key
- `POST /v2alpha1/admin/apiKeys:batchVerify` — batch verify
- `POST /v2alpha1/admin/apiKeys:derive` — derive token

### Public

- `GET /v2alpha1/derivedKeys/jwks.json` — JWKS

### Self-service

- `POST /v2alpha1/apiKeys:selfRevoke` — self-revoke

## Output

Results are saved to:

- `.test/k6-output.txt` — human-readable console output
- `.test/k6-results.json` — machine-readable JSON (for CI analysis)
- `.test/k6-summary.json` — k6 summary export

For detailed benchmark results and interpretation guidance, see the
[benchmarks documentation](../../docs/operate/benchmarks.md).
