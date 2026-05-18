# Ory Talos - Test Suite

## Test Organization

This directory contains **integration and end-to-end tests** for the Ory Talos.

**Unit and functional tests** are located alongside the code they test (e.g.,
`internal/cache/cache_test.go`).

### Directory Structure

```
test/
├── api/                         # End-to-end API tests (Go)
│   ├── setup_test.go           # Test suite setup, helpers, and fixtures
│   ├── admin_test.go           # Admin endpoint tests (gRPC and HTTP/REST)
│   ├── self_service_test.go    # Self-service endpoint tests (gRPC and HTTP/REST)
│   ├── self_revoke_test.go     # Proof-of-possession self-revocation tests
│   ├── workload_basic_test.go  # Developer workflow workload
│   ├── workload_gateway_test.go # API gateway authentication workload
│   └── workload_llm_test.go    # LLM agent initialization workload
├── load/                        # Load testing scripts (k6)
├── test_config.yaml            # Test configuration
└── README.md                   # This file
```

### Test File Organization

Tests are organized by **surface**: admin (management) versus self-service (public).

- **setup_test.go**: Suite definition, setup/teardown, HTTP helpers, assertion helpers.
- **admin_test.go**: Issue, revoke, derive tokens, verify, batch verify, scopes, metadata, audit
  events — over both gRPC and HTTP/REST.
- **self_service_test.go**: Self-service endpoint behaviour over both gRPC and HTTP/REST.
- **self_revoke_test.go**: Proof-of-possession self-revocation over the self-service endpoint.

### Workload Tests

Workload tests simulate realistic production usage patterns:

- **workload_basic_test.go**: Developer workflow (create, verify, derive, rotate keys)
- **workload_gateway_test.go**: High-throughput API gateway authentication with key rotation
- **workload_llm_test.go**: LLM agent initialization storm with burst token derivation

These tests are tagged with `//go:build !short` and are skipped when running with `-short` flag.

For detailed workload test documentation, see `docs/notes/WORKLOAD_TEST_SUMMARY.md`.

## Test Configuration

- `test_config.yaml` - Shared test configuration
- API tests use in-memory SQLite by default with `testutil.TestServer`
- All tests use `testify/suite` for setup/teardown and assertions
- Load tests may require external services (see individual test files)

## Running Tests

**API end-to-end tests:**

```bash
go test ./test/api/...              # All API tests
go test -race ./test/api/...        # With race detector
go test -v ./test/api/...           # Verbose output
```

**Run specific test suites:**

```bash
go test ./test/api/ -run TestGRPC_Admin            # gRPC admin tests
go test ./test/api/ -run TestGRPC_SelfService      # gRPC self-service tests
go test ./test/api/ -run TestHTTP_Admin            # HTTP admin tests
go test ./test/api/ -run TestHTTP_SelfService      # HTTP self-service tests
```

**Run workload tests:**

```bash
go test ./test/api/ -run TestDeveloperWorkflow         # Developer workflow
go test ./test/api/ -run TestAPIGatewayWorkload        # API gateway simulation
go test ./test/api/ -run TestLLMAgentInitializationStorm  # LLM agent burst
```

**Skip workload tests (fast):**

```bash
go test -short ./test/api/...     # Skips workload tests (build tag: !short)
```

**All tests (unit + integration + e2e):**

```bash
make test              # All tests
make verify            # Full verification including linting
```
