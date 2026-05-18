#!/usr/bin/env bash
# run.sh — set up and run k6 load tests, both locally and in CI.
#
# In CI (CI=true or SKIP_DOCKER=true): expects Postgres already running at DB_DSN.
# Locally: starts a Docker container, tears it down on exit.
#
# Usage:
#   ./test/load/run.sh                   # local, starts Docker Postgres
#   SKIP_DOCKER=true ./test/load/run.sh  # local with existing Postgres
#   CI=true ./test/load/run.sh           # same as SKIP_DOCKER=true, used by GitHub Actions
#
# Environment:
#   TEST_PROFILE  smoke|load|stress (default: smoke)
#   AUTH_TOKEN    Bearer token for admin endpoints (default: test-token)

set -euo pipefail

# --- Configuration -----------------------------------------------------------

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-talos}"
DB_PASS="${DB_PASS:-talos}"
DB_NAME="${DB_NAME:-talos_test}"
DB_DSN="${DB_DSN:-postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable}"

SERVER_HOST="${SERVER_HOST:-0.0.0.0}"
SERVER_PORT="${SERVER_PORT:-4420}"
BASE_URL="${BASE_URL:-http://localhost:${SERVER_PORT}}"
AUTH_TOKEN="${AUTH_TOKEN:-test-token}"
TEST_PROFILE="${TEST_PROFILE:-smoke}"

DOCKER_CONTAINER="talos-loadtest"
TEST_DIR=".test"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${REPO_ROOT}/.bin/talos"
K6_SCRIPT="${REPO_ROOT}/test/load/k6_load_test.js"

# --- State tracking for cleanup ----------------------------------------------

DOCKER_STARTED=false
SERVER_PID=""

cleanup() {
  echo ""
  echo "--- Cleaning up ---"

  if [[ -n "$SERVER_PID" ]]; then
    echo "Stopping server (pid $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
  fi

  if [[ "$DOCKER_STARTED" == "true" ]]; then
    echo "Removing Docker container ${DOCKER_CONTAINER}..."
    docker rm -f "$DOCKER_CONTAINER" 2>/dev/null || true
  fi
}

trap cleanup EXIT

# --- Helpers -----------------------------------------------------------------

log() { echo "[run.sh] $*"; }
die() { echo "[run.sh] ERROR: $*" >&2; exit 1; }

wait_for_postgres() {
  log "Waiting for Postgres at ${DB_HOST}:${DB_PORT}..."
  for i in $(seq 1 30); do
    if PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c '\q' 2>/dev/null; then
      log "Postgres is ready."
      return 0
    fi
    log "  attempt $i/30..."
    sleep 1
  done
  die "Postgres did not become ready in time."
}

wait_for_server() {
  log "Waiting for server at ${BASE_URL}/health..."
  for i in $(seq 1 30); do
    if curl -sf "${BASE_URL}/health" > /dev/null 2>&1; then
      log "Server is ready."
      return 0
    fi
    log "  attempt $i/30..."
    sleep 1
  done
  die "Server did not become ready in time. Check ${TEST_DIR}/server.log."
}

# Helper: write a tenant-specific config file
write_tenant_config() {
  local file="$1"
  local prefix="$2"

  cat > "$file" << TENANT_EOF
credentials:
  issuer: "talos-ci-load-test"
  api_keys:
    default_ttl: "2160h"
    prefix:
      current: "${prefix}"
  derived_tokens:
    jwt:
      default_ttl: "1h"
      signing_keys:
        urls:
          - "file://${REPO_ROOT}/${TEST_DIR}/jwks.json"
    macaroon:
      prefix:
        current: "mc"

secrets:
  default:
    current: "test-secret-for-ci-load-testing-minimum-32-characters-long"
    retired: []
  hmac:
    current: "test-hmac-secret-for-ci-load-testing-minimum-32-chars"
    retired: []
TENANT_EOF
}

# --- Main --------------------------------------------------------------------

cd "$REPO_ROOT"
mkdir -p "$TEST_DIR"

# 1. Build
log "Building commercial binary..."
TAGS=commercial make build

# 2. Postgres: start Docker unless in CI or SKIP_DOCKER is set
if [[ "${CI:-false}" == "true" || "${SKIP_DOCKER:-false}" == "true" ]]; then
  log "Skipping Docker setup (CI or SKIP_DOCKER=true). Expecting Postgres at ${DB_HOST}:${DB_PORT}."
  wait_for_postgres
else
  log "Starting Postgres Docker container..."
  # Remove stale container if one exists from a previous interrupted run
  docker rm -f "$DOCKER_CONTAINER" 2>/dev/null || true

  docker run -d \
    --name "$DOCKER_CONTAINER" \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASS" \
    -e POSTGRES_DB="$DB_NAME" \
    -p "${DB_PORT}:5432" \
    postgres:16

  DOCKER_STARTED=true
  wait_for_postgres
fi

# 3. Generate signing keys
log "Generating JWKS..."
"$BINARY" jwk generate eddsa --output "${TEST_DIR}/jwks.json"

# 4. Write per-tenant config files
log "Writing tenant configs..."
write_tenant_config "${TEST_DIR}/tenant-default.yaml" "sk_test"
write_tenant_config "${TEST_DIR}/tenant-a.yaml" "ta_test"
write_tenant_config "${TEST_DIR}/tenant-b.yaml" "tb_test"

# 5. Write main config with multitenancy
log "Writing config..."
cat > "${TEST_DIR}/config.yaml" << EOF
serve:
  http:
    host: "${SERVER_HOST}"
    port: ${SERVER_PORT}
    cors:
      enabled: true
      allowed_origins:
        - "*"
  metrics:
    host: "0.0.0.0"
    port: 4422

db:
  dsn: "${DB_DSN}"

log:
  level: "warn"
  format: "json"

credentials:
  issuer: "talos-ci-load-test"
  api_keys:
    default_ttl: "2160h"
    prefix:
      current: "sk_test"
  derived_tokens:
    jwt:
      default_ttl: "1h"
      signing_keys:
        urls:
          - "file://${REPO_ROOT}/${TEST_DIR}/jwks.json"
    macaroon:
      prefix:
        current: "mc"

secrets:
  default:
    current: "test-secret-for-ci-load-testing-minimum-32-characters-long"
    retired: []
  hmac:
    current: "test-hmac-secret-for-ci-load-testing-minimum-32-chars"
    retired: []

multitenancy:
  enabled: true
  networks:
    - hostname: "localhost"
      id: "00000000-0000-0000-0000-000000000000"
      config_path: "${REPO_ROOT}/${TEST_DIR}/tenant-default.yaml"
    - hostname: "tenant-a.localhost"
      id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      config_path: "${REPO_ROOT}/${TEST_DIR}/tenant-a.yaml"
    - hostname: "tenant-b.localhost"
      id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      config_path: "${REPO_ROOT}/${TEST_DIR}/tenant-b.yaml"
EOF

# 6. Migrate
log "Running migrations..."
"$BINARY" migrate up --database "$DB_DSN"

# 7. Seed tenant networks
log "Seeding tenant networks..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -c "INSERT INTO networks (id, created_at, updated_at) VALUES
    ('00000000-0000-0000-0000-000000000000', NOW(), NOW()),
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', NOW(), NOW()),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', NOW(), NOW())
  ON CONFLICT DO NOTHING;"

# 8. Start server
log "Starting server..."
"$BINARY" serve --config "${TEST_DIR}/config.yaml" > "${TEST_DIR}/server.log" 2>&1 &
SERVER_PID=$!
wait_for_server

# 9. Run k6
log "Running k6 load tests (profile: ${TEST_PROFILE})..."
set +e  # allow k6 to exit non-zero without aborting the script immediately
k6 run \
  --env BASE_URL="$BASE_URL" \
  --env AUTH_TOKEN="$AUTH_TOKEN" \
  --env TEST_PROFILE="$TEST_PROFILE" \
  --out json="${TEST_DIR}/k6-results.json" \
  --summary-export="${TEST_DIR}/k6-summary.json" \
  "$K6_SCRIPT" 2>&1 | tee "${TEST_DIR}/k6-output.txt"
K6_EXIT=${PIPESTATUS[0]}
set -e

log "k6 exited with code ${K6_EXIT}."
log "Server log: ${TEST_DIR}/server.log"
log "k6 output:  ${TEST_DIR}/k6-output.txt"

exit "$K6_EXIT"
