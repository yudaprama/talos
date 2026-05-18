#!/usr/bin/env bash
# Generate signing keys for multi-tenancy test fixtures
# This script generates test keys that are safe to commit to git.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGNING_KEYS_DIR="${SCRIPT_DIR}/signing-keys"

# Build talos if not already built (needed for key generation)
if [ ! -f "${SCRIPT_DIR}/../../../.bin/talos" ]; then
    echo "Building talos..."
    (cd "${SCRIPT_DIR}/../../.." && go build -o .bin/talos .)
fi

TALOS="${SCRIPT_DIR}/../../../.bin/talos"

# Create signing keys directory
mkdir -p "${SIGNING_KEYS_DIR}"

# Generate tenant1 EdDSA key
echo "Generating tenant1 EdDSA signing key..."
"${TALOS}" jwk generate eddsa \
    --kid "tenant1-eddsa-test-key" \
    --jwks \
    -o "${SIGNING_KEYS_DIR}/tenant1-ed25519.jwks.json"

# Generate tenant2 RSA key
echo "Generating tenant2 RSA signing key..."
"${TALOS}" jwk generate rsa \
    --kid "tenant2-rsa-test-key" \
    --alg RS256 \
    --jwks \
    -o "${SIGNING_KEYS_DIR}/tenant2-rsa.jwks.json"

echo "✓ Test signing keys generated successfully"
echo "  - ${SIGNING_KEYS_DIR}/tenant1-ed25519.jwks.json"
echo "  - ${SIGNING_KEYS_DIR}/tenant2-rsa.jwks.json"
