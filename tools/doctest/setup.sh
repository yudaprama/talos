#!/usr/bin/env bash
# Shared doctest setup: build, migrate, start Talos server.
# Exports TALOS_PID and TALOS_URL to $DOCTEST_ENV_FILE.
set -euo pipefail

# Kill any leftover server from a previous run
kill $(lsof -ti :14420) 2>/dev/null || true

# Build as "talos" so CLI examples in docs can call it directly.
# Skip the build if the binary is already up-to-date (e.g. when multiple
# docs files share this setup script and it runs more than once per job).
if [ ! -f .bin/talos ] || find . -name "*.go" -newer .bin/talos -not -path "./commercial/*" | grep -q .; then
  CGO_ENABLED=1 go build -o .bin/talos .
fi

# Add .bin/ to PATH so subsequent doctest blocks can call "talos"
echo "export PATH=$(pwd)/.bin:\$PATH" >> "$DOCTEST_ENV_FILE"

# Prepare runtime config with base64-encoded JWKS literal.
# The config schema only accepts base64:// URLs for JWKS sources.
JWKS_BASE64=$(base64 < tools/doctest/testdata/jwks.json | tr -d '\n')
sed "s|DOCTEST_JWKS_PATH|$JWKS_BASE64|" \
  tools/doctest/testdata/config.yaml > /tmp/doctest-talos-config.yaml

# Remove stale database and run migrations
rm -f /tmp/doctest-talos.db
./.bin/talos migrate up --database "sqlite:///tmp/doctest-talos.db"

# Start the server in the background
nohup ./.bin/talos serve --config /tmp/doctest-talos-config.yaml > /tmp/doctest-talos.log 2>&1 &
TALOS_PID=$!

# Export state for subsequent blocks
echo "export TALOS_PID=$TALOS_PID" >> "$DOCTEST_ENV_FILE"
echo "export TALOS_URL=http://127.0.0.1:14420" >> "$DOCTEST_ENV_FILE"

# Wait for the server to become healthy
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:14420/health/alive > /dev/null 2>&1; then
    echo "Server is ready"
    exit 0
  fi
  if ! kill -0 "$TALOS_PID" 2>/dev/null; then
    echo "Talos server exited during doctest setup" >&2
    cat /tmp/doctest-talos.log >&2
    exit 1
  fi
  sleep 1
done

echo "Talos server did not become ready during doctest setup" >&2
cat /tmp/doctest-talos.log >&2
exit 1
