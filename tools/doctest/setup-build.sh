#!/usr/bin/env bash
# Doctest setup: build Talos binary only (no server start).
set -euo pipefail
CGO_ENABLED=1 go build -o .bin/talos .

# Add .bin/ to PATH so subsequent doctest blocks can call "talos" directly.
echo "export PATH=$(pwd)/.bin:\$PATH" >> "$DOCTEST_ENV_FILE"
