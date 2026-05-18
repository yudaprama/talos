#!/usr/bin/env bash
# Doctest setup: build Talos binary only (no server start).
set -euo pipefail
CGO_ENABLED=1 go build -o .bin/talos .
