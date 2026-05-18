#!/usr/bin/env bash
# Shared doctest teardown: kill server, clean temp files.
kill $TALOS_PID 2>/dev/null || true
wait $TALOS_PID 2>/dev/null || true
rm -f /tmp/doctest-talos.db /tmp/doctest-talos-config.yaml /tmp/doctest-talos.log
