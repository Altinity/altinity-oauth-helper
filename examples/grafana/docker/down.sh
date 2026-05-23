#!/usr/bin/env bash
# Tear the stack down + remove named volumes (postgres + clickhouse +
# grafana data).
set -euo pipefail

cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then
    DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    DC=(docker-compose)
else
    echo "error: neither 'docker compose' nor 'docker-compose' is on PATH" >&2
    exit 1
fi

# Stack composition is via compose.yml's `include:` directive — pulls
# in ../../_platform/docker/compose.yml automatically. Any local
# docker-compose.override.yml is also picked up by convention.
"${DC[@]}" down -v
echo "✓ stack down (volumes removed)"
