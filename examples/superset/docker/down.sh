#!/usr/bin/env bash
# Tear the stack down + remove named volumes (postgres + clickhouse data).
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

PLATFORM=../../_platform/docker/compose.yml
LOCAL=./compose.yml
OVERRIDE_ARGS=()
if [[ -f docker-compose.override.yml ]]; then
    OVERRIDE_ARGS=(-f docker-compose.override.yml)
fi

"${DC[@]}" -f "$PLATFORM" -f "$LOCAL" "${OVERRIDE_ARGS[@]}" down -v
echo "✓ stack down (volumes removed)"
