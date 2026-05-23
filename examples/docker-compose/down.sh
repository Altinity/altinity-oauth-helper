#!/usr/bin/env bash
# Tear the stack down + remove its named volumes (postgres + clickhouse data).
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

"${DC[@]}" down -v
echo "✓ stack down (volumes removed)"
