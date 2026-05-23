#!/usr/bin/env bash
# Bring the whole stack up. Idempotent: re-run picks up where it left off.
set -euo pipefail

cd "$(dirname "$0")"

# Prefer the modern `docker compose` subcommand; fall back to the
# standalone `docker-compose` binary. Quoting + word-splitting around
# the variable means it survives passing as an argv prefix.
if docker compose version >/dev/null 2>&1; then
    DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    DC=(docker-compose)
else
    echo "error: neither 'docker compose' nor 'docker-compose' is on PATH" >&2
    exit 1
fi

# Materialise .env if missing. Only the secret needs randomness; the rest
# uses the documented defaults from .env.example.
if [[ ! -f .env ]]; then
    echo "→ generating .env"
    SECRET_KEY="$(openssl rand -base64 42 | tr -d '\n')"
    sed "s|SUPERSET_SECRET_KEY=.*|SUPERSET_SECRET_KEY=${SECRET_KEY}|" \
        .env.example > .env
fi

# Legacy builder. The default BuildKit needs a privileged container to
# boot its `buildkitd` helper, which some hardened docker proxies refuse
# (`isolator: Privileged is not allowed`). DOCKER_BUILDKIT=0 falls back
# to the classic dockerd builder which works without privileges.
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0

echo "→ ${DC[*]} up -d --wait"
# --wait (Compose v2.6+) blocks until every service is healthy or the
# timeout fires; saves a polling loop.
"${DC[@]}" up -d --wait --wait-timeout 300

cat <<'EOF'

✓ stack up.

  Automated tests:  ./run-tests.sh
  Browser flow:     open http://localhost:8088
                    "Sign in with dex" → alice@example.com / alice
                    SQL Lab → add a ClickHouse database, then SELECT 1
  Tail sidecar:     docker compose logs -f ch-jwt-verify
  Tear down:        ./down.sh
EOF
