#!/usr/bin/env bash
# Bring the Superset + ch-jwt-verify stack up.
#
# Layers the platform compose file (../../_platform/docker/compose.yml,
# which brings up postgres + dex + clickhouse + ch-jwt-verify) under
# this directory's compose.yml (which adds superset-init + superset).
#
# Idempotent: re-run picks up where it left off.
set -euo pipefail

cd "$(dirname "$0")"

# Prefer the modern `docker compose` subcommand; fall back to the
# standalone `docker-compose` binary.
if docker compose version >/dev/null 2>&1; then
    DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    DC=(docker-compose)
else
    echo "error: neither 'docker compose' nor 'docker-compose' is on PATH" >&2
    exit 1
fi

# Materialise .env if missing. Only the secret needs randomness; the
# rest uses the documented defaults from .env.example.
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

# Stack composition is handled by compose.yml's `include:` directive,
# which pulls in ../../_platform/docker/compose.yml with paths anchored
# to each file's own directory. `docker-compose.override.yml` is picked
# up automatically when present (compose's built-in convention).
echo "→ ${DC[*]} up -d --wait"
"${DC[@]}" up -d --wait --wait-timeout 300

cat <<'EOF'

✓ stack up.

  Automated tests:  ./run-tests.sh
  Browser flow:     open http://localhost:8088
                    "Sign in with dex" → alice@example.com / alice
                    SQL Lab → "ClickHouse (oauth)" connection (pre-seeded)
                    → SELECT 1
  Tail sidecar:     docker compose logs -f ch-jwt-verify
  Tear down:        ./down.sh
EOF
