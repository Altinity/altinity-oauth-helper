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

# Compose stack: platform + this consumer. The platform compose file
# also resolves its own relative paths from its own directory, so the
# bind mounts under `_platform/docker/` work even though we invoke
# compose from this directory.
PLATFORM=../../_platform/docker/compose.yml
LOCAL=./compose.yml
OVERRIDE_ARGS=()
if [[ -f docker-compose.override.yml ]]; then
    OVERRIDE_ARGS=(-f docker-compose.override.yml)
fi

echo "→ ${DC[*]} -f $PLATFORM -f $LOCAL up -d --wait"
"${DC[@]}" -f "$PLATFORM" -f "$LOCAL" "${OVERRIDE_ARGS[@]}" \
    up -d --wait --wait-timeout 300

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
