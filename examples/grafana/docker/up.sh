#!/usr/bin/env bash
# Bring the Grafana + ch-jwt-verify stack up.
#
# Layers the platform compose file (../../_platform/docker/compose.yml,
# which brings up postgres + dex + clickhouse + ch-jwt-verify) under
# this directory's compose.yml (which adds the patched-plugin Grafana).
#
# First run takes ~3-5 minutes because the Altinity ClickHouse plugin
# is built from source against a local patch (the patch threads the
# per-user OAuth token into the plugin's outbound HTTP requests; see
# grafana/plugin/0001-jwt-as-password.patch). Subsequent runs are
# cached and come up in seconds.
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

# Materialise .env if missing. Nothing secret here — just the pinned
# upstream plugin tag — but the same idempotent shape as Superset's
# up.sh keeps the muscle memory consistent.
if [[ ! -f .env ]]; then
    echo "→ generating .env"
    cp .env.example .env
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
echo "→ ${DC[*]} up -d --wait (first build is ~3-5 minutes)"
"${DC[@]}" up -d --wait --wait-timeout 600

cat <<'EOF'

✓ stack up.

  Automated tests:  ./run-tests.sh
  Browser flow:     open http://localhost:3000
                    "Sign in with Dex" → alice@example.com / alice
                    Explore → "ClickHouse (oauth)" datasource (pre-provisioned)
                    → SELECT 1 AS one, currentUser() AS who
                    → expect: 1 | alice@example.com
  Tail sidecar:     docker compose logs -f ch-jwt-verify
  Tear down:        ./down.sh
EOF
