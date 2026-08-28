#!/usr/bin/env bash
#
# integration/clickhouse/run-ha.sh
#
# Phase-5 Docker HA harness (issue #19 phase 5, plan §15-§19): brings up the
# same real-ClickHouse fixture as run.sh, except `ch-oauth-ldap` is now an
# HAProxy TCP frontend load-balancing across TWO independently running
# `ch-oauth-ldap` replicas, then proves live — via a persistent LDAP
# session probe and mechanical HAProxy stats-socket observation, never a
# fixed sleep — the claims in the plan's §19 "Docker HA claim boundary":
# two independent helpers both authenticate; no shared session/verifier/
# role-cache state is required for correctness; a killed replica's existing
# session fails outright rather than migrating to the survivor; fresh
# authentication keeps working through the survivor; and a recreated
# replica is re-admitted once its DNS name resolves again. See that
# section (and §25's high-risk invariant map) for exactly what this DOES
# NOT prove — Kubernetes ClusterIP/EndpointSlice/kube-proxy/CNI failover
# behavior needs the real-Kubernetes runbook (plan §20) instead.
#
# This is a manual, local gate, exactly like run.sh — not wired into any CI
# workflow. Run it before calling any change to `internal/ldap`'s
# connection-local-state invariants, `cmd/ch-oauth-ldap`'s HA-relevant
# wiring, or `integration/clickhouse/ha/**` done.
#
# Usage:
#   ./integration/clickhouse/run-ha.sh
#
# Same "never enable set -x" discipline as run.sh applies here (see that
# file's own header): this script and everything it sources handle raw
# JWTs, and never place one in argv, an exported environment variable, or a
# Docker `-e`/`exec` argument. The persistent session probe
# (ha/session-probe/main.go) enforces the same discipline independently —
# see its own package doc comment.
#
# ── One integration fixture owns the Docker daemon at a time ─────────────
# This fixture is COMPOSE_PROJECT_NAME="ch-phase5-ha" with its own
# ch-phase5-ha-auth-net/ch-phase5-ha-cluster-net networks — distinct names
# from run.sh's ch-phase3/ch-phase3-*-net — but it still refuses to start
# (see the preflight below) if the phase-3 fixture's containers or networks
# are present on this same Docker daemon, matching README.md's
# "Concurrency: one run per Docker daemon at a time" discipline exactly.

set -euo pipefail
umask 077

TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# HA-shaped active service array (plan §17.1): reassigned immediately after
# sourcing lib/common.sh, which is exactly what that file's own sourcing
# guard exists to survive — every helper below (wait_for_health,
# capture_diagnostics) derives its service count/list from this array
# rather than a hardcoded "all four"/"all six" phrase.
PHASE3_SERVICES=(synthetic-idp ch-oauth-ldap ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-origin clickhouse-remote)

# shellcheck source=lib/oauth.sh
source "$SCRIPT_DIR/lib/oauth.sh"
# shellcheck source=lib/leakscan.sh
source "$SCRIPT_DIR/lib/leakscan.sh"

# HA-shaped leak-scan arrays (plan §17.2): reassigned immediately after
# sourcing lib/leakscan.sh, under that file's own sourcing guard. A missing
# or empty A/B/HAProxy log, node log, or the session-probe transcript is
# now a hard failure of leakscan_require_artifacts_complete, not a
# trivially "clean" scan over a narrower corpus.
LEAKSCAN_COMPOSE_SERVICES=(ch-oauth-ldap ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-origin clickhouse-remote)
LEAKSCAN_NODES=(clickhouse-origin clickhouse-remote)
LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS=(session-probe.log)

# shellcheck source=lib/expectations.sh
source "$SCRIPT_DIR/lib/expectations.sh"

export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0

COMPOSE_FILE="$SCRIPT_DIR/compose-ha.yml"
COMPOSE_PROJECT_NAME="ch-phase5-ha"

# ── Preflight: refuse to run alongside the phase-3 fixture ───────────────
# Cheap, side-effect-free, and runs before any state this script owns
# exists — a die() here needs no cleanup. Matched by substring (docker's
# own --filter name= semantics), not an exact name, so it also catches a
# crashed phase-3 run's leftover containers/networks, not just a live one.
ha_preflight_no_phase3_collision() {
    local hits
    hits="$(docker ps -a --filter 'name=ch-phase3' --format '{{.Names}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: phase-3 fixture container(s) present on this Docker daemon ($hits) — the phase-3 and phase-5-HA fixtures must not run concurrently (README.md: 'Concurrency: one run per Docker daemon at a time'); tear down phase-3 first (docker rm -f the listed containers, then docker network rm ch-phase3-auth-net ch-phase3-cluster-net if they remain)"
    fi
    hits="$(docker network ls --filter 'name=ch-phase3-auth-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover phase-3 network '$hits' exists — remove it (docker network rm ch-phase3-auth-net) before running the HA fixture"
    fi
    hits="$(docker network ls --filter 'name=ch-phase3-cluster-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover phase-3 network '$hits' exists — remove it (docker network rm ch-phase3-cluster-net) before running the HA fixture"
    fi
    log "preflight: no phase-3 fixture collision detected — proceeding"
}
ha_preflight_no_phase3_collision

# ── Cleanup trap installed BEFORE any per-run state exists ────────────────
# Exactly the ordering discipline run.sh's own header explains at length
# (T9/finding-8/finding-9): install the trap first, so a SIGINT/SIGTERM at
# ANY later point is guaranteed to run cleanup(), then create RUN_TMP_DIR
# via a pre-computed candidate path (never a `$(mktemp -d ...)` command
# substitution — see run.sh's identical comment for why that specific
# construction closes an otherwise-real leak window). cleanup() below
# tolerates running with none, some, or all of ENV_FILE/RUN_TMP_DIR/
# FALLBACK_NETWORKS_CREATED set, for the same reason.
cleanup() {
    local rc=$?
    set +e
    log "cleanup: tearing down the compose project and removing generated material"
    if [ -n "${ENV_FILE:-}" ]; then
        local down_rc
        compose down -v --remove-orphans >/dev/null 2>&1
        down_rc=$?
        if [ "$down_rc" -ne 0 ]; then
            log "cleanup: WARNING — 'compose down -v --remove-orphans' exited $down_rc; containers/volumes of project $COMPOSE_PROJECT_NAME may be left behind (check 'docker ps -a --filter name=${COMPOSE_PROJECT_NAME}')"
        fi
    fi
    if [ "${FALLBACK_NETWORKS_CREATED:-0}" = "1" ]; then
        docker network rm ch-phase5-ha-auth-net ch-phase5-ha-cluster-net >/dev/null 2>&1 \
            || log "cleanup: WARNING — could not remove one or both hand-made fallback networks (ch-phase5-ha-auth-net, ch-phase5-ha-cluster-net); a later run tolerates pre-existing ones"
    fi
    if [ -n "${RUN_TMP_DIR:-}" ]; then
        rm -rf "$RUN_TMP_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT

RUN_TMP_DIR=""
for _run_tmp_attempt in {1..10}; do
    _run_tmp_candidate="$TMPDIR/ch-phase5-ha-run.$(gen_secret 8)"
    RUN_TMP_DIR="$_run_tmp_candidate"
    if mkdir -m 700 "$RUN_TMP_DIR" 2>/dev/null; then
        unset _run_tmp_candidate _run_tmp_attempt
        break
    fi
    RUN_TMP_DIR=""
done
if [ -z "$RUN_TMP_DIR" ]; then
    die "failed to create a unique run directory under $TMPDIR (ch-phase5-ha-run.*) after 10 attempts"
fi

ENV_FILE="$RUN_TMP_DIR/compose.env"
: >"$ENV_FILE"
chmod 600 "$ENV_FILE"

RUN_LOG="$RUN_TMP_DIR/run.log"
exec > >(tee -a "$RUN_LOG") 2>&1

log "run started; private per-run state under $RUN_TMP_DIR"

# PHASE3_CH_IMAGE/EXPECTED_CH_VERSION: same validation/derivation as run.sh
# (env var name deliberately unchanged — see compose-ha.yml's own header).
# This fixture does not itself run the per-build distributed-propagation
# scenarios (H/H'), but keeping this identical to run.sh means
# lib/expectations.sh's build-derived machinery stays usable/consistent if
# a future sub-task needs it here too.
PHASE3_CH_IMAGE="${PHASE3_CH_IMAGE:-altinity/clickhouse-server:24.8.11.51285.altinitystable}"
case "$PHASE3_CH_IMAGE" in
*@*) die "PHASE3_CH_IMAGE='$PHASE3_CH_IMAGE' is a digest reference; this suite needs a TAGGED image whose tag equals the server's version() string (e.g. altinity/clickhouse-server:24.8.11.51285.altinitystable)" ;;
*:*) : ;;
*) die "PHASE3_CH_IMAGE='$PHASE3_CH_IMAGE' has no tag; this suite needs a TAGGED image whose tag equals the server's version() string" ;;
esac
EXPECTED_CH_VERSION="${PHASE3_CH_IMAGE##*:}"

# ── HAProxy digest — the reproducibility invariant (plan §16.1) ──────────
# Resolved once, at implementation time, via `docker buildx imagetools
# inspect haproxy:lts-alpine` against the coordinator-approved
# `haproxy:lts-alpine` tag, then pinned here AND in the sandbox-fallback
# template generated below — never a floating tag in either definition.
# This constant is the SINGLE source both definitions read from, so the
# assertion right after it is a live proof (every run, not just at review
# time) that compose-ha.yml's own literal has not drifted from it.
HAPROXY_DIGEST_IMAGE="haproxy@sha256:ac78ddd4921742360f533c28d24ecd0a003ea8065e2bfd5697c565ce1427f4b0"

ha_assert_haproxy_digest_parity() {
    local real_ref
    real_ref="$(command grep -oE 'haproxy@sha256:[0-9a-f]+' "$SCRIPT_DIR/compose-ha.yml" | head -n1)"
    [ -n "$real_ref" ] || die "compose-ha.yml has no 'haproxy@sha256:...' image reference — cannot verify digest parity"
    [ "$real_ref" = "$HAPROXY_DIGEST_IMAGE" ] \
        || die "HAProxy digest MISMATCH: compose-ha.yml pins '$real_ref' but run-ha.sh's own HAPROXY_DIGEST_IMAGE constant (used to build the sandbox-fallback template) is '$HAPROXY_DIGEST_IMAGE' — these must be the identical digest; update whichever one drifted"
    log "HAProxy digest parity: compose-ha.yml and run-ha.sh's fallback-template constant both pin $HAPROXY_DIGEST_IMAGE"
}
ha_assert_haproxy_digest_parity

# ── Fresh per-run interserver secret ──────────────────────────────────────
# Same env var NAME as run.sh (PHASE3_CLUSTER_SECRET, never renamed) — see
# compose-ha.yml's header: clickhouse/common/config.d/remote_servers.xml,
# mounted unmodified here too, literally names
# <secret from_env="PHASE3_CLUSTER_SECRET"/>.
PHASE5_HA_CLUSTER_SECRET="$(gen_secret 32)"
printf 'PHASE3_CLUSTER_SECRET=%s\n' "$PHASE5_HA_CLUSTER_SECRET" >>"$ENV_FILE"
unset PHASE5_HA_CLUSTER_SECRET

printf 'PHASE3_CH_IMAGE=%s\n' "$PHASE3_CH_IMAGE" >>"$ENV_FILE"

# ── Sandbox/CI network-isolator compatibility fallback ────────────────────
# Mirrors run.sh's own bring_up_fixture/bring_up_fixture_fallback exactly
# (see that file's extensive header comments for the full rationale) but
# reshaped for this fixture's six services and two HA-only network names.
FALLBACK_NETWORKS_CREATED=0
USING_FALLBACK=0

bring_up_fixture_fallback() {
    local shared_net="${DOCKER_NETWORK:-iso-altinity}"
    local repo_root
    repo_root="$(cd "$SCRIPT_DIR/../.." && pwd)"

    FALLBACK_COMPOSE_FILE="$RUN_TMP_DIR/fallback-compose-ha.yml"
    {
        printf 'services:\n'
        printf '  synthetic-idp:\n'
        printf '    build:\n'
        printf '      context: %s\n' "$repo_root"
        printf '      dockerfile: integration/clickhouse/Dockerfile\n'
        printf '    image: altinity-oauth-helper-phase3-helper:local\n'
        printf '    command: ["/bin/synthetic-idp"]\n'
        printf '    environment:\n'
        printf '      ISSUER: http://synthetic-idp/\n'
        printf '      AUDIENCE: clickhouse\n'
        printf '      LISTEN: :80\n'
        printf '    networks: [shared]\n'
        printf '    ports:\n'
        printf '      - "127.0.0.1:${PHASE3_IDP_PORT:-18080}:80"\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "curl", "-fsS", "http://127.0.0.1/healthz"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  ch-oauth-ldap-a:\n'
        printf '    build:\n'
        printf '      context: %s\n' "$repo_root"
        printf '      dockerfile: integration/clickhouse/Dockerfile\n'
        printf '    image: altinity-oauth-helper-phase3-helper:local\n'
        printf '    command: ["/bin/ch-oauth-ldap", "--config", "/etc/ch-oauth-ldap/config.yaml"]\n'
        printf '    volumes:\n'
        printf '      - %s/helper/config.yaml:/etc/ch-oauth-ldap/config.yaml:ro\n' "$SCRIPT_DIR"
        printf '    networks: [shared]\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "nc", "-z", "127.0.0.1", "389"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  ch-oauth-ldap-b:\n'
        printf '    build:\n'
        printf '      context: %s\n' "$repo_root"
        printf '      dockerfile: integration/clickhouse/Dockerfile\n'
        printf '    image: altinity-oauth-helper-phase3-helper:local\n'
        printf '    command: ["/bin/ch-oauth-ldap", "--config", "/etc/ch-oauth-ldap/config.yaml"]\n'
        printf '    volumes:\n'
        printf '      - %s/helper/config.yaml:/etc/ch-oauth-ldap/config.yaml:ro\n' "$SCRIPT_DIR"
        printf '    networks: [shared]\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "nc", "-z", "127.0.0.1", "389"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  ch-oauth-ldap:\n'
        printf '    image: %s\n' "$HAPROXY_DIGEST_IMAGE"
        printf '    volumes:\n'
        printf '      - %s/ha/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro\n' "$SCRIPT_DIR"
        printf '    networks: [shared]\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD-SHELL", "echo '"'"'show info'"'"' | socat stdio UNIX-CONNECT:/var/lib/haproxy/haproxy.sock | grep -q '"'"'^Uptime_sec'"'"'"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  clickhouse-origin:\n'
        printf '    image: %s\n' "$PHASE3_CH_IMAGE"
        printf '    volumes:\n'
        printf '      - %s/clickhouse/common/config.d:/etc/clickhouse-server/config.d:ro\n' "$SCRIPT_DIR"
        printf '      - %s/clickhouse/common/users.d:/etc/clickhouse-server/users.d:ro\n' "$SCRIPT_DIR"
        printf '    environment:\n'
        printf '      PHASE3_CLUSTER_SECRET: ${PHASE3_CLUSTER_SECRET:?PHASE3_CLUSTER_SECRET must be set by run-ha.sh}\n'
        printf '    networks: [shared]\n'
        printf '    ports:\n'
        printf '      - "127.0.0.1:${PHASE3_CH_HTTP_PORT:-18123}:8123"\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  clickhouse-remote:\n'
        printf '    image: %s\n' "$PHASE3_CH_IMAGE"
        printf '    volumes:\n'
        printf '      - %s/clickhouse/common/config.d:/etc/clickhouse-server/config.d:ro\n' "$SCRIPT_DIR"
        printf '      - %s/clickhouse/common/users.d:/etc/clickhouse-server/users.d:ro\n' "$SCRIPT_DIR"
        printf '    environment:\n'
        printf '      PHASE3_CLUSTER_SECRET: ${PHASE3_CLUSTER_SECRET:?PHASE3_CLUSTER_SECRET must be set by run-ha.sh}\n'
        printf '    networks: [shared]\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf 'networks:\n'
        printf '  shared:\n'
        printf '    external: true\n'
        printf '    name: %s\n' "$shared_net"
    } >"$FALLBACK_COMPOSE_FILE"
    chmod 600 "$FALLBACK_COMPOSE_FILE"

    COMPOSE_FILE="$FALLBACK_COMPOSE_FILE"
    USING_FALLBACK=1

    # Bring up every service EXCEPT HAProxy first, reshape THEIR network
    # membership onto the real auth-net/cluster-net, and only THEN bring up
    # HAProxy (separately, below). This ordering matters: HAProxy's
    # `resolvers docker` performs its first DNS lookup for
    # ch-oauth-ldap-a/ch-oauth-ldap-b the moment its own process starts. If
    # HAProxy started concurrently with everyone else (a single `compose up`
    # for all six services), its first lookup would resolve their addresses
    # on the SHARED network — the only network they have at that instant —
    # and then, once the reshape below moves them onto auth-net (a
    # DIFFERENT address), HAProxy would keep trusting that now-stale answer
    # for up to `hold valid`/`hold obsolete` (ha/haproxy.cfg: 10s/30s —
    # deliberately long so a genuinely killed backend reads as a
    # health-check DOWN rather than a DNS-outage MAINT state; see that
    # file's own header) before ever re-querying. Reproduced live: bringing
    # up all six services together made the initial `show stat` gate below
    # take right up to its 30s bound before A/B ever reported UP. Starting
    # HAProxy only after A/B already have their FINAL auth-net address
    # removes the need for any such wait entirely — verified live, this
    # reordering brings the initial UP/UP observation down to seconds again.
    log "fallback: docker compose up --build -d for every service except HAProxy (single shared network: $shared_net)"
    compose up --build -d synthetic-idp ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-origin clickhouse-remote

    log "fallback: creating the real auth-net/cluster-net networks and reshaping the non-HAProxy services onto them"
    FALLBACK_NETWORKS_CREATED=1
    local net
    for net in ch-phase5-ha-auth-net ch-phase5-ha-cluster-net; do
        if docker network inspect "$net" >/dev/null 2>&1; then
            log "fallback: network $net already exists (left over from an earlier run?) — reusing it"
        else
            docker network create "$net" >/dev/null
        fi
    done

    local svc cname
    for svc in synthetic-idp ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-origin; do
        cname="$(container_name_for "$svc")"
        docker network connect --alias "$svc" ch-phase5-ha-auth-net "$cname"
    done
    for svc in clickhouse-origin clickhouse-remote; do
        cname="$(container_name_for "$svc")"
        docker network connect --alias "$svc" ch-phase5-ha-cluster-net "$cname"
    done
    # Only disconnect the services with NO published host port
    # (ch-oauth-ldap-a, ch-oauth-ldap-b, clickhouse-remote) from the shared
    # network — synthetic-idp and clickhouse-origin keep their
    # shared-network membership because Docker's published-port NAT rule is
    # tied to the network a container had at creation time (identical
    # reasoning to run.sh's own fallback; see that file's comment on this
    # exact point).
    for svc in ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-remote; do
        cname="$(container_name_for "$svc")"
        docker network disconnect "$shared_net" "$cname"
    done
    log "fallback: non-HAProxy network reshape complete — clickhouse-remote/ch-oauth-ldap-a/ch-oauth-ldap-b now match compose-ha.yml's auth-net/cluster-net design exactly"

    log "fallback: docker compose up --build -d for HAProxy (ch-oauth-ldap), now that ch-oauth-ldap-a/b already have their final auth-net address"
    compose up --build -d ch-oauth-ldap
    cname="$(container_name_for ch-oauth-ldap)"
    docker network connect --alias ch-oauth-ldap ch-phase5-ha-auth-net "$cname"
    docker network disconnect "$shared_net" "$cname"
    log "fallback: HAProxy reshape complete — ch-oauth-ldap now matches compose-ha.yml's auth-net design exactly"
}

# ── Test hook (used only by tests/cases/ha-fallback-parity.sh) ───────────
# Identical mechanism to run.sh's PHASE3_TEST_INVOKE_FALLBACK hook: lets a
# daemon-free shell test exercise this fallback's exact Docker/Compose call
# sequence and generated compose content under a stub `docker` binary, with
# no real daemon involved and none of this script's later stages running.
if [ -n "${PHASE5_HA_TEST_INVOKE_FALLBACK:-}" ]; then
    bring_up_fixture_fallback
    if [ -n "${PHASE5_HA_TEST_FALLBACK_COMPOSE_COPY:-}" ]; then
        cp "$FALLBACK_COMPOSE_FILE" "$PHASE5_HA_TEST_FALLBACK_COMPOSE_COPY"
    fi
    log "test hook: bring_up_fixture_fallback completed; exiting before the real health gate/bootstrap/HA flow"
    exit 0
fi

bring_up_fixture() {
    local attempt_log="$RUN_TMP_DIR/compose-up-attempt1.log"
    local up_rc

    set +e
    compose up --build -d 2>&1 | tee "$attempt_log"
    up_rc=${PIPESTATUS[0]}
    set -e

    if [ "$up_rc" -eq 0 ]; then
        rm -f "$attempt_log"
        return 0
    fi

    if ! grep -q 'isolator:.*not allowed' "$attempt_log"; then
        die "docker compose up --build -d failed for a reason other than the sandbox network isolator; see the output above"
    fi
    rm -f "$attempt_log"

    log "docker compose up was rejected by this host's Docker network isolator (only \"${DOCKER_NETWORK:-iso-altinity}\" is a permitted container network here) rather than by a real fixture problem; engaging the sandbox compatibility fallback"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    bring_up_fixture_fallback
}

log "bringing up the HA fixture (docker compose up --build -d)"
bring_up_fixture

# ── Rootless-port preflight (plan §16.2) ──────────────────────────────────
# HAProxy runs as the image's own unprivileged `haproxy` user and binds
# :389 directly — no root, no added Linux capability. That only works if
# the container's own user-namespace-visible
# /proc/sys/net/ipv4/ip_unprivileged_port_start permits an unprivileged
# bind at or below 389. Fail loudly here, before even attempting the health
# gate, if it does not — no root/capability workaround is acceptable (see
# the plan: "Fail the fixture if not; do not add root/capability
# workarounds").
ha_rootless_port_preflight() {
    local deadline=20 start=$SECONDS cid port_start
    while [ $((SECONDS - start)) -lt "$deadline" ]; do
        cid="$(compose ps -q ch-oauth-ldap 2>/dev/null || true)"
        [ -n "$cid" ] && break
        sleep 1
    done
    [ -n "$cid" ] || die "rootless-port preflight: the ch-oauth-ldap (HAProxy) container never appeared — cannot read its /proc/sys/net/ipv4/ip_unprivileged_port_start"

    port_start="$(compose exec -T ch-oauth-ldap cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>&1)" \
        || die "rootless-port preflight: could not read /proc/sys/net/ipv4/ip_unprivileged_port_start inside the HAProxy container (it may have exited — an unprivileged :389 bind failure is fatal to the haproxy master process); output: $port_start"
    case "$port_start" in
    '' | *[!0-9]*) die "rootless-port preflight: unexpected non-numeric sysctl value '$port_start'" ;;
    esac

    if [ "$port_start" -gt 389 ]; then
        die "rootless-port preflight FAILED: this container's ip_unprivileged_port_start=$port_start forbids an unprivileged bind to :389; refusing to add a root/capability workaround (see plan §16.2) — reconfigure the Docker host's net.ipv4.ip_unprivileged_port_start to <= 389 (or 0) before running this fixture"
    fi
    log "rootless-port preflight PASSED: ip_unprivileged_port_start=$port_start permits an unprivileged bind to :389"
}
ha_rootless_port_preflight

log "waiting for the mechanical health gate (deadline 180s, ${#PHASE3_SERVICES[@]} services)"
wait_for_health 180 || die "one or more services never became healthy; see diagnostics above"

log "host -> origin HTTP reachability check"
curl -fsS "http://127.0.0.1:${PHASE3_CH_HTTP_PORT}/ping" >/dev/null \
    || die "curl http://127.0.0.1:${PHASE3_CH_HTTP_PORT}/ping failed after the health gate passed"

# ── RBAC bootstrap ─────────────────────────────────────────────────────────
# Only common.sql is needed here (roles ch_readonly/ch_engineer/
# ch_distributed_reader) — this fixture proves HA authentication/session
# affinity, not distributed-role propagation (that is run.sh's scenario H/H'
# territory), so remote.sql's distributed-probe tables and origin.sql's
# local-precedence admin user are deliberately not applied.
log "bootstrap: common.sql on both nodes"
ch_admin_exec_file clickhouse-origin "$SCRIPT_DIR/bootstrap/common.sql"
ch_admin_exec_file clickhouse-remote "$SCRIPT_DIR/bootstrap/common.sql"
log "bootstrap complete"

# ── HAProxy stats-socket helpers (plan §16.5) ─────────────────────────────
# All mechanical: every state assertion below reads HAProxy's own runtime
# stats socket via `show stat`/`show info` (through socat, already present
# in the Official image), or the helper's own Bind-success log lines
# (identical technique to run.sh's scenario H) — never a fixed sleep
# standing in for an actual observation.
ha_show_stat() {
    compose exec -T ch-oauth-ldap sh -c "printf 'show stat\n' | socat stdio UNIX-CONNECT:/var/lib/haproxy/haproxy.sock" 2>/dev/null || true
}

# haproxy_backend_status SERVER — prints the CSV "status" field (column 18)
# of ldap_back/SERVER's row, or empty if the row is absent (e.g. HAProxy
# itself is not yet reachable).
haproxy_backend_status() {
    local server="$1"
    ha_show_stat | awk -F, -v px="ldap_back" -v sv="$server" '$1==px && $2==sv {print $18}'
}

haproxy_wait_status() {
    local server="$1" expected="$2" deadline="${3:-20}" start=$SECONDS status
    while [ $((SECONDS - start)) -lt "$deadline" ]; do
        status="$(haproxy_backend_status "$server")"
        if [ "$status" = "$expected" ]; then
            printf '%s' "$status"
            return 0
        fi
        sleep 1
    done
    return 1
}

log "HA: checking initial HAProxy backend state via show stat"
haproxy_wait_status ch-oauth-ldap-a UP 30 >/dev/null \
    || die "HA: helper A never reached HAProxy status UP within the bound (last seen: '$(haproxy_backend_status ch-oauth-ldap-a)')"
haproxy_wait_status ch-oauth-ldap-b UP 30 >/dev/null \
    || die "HA: helper B never reached HAProxy status UP within the bound (last seen: '$(haproxy_backend_status ch-oauth-ldap-b)')"
log "HA: show stat confirms A=UP B=UP"

# ── Helper Bind-count helpers (same ANSI-stripping technique as run.sh's
# scenario H — ch-oauth-ldap's zerolog console writer colorizes each
# key=/value token pair separately, splicing an SGR reset between '=' and
# the value) ────────────────────────────────────────────────────────────
ha_strip_ansi() {
    sed -E $'s/\x1b\\[[0-9;]*m//g'
}

# capture_bind_counts SERVICE — prints "SUCCESS_COUNT FAILED_COUNT" for
# SERVICE's own compose log (a fresh, full capture each call — `compose
# logs` always returns the whole buffered log, never just what's new, so
# every "delta" in this file is re-derived by subtracting two full
# captures, exactly like run.sh's scenario H).
capture_bind_counts() {
    local svc="$1" logf succ fail rc
    logf="$(mktemp "$RUN_TMP_DIR/bindcount.XXXXXX.log")"
    set +e
    compose logs --no-color "$svc" >"$logf" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die "capture_bind_counts: 'compose logs $svc' failed (rc=$rc) — cannot derive a trustworthy Bind count"
    succ="$(ha_strip_ansi <"$logf" | { grep -c -F 'ldap bind succeeded' || true; })"
    fail="$(ha_strip_ansi <"$logf" | { grep -c -F 'ldap bind failed' || true; })"
    rm -f "$logf"
    printf '%s %s\n' "$succ" "$fail"
}

# capture_bind_counts_into SERVICE VAR_SUCC VAR_FAIL — assigns
# capture_bind_counts' two numbers into the NAMED variables VAR_SUCC/
# VAR_FAIL. Deliberately NOT written as
# `read -r a b <<<"$(capture_bind_counts svc)"` at any call site: a
# command-substitution subshell's `die` (== `exit 1`) only terminates that
# subshell, and bash's `set -e` only propagates a command substitution's
# exit status into the ENCLOSING command when that substitution is itself
# the value of a bare assignment (`x="$(cmd)"`) — never when it merely
# feeds a `<<<` here-string into `read`, whose own exit status is what
# `set -e` actually observes there. Splitting into a bare intermediate
# assignment first (which DOES propagate a die() correctly) and only then
# feeding that already-captured string into `read` is what makes a
# capture_bind_counts failure actually abort this script instead of
# silently continuing with two empty counts.
capture_bind_counts_into() {
    local svc="$1" var_succ="$2" var_fail="$3" _bc
    _bc="$(capture_bind_counts "$svc")"
    read -r "$var_succ" "$var_fail" <<<"$_bc"
}

# ── §18.2: prove both replicas independently authenticate ────────────────
log "HA: proving both helpers independently serve fresh Binds (bounded fresh ClickHouse authentications)"
capture_bind_counts_into ch-oauth-ldap-a HA_BASE_A_SUCC HA_BASE_A_FAIL
capture_bind_counts_into ch-oauth-ldap-b HA_BASE_B_SUCC HA_BASE_B_FAIL
log "HA: Bind baselines — A: success=$HA_BASE_A_SUCC failed=$HA_BASE_A_FAIL, B: success=$HA_BASE_B_SUCC failed=$HA_BASE_B_FAIL"

HA_DUAL_AUTH_TOKEN="$(oauth_mint ha-dual-auth@example.com idp-readers)"
oauth_retain HA_DUAL_AUTH_TOKEN

ha_a_hit=0
ha_b_hit=0
ha_dual_attempts=0
while [ "$ha_dual_attempts" -lt 20 ] && { [ "$ha_a_hit" -eq 0 ] || [ "$ha_b_hit" -eq 0 ]; }; do
    ha_dual_attempts=$((ha_dual_attempts + 1))
    oauth_run ha-dual-auth@example.com "$HA_DUAL_AUTH_TOKEN" "SELECT currentUser()"
    oauth_expect_status 200 "HA dual-auth proof attempt $ha_dual_attempts"
    oauth_expect_exact_body "ha-dual-auth@example.com" "HA dual-auth proof attempt $ha_dual_attempts"
    capture_bind_counts_into ch-oauth-ldap-a ha_cur_a_succ _
    capture_bind_counts_into ch-oauth-ldap-b ha_cur_b_succ _
    [ "$ha_cur_a_succ" -gt "$HA_BASE_A_SUCC" ] && ha_a_hit=1
    [ "$ha_cur_b_succ" -gt "$HA_BASE_B_SUCC" ] && ha_b_hit=1
done
[ "$ha_a_hit" -eq 1 ] && [ "$ha_b_hit" -eq 1 ] \
    || die "HA: after $ha_dual_attempts fresh authentications, helper A and/or B never independently served a new successful Bind (A hit=$ha_a_hit, B hit=$ha_b_hit) — HAProxy round-robin may not be distributing across both backends"
log "HA: both helpers independently served a fresh successful Bind within $ha_dual_attempts attempt(s) — Bind deltas: A>0=$ha_a_hit B>0=$ha_b_hit"

# ── §18.1/18.3: persistent session probe, retried through HAProxy until it
# lands on helper A ────────────────────────────────────────────────────────
HA_PROBE_LDAP_ADDR="ch-oauth-ldap:389"
HA_PROBE_USER_BASE_DN='ou=users,dc=altinity,dc=internal'
HA_PROBE_GROUP_BASE_DN='ou=groups,dc=altinity,dc=internal'
HA_PROBE_RDN_ATTR='uid'
HA_PROBE_ROLE_PREFIX='clickhouse_'
HA_PROBE_LOG_PATH='/tmp/session-probe.log'
HA_PROBE_CRED_PATH='/tmp/probe-cred.txt'
HA_PROBE_PID_PATH='/tmp/probe.pid'
HA_PROBE_RC_PATH='/tmp/probe.rc'

HA_PROBE_TOKEN="$(oauth_mint ha-probe@example.com idp-readers)"
oauth_retain HA_PROBE_TOKEN

# Credentials cross into the container's filesystem via a private, mode-0600
# host file piped as this (short, foreground) exec's OWN stdin — never
# argv, never an exported/Docker `-e` environment variable. See
# ha/session-probe/main.go's package doc for the matching in-process
# discipline on the probe binary's own side.
HA_PROBE_CRED_HOST_FILE="$(mktemp "$RUN_TMP_DIR/probe-cred.XXXXXX")"
chmod 600 "$HA_PROBE_CRED_HOST_FILE"
{
    printf '%s\n' 'ha-probe@example.com'
    printf '%s\n' "$HA_PROBE_TOKEN"
} >"$HA_PROBE_CRED_HOST_FILE"
compose exec -T synthetic-idp sh -c "umask 077; cat > $HA_PROBE_CRED_PATH" <"$HA_PROBE_CRED_HOST_FILE"
rm -f "$HA_PROBE_CRED_HOST_FILE"

# probe_launch — starts a NEW, detached (docker exec -d) probe instance
# inside the stable synthetic-idp container, reading the credential file
# written above. `-d` is what lets the probe outlive this script's own
# `compose exec` invocation without needing a locally-tracked background
# job (killing a *local* docker-exec client does not reliably terminate the
# corresponding remote process — verified against this exact Docker
# version; `-d` sidesteps that entirely). The wrapper captures the probe
# binary's OWN pid (via `$!` on the direct backgrounded command, not a
# subshell) into HA_PROBE_PID_PATH so probe_kill_current below can signal
# exactly one instance, and blocks on `wait` so HA_PROBE_RC_PATH is written
# only once that exact instance actually exits — whether from our own
# SIGTERM (wrong-backend retry) or from a real connection failure once
# helper A is killed later.
probe_launch() {
    compose exec -d -T synthetic-idp sh -c "
        rm -f $HA_PROBE_PID_PATH $HA_PROBE_RC_PATH
        /bin/ldap-session-probe -addr $HA_PROBE_LDAP_ADDR -user-base-dn '$HA_PROBE_USER_BASE_DN' -rdn-attr $HA_PROBE_RDN_ATTR -group-base-dn '$HA_PROBE_GROUP_BASE_DN' -role-cn-prefix $HA_PROBE_ROLE_PREFIX -interval 2s -output $HA_PROBE_LOG_PATH <$HA_PROBE_CRED_PATH &
        pid=\$!
        echo \"\$pid\" >$HA_PROBE_PID_PATH
        wait \"\$pid\"
        echo \$? >$HA_PROBE_RC_PATH
    "
}

probe_kill_current() {
    compose exec -T synthetic-idp sh -c "[ -f $HA_PROBE_PID_PATH ] && kill -TERM \"\$(cat $HA_PROBE_PID_PATH)\" 2>/dev/null; exit 0" >/dev/null 2>&1 || true
    sleep 1
}

fetch_probe_log() {
    compose exec -T synthetic-idp cat "$HA_PROBE_LOG_PATH" 2>/dev/null || true
}

# wait_probe_lands BASE_A_SUCC BASE_B_SUCC — polls the two helpers' Bind
# success counts (bounded) and reports which one increased first; prints
# "a"/"b" and returns 0, or returns 1 on timeout.
wait_probe_lands() {
    local base_a="$1" base_b="$2" deadline=15 start=$SECONDS cur_a cur_b
    while [ $((SECONDS - start)) -lt "$deadline" ]; do
        capture_bind_counts_into ch-oauth-ldap-a cur_a _
        if [ "$cur_a" -gt "$base_a" ]; then
            printf 'a'
            return 0
        fi
        capture_bind_counts_into ch-oauth-ldap-b cur_b _
        if [ "$cur_b" -gt "$base_b" ]; then
            printf 'b'
            return 0
        fi
        sleep 1
    done
    return 1
}

# portable_epoch_from_rfc3339 TIMESTAMP — TIMESTAMP is the RFC3339Nano UTC
# marker prefix the probe binary prints (e.g.
# 2026-08-28T12:34:56.789012345Z). Tries GNU `date -d` first, then BSD/macOS
# `date -j -f`, so the freshness check below works whether this script runs
# on a GNU-userland CI host or (as in this development sandbox) a macOS
# host — never assume one date(1) dialect.
portable_epoch_from_rfc3339() {
    local ts="$1" sec_part="${1%%.*}"
    date -u -d "$sec_part" +%s 2>/dev/null && return 0
    date -u -j -f '%Y-%m-%dT%H:%M:%S' "$sec_part" +%s 2>/dev/null && return 0
    return 1
}

# wait_for_two_fresh_heartbeats — the plan's "before failure injection
# require two consecutive heartbeats and the newest no older than four
# seconds" (ha/session-probe/main.go's own documented contract). Polls the
# probe's log for its most recent "probe: heartbeat n=K" marker; once K
# strictly increases between polls (consecutive-in-practice at this
# probe's fixed 2s interval) AND that newest marker's own printed timestamp
# is within 4 real seconds of now, prints K and returns 0.
wait_for_two_fresh_heartbeats() {
    local deadline=20 start=$SECONDS content last_line n ts now epoch elapsed prev_n=""
    while [ $((SECONDS - start)) -lt "$deadline" ]; do
        content="$(fetch_probe_log)"
        last_line="$(printf '%s\n' "$content" | grep 'probe: heartbeat' | tail -n1)"
        if [ -n "$last_line" ]; then
            n="$(printf '%s\n' "$last_line" | sed -n 's/.*heartbeat n=\([0-9]*\).*/\1/p')"
            ts="$(printf '%s\n' "$last_line" | awk '{print $1}')"
            if [ -n "$n" ] && [ -n "$prev_n" ] && [ "$n" -gt "$prev_n" ]; then
                now="$(date -u +%s)"
                if epoch="$(portable_epoch_from_rfc3339 "$ts")"; then
                    elapsed=$((now - epoch))
                    if [ "$elapsed" -le 4 ] && [ "$elapsed" -ge -2 ]; then
                        printf '%s' "$n"
                        return 0
                    fi
                fi
            fi
            prev_n="$n"
        fi
        sleep 1
    done
    return 1
}

log "HA: acquiring an A-owned persistent session (retry through HAProxy until the probe's Bind lands on helper A)"
ha_probe_bound=""
ha_probe_attempts=0
while [ "$ha_probe_bound" != "a" ] && [ "$ha_probe_attempts" -lt 8 ]; do
    ha_probe_attempts=$((ha_probe_attempts + 1))
    capture_bind_counts_into ch-oauth-ldap-a ha_probe_base_a _
    capture_bind_counts_into ch-oauth-ldap-b ha_probe_base_b _
    probe_launch
    if ! ha_probe_bound="$(wait_probe_lands "$ha_probe_base_a" "$ha_probe_base_b")"; then
        die "HA: session-probe attempt $ha_probe_attempts never Bound to either helper within the bound — see synthetic-idp's $HA_PROBE_LOG_PATH"
    fi
    log "HA: session-probe attempt $ha_probe_attempts bound to helper '$ha_probe_bound'"
    if [ "$ha_probe_bound" != "a" ]; then
        probe_kill_current
    fi
done
[ "$ha_probe_bound" = "a" ] \
    || die "HA: session-probe never landed on helper A after $ha_probe_attempts attempts"

HA_HEARTBEAT_N="$(wait_for_two_fresh_heartbeats)" \
    || die "HA: the A-bound session-probe did not show two consecutive, fresh (<=4s old) heartbeats within the bound before failure injection"
log "HA: A-bound session-probe confirmed live — heartbeat n=$HA_HEARTBEAT_N, freshness bound satisfied"

# ── §18.4: kill A ──────────────────────────────────────────────────────────
capture_bind_counts_into ch-oauth-ldap-b HA_B_BASELINE_BEFORE_KILL _
HA_HELPER_A_CNAME="$(container_name_for ch-oauth-ldap-a)"
[ -n "$HA_HELPER_A_CNAME" ] || die "HA: could not resolve helper A's container name before killing it"
log "HA: abruptly killing helper A ($HA_HELPER_A_CNAME)"
docker kill "$HA_HELPER_A_CNAME" >/dev/null

wait_probe_exit_rc() {
    local deadline=20 start=$SECONDS rc
    while [ $((SECONDS - start)) -lt "$deadline" ]; do
        rc="$(compose exec -T synthetic-idp sh -c "[ -f $HA_PROBE_RC_PATH ] && cat $HA_PROBE_RC_PATH" 2>/dev/null || true)"
        if [ -n "$rc" ]; then
            printf '%s' "$rc"
            return 0
        fi
        sleep 1
    done
    return 1
}

HA_PROBE_EXIT_RC="$(wait_probe_exit_rc)" \
    || die "HA: the A-bound session-probe did not exit within the bound after killing helper A — it may have silently reconnected/migrated instead of failing"
[ "$HA_PROBE_EXIT_RC" != "0" ] \
    || die "HA: the A-bound session-probe exited 0 (a clean stop) after killing helper A — it must fail (nonzero exit) because its own connection died, not be stopped by us"
log "HA: A-bound session-probe correctly failed (exit=$HA_PROBE_EXIT_RC) within the bound after killing helper A"

capture_bind_counts_into ch-oauth-ldap-b HA_B_AFTER_KILL _
[ "$HA_B_AFTER_KILL" -eq "$HA_B_BASELINE_BEFORE_KILL" ] \
    || die "HA: helper B's successful-Bind count changed after killing helper A ($HA_B_BASELINE_BEFORE_KILL -> $HA_B_AFTER_KILL) — the dead A-owned session must never migrate to B"
log "HA: helper B's Bind count is unchanged by killing A ($HA_B_AFTER_KILL) — no session migration occurred"

haproxy_wait_status ch-oauth-ldap-a DOWN 20 >/dev/null \
    || die "HA: HAProxy never reported helper A as DOWN within the bound after killing it (last seen: '$(haproxy_backend_status ch-oauth-ldap-a)')"
haproxy_wait_status ch-oauth-ldap-b UP 5 >/dev/null \
    || die "HA: HAProxy no longer reports helper B as UP after killing helper A (last seen: '$(haproxy_backend_status ch-oauth-ldap-b)')"
log "HA: show stat confirms A=DOWN B=UP after killing helper A"

# A NEW token, minted only now (after A is dead) and retained for the leak
# scan — proves B's success below cannot be attributed to anything A left
# behind (no shared cache/session memory; see plan §19/§25 "B needs none of
# A's memory").
HA_POST_KILL_TOKEN="$(oauth_mint ha-post-kill@example.com idp-readers)"
oauth_retain HA_POST_KILL_TOKEN

ha_post_kill_iter=0
while [ "$ha_post_kill_iter" -lt 2 ]; do
    ha_post_kill_iter=$((ha_post_kill_iter + 1))
    oauth_run ha-post-kill@example.com "$HA_POST_KILL_TOKEN" "SELECT currentUser()"
    oauth_expect_status 200 "HA post-kill auth via B ($ha_post_kill_iter)"
    oauth_expect_exact_body "ha-post-kill@example.com" "HA post-kill auth via B ($ha_post_kill_iter)"
done
capture_bind_counts_into ch-oauth-ldap-b HA_B_AFTER_POST_KILL_AUTH _
[ "$HA_B_AFTER_POST_KILL_AUTH" -gt "$HA_B_AFTER_KILL" ] \
    || die "HA: helper B's Bind count did not rise after $ha_post_kill_iter fresh post-kill authentications (still $HA_B_AFTER_POST_KILL_AUTH)"
log "HA: fresh authentication with a NEWLY minted token succeeds via B while A is absent (Bind count $HA_B_AFTER_KILL -> $HA_B_AFTER_POST_KILL_AUTH)"

# ── §18.5: recreate A ──────────────────────────────────────────────────────
log "HA: recreating helper A"
# Deliberately NOT `compose up -d --force-recreate --no-deps ch-oauth-ldap-a`:
# Compose's recreate strategy renames the outgoing container via the Docker
# API (create-new, stop/rename-away-old, rename-new-into-place) even when
# the old container is already dead — and this sandbox's Docker network
# isolator blocks the `rename` endpoint outright ("isolator: endpoint not
# allowed: POST .../rename"), which is a general container-management
# restriction here, not a networking one, so it would bite on a normal,
# unrestricted host's compose the same way only if that host also disallows
# renames (it does not — this failure is sandbox-specific, verified live).
# Removing the already-dead container explicitly first means the
# subsequent plain `up` has nothing to recreate — it simply creates a new
# container, exactly as it would if this were the very first `up` for this
# service — so no rename call is ever issued.
docker rm -f "$HA_HELPER_A_CNAME" >/dev/null
compose up -d --no-deps ch-oauth-ldap-a
if [ "$USING_FALLBACK" = "1" ]; then
    HA_HELPER_A_NEW_CNAME="$(container_name_for ch-oauth-ldap-a)"
    [ -n "$HA_HELPER_A_NEW_CNAME" ] || die "HA: could not resolve helper A's recreated container name (fallback mode)"
    docker network connect --alias ch-oauth-ldap-a ch-phase5-ha-auth-net "$HA_HELPER_A_NEW_CNAME"
    docker network disconnect "${DOCKER_NETWORK:-iso-altinity}" "$HA_HELPER_A_NEW_CNAME"
    log "HA: recreated helper A reconnected to ch-phase5-ha-auth-net with alias ch-oauth-ldap-a, then disconnected from the shared network (fallback mode)"
fi

wait_service_healthy() {
    local svc="$1" deadline="${2:-60}" start=$SECONDS cid status
    while [ $((SECONDS - start)) -lt "$deadline" ]; do
        cid="$(compose ps -q "$svc" 2>/dev/null || true)"
        if [ -n "$cid" ]; then
            status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$cid" 2>/dev/null || echo unknown)"
            [ "$status" = "healthy" ] && return 0
        fi
        sleep 1
    done
    return 1
}

wait_service_healthy ch-oauth-ldap-a 60 \
    || die "HA: recreated helper A never became Docker-healthy within the bound"
log "HA: recreated helper A is Docker-healthy"

haproxy_wait_status ch-oauth-ldap-a UP 30 >/dev/null \
    || die "HA: HAProxy never re-admitted recreated helper A as UP within the bound (last seen: '$(haproxy_backend_status ch-oauth-ldap-a)') — runtime DNS re-resolution may not have picked up its new address"
log "HA: show stat confirms recreated helper A=UP"

HA_POST_RECREATE_TOKEN="$(oauth_mint ha-post-recreate@example.com idp-readers)"
oauth_retain HA_POST_RECREATE_TOKEN

capture_bind_counts_into ch-oauth-ldap-a HA_A_BASELINE_RECREATE _
ha_recreate_attempts=0
ha_a_recreate_hit=0
while [ "$ha_recreate_attempts" -lt 20 ] && [ "$ha_a_recreate_hit" -eq 0 ]; do
    ha_recreate_attempts=$((ha_recreate_attempts + 1))
    oauth_run ha-post-recreate@example.com "$HA_POST_RECREATE_TOKEN" "SELECT currentUser()"
    oauth_expect_status 200 "HA post-recreate auth ($ha_recreate_attempts)"
    capture_bind_counts_into ch-oauth-ldap-a ha_cur_a_recreate _
    [ "$ha_cur_a_recreate" -gt "$HA_A_BASELINE_RECREATE" ] && ha_a_recreate_hit=1
done
[ "$ha_a_recreate_hit" -eq 1 ] \
    || die "HA: recreated helper A's Bind count never rose after $ha_recreate_attempts fresh authentications"
log "HA: recreated helper A served a fresh successful Bind within $ha_recreate_attempts attempt(s)"

wait_service_healthy ch-oauth-ldap-b 10 \
    || die "HA: helper B is no longer Docker-healthy after recreating helper A"
haproxy_wait_status ch-oauth-ldap-b UP 10 >/dev/null \
    || die "HA: HAProxy no longer reports helper B as UP after recreating helper A"
log "HA: helper B remains healthy and UP after helper A's recreation"

# ── §18.6: HA leak scan ────────────────────────────────────────────────────
log "HA leak scan: starting"
HA_LEAKSCAN_DIR="$(mktemp -d "$RUN_TMP_DIR/ha-leakscan.XXXXXX")"
chmod 700 "$HA_LEAKSCAN_DIR"

leakscan_self_test "${OAUTH_RETAINED_TOKEN_NAMES[0]}"

# Auth-failure probes BEFORE the final artifact snapshot — same ordering
# rule scenarios/80-leak-scan.sh follows (see lib-tests.sh's "Finding 2"),
# so these probes' own log side effects land inside the scanned corpus.
leakscan_capture_auth_failure_bodies "$HA_LEAKSCAN_DIR" "${OAUTH_RETAINED_TOKEN_NAMES[@]}"
leakscan_collect_artifacts "$HA_LEAKSCAN_DIR"

compose exec -T synthetic-idp cat "$HA_PROBE_LOG_PATH" >"$HA_LEAKSCAN_DIR/session-probe.log" 2>&1 \
    || die "HA leak scan: reading $HA_PROBE_LOG_PATH from synthetic-idp failed — a missing/unreadable session-probe log is a real gap in the artifact corpus, not 'nothing to scan'"
chmod 600 "$HA_LEAKSCAN_DIR/session-probe.log"

leakscan_require_artifacts_complete "$HA_LEAKSCAN_DIR"

if leakscan_scan_artifacts "$HA_LEAKSCAN_DIR" "${OAUTH_RETAINED_TOKEN_NAMES[@]}"; then
    log "HA leak scan: clean — none of the ${#OAUTH_RETAINED_TOKEN_NAMES[@]} retained credentials were found in any captured artifact"
else
    die "HA leak scan: LEAK DETECTED — see the log lines above for which retained credential and which file(s)"
fi

log "HA fixture completed successfully — all Docker HA claims proved (see plan §19 for the claim boundary; Kubernetes-specific behavior is NOT proved by this run)"
