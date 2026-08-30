#!/usr/bin/env bash
#
# integration/clickhouse/capture-ldap-wire.sh
#
# Issue #33 phase-1 wire-capture generate/verify driver (plan §8.2/§8.4/
# §15-§29, §40-§41; Amendments 1, 2, 3, 5, 6). Brings up the standalone
# capture fixture (integration/clickhouse/compose-wirecapture.yml,
# COMPOSE_PROJECT_NAME=ch-wirecap), records one controlled ClickHouse LDAP
# session per (tracked line x outcome) pair through the passive
# `ldap-wire-recorder` MITM, sanitizes the raw evidence INSIDE that
# container, exports only the sanitized subtree to private host staging,
# leak-scans it, and either promotes it into a committed fixture tree
# (--mode generate) or byte-compares it against one (--mode verify) —
# never mutating --fixtures.
#
# Usage:
#   ./integration/clickhouse/capture-ldap-wire.sh --mode generate --output <dir>
#   ./integration/clickhouse/capture-ldap-wire.sh --mode verify   --fixtures <dir>
#
# ── Determinism basis (Amendment 5) ───────────────────────────────────────
# Verify-mode byte-equality (session/PDU metadata, not raw timing) relies on
# three independent facts, not an unstated assumption:
#   1. libldap's `ldap_create` zero-initializes ld_msgid, so MessageIDs on a
#      FRESH connection always restart at 1 in request order: Bind=1,
#      Search=2, Abandon=3 (timeout-abandon only), Unbind=4 (whichever of
#      Abandon/Unbind is last observed) — this is why the constructed
#      MessageID-127/128 boundary fixtures (internal/wirefixture/
#      constructed.go) are a SEPARATE, hand-built pair rather than something
#      this driver could ever observe live.
#   2. Bind DN/filter/attribute content derive only from the one fixed HTTP
#      user this driver ever authenticates as (alice@example.com, roles
#      idp-readers + idp-unprovisioned) and the one fixed controlled SQL
#      statement (SELECT currentUser()) — no other client input varies
#      between runs.
#   3. Placeholder-LENGTH constancy (never byte-VALUE constancy — the
#      sanitizer always redacts the credential) depends on the synthetic
#      IdP's /sign endpoint (cmd/synthetic-idp/main.go) emitting a FIXED
#      claim set with fixed-digit iat/exp and no random jti for a given
#      email+role-list+exp — oauth_mint below always requests the same
#      email/roles/exp=3600 for a given (line, session) pair, so a fresh
#      token's byte length matches the committed placeholder_length unless
#      the IdP's own claim shape changed.
# The constructed boundary Bind's fixed non-token DN/password literal is,
# by construction (internal/wirefixture/constructed.go), never JWT-shaped —
# it would otherwise trip its own §30.6 all-file JWT scanner.
#
# ── Amendment 1 (recorder readiness) ──────────────────────────────────────
# The recorder's Compose healthcheck polls a readiness FILE
# (/run/ldap-wirecapture/ready), never a TCP probe — an accepted-but-
# unauthenticated `nc -z` connection every 2s would itself count as a
# captured session and violate the fixture's required N==1 invariant (plan
# §8.4/§21). This driver relies on that file-based healthcheck via the
# ordinary wait_for_health gate; it never opens its own probe connection to
# the recorder.
#
# ── Amendment 2 (recorder tmpfs) ──────────────────────────────────────────
# Both compose-wirecapture.yml and this file's sandbox fallback template
# give the recorder the IDENTICAL private raw/sanitized staging tmpfs via
# the long Compose `volumes:` form (`type: tmpfs`, `target:
# /run/ldap-wirecapture`, `tmpfs: {mode: 0700}`) — the short `tmpfs:` list
# form carries no mode option and cannot express this.
#
# ── Amendment 3 (host-side leak scan) ─────────────────────────────────────
# capture_diagnostics (lib/common.sh) can dump `compose logs` of every
# PHASE3_SERVICES entry — including the recorder — into
# $RUN_TMP_DIR/diagnostics on a health-gate timeout, and this driver's own
# transcript is host-side too. Before promoting (generate) or comparing
# (verify) ANY single capture, this driver runs the existing exact-token
# leak scanner (lib/leakscan.sh) over: a fresh copy of its own transcript,
# $RUN_TMP_DIR/diagnostics (if present), a fresh `compose logs` capture of
# ALL FIVE capture services (including the recorder and the upstream
# helper, not just the three lib/leakscan.sh defaults to), and the exported
# sanitized staging tree itself. A leak anywhere in that corpus discards
# the capture and stops the run (die), exactly like a sanitizer failure.
#
# ── Amendment 6 (fallback test hook) ──────────────────────────────────────
# WIRECAP_TEST_INVOKE_FALLBACK, mechanically identical to run-ha.sh's
# PHASE5_HA_TEST_INVOKE_FALLBACK: when set, calls bring_up_fixture_fallback
# directly (using WIRECAP_MODE/PHASE3_CH_IMAGE from the environment, or
# their documented defaults) and exits before any real health gate/
# bootstrap/capture logic runs, so a daemon-free shell test can drive the
# fallback generator under a stub `docker` with no real daemon involved.
#
# Same "never enable set -x", never-argv/exported-env/Docker--e/host-path
# credential discipline as run.sh/run-ha.sh — see those files' own headers.
# The one credential this script ever handles (the minted JWT) travels only
# as an unexported shell variable and, into the recorder container, only
# over `compose exec -T ... sanitize`'s own stdin (plan §24).

set -euo pipefail
umask 077

TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Capture-shaped active service array (plan §15.5), reassigned immediately
# after sourcing lib/common.sh — mirrors run-ha.sh's own reassignment of
# this same variable. Every helper below (wait_for_health,
# capture_diagnostics, and this file's own leak-scan loop) derives its
# service list from this array.
PHASE3_SERVICES=(synthetic-idp ch-oauth-ldap ldap-helper-upstream clickhouse-origin clickhouse-remote)

# shellcheck source=lib/oauth.sh
source "$SCRIPT_DIR/lib/oauth.sh"
# shellcheck source=lib/leakscan.sh
source "$SCRIPT_DIR/lib/leakscan.sh"

# Amendment 3: scan compose logs of ALL FIVE capture services, not
# lib/leakscan.sh's three-service phase-3 default.
LEAKSCAN_COMPOSE_SERVICES=(synthetic-idp ch-oauth-ldap ldap-helper-upstream clickhouse-origin clickhouse-remote)
LEAKSCAN_NODES=(clickhouse-origin clickhouse-remote)

export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0

COMPOSE_FILE="$SCRIPT_DIR/compose-wirecapture.yml"
COMPOSE_PROJECT_NAME="ch-wirecap"

# ── Argument parsing ───────────────────────────────────────────────────────
MODE=""
OUTPUT_ARG=""
FIXTURES_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
    --mode)
        MODE="${2:-}"
        shift 2
        ;;
    --output)
        OUTPUT_ARG="${2:-}"
        shift 2
        ;;
    --fixtures)
        FIXTURES_ARG="${2:-}"
        shift 2
        ;;
    *)
        die "usage: $0 --mode generate --output <dir> | --mode verify --fixtures <dir> (unknown argument: $1)"
        ;;
    esac
done

case "$MODE" in
generate)
    [ -n "$OUTPUT_ARG" ] || die "--mode generate requires --output <dir>"
    ;;
verify)
    [ -n "$FIXTURES_ARG" ] || die "--mode verify requires --fixtures <dir>"
    [ -d "$FIXTURES_ARG" ] || die "--fixtures '$FIXTURES_ARG' does not exist or is not a directory — verify never creates it"
    ;;
*)
    die "usage: $0 --mode generate --output <dir> | --mode verify --fixtures <dir> (--mode must be 'generate' or 'verify', got '${MODE:-<empty>}')"
    ;;
esac

# ── Capture-side preflights (plan §16) — before ANY mutation ──────────────
# Reciprocal of run.sh's phase3_preflight_no_wirecap_collision and
# run-ha.sh's ha_preflight_no_wirecap_collision. All three checks below run
# before the EXIT trap, RUN_TMP_DIR, or any docker/compose command that
# could mutate state, and never delete another fixture's resources — only
# inspect and tell the operator what to remove by hand.
wirecap_preflight_no_phase3_collision() {
    local hits
    hits="$(docker ps -a --filter 'name=ch-phase3' --format '{{.Names}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: phase-3 fixture container(s) present on this Docker daemon ($hits) — the phase-3 and wire-capture fixtures must not run concurrently (README.md: 'Concurrency: one run per Docker daemon at a time'); tear down phase-3 first (docker rm -f the listed containers, then docker network rm ch-phase3-auth-net ch-phase3-cluster-net if they remain)"
    fi
    hits="$(docker network ls --filter 'name=ch-phase3-auth-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover phase-3 network '$hits' exists — remove it (docker network rm ch-phase3-auth-net) before running the wire-capture fixture"
    fi
    hits="$(docker network ls --filter 'name=ch-phase3-cluster-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover phase-3 network '$hits' exists — remove it (docker network rm ch-phase3-cluster-net) before running the wire-capture fixture"
    fi
    log "preflight: no phase-3 fixture collision detected — proceeding"
}
wirecap_preflight_no_phase3_collision

wirecap_preflight_no_ha_collision() {
    local hits
    hits="$(docker ps -a --filter 'name=ch-phase5-ha' --format '{{.Names}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: phase-5-HA fixture container(s) present on this Docker daemon ($hits) — the phase-5-HA and wire-capture fixtures must not run concurrently (README.md: 'Concurrency: one run per Docker daemon at a time'); tear down the HA fixture first (docker rm -f the listed containers, then docker network rm ch-phase5-ha-auth-net ch-phase5-ha-cluster-net if they remain)"
    fi
    hits="$(docker network ls --filter 'name=ch-phase5-ha-auth-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover phase-5-HA network '$hits' exists — remove it (docker network rm ch-phase5-ha-auth-net) before running the wire-capture fixture"
    fi
    hits="$(docker network ls --filter 'name=ch-phase5-ha-cluster-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover phase-5-HA network '$hits' exists — remove it (docker network rm ch-phase5-ha-cluster-net) before running the wire-capture fixture"
    fi
    log "preflight: no phase-5-HA fixture collision detected — proceeding"
}
wirecap_preflight_no_ha_collision

wirecap_preflight_no_stale_wirecap_collision() {
    local hits
    hits="$(docker ps -a --filter 'name=ch-wirecap' --format '{{.Names}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: a stale wire-capture fixture container(s) already present on this Docker daemon ($hits) — a previous capture run may have crashed without tearing down; remove them (docker rm -f the listed containers, then docker network rm ch-wirecap-auth-net ch-wirecap-cluster-net if they remain) before running this one"
    fi
    hits="$(docker network ls --filter 'name=ch-wirecap-auth-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover wire-capture network '$hits' exists from a previous run — remove it (docker network rm ch-wirecap-auth-net) before running this one"
    fi
    hits="$(docker network ls --filter 'name=ch-wirecap-cluster-net' --format '{{.Name}}' 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        die "preflight: leftover wire-capture network '$hits' exists from a previous run — remove it (docker network rm ch-wirecap-cluster-net) before running this one"
    fi
    log "preflight: no stale wire-capture fixture state detected — proceeding"
}
wirecap_preflight_no_stale_wirecap_collision

# ── Cleanup trap installed BEFORE any per-run state exists ────────────────
# Same ordering discipline as run.sh/run-ha.sh (see run.sh's own extensive
# header comment on why this specific ordering, and the pre-computed-path
# RUN_TMP_DIR construction below, close a real SIGINT leak window).
FALLBACK_NETWORKS_CREATED=0
STACK_UP=0
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
        docker network rm ch-wirecap-auth-net ch-wirecap-cluster-net >/dev/null 2>&1 \
            || log "cleanup: WARNING — could not remove one or both hand-made fallback networks (ch-wirecap-auth-net, ch-wirecap-cluster-net); a later run tolerates pre-existing ones"
    fi
    if [ -n "${RUN_TMP_DIR:-}" ]; then
        rm -rf "$RUN_TMP_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT

RUN_TMP_DIR=""
for _run_tmp_attempt in {1..10}; do
    _run_tmp_candidate="$TMPDIR/ch-wirecap-run.$(gen_secret 8)"
    RUN_TMP_DIR="$_run_tmp_candidate"
    if mkdir -m 700 "$RUN_TMP_DIR" 2>/dev/null; then
        unset _run_tmp_candidate _run_tmp_attempt
        break
    fi
    RUN_TMP_DIR=""
done
if [ -z "$RUN_TMP_DIR" ]; then
    die "failed to create a unique run directory under $TMPDIR (ch-wirecap-run.*) after 10 attempts"
fi

ENV_FILE="$RUN_TMP_DIR/compose.env"
: >"$ENV_FILE"
chmod 600 "$ENV_FILE"

RUN_LOG="$RUN_TMP_DIR/run.log"
exec > >(tee -a "$RUN_LOG") 2>&1

log "run started; private per-run state under $RUN_TMP_DIR"

# ── Resolve OUTPUT_DIR / FIXTURES_DIR to absolute paths ───────────────────
if [ "$MODE" = "generate" ]; then
    mkdir -p "$OUTPUT_ARG"
    OUTPUT_DIR="$(cd "$OUTPUT_ARG" && pwd)"
else
    FIXTURES_DIR="$(cd "$FIXTURES_ARG" && pwd)"
fi

# ── Tracked-line authority (plan §2.1): derive lines/images from
# run-all-builds.sh's own BUILDS array — never a private duplicate list.
# BUILDS itself is never sourced (it would execute run.sh once per image);
# only its literal array body is parsed. ────────────────────────────────────
wirecap_parse_builds_raw() {
    local builds_file="$SCRIPT_DIR/run-all-builds.sh"
    [ -f "$builds_file" ] || die "cannot find $builds_file to derive tracked lines from"
    awk '
        /^BUILDS=\(/ { inblock=1; next }
        inblock && /^\)/ { inblock=0; next }
        inblock { print }
    ' "$builds_file" | grep -oE '"[^"]+"' | tr -d '"'
}

declare -A WIRECAP_LINE_IMAGE=()
LINES=()
while IFS= read -r wirecap_image; do
    [ -n "$wirecap_image" ] || continue
    wirecap_tag="${wirecap_image##*:}"
    wirecap_line="$(printf '%s' "$wirecap_tag" | awk -F. '{print $1"."$2}')"
    case "$wirecap_line" in
    '' | *[!0-9.]*)
        die "could not derive a MAJOR.MINOR tracked-line label from run-all-builds.sh image '$wirecap_image' (tag '$wirecap_tag')"
        ;;
    esac
    if [ -n "${WIRECAP_LINE_IMAGE[$wirecap_line]:-}" ]; then
        if [ "${WIRECAP_LINE_IMAGE[$wirecap_line]}" != "$wirecap_image" ]; then
            die "run-all-builds.sh's BUILDS lists two different images for the same derived tracked line '$wirecap_line' (${WIRECAP_LINE_IMAGE[$wirecap_line]} vs $wirecap_image)"
        fi
    else
        LINES+=("$wirecap_line")
    fi
    WIRECAP_LINE_IMAGE["$wirecap_line"]="$wirecap_image"
done < <(wirecap_parse_builds_raw)
unset wirecap_image wirecap_tag wirecap_line
[ "${#LINES[@]}" -gt 0 ] || die "run-all-builds.sh's BUILDS yielded zero tracked lines — refusing to run an empty capture"
log "tracked lines derived from run-all-builds.sh: ${LINES[*]}"

# ── Exact ClickHouse/OpenLDAP source provenance per tracked line (plan
# §2.2/§2.3) — the committed audited matrix, carried into every sanitized
# session's profile.json via `ldap-wire-recorder sanitize`'s profile flags
# (the wirecapture-profile-writer sub-task). A line present in BUILDS but
# absent here is a real gap: fail loudly rather than capture without
# provenance (checked per-line inside the main loop below). ────────────────
declare -A WIRECAP_CH_REPO=(
    ["24.8"]="Altinity/ClickHouse"
    ["25.8"]="Altinity/ClickHouse"
)
declare -A WIRECAP_CH_TAG=(
    ["24.8"]="v24.8.11.51285.altinitystable"
    ["25.8"]="v25.8.28.10001.altinitystable"
)
declare -A WIRECAP_CH_COMMIT=(
    ["24.8"]="351edb1a2ec26940aee4c2d1d332fd280c232964"
    ["25.8"]="568824f4327b379e86bce93f12b9cebe0cfd9ff5"
)
declare -A WIRECAP_BLOB_LDAPCLIENT_CPP=(
    ["24.8"]="3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0"
    ["25.8"]="3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0"
)
declare -A WIRECAP_BLOB_LDAPCLIENT_H=(
    ["24.8"]="0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6"
    ["25.8"]="0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6"
)
declare -A WIRECAP_BLOB_LDAPACCESSSTORAGE_CPP=(
    ["24.8"]="917ad7cbb922083ab82f85ab25c120a17fd009c7"
    ["25.8"]="fc55c6b081b38ecccbf4894a9a5fa223d3cd2bd8"
)
declare -A WIRECAP_BLOB_EXTERNALAUTHENTICATORS_CPP=(
    ["24.8"]="77812ac5eb5d0027f081ac43dccc6b89110aeb73"
    ["25.8"]="ca61b55dc5dc200353971ff53580b2ee04439334"
)
declare -A WIRECAP_OPENLDAP_REPO=(
    ["24.8"]="ClickHouse/openldap"
    ["25.8"]="openldap/openldap"
)
declare -A WIRECAP_OPENLDAP_PIN=(
    ["24.8"]="5671b80e369df2caf5f34e02924316205a43c895"
    ["25.8"]="22fe35c6b4098e3ad166469f9574c79832c42952"
)
declare -A WIRECAP_OPENLDAP_VERSION=(
    ["24.8"]="2.5.16"
    ["25.8"]="2.6.10"
)

WIRECAP_CONFIG_PATH="integration/clickhouse/clickhouse/common/config.d/ldap.xml"
WIRECAP_CONFIG_HOST_FILE="$SCRIPT_DIR/clickhouse/common/config.d/ldap.xml"
WIRECAP_CONFIG_CONTAINER_PATH="/tmp/wirecap-ldap-config.xml"
WIRECAP_SQL="SELECT currentUser()"
# Must equal internal/wirefixture.FixedTokenClaimRecipe verbatim — that Go
# constant and this shell literal describe the same fixed, non-secret
# recipe (plan §19/§26/§27) and cannot share a literal across the Go/shell
# boundary, so wire_profile_contract_test.go's
# TestWireProfileContract_FixtureInventory is what actually enforces they
# stay in sync (by checking every committed session against the Go
# constant), not this comment.
WIRECAP_TOKEN_CLAIM_RECIPE="sub=alice@example.com; groups=idp-readers,idp-unprovisioned; fixed-digit iat/exp; no jti"
[ -f "$WIRECAP_CONFIG_HOST_FILE" ] || die "canonical LDAP config not found at $WIRECAP_CONFIG_HOST_FILE"

# ── Fresh per-run interserver secret (plan §15.7) ─────────────────────────
PHASE3_CLUSTER_SECRET="$(gen_secret 32)"

wirecap_write_env_file() {
    local image="$1" wirecap_mode="$2"
    : >"$ENV_FILE"
    chmod 600 "$ENV_FILE"
    {
        printf 'PHASE3_CLUSTER_SECRET=%s\n' "$PHASE3_CLUSTER_SECRET"
        printf 'PHASE3_CH_IMAGE=%s\n' "$image"
        printf 'WIRECAP_MODE=%s\n' "$wirecap_mode"
    } >>"$ENV_FILE"
}

# ── Sandbox/CI network-isolator compatibility fallback (plan §17) ────────
# Mirrors run.sh/run-ha.sh's own bring_up_fixture/bring_up_fixture_fallback
# exactly (see run.sh's header for the full rationale), reshaped for this
# fixture's five services and ch-wirecap-*-net network names. The template
# is STATIC (identical bytes every call): the actual image/mode/secret
# values are resolved by docker compose from --env-file at `up` time via
# the same ${WIRECAP_MODE}/${PHASE3_CH_IMAGE}/${PHASE3_CLUSTER_SECRET}
# substitutions compose-wirecapture.yml itself uses, so
# wirecap_write_env_file must always run before this.
USING_FALLBACK=0

bring_up_fixture_fallback() {
    local shared_net="${DOCKER_NETWORK:-iso-altinity}"

    FALLBACK_COMPOSE_FILE="$RUN_TMP_DIR/fallback-compose-wirecapture.yml"
    {
        printf 'services:\n'
        printf '  synthetic-idp:\n'
        printf '    build:\n'
        printf '      context: %s\n' "$REPO_ROOT"
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
        printf '  ch-oauth-ldap:\n'
        printf '    build:\n'
        printf '      context: %s\n' "$REPO_ROOT"
        printf '      dockerfile: integration/clickhouse/Dockerfile\n'
        printf '    image: altinity-oauth-helper-phase3-helper:local\n'
        printf '    command:\n'
        printf '      [\n'
        printf '        "/bin/ldap-wire-recorder",\n'
        printf '        "serve",\n'
        printf '        "--mode",\n'
        printf '        "${WIRECAP_MODE:?WIRECAP_MODE must be set by capture-ldap-wire.sh}",\n'
        printf '        "--upstream",\n'
        printf '        "ldap-helper-upstream:389",\n'
        printf '      ]\n'
        printf '    networks: [shared]\n'
        # Amendment 2: identical long-form tmpfs to compose-wirecapture.yml.
        printf '    volumes:\n'
        printf '      - type: tmpfs\n'
        printf '        target: /run/ldap-wirecapture\n'
        printf '        tmpfs:\n'
        printf '          mode: 0700\n'
        # Amendment 1: readiness FILE, never a TCP probe.
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "test", "-f", "/run/ldap-wirecapture/ready"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  ldap-helper-upstream:\n'
        printf '    build:\n'
        printf '      context: %s\n' "$REPO_ROOT"
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
        printf '  clickhouse-origin:\n'
        printf '    image: %s\n' "${PHASE3_CH_IMAGE:-altinity/clickhouse-server:24.8.11.51285.altinitystable}"
        printf '    volumes:\n'
        printf '      - %s/clickhouse/common/config.d:/etc/clickhouse-server/config.d:ro\n' "$SCRIPT_DIR"
        printf '      - %s/clickhouse/common/users.d:/etc/clickhouse-server/users.d:ro\n' "$SCRIPT_DIR"
        printf '    environment:\n'
        printf '      PHASE3_CLUSTER_SECRET: ${PHASE3_CLUSTER_SECRET:?PHASE3_CLUSTER_SECRET must be set by capture-ldap-wire.sh}\n'
        printf '    networks: [shared]\n'
        printf '    ports:\n'
        printf '      - "127.0.0.1:${PHASE3_CH_HTTP_PORT:-18123}:8123"\n'
        printf '    healthcheck:\n'
        printf '      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]\n'
        printf '      interval: 2s\n'
        printf '      timeout: 2s\n'
        printf '      retries: 60\n'
        printf '  clickhouse-remote:\n'
        printf '    image: %s\n' "${PHASE3_CH_IMAGE:-altinity/clickhouse-server:24.8.11.51285.altinitystable}"
        printf '    volumes:\n'
        printf '      - %s/clickhouse/common/config.d:/etc/clickhouse-server/config.d:ro\n' "$SCRIPT_DIR"
        printf '      - %s/clickhouse/common/users.d:/etc/clickhouse-server/users.d:ro\n' "$SCRIPT_DIR"
        printf '    environment:\n'
        printf '      PHASE3_CLUSTER_SECRET: ${PHASE3_CLUSTER_SECRET:?PHASE3_CLUSTER_SECRET must be set by capture-ldap-wire.sh}\n'
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

    log "fallback: docker compose up --build -d (single shared network: $shared_net)"
    compose up --build -d

    log "fallback: creating the real auth-net/cluster-net networks and reshaping container network membership onto them"
    FALLBACK_NETWORKS_CREATED=1
    local net
    for net in ch-wirecap-auth-net ch-wirecap-cluster-net; do
        if docker network inspect "$net" >/dev/null 2>&1; then
            log "fallback: network $net already exists (left over from an earlier capture in this same run, or a crashed prior run) — reusing it"
        else
            docker network create "$net" >/dev/null
        fi
    done

    local svc cname
    for svc in synthetic-idp ch-oauth-ldap ldap-helper-upstream clickhouse-origin; do
        cname="$(container_name_for "$svc")"
        docker network connect --alias "$svc" ch-wirecap-auth-net "$cname"
    done
    for svc in clickhouse-origin clickhouse-remote; do
        cname="$(container_name_for "$svc")"
        docker network connect --alias "$svc" ch-wirecap-cluster-net "$cname"
    done
    # Only the services with NO published host port (recorder, upstream
    # helper, remote) are disconnected from the shared network — idp/origin
    # keep it alongside their real network for their published loopback
    # ports, exactly like run.sh's own fallback.
    for svc in ch-oauth-ldap ldap-helper-upstream clickhouse-remote; do
        cname="$(container_name_for "$svc")"
        docker network disconnect "$shared_net" "$cname"
    done
    log "fallback: network reshape complete — recorder/upstream-helper/clickhouse-remote now match compose-wirecapture.yml's auth-net/cluster-net design exactly"
}

# ── Test hook (Amendment 6) ────────────────────────────────────────────────
# Mechanically identical to run-ha.sh's PHASE5_HA_TEST_INVOKE_FALLBACK.
if [ -n "${WIRECAP_TEST_INVOKE_FALLBACK:-}" ]; then
    wirecap_write_env_file \
        "${PHASE3_CH_IMAGE:-altinity/clickhouse-server:24.8.11.51285.altinitystable}" \
        "${WIRECAP_MODE:-pass}"
    USING_FALLBACK=1
    bring_up_fixture_fallback
    if [ -n "${WIRECAP_TEST_FALLBACK_COMPOSE_COPY:-}" ]; then
        cp "$FALLBACK_COMPOSE_FILE" "$WIRECAP_TEST_FALLBACK_COMPOSE_COPY"
    fi
    log "test hook: bring_up_fixture_fallback completed; exiting before the real health gate/bootstrap/capture flow"
    exit 0
fi

wirecap_bring_up_normal() {
    local attempt_log="$RUN_TMP_DIR/compose-up-attempt.log"
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

    log "docker compose up was rejected by this host's Docker network isolator (only \"${DOCKER_NETWORK:-iso-altinity}\" is a permitted container network here) rather than by a real fixture problem; engaging the sandbox compatibility fallback for the rest of this run"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    USING_FALLBACK=1
    bring_up_fixture_fallback
}

# wirecap_bring_up_iteration WIRECAP_MODE IMAGE — brings up one fresh
# capture stack for one (line, session) pair. Once the sandbox isolator has
# rejected a normal `compose up` once, every subsequent iteration in this
# run goes straight to the fallback (the isolator's rejection is a host
# property, not a per-attempt fluke).
wirecap_bring_up_iteration() {
    local wirecap_mode="$1" image="$2"
    wirecap_write_env_file "$image" "$wirecap_mode"
    if [ "$USING_FALLBACK" = "1" ]; then
        bring_up_fixture_fallback
    else
        wirecap_bring_up_normal
    fi
}

# wirecap_transfer_config — copies the canonical (non-secret) ClickHouse
# LDAP config file into the fresh recorder container so profile.json's
# trimmed-<clickhouse>-element hash (plan §3.1/§26) can be computed
# in-container by `sanitize --config-file`. The runtime image does not ship
# this file (it lives only in the host checkout's clickhouse/ tree, mounted
# into the ClickHouse services, never into the recorder), so it is streamed
# in over the same `compose exec -T ... < file` pattern already used
# elsewhere in this suite for non-secret file content.
wirecap_transfer_config() {
    compose exec -T ch-oauth-ldap sh -c "umask 077; cat > $WIRECAP_CONFIG_CONTAINER_PATH" \
        <"$WIRECAP_CONFIG_HOST_FILE" \
        || die "could not transfer the canonical LDAP config file into the recorder container for provenance hashing"
}

# wirecap_session_paths_csv — comma-separated session directory names
# (e.g. "success,timeout-abandon"), derived from WIRECAP_SESSION_SPECS
# rather than kept as a second, independently maintained literal. Callable
# from anywhere after WIRECAP_SESSION_SPECS is set (bash resolves the array
# reference when the function actually runs, not when it is defined).
wirecap_session_paths_csv() {
    local spec names=()
    for spec in "${WIRECAP_SESSION_SPECS[@]}"; do
        names+=("${spec%%:*}")
    done
    local IFS=,
    echo "${names[*]}"
}

# wirecap_sanitize LINE SESSION_MODE TOKEN — invokes the recorder's
# `sanitize` subcommand inside the fresh container, feeding TOKEN over
# stdin only (plan §24: never argv, exported env, Docker -e, or a host
# token-path argument). Writes session.json + sanitized PDUs under
# /run/ldap-wirecapture/sanitized/session and profile.json under
# /run/ldap-wirecapture/sanitized/profile — both nested under sanitized/,
# the only subtree this driver ever exports (raw/ is never touched).
wirecap_sanitize() {
    local line="$1" session_mode="$2" token="$3"
    local out rc
    set +e
    out="$(printf '%s' "$token" | compose exec -T ch-oauth-ldap ldap-wire-recorder sanitize \
        --sanitized-dir /run/ldap-wirecapture/sanitized/session \
        --line "$line" \
        --mode "$session_mode" \
        --sql "$WIRECAP_SQL" \
        --token-claim-recipe "$WIRECAP_TOKEN_CLAIM_RECIPE" \
        --profile-out /run/ldap-wirecapture/sanitized/profile \
        --tracked-image "${WIRECAP_LINE_IMAGE[$line]}" \
        --clickhouse-repository "${WIRECAP_CH_REPO[$line]}" \
        --clickhouse-tag "${WIRECAP_CH_TAG[$line]}" \
        --clickhouse-commit "${WIRECAP_CH_COMMIT[$line]}" \
        --blob-ldapclient-cpp "${WIRECAP_BLOB_LDAPCLIENT_CPP[$line]}" \
        --blob-ldapclient-h "${WIRECAP_BLOB_LDAPCLIENT_H[$line]}" \
        --blob-ldapaccessstorage-cpp "${WIRECAP_BLOB_LDAPACCESSSTORAGE_CPP[$line]}" \
        --blob-externalauthenticators-cpp "${WIRECAP_BLOB_EXTERNALAUTHENTICATORS_CPP[$line]}" \
        --openldap-repository "${WIRECAP_OPENLDAP_REPO[$line]}" \
        --openldap-pin "${WIRECAP_OPENLDAP_PIN[$line]}" \
        --openldap-version "${WIRECAP_OPENLDAP_VERSION[$line]}" \
        --config-path "$WIRECAP_CONFIG_PATH" \
        --config-file "$WIRECAP_CONFIG_CONTAINER_PATH" \
        --session-paths "$(wirecap_session_paths_csv)" \
        2>&1)"
    rc=$?
    set -e
    # The tool's own stdout/stderr never carries raw credential/PDU content
    # (internal/securitytest/testdata/redaction-sites.tsv;
    # TestWireRecorderRedaction_MarkerNeverLogged) — safe to log directly.
    printf '%s\n' "$out"
    [ "$rc" -eq 0 ] \
        || die "sanitize FAILED for line=$line session=$session_mode (rc=$rc) — discarding this capture; see the tool output above"
}

# wirecap_export_sanitized OUT_DIR — the ONLY export path out of the
# recorder container (plan §14/§24): a tar stream of exactly the
# sanitized/ subtree, never raw/, never a `docker cp`.
wirecap_export_sanitized() {
    local out_dir="$1"
    mkdir -p "$out_dir"
    local tar_err="$RUN_TMP_DIR/export-tar.stderr"
    local compose_rc host_rc
    local -a wirecap_pipestatus
    set +e
    compose exec -T ch-oauth-ldap tar -C /run/ldap-wirecapture -cf - sanitized 2>"$tar_err" \
        | tar -x -C "$out_dir"
    # Snapshot the whole array in one shot before indexing it — on this
    # bash (reproduced on 5.3.9), reading ${PIPESTATUS[0]} first can leave
    # a subsequent ${PIPESTATUS[1]} read seeing an unbound index under
    # `set -u`, even though the array itself has both elements.
    wirecap_pipestatus=("${PIPESTATUS[@]}")
    compose_rc="${wirecap_pipestatus[0]}"
    host_rc="${wirecap_pipestatus[1]}"
    set -e
    if [ "$compose_rc" -ne 0 ] || [ "$host_rc" -ne 0 ]; then
        die "export: tar pipeline from the recorder's sanitized/ subtree failed (compose-exec rc=$compose_rc, host-tar rc=$host_rc); stderr: $(cat "$tar_err" 2>/dev/null)"
    fi
    rm -f "$tar_err"
    [ -f "$out_dir/sanitized/session/session.json" ] \
        || die "export: exported sanitized/ subtree has no sanitized/session/session.json — sanitize did not actually run/write before export"
}

# wirecap_leak_scan LABEL EXPORT_DIR — Amendment 3: before promoting
# (generate) or comparing (verify) this capture's evidence, scans a fresh
# per-iteration corpus (own transcript, $RUN_TMP_DIR/diagnostics if
# present, a fresh `compose logs` of all five services, and the exported
# sanitized staging tree) for every retained credential.
wirecap_leak_scan() {
    local label="$1" export_dir="$2"
    local scan_dir
    scan_dir="$(mktemp -d "$RUN_TMP_DIR/leakscan.XXXXXX")"
    chmod 700 "$scan_dir"

    cp "$RUN_LOG" "$scan_dir/run-transcript.log"

    if [ -d "$RUN_TMP_DIR/diagnostics" ]; then
        cp -r "$RUN_TMP_DIR/diagnostics" "$scan_dir/diagnostics"
    fi

    mkdir -p "$scan_dir/compose-logs"
    local svc rc
    for svc in "${PHASE3_SERVICES[@]}"; do
        set +e
        compose logs --no-color "$svc" >"$scan_dir/compose-logs/${svc}.log" 2>&1
        rc=$?
        set -e
        [ "$rc" -eq 0 ] \
            || die "leak scan ($label): 'compose logs $svc' failed (rc=$rc) — cannot build a trustworthy artifact corpus"
    done

    cp -r "$export_dir" "$scan_dir/staging-export"
    chmod -R u+rwX,go-rwx "$scan_dir" 2>/dev/null || true

    if leakscan_scan_artifacts "$scan_dir" "${OAUTH_RETAINED_TOKEN_NAMES[@]}"; then
        log "leak scan ($label): clean — no retained credential found in transcript/diagnostics/compose-logs/exported-staging"
    else
        rm -rf "$scan_dir"
        die "leak scan ($label): LEAK DETECTED — see the log line(s) above for which retained credential and which file(s); discarding this capture"
    fi
    rm -rf "$scan_dir"
}

# wirecap_promote_session LINE SESSION_MODE EXPORT_DIR OUTPUT_ROOT —
# generate-mode only. Writes OUTPUT_ROOT/LINE/SESSION_MODE/{session.json,
# *.ber} and OUTPUT_ROOT/LINE/profile.json (the latter idempotently: a
# profile.json already promoted earlier IN THIS SAME RUN — from this
# line's other session — must byte-match, or this dies rather than
# silently overwriting drifted provenance; a profile.json already present
# from an earlier committed corpus, e.g. when regenerating over
# internal/ldap/testdata/clickhouse-wire, is simply refreshed).
wirecap_promote_session() {
    local line="$1" session_mode="$2" export_dir="$3" output_root="$4"
    local dest="$output_root/$line/$session_mode"
    rm -rf "$dest"
    mkdir -p "$dest"
    cp "$export_dir/sanitized/session/session.json" "$dest/"
    local f
    for f in "$export_dir/sanitized/session/"*.ber; do
        [ -e "$f" ] || continue
        cp "$f" "$dest/"
    done
    chmod 644 "$dest"/* 2>/dev/null || true

    local profile_src="$export_dir/sanitized/profile/profile.json"
    local profile_dest="$output_root/$line/profile.json"
    [ -f "$profile_src" ] || die "promote: exported bundle for line=$line session=$session_mode has no sanitized/profile/profile.json"
    if [ -f "$profile_dest" ]; then
        local already_promoted="${WIRECAP_LINE_PROMOTED_PROFILE[$line]:-}"
        if [ "$already_promoted" = "1" ] && ! cmp -s "$profile_src" "$profile_dest"; then
            die "promote: profile.json for line=$line drifted between its own two sessions within this SAME run ($profile_dest vs the session=$session_mode capture) — investigate before promoting"
        fi
        if [ "$already_promoted" != "1" ]; then
            cp "$profile_src" "$profile_dest"
        fi
    else
        cp "$profile_src" "$profile_dest"
    fi
    chmod 644 "$profile_dest"
    WIRECAP_LINE_PROMOTED_PROFILE["$line"]=1
}
declare -A WIRECAP_LINE_PROMOTED_PROFILE=()

# wirecap_verify_session LINE SESSION_MODE EXPORT_DIR FIXTURES_ROOT —
# verify-mode only. Runs `ldap-wire-recorder compare` on the HOST (it only
# ever touches already-sanitized, already-non-secret bytes/metadata — see
# compare.go — so it needs no container). Compare itself checks fresh vs
# committed placeholder_length FIRST and reports that distinctly from a
# wire-drift diff (plan §41); this wrapper only routes that distinction
# into a differently-worded die(). Never writes into FIXTURES_ROOT.
wirecap_verify_session() {
    local line="$1" session_mode="$2" export_dir="$3" fixtures_root="$4"
    local committed_dir="$fixtures_root/$line/$session_mode"
    local committed_profile_dir="$fixtures_root/$line"
    local fresh_dir="$export_dir/sanitized/session"
    local fresh_profile_dir="$export_dir/sanitized/profile"

    [ -d "$committed_dir" ] \
        || die "verify: no committed fixture directory for line=$line session=$session_mode at $committed_dir"
    [ -f "$committed_profile_dir/profile.json" ] \
        || die "verify: no committed profile.json for line=$line at $committed_profile_dir/profile.json"

    local out rc
    set +e
    out="$(cd "$REPO_ROOT" && go run ./integration/clickhouse/wirecapture compare \
        --committed-dir "$committed_dir" \
        --fresh-dir "$fresh_dir" \
        --committed-profile-dir "$committed_profile_dir" \
        --fresh-profile-dir "$fresh_profile_dir" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    if [ "$rc" -ne 0 ]; then
        case "$out" in
        *"credential-length mismatch"*)
            die "verify FAILED for line=$line session=$session_mode: credential-length mismatch (a freshly minted token's byte length differs from this fixture's committed placeholder_length — see the determinism basis in this file's own header) — see output above"
            ;;
        *)
            die "verify FAILED for line=$line session=$session_mode: wire evidence does not match the committed fixture — see output above"
            ;;
        esac
    fi
    log "verify: line=$line session=$session_mode OK"
}

# wirecap_generate_constructed OUTPUT_ROOT LINE... — generate-mode only.
# Regenerates the deterministic MessageID-127/128 boundary bundle through
# the committed generator (plan §29), on the host — construct-message-id-
# boundary never touches any credential either.
wirecap_generate_constructed() {
    local output_root="$1"
    shift
    local lines_csv
    lines_csv="$(
        IFS=,
        echo "$*"
    )"
    local out_dir="$output_root/constructed/message-id-boundary"
    mkdir -p "$out_dir"
    (cd "$REPO_ROOT" && go run ./integration/clickhouse/wirecapture construct-message-id-boundary \
        --output-dir "$out_dir" --lines "$lines_csv") \
        || die "generate: construct-message-id-boundary failed"
    log "generate: constructed MessageID-127/128 boundary bundle written to $out_dir"
}

# ── Main loop: one fresh stack per (line, session outcome) pair ──────────
# (plan §19 "Controlled capture prerequisites", §21 session definition).
WIRECAP_SESSION_SPECS=("success:pass" "timeout-abandon:stall-after-bind")

for wirecap_line in "${LINES[@]}"; do
    wirecap_image="${WIRECAP_LINE_IMAGE[$wirecap_line]}"
    [ -n "${WIRECAP_CH_REPO[$wirecap_line]:-}" ] \
        || die "no committed ClickHouse/OpenLDAP source provenance recorded for tracked line '$wirecap_line' (derived from run-all-builds.sh's BUILDS) — add it to this script's provenance tables before capturing this line"

    for wirecap_spec in "${WIRECAP_SESSION_SPECS[@]}"; do
        wirecap_session_mode="${wirecap_spec%%:*}"
        wirecap_recorder_mode="${wirecap_spec##*:}"

        log "==== capture: line=$wirecap_line session=$wirecap_session_mode (WIRECAP_MODE=$wirecap_recorder_mode) image=$wirecap_image ===="

        if [ "$STACK_UP" = "1" ]; then
            compose down -v --remove-orphans >/dev/null 2>&1 \
                || log "WARNING: 'compose down' before the next capture exited non-zero; continuing"
        fi
        wirecap_bring_up_iteration "$wirecap_recorder_mode" "$wirecap_image"
        STACK_UP=1

        wait_for_health 120 \
            || die "health gate failed for line=$wirecap_line session=$wirecap_session_mode; see diagnostics above"

        log "bootstrap: common.sql on both nodes"
        ch_admin_exec_file clickhouse-origin "$SCRIPT_DIR/bootstrap/common.sql"
        ch_admin_exec_file clickhouse-remote "$SCRIPT_DIR/bootstrap/common.sql"

        wirecap_transfer_config

        token="$(oauth_mint alice@example.com idp-readers idp-unprovisioned)"
        oauth_retain token
        leakscan_self_test token

        oauth_run "alice@example.com" "$token" "$WIRECAP_SQL"
        if [ "$wirecap_session_mode" = "success" ]; then
            oauth_expect_status 200 "wirecapture $wirecap_line/$wirecap_session_mode"
            oauth_expect_exact_body "alice@example.com" "wirecapture $wirecap_line/$wirecap_session_mode"
        else
            oauth_expect_auth_failure "wirecapture $wirecap_line/$wirecap_session_mode"
        fi

        wirecap_sanitize "$wirecap_line" "$wirecap_session_mode" "$token"

        wirecap_export_dir="$(mktemp -d "$RUN_TMP_DIR/export.XXXXXX")"
        chmod 700 "$wirecap_export_dir"
        wirecap_export_sanitized "$wirecap_export_dir"

        # Leak-scan while $token still holds this iteration's real value —
        # OAUTH_RETAINED_TOKEN_NAMES resolves "token" indirectly at SCAN
        # time (bash `${!name}`), so clearing it before this call would
        # silently turn the scan into a no-op for the one credential that
        # just flowed through the sanitizer/export pipeline. Only scrub the
        # variable afterward, once nothing left in this iteration needs it.
        wirecap_leak_scan "line=$wirecap_line session=$wirecap_session_mode" "$wirecap_export_dir"

        case "$MODE" in
        generate)
            wirecap_promote_session "$wirecap_line" "$wirecap_session_mode" "$wirecap_export_dir" "$OUTPUT_DIR"
            log "generate: promoted line=$wirecap_line session=$wirecap_session_mode into $OUTPUT_DIR/$wirecap_line/$wirecap_session_mode"
            ;;
        verify)
            wirecap_verify_session "$wirecap_line" "$wirecap_session_mode" "$wirecap_export_dir" "$FIXTURES_DIR"
            ;;
        esac

        rm -rf "$wirecap_export_dir"
        token=""
    done
done

if [ "$STACK_UP" = "1" ]; then
    compose down -v --remove-orphans >/dev/null 2>&1 \
        || log "WARNING: final 'compose down' exited non-zero"
    STACK_UP=0
fi

if [ "$MODE" = "generate" ]; then
    wirecap_generate_constructed "$OUTPUT_DIR" "${LINES[@]}"
fi

log "capture-ldap-wire.sh: --mode $MODE completed successfully for tracked lines: ${LINES[*]}"
