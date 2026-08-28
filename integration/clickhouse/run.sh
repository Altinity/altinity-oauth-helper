#!/usr/bin/env bash
#
# integration/clickhouse/run.sh
#
# Phase-3 real-ClickHouse integration test coordinator (issue #19). Brings
# up the four-service fixture, waits for a mechanical Docker health gate,
# applies RBAC/data bootstrap, runs the acceptance scenario-A
# infrastructure/compatibility preflight, then sources every
# integration/clickhouse/scenarios/*.sh file in lexical order (scenarios B
# through I; dies if none are found). See integration/clickhouse/README.md
# for the full design and rationale; integration/clickhouse/lib/common.sh
# documents the exact sourcing contract scenario files can rely on.
#
# Usage:
#   ./integration/clickhouse/run.sh
#
# Never enable `set -x` here, in lib/common.sh, or in any scenario file —
# see "Administrative versus OAuth client paths" in the plan. This script
# never places a JWT in argv, an exported environment variable, or a
# Docker `-e` argument.

set -euo pipefail
umask 077

# Per-run private state lives under $TMPDIR. Most Linux dev/CI hosts leave
# TMPDIR unset, so default it to $HOME/tmp rather than refusing to run —
# deliberately NOT /tmp: sandboxed Docker hosts (including the one this
# fixture was developed on) block /tmp for container bind mounts, and the
# fixture bind-mounts generated files from here.
TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Force the legacy (non-BuildKit) builder, matching this repo's existing
# convention (scripts/build-image.sh: "legacy DOCKER_BUILDKIT=0") — some
# Docker hosts (including sandboxed/CI ones) refuse the privileged
# buildx/buildkit container BuildKit needs, and this fixture's build has
# no multi-arch/cache-export requirement that would need BuildKit anyway.
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0

COMPOSE_FILE="$SCRIPT_DIR/compose.yml"
# A fixed, distinctive project name (rather than the compose-default
# directory-derived "clickhouse") so this fixture's containers/networks
# never collide by name with unrelated Docker resources on a shared host,
# and so `docker compose -p ... down -v --remove-orphans` only ever tears
# down what this run created.
COMPOSE_PROJECT_NAME="ch-phase3"

RUN_TMP_DIR="$(mktemp -d "$TMPDIR/ch-phase3-run.XXXXXX")"
chmod 700 "$RUN_TMP_DIR"

# ENV_FILE is established here, BEFORE the cleanup trap is installed below,
# because cleanup() calls compose(), and compose() (lib/common.sh) expands
# "--env-file $ENV_FILE" unconditionally. With `set -u` active, an EXIT
# trap that fires while ENV_FILE is still unset (e.g. a SIGINT delivered in
# the narrow window that used to exist between installing the trap and
# assigning ENV_FILE) dies on "ENV_FILE: unbound variable" before reaching
# `rm -rf "$RUN_TMP_DIR"`, leaking the run's temp directory on exactly the
# kind of interrupt this trap exists to handle. Keep ENV_FILE's assignment
# above the trap install, not just above the PHASE3_CH_IMAGE validation.
ENV_FILE="$RUN_TMP_DIR/compose.env"
: >"$ENV_FILE"
chmod 600 "$ENV_FILE"

# The cleanup trap is installed IMMEDIATELY after RUN_TMP_DIR/ENV_FILE are
# established — before the tee or the PHASE3_CH_IMAGE validation below,
# either of which can now (or in the future) call die() — so that no exit
# path between here and the end of the script can ever leave RUN_TMP_DIR
# behind. `trap` only fires for exits that occur after it is registered; a
# die() reached before this line would otherwise skip cleanup entirely,
# contradicting the README's "deleted by the EXIT trap on every exit path"
# guarantee. cleanup() only touches RUN_TMP_DIR, ENV_FILE, and
# COMPOSE_PROJECT_NAME (all already set above) plus compose/log from
# lib/common.sh (already sourced) — nothing below this point that cleanup
# itself depends on.
cleanup() {
    local rc=$?
    set +e
    log "cleanup: tearing down the compose project and removing generated material"
    local down_rc
    compose down -v --remove-orphans >/dev/null 2>&1
    down_rc=$?
    if [ "$down_rc" -ne 0 ]; then
        log "cleanup: WARNING — 'compose down -v --remove-orphans' exited $down_rc; containers/volumes of project $COMPOSE_PROJECT_NAME may be left behind (check 'docker ps -a --filter name=${COMPOSE_PROJECT_NAME}')"
    fi
    if [ "${FALLBACK_NETWORKS_CREATED:-0}" = "1" ]; then
        # These two networks were created by hand in the sandbox
        # compatibility fallback (see bring_up_fixture_fallback) rather
        # than by compose, so `compose down` above does not know about
        # them.
        docker network rm ch-phase3-auth-net ch-phase3-cluster-net >/dev/null 2>&1 \
            || log "cleanup: WARNING — could not remove one or both hand-made fallback networks (ch-phase3-auth-net, ch-phase3-cluster-net); a later run tolerates pre-existing ones"
    fi
    # RUN_LOG lives under RUN_TMP_DIR, so this also removes the transcript
    # tee'd above, along with the per-run secret env file, any curl
    # credential configs a scenario left behind, and diagnostics captured
    # on a health-gate timeout.
    rm -rf "$RUN_TMP_DIR"
    exit "$rc"
}
trap cleanup EXIT

RUN_LOG="$RUN_TMP_DIR/run.log"
# Tee our own stdout+stderr into a private, per-run transcript. This is
# part of the "captured runner stdout/stderr" artifact acceptance scenario
# I's JWT leak scan checks — nothing else in this file treats it specially.
exec > >(tee -a "$RUN_LOG") 2>&1

# PHASE3_CH_IMAGE selects which ClickHouse build this run targets, defaulted
# to the issue's pinned 24.8 baseline. EXPECTED_CH_VERSION is derived from it
# (the tag after the LAST colon — `##*:`, so a registry host with a port,
# e.g. `ghcr.io:5000/…:24.8.x`, still yields the tag) rather than
# hardcoded, so scenario A's own version-pin check and
# lib/expectations.sh's per-build behavioral table (see that file) both
# stay correct for whichever build PHASE3_CH_IMAGE names —
# run-all-builds.sh drives this same script once per known build. Digest
# references (`image@sha256:…`) carry no tag to compare version() against
# and are rejected up front. This validation runs AFTER the cleanup trap is
# installed (above) specifically so a die() here still tears down
# RUN_TMP_DIR instead of leaking it.
PHASE3_CH_IMAGE="${PHASE3_CH_IMAGE:-altinity/clickhouse-server:24.8.11.51285.altinitystable}"
case "$PHASE3_CH_IMAGE" in
*@*) die "PHASE3_CH_IMAGE='$PHASE3_CH_IMAGE' is a digest reference; this suite needs a TAGGED image whose tag equals the server's version() string (e.g. altinity/clickhouse-server:24.8.11.51285.altinitystable)" ;;
*:*) : ;;
*) die "PHASE3_CH_IMAGE='$PHASE3_CH_IMAGE' has no tag; this suite needs a TAGGED image whose tag equals the server's version() string" ;;
esac
EXPECTED_CH_VERSION="${PHASE3_CH_IMAGE##*:}"

log "run started; private per-run state under $RUN_TMP_DIR"

# ── Fresh per-run interserver secret ──────────────────────────────────────
# Generated once per run, never committed, never exported into this
# process's own environment — it only ever exists in the private env file
# docker compose reads via --env-file, matching "Interserver-secret
# configuration" in the plan.
PHASE3_CLUSTER_SECRET="$(gen_secret 32)"
printf 'PHASE3_CLUSTER_SECRET=%s\n' "$PHASE3_CLUSTER_SECRET" >>"$ENV_FILE"
unset PHASE3_CLUSTER_SECRET

# Not a secret — written to the same env-file purely so compose.yml's
# `${PHASE3_CH_IMAGE:-...}` substitution (docker compose reads --env-file,
# not this process's own environment, for that) resolves to the build this
# run actually targets.
printf 'PHASE3_CH_IMAGE=%s\n' "$PHASE3_CH_IMAGE" >>"$ENV_FILE"

# ── Sandbox/CI network-isolator compatibility fallback ────────────────────
# Track whether the fallback below actually ran, so cleanup() knows whether
# it also owns removing the two networks it created by hand.
FALLBACK_NETWORKS_CREATED=0

# bring_up_fixture_fallback re-creates the exact same four services on a
# single pre-approved network (whatever $DOCKER_NETWORK already is on this
# host — see CLAUDE.md's "Docker" section — default iso-altinity), then
# reshapes that into the REAL auth-net/cluster-net topology with `docker
# network connect`/`disconnect`, which this sandbox's Docker network
# isolator allows even though it rejects creating/attaching a brand-new
# custom bridge network at container-create time. A normal, unrestricted
# Docker host never takes this path: compose.yml's own two real networks
# are what `bring_up_fixture` tries FIRST, and that is what ships to CI/dev
# machines without this sandbox's isolator.
#
# This mirrors compose.yml service-for-service. If compose.yml's services
# change, this template must change with it.
bring_up_fixture_fallback() {
    local shared_net="${DOCKER_NETWORK:-iso-altinity}"
    local repo_root
    repo_root="$(cd "$SCRIPT_DIR/../.." && pwd)"

    FALLBACK_COMPOSE_FILE="$RUN_TMP_DIR/fallback-compose.yml"
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
        printf '  ch-oauth-ldap:\n'
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
        printf '  clickhouse-origin:\n'
        printf '    image: %s\n' "$PHASE3_CH_IMAGE"
        printf '    volumes:\n'
        printf '      - %s/clickhouse/common/config.d:/etc/clickhouse-server/config.d:ro\n' "$SCRIPT_DIR"
        printf '      - %s/clickhouse/common/users.d:/etc/clickhouse-server/users.d:ro\n' "$SCRIPT_DIR"
        printf '    environment:\n'
        printf '      PHASE3_CLUSTER_SECRET: ${PHASE3_CLUSTER_SECRET:?PHASE3_CLUSTER_SECRET must be set by run.sh}\n'
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
        printf '      PHASE3_CLUSTER_SECRET: ${PHASE3_CLUSTER_SECRET:?PHASE3_CLUSTER_SECRET must be set by run.sh}\n'
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

    # Every subsequent compose() call (health polling, exec, logs, down)
    # now transparently targets the fallback file instead.
    COMPOSE_FILE="$FALLBACK_COMPOSE_FILE"

    log "fallback: docker compose up --build -d (single shared network: $shared_net)"
    compose up --build -d

    log "fallback: creating the real auth-net/cluster-net networks and reshaping container network membership onto them"
    # Flag set BEFORE creating, so cleanup() removes whatever subset got
    # created even if the second `create` fails partway; and a network
    # left behind by a crashed earlier run ("already exists") is tolerated
    # rather than failing every subsequent run the same way.
    FALLBACK_NETWORKS_CREATED=1
    local net
    for net in ch-phase3-auth-net ch-phase3-cluster-net; do
        if docker network inspect "$net" >/dev/null 2>&1; then
            log "fallback: network $net already exists (left over from an earlier run?) — reusing it"
        else
            docker network create "$net" >/dev/null
        fi
    done

    local svc cname
    for svc in synthetic-idp ch-oauth-ldap clickhouse-origin; do
        cname="$(container_name_for "$svc")"
        docker network connect --alias "$svc" ch-phase3-auth-net "$cname"
    done
    for svc in clickhouse-origin clickhouse-remote; do
        cname="$(container_name_for "$svc")"
        docker network connect --alias "$svc" ch-phase3-cluster-net "$cname"
    done
    # Only disconnect the two services with NO published host port
    # (ch-oauth-ldap, clickhouse-remote) from the shared network — this is
    # what makes clickhouse-remote's exclusion from auth-net (the actual
    # security property acceptance scenario A/H checks) real: it can no
    # longer reach synthetic-idp or ch-oauth-ldap by any path once this
    # runs. synthetic-idp and clickhouse-origin instead KEEP their shared-
    # network membership alongside their real one, because Docker's
    # published-port NAT rule is tied to the network a container had at
    # creation time — fully disconnecting them would silently break the
    # very `127.0.0.1:$PHASE3_IDP_PORT`/`$PHASE3_CH_HTTP_PORT` host ports
    # scenario A's own preflight depends on. The only thing this trades
    # away is that origin/idp remain reachable from whatever else happens
    # to share this sandbox's single pre-approved network — it does not
    # weaken the auth-net/cluster-net separation itself.
    for svc in ch-oauth-ldap clickhouse-remote; do
        cname="$(container_name_for "$svc")"
        docker network disconnect "$shared_net" "$cname"
    done
    log "fallback: network reshape complete — clickhouse-remote and ch-oauth-ldap now match compose.yml's auth-net/cluster-net design exactly"
}

bring_up_fixture() {
    local attempt_log="$RUN_TMP_DIR/compose-up-attempt1.log"
    local up_rc

    # Stream live (via tee) rather than buffering the whole build in a
    # command-substitution variable, while still keeping a copy to grep
    # for the sandbox isolator's specific rejection text below.
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

log "bringing up the fixture (docker compose up --build -d)"
bring_up_fixture

log "waiting for the mechanical health gate (deadline 120s)"
wait_for_health 120 || die "one or more services never became healthy; see diagnostics above"

log "host -> origin HTTP reachability check"
curl -fsS "http://127.0.0.1:${PHASE3_CH_HTTP_PORT}/ping" >/dev/null \
    || die "curl http://127.0.0.1:${PHASE3_CH_HTTP_PORT}/ping failed after the health gate passed"

# ── RBAC/data bootstrap ────────────────────────────────────────────────────
# All administrative — no JWT is ever supplied to these invocations (see
# "Administrative versus OAuth client paths" in the plan).
log "bootstrap: common.sql on both nodes"
ch_admin_exec_file clickhouse-origin "$SCRIPT_DIR/bootstrap/common.sql"
ch_admin_exec_file clickhouse-remote "$SCRIPT_DIR/bootstrap/common.sql"

log "bootstrap: remote.sql"
ch_admin_exec_file clickhouse-remote "$SCRIPT_DIR/bootstrap/remote.sql"

log "bootstrap: origin.sql (generating the local-precedence admin password)"
CH_LOCAL_ADMIN_PASSWORD="$(gen_secret 24)"
CH_LOCAL_ADMIN_SHA256_HEX="$(printf '%s' "$CH_LOCAL_ADMIN_PASSWORD" | sha256_hex)"
origin_sql_template="$(cat "$SCRIPT_DIR/bootstrap/origin.sql")"
# Pure bash string substitution — never `sed -e "s/.../$value/"`, which
# would put the substituted value on that external process's own argv.
origin_sql_rendered="${origin_sql_template//__CH_LOCAL_ADMIN_SHA256_HEX__/$CH_LOCAL_ADMIN_SHA256_HEX}"
origin_sql_file="$(mktemp "$RUN_TMP_DIR/origin-bootstrap.XXXXXX.sql")"
chmod 600 "$origin_sql_file"
printf '%s\n' "$origin_sql_rendered" >"$origin_sql_file"
ch_admin_exec_file clickhouse-origin "$origin_sql_file"
rm -f "$origin_sql_file"
unset origin_sql_template origin_sql_rendered CH_LOCAL_ADMIN_SHA256_HEX
log "bootstrap complete"

# ── Acceptance scenario A — infrastructure and compatibility preflight ───
# The 12 points from "Acceptance scenario A" in the plan, plus two live
# grant-exclusivity checks (A.13, A.14) added after review: scenario H's
# negative control is only a causal proof if ch_distributed_reader is the
# ONLY grantee of anything in phase3 on the remote and alice has no local
# role grant anywhere, and reading bootstrap/*.sql does not prove that
# about the live servers. No acceptance JWT is minted until every point
# here passes.
scenario_a_preflight() {
    log "scenario A: preflight starting"

    # 1. origin and remote version() equal the pinned target.
    local svc v
    for svc in clickhouse-origin clickhouse-remote; do
        v="$(ch_admin_query "$svc" "SELECT version()")"
        [ "$v" = "$EXPECTED_CH_VERSION" ] \
            || die "scenario A.1: $svc version() = '$v', expected '$EXPECTED_CH_VERSION'"
    done
    log "scenario A.1: pinned version confirmed on both nodes ($EXPECTED_CH_VERSION)"

    # 2. host -> origin /ping already proven above (before bootstrap), but
    # scenario A restates it explicitly as its own acceptance point.
    curl -fsS "http://127.0.0.1:${PHASE3_CH_HTTP_PORT}/ping" >/dev/null \
        || die "scenario A.2: host -> origin /ping failed"
    log "scenario A.2: host -> origin HTTP /ping OK"

    # 3 & 4. origin -> remote native reachability, proven by getting a
    # server-side protocol exception ("Received from host:port") rather
    # than a client-side connection failure, AND that the ordinary
    # passwordless `default` login is denied once reached. Empirically
    # verified against the pinned image: a network-denied `default` login
    # produces "Code: 516 ... Received from <host>:<port> ...
    # AUTHENTICATION_FAILED" — the SAME generic message ClickHouse also
    # uses for a plain wrong password, which is why this is checked as a
    # single combined probe rather than trying to distinguish reasons.
    local probe_out probe_rc
    set +e
    probe_out="$(compose exec -T clickhouse-origin clickhouse-client \
        --host clickhouse-remote --port 9000 --user default --password "" \
        --query "SELECT 1" 2>&1)"
    probe_rc=$?
    set -e
    case "$probe_out" in
    *"Received from clickhouse-remote:9000"*) : ;;
    *) die "scenario A.3: origin never reached clickhouse-remote:9000 (infrastructure failure, not a login denial): $probe_out" ;;
    esac
    log "scenario A.3: origin reached clickhouse-remote:9000 (server responded)"
    if [ "$probe_rc" -eq 0 ]; then
        die "scenario A.4: passwordless default login from origin to remote:9000 UNEXPECTEDLY SUCCEEDED"
    fi
    case "$probe_out" in
    *AUTHENTICATION_FAILED*) : ;;
    *) die "scenario A.4: expected an AUTHENTICATION_FAILED denial, got: $probe_out" ;;
    esac
    log "scenario A.4: ordinary passwordless default fallback correctly denied"

    # 5. push_external_roles_in_interserver_queries exists and is 1 on
    # both nodes, with no fixture profile override masking the pinned
    # target's own default.
    local val cnt
    for svc in clickhouse-origin clickhouse-remote; do
        val="$(ch_admin_query "$svc" "SELECT value FROM system.settings WHERE name = 'push_external_roles_in_interserver_queries'")"
        cnt="$(ch_admin_query "$svc" "SELECT count() FROM system.settings WHERE name = 'push_external_roles_in_interserver_queries'")"
        [ "$cnt" = "1" ] || die "scenario A.5: $svc has $cnt rows for push_external_roles_in_interserver_queries, expected exactly 1"
        [ "$val" = "1" ] || die "scenario A.5: $svc push_external_roles_in_interserver_queries = '$val', expected '1'"
    done
    log "scenario A.5: push_external_roles_in_interserver_queries = 1 on both nodes"

    # 6. alice@example.com absent from persistent/local user definitions
    # on both nodes, before any OAuth testing.
    for svc in clickhouse-origin clickhouse-remote; do
        cnt="$(ch_admin_query "$svc" "SELECT count() FROM system.users WHERE name = 'alice@example.com'")"
        [ "$cnt" = "0" ] || die "scenario A.6: $svc already has a persistent alice@example.com user"
    done
    log "scenario A.6: alice@example.com absent on both nodes"

    # 7. ch_readonly, ch_engineer, ch_distributed_reader exist on both
    # nodes.
    for svc in clickhouse-origin clickhouse-remote; do
        cnt="$(ch_admin_query "$svc" "SELECT count() FROM system.roles WHERE name IN ('ch_readonly','ch_engineer','ch_distributed_reader')")"
        [ "$cnt" = "3" ] || die "scenario A.7: $svc has $cnt/3 of the expected local roles"
    done
    log "scenario A.7: ch_readonly/ch_engineer/ch_distributed_reader present on both nodes"

    # 8. ch_unprovisioned absent on both nodes.
    for svc in clickhouse-origin clickhouse-remote; do
        cnt="$(ch_admin_query "$svc" "SELECT count() FROM system.roles WHERE name = 'ch_unprovisioned'")"
        [ "$cnt" = "0" ] || die "scenario A.8: $svc has a ch_unprovisioned role, which must never be created"
    done
    log "scenario A.8: ch_unprovisioned absent on both nodes"

    # 9. admin@example.com exists only as the deliberate local origin
    # user.
    cnt="$(ch_admin_query clickhouse-origin "SELECT count() FROM system.users WHERE name = 'admin@example.com'")"
    [ "$cnt" = "1" ] || die "scenario A.9: clickhouse-origin has $cnt admin@example.com users, expected exactly 1"
    cnt="$(ch_admin_query clickhouse-remote "SELECT count() FROM system.users WHERE name = 'admin@example.com'")"
    [ "$cnt" = "0" ] || die "scenario A.9: clickhouse-remote unexpectedly has an admin@example.com user"
    log "scenario A.9: admin@example.com exists only on origin"

    # 10. Docker network membership: auth-net has idp/helper/origin;
    # cluster-net has origin/remote; remote is absent from auth-net.
    local idp_name ldap_name origin_name remote_name
    idp_name="$(container_name_for synthetic-idp)"
    ldap_name="$(container_name_for ch-oauth-ldap)"
    origin_name="$(container_name_for clickhouse-origin)"
    remote_name="$(container_name_for clickhouse-remote)"

    network_has_container ch-phase3-auth-net "$idp_name" || die "scenario A.10: synthetic-idp is not on auth-net"
    network_has_container ch-phase3-auth-net "$ldap_name" || die "scenario A.10: ch-oauth-ldap is not on auth-net"
    network_has_container ch-phase3-auth-net "$origin_name" || die "scenario A.10: clickhouse-origin is not on auth-net"
    if network_has_container ch-phase3-auth-net "$remote_name"; then
        die "scenario A.10: clickhouse-remote MUST NOT be on auth-net"
    fi
    network_has_container ch-phase3-cluster-net "$origin_name" || die "scenario A.10: clickhouse-origin is not on cluster-net"
    network_has_container ch-phase3-cluster-net "$remote_name" || die "scenario A.10: clickhouse-remote is not on cluster-net"
    log "scenario A.10: Docker network membership matches the required topology"

    # 11 & 12. synthetic IdP and helper health are green (already required
    # by wait_for_health above; re-asserted explicitly here per the plan's
    # 12-point list).
    local cid status
    cid="$(compose ps -q synthetic-idp)"
    status="$(docker inspect -f '{{.State.Health.Status}}' "$cid")"
    [ "$status" = "healthy" ] || die "scenario A.11: synthetic-idp health = '$status'"
    log "scenario A.11: synthetic-idp health is green"

    cid="$(compose ps -q ch-oauth-ldap)"
    status="$(docker inspect -f '{{.State.Health.Status}}' "$cid")"
    [ "$status" = "healthy" ] || die "scenario A.12: ch-oauth-ldap health = '$status'"
    log "scenario A.12: ch-oauth-ldap (helper) TCP/389 health is green"

    # 13. On the remote, NOTHING in database phase3 is granted to any user
    # directly, nor to any role other than ch_distributed_reader. This is
    # what makes scenario H's negative control (propagation disabled ->
    # denied) a causal proof rather than an accident of configuration.
    # role_name is Nullable: a direct user grant has role_name = NULL, and
    # `NULL != 'x'` is NULL, so the user_name IS NOT NULL disjunct is what
    # catches those.
    cnt="$(ch_admin_query clickhouse-remote "SELECT count() FROM system.grants WHERE database = 'phase3' AND (user_name IS NOT NULL OR role_name != 'ch_distributed_reader')")"
    [ "$cnt" = "0" ] || die "scenario A.13: clickhouse-remote has $cnt grant(s) in database phase3 to a user or to a role other than ch_distributed_reader — the fixture over-grants and scenario H's negative control would be vacuous"
    log "scenario A.13: on remote, phase3 is granted to ch_distributed_reader only"

    # 14. alice@example.com holds no LOCAL role grant on either node — her
    # only authority anywhere must come from LDAP role mapping on origin
    # and from interserver propagation on the remote.
    for svc in clickhouse-origin clickhouse-remote; do
        cnt="$(ch_admin_query "$svc" "SELECT count() FROM system.role_grants WHERE user_name = 'alice@example.com'")"
        [ "$cnt" = "0" ] || die "scenario A.14: $svc has $cnt local role grant(s) for alice@example.com — her authority must be LDAP-mapped/propagated only"
    done
    log "scenario A.14: alice@example.com has no local role grants on either node"

    log "scenario A: preflight passed (all 14 points)"
}

scenario_a_preflight

# ── Auto-source scenarios/*.sh in lexical order ───────────────────────────
# See the "Sourcing contract" header in lib/common.sh for exactly what a
# scenario file can assume at this point. The suite ships with scenarios
# B–I, so an empty glob is a broken checkout/path, never a legitimate
# "nothing to run" — dying here stops a silent preflight-only pass from
# masquerading as a full green run.
shopt -s nullglob
scenario_files=("$SCRIPT_DIR"/scenarios/*.sh)
shopt -u nullglob

if [ "${#scenario_files[@]}" -eq 0 ]; then
    die "no integration/clickhouse/scenarios/*.sh files found under $SCRIPT_DIR/scenarios — refusing to report a preflight-only run as a passing suite"
fi
log "found ${#scenario_files[@]} scenario file(s) to source"

for f in "${scenario_files[@]}"; do
    log "sourcing scenario file: $f"
    # shellcheck disable=SC1090
    source "$f"
done

log "all scenario files completed successfully"
