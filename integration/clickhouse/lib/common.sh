#!/usr/bin/env bash
# integration/clickhouse/lib/common.sh
#
# Shared shell library for integration/clickhouse/run.sh and every scenario
# script under integration/clickhouse/scenarios/*.sh. This file is SOURCED,
# never executed directly, and assumes the caller has already run
# `set -euo pipefail` and `umask 077` (run.sh does both before sourcing
# this file). Never add `set -x` here or anywhere it is sourced — see
# "Administrative versus OAuth client paths" in the phase-3 plan.
#
# ── Sourcing contract for integration/clickhouse/scenarios/*.sh ──────────
#
# run.sh sources every integration/clickhouse/scenarios/*.sh file in
# lexical (glob) order, but only AFTER:
#   1. the mechanical Docker health gate has passed for all four services;
#   2. RBAC/data bootstrap (bootstrap/common.sql, then origin.sql/
#      remote.sql) has been applied;
#   3. the full scenario-A infrastructure/compatibility preflight
#      (implemented directly in run.sh, not as a scenarios/ file) has
#      passed.
# If integration/clickhouse/scenarios/ matches no `*.sh` files, run.sh
# `die`s — the suite ships with scenarios B–I, so an empty glob means a bad
# checkout or a broken path, never a legitimate "nothing to run".
#
# Each scenario file is sourced (not exec'd as a subprocess) directly into
# run.sh's own shell, so:
#   - it runs under the SAME `set -euo pipefail`: an unhandled non-zero
#     exit anywhere in a sourced scenario file aborts run.sh, and run.sh's
#     EXIT trap (secret/temp-file cleanup + `compose down -v
#     --remove-orphans`) still fires, exactly as it would for a failure in
#     run.sh itself. Call `die "message"` below for a deliberate, logged
#     failure.
#   - it sees every variable and function this file and run.sh define
#     (PHASE3_IDP_PORT, PHASE3_CH_HTTP_PORT, RUN_TMP_DIR,
#     CH_LOCAL_ADMIN_PASSWORD, every helper function below, etc). It does
#     NOT get a fresh subshell, so a scenario file that does `cd` or
#     mutates a shared variable affects every scenario sourced after it —
#     keep scenario-local state in scenario-file-local variable names or
#     explicitly restore what you changed.
#   - it MUST keep any signed JWT or generated credential in a local,
#     UNEXPORTED shell variable (never `export` it, never pass it as an
#     argv literal to curl/clickhouse-client/docker) — see "Administrative
#     versus OAuth client paths" in the phase-3 plan. Use idp_sign and
#     ch_http_query_as below, which already follow that discipline.
#   - filenames sort (lexically) in the dependency order the plan's
#     scenarios need, via a two-digit numeric prefix:
#     `10-ephemeral-user.sh` (B), `20-dynamic-roles.sh` (C),
#     `30-username-mismatch.sh` (D), `40-invalid-expired.sh` (E),
#     `50-role-refresh.sh` (F), `60-local-precedence.sh` (G),
#     `70-distributed-propagation.sh` (H, the base-table authorization
#     oracle), `75-distributed-propagation-view.sh` (H's expected-fail
#     sibling: a view-based oracle tracking an independent ClickHouse
#     defect — see lib/expectations.sh), `80-leak-scan.sh` (I, which must
#     run last so every earlier scenario's retained credentials are in the
#     registry). Leave gaps for new scenarios.
#   - a scenario probing a known, tracked upstream ClickHouse behavioral
#     difference between builds (see lib/expectations.sh) should source
#     that file (same pattern as lib/oauth.sh: sourced by the scenario
#     file itself, not by run.sh) and route its build-dependent assertion
#     through `assert_propagation_outcome`/`expectation_for` rather than
#     hardcoding a pass/fail expectation inline.
#   - a scenario file that needs its own throwaway temp file should create
#     it under $RUN_TMP_DIR (already private: created via `mktemp -d`
#     after run.sh's `umask 077`) and remove it itself when it's no longer
#     needed, rather than relying solely on the final EXIT trap to do it.
#
# ── Variables run.sh must set before calling any compose()-based helper ──
# (sourcing this file itself only defines functions and runs
# detect_compose_cmd, so it's safe to source before these exist — but
# every function below except log/die/sha256_hex/gen_secret needs them):
#   SCRIPT_DIR            integration/clickhouse directory (absolute path)
#   RUN_TMP_DIR           private per-run temp dir under $TMPDIR, mode 0700
#   ENV_FILE              private per-run docker-compose --env-file path
#   COMPOSE_PROJECT_NAME  docker compose project name (see run.sh)
#   COMPOSE_FILE          absolute path to compose.yml
#
# ── Variables this file itself defines (safe defaults if unset) ──────────
#   PHASE3_IDP_PORT       host loopback port for synthetic-idp (default 18080)
#   PHASE3_CH_HTTP_PORT   host loopback port for clickhouse-origin (default 18123)
#   CH_HTTP_STATUS        set by ch_http_query_as after each call
#
# ── Other variables run.sh sets that scenario files can rely on ──────────
#   RUN_LOG                path to this run's own captured stdout+stderr
#                           transcript (run.sh tees itself into it from the
#                           top) — the "captured runner stdout/stderr"
#                           artifact acceptance scenario I's leak scan
#                           needs; scenario files needing `compose logs`
#                           output should call `compose logs --no-color
#                           <service>` themselves (the `compose` function
#                           above) rather than expecting run.sh to have
#                           pre-captured it.
#   CH_LOCAL_ADMIN_PASSWORD  plaintext runtime-generated password for the
#                           local-precedence `admin@example.com` ClickHouse
#                           user (see bootstrap/origin.sql); unexported.
#   PHASE3_CH_IMAGE         the ClickHouse image this run targets (default:
#                           the issue's pinned 24.8 baseline) — set from the
#                           environment, written into the private
#                           --env-file for compose.yml's own substitution.
#   EXPECTED_CH_VERSION     derived from PHASE3_CH_IMAGE (the tag after the
#                           colon) — scenario A's own version-pin check uses
#                           this, and so does lib/expectations.sh's
#                           ch_build_prefix/expectation_for.
#
# ── Functions this file provides ──────────────────────────────────────────
#   log MSG                          timestamped stderr log line
#   die MSG                          log MSG, then `exit 1`
#   compose ARGS...                  docker compose / docker-compose wrapper,
#                                     already pinned to this project + file
#                                     + env-file
#   container_name_for SERVICE       prints the actual container name
#                                     compose assigned to SERVICE
#   sha256_hex                       reads stdin, prints lowercase hex sha256
#   gen_secret [BYTES]               prints BYTES (default 32) random hex
#                                     bytes (via `openssl rand -hex`)
#   ch_admin_query SERVICE SQL       administrative (no-JWT) query via
#                                     `compose exec -T SERVICE
#                                     clickhouse-client`, SQL fed over
#                                     stdin (never argv); prints stdout
#   ch_admin_exec_file SERVICE FILE  same, feeding FILE's contents over
#                                     stdin
#   idp_sign QUERYSTRING             GETs the synthetic-idp /sign endpoint
#                                     on the loopback port with the given
#                                     raw query string (e.g.
#                                     "email=alice@example.com&aud=clickhouse
#                                     &exp=3600&role=idp-readers"); prints
#                                     the signed JWT to stdout. Caller MUST
#                                     capture it into a local, unexported
#                                     variable.
#   ch_http_query_as USER PASS SQL  HTTP Basic-authenticated query against
#                                     clickhouse-origin's loopback port.
#                                     PASS is received as a function
#                                     parameter only — never argv of an
#                                     external process, never exported —
#                                     and is written to a private,
#                                     mode-0600, single-use curl config
#                                     file under $RUN_TMP_DIR that this
#                                     function deletes before returning.
#                                     Prints the HTTP response body to
#                                     stdout and sets $CH_HTTP_STATUS to
#                                     the numeric HTTP status code. Returns
#                                     non-zero only on a curl
#                                     transport-level failure — callers
#                                     must check $CH_HTTP_STATUS (e.g.
#                                     "200") for the ClickHouse-level
#                                     authentication/query outcome, not
#                                     just this function's exit code.
#   network_has_container NET NAME  returns 0 if Docker network NET
#                                     currently has a container named NAME
#                                     attached, 1 otherwise
#   wait_for_health [DEADLINE_SECS]  poll all four services' Docker health
#                                     status (default deadline 120s); 0
#                                     once all report "healthy"; 1 (after
#                                     calling capture_diagnostics) on
#                                     timeout
#   capture_diagnostics              dump `compose ps` and all four
#                                     services' logs into
#                                     $RUN_TMP_DIR/diagnostics for a
#                                     timeout/failure post-mortem

PHASE3_IDP_PORT="${PHASE3_IDP_PORT:-18080}"
PHASE3_CH_HTTP_PORT="${PHASE3_CH_HTTP_PORT:-18123}"
CH_HTTP_STATUS=""

PHASE3_SERVICES=(synthetic-idp ch-oauth-ldap clickhouse-origin clickhouse-remote)

log() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

# detect_compose_cmd picks whichever of `docker compose` (v2 plugin) or the
# standalone `docker-compose` binary is actually available on this host and
# records it in COMPOSE_CMD. Detected once, at source time, so `compose()`
# below never needs to re-detect on every call.
detect_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        die "neither 'docker compose' nor 'docker-compose' is available on PATH"
    fi
}

# compose ARGS... runs the detected compose command against THIS fixture's
# project/file/env-file. Every run.sh and scenario-file call into Docker
# Compose should go through this, never a bare `docker compose`/
# `docker-compose` invocation, so the project/env-file stay consistent.
compose() {
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

#   container_name_for SERVICE       prints the actual container name
#                                     compose assigned to SERVICE, via
#                                     `compose ps -q` + `docker inspect`
#                                     rather than `compose ps --format`:
#                                     classic standalone docker-compose
#                                     (v1) never supported `ps --format`
#                                     (only the v2 plugin/rewrite does),
#                                     and this suite's README explicitly
#                                     claims support for either.
container_name_for() {
    local service="$1"
    local cid
    cid="$(compose ps -q "$service" 2>/dev/null | head -n1)"
    [ -n "$cid" ] || return 0
    # `docker inspect -f '{{.Name}}'` carries a leading '/'; strip it to
    # match what `compose ps --format '{{.Name}}'` used to print.
    docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##'
}

sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        openssl dgst -sha256 -r | awk '{print $1}'
    fi
}

gen_secret() {
    local bytes="${1:-32}"
    openssl rand -hex "$bytes"
}

ch_admin_query() {
    local service="$1" sql="$2"
    compose exec -T "$service" clickhouse-client --multiquery <<<"$sql"
}

ch_admin_exec_file() {
    local service="$1" file="$2"
    compose exec -T "$service" clickhouse-client --multiquery <"$file"
}

# idp_sign QUERYSTRING — see contract above. Uses -fsS so a non-2xx
# response (e.g. an unknown kid) fails loudly rather than "succeeding"
# with an HTML/JSON error body mistaken for a token.
idp_sign() {
    local qs="$1"
    curl -fsS "http://127.0.0.1:${PHASE3_IDP_PORT}/sign?${qs}"
}

# ch_http_query_as USER PASS SQL — see contract above.
ch_http_query_as() {
    local username="$1" password="$2" sql="$3"
    local curl_cfg body_file http_code rc

    curl_cfg=$(mktemp "$RUN_TMP_DIR/curl-cfg.XXXXXX")
    body_file=$(mktemp "$RUN_TMP_DIR/curl-body.XXXXXX")
    chmod 600 "$curl_cfg" "$body_file"

    {
        printf 'user = "%s:%s"\n' "$username" "$password"
        printf 'silent\n'
        printf 'show-error\n'
        printf 'header = "Connection: close"\n'
    } >"$curl_cfg"

    set +e
    http_code=$(curl --config "$curl_cfg" \
        -o "$body_file" -w '%{http_code}' \
        --data-binary @- \
        "http://127.0.0.1:${PHASE3_CH_HTTP_PORT}/" <<<"$sql")
    rc=$?
    set -e

    CH_HTTP_STATUS="$http_code"
    cat "$body_file"
    rm -f "$curl_cfg" "$body_file"
    return $rc
}

network_has_container() {
    local net="$1" name="$2"
    docker network inspect "$net" --format '{{range .Containers}}{{.Name}}{{"\n"}}{{end}}' 2>/dev/null | grep -qx "$name"
}

capture_diagnostics() {
    local dir="$RUN_TMP_DIR/diagnostics"
    mkdir -p "$dir"
    compose ps >"$dir/compose-ps.txt" 2>&1 || true
    log "--- compose ps ---"
    cat "$dir/compose-ps.txt" >&2 || true

    local svc
    for svc in "${PHASE3_SERVICES[@]}"; do
        compose logs --no-color "$svc" >"$dir/${svc}.log" 2>&1 || true
        log "--- last 20 lines of ${svc} log ---"
        tail -n 20 "$dir/${svc}.log" >&2 || true
    done
    log "full diagnostics captured under $dir (removed by the EXIT trap when run.sh finishes)"
}

# wait_for_health [DEADLINE_SECS] — see contract above.
wait_for_health() {
    local deadline_secs="${1:-120}"
    local start=$SECONDS
    local svc cid status all_ok

    while true; do
        all_ok=1
        for svc in "${PHASE3_SERVICES[@]}"; do
            cid=$(compose ps -q "$svc" 2>/dev/null || true)
            if [ -z "$cid" ]; then
                all_ok=0
                continue
            fi
            status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$cid" 2>/dev/null || echo "unknown")
            if [ "$status" != "healthy" ]; then
                all_ok=0
            fi
        done

        if [ "$all_ok" -eq 1 ]; then
            log "all four services report healthy"
            return 0
        fi

        if [ $((SECONDS - start)) -ge "$deadline_secs" ]; then
            log "health gate timed out after ${deadline_secs}s"
            compose ps || true
            capture_diagnostics
            return 1
        fi

        sleep 2
    done
}

detect_compose_cmd
