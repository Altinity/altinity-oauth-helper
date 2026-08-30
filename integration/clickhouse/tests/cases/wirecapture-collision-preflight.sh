#!/usr/bin/env bash
# integration/clickhouse/tests/cases/wirecapture-collision-preflight.sh
#
# Issue #33 phase 1, plan §16 ("Three-fixture mutual exclusion") and §18
# ("wirecapture-collision-preflight.sh"), Amendment 6. Proves, daemon-free,
# that all five pairwise fixture-collision refusals actually `die` BEFORE
# any mutating Docker/Compose call — never merely that a message is
# printed somewhere.
#
# Sourced by tests/lib-tests.sh's cases/ auto-discovery hook — see that
# file's own header and ha-fallback-parity.sh's header — so it inherits
# SCRIPT_DIR, RUN_TMP_DIR, pass/fail/run_and_capture, and every sourced
# lib/*.sh function. It defines and uses only its own local helpers below.
#
# ── Proof technique (Amendment 6) ─────────────────────────────────────────
# lib-tests.sh's existing daemon-free driver tests (test_bring_up_fixture_
# fallback, ha-fallback-parity.sh's HA sibling) use a stub `docker` that
# exits 0 with NO output for every unmodelled subcommand — including `ps -a
# --filter name=...` and `network ls --filter name=...`. That default would
# silently satisfy run.sh's/run-ha.sh's/capture-ldap-wire.sh's `ch-wirecap*`
# collision preflights (no hits ever reported), which is fine for those
# other tests' purposes but means it can never exercise the refusal path
# itself. This file's own stub instead returns a HIT for exactly one
# configured `--filter name=<pattern>` substring (docker's own `--filter
# name=` semantics are substring, not exact-match) and answers every other
# filter with no hits — so a run only ever collides on the ONE preflight
# under test, in each script's real, unmodified preflight ORDER:
#   - run.sh checks ch-phase5-ha, then ch-wirecap;
#   - run-ha.sh checks ch-phase3, then ch-wirecap;
#   - capture-ldap-wire.sh checks ch-phase3, then ch-phase5-ha, then a
#     stale ch-wirecap.
# Every invocation the stub ever receives (not only the modelled ones) is
# appended verbatim to $DOCKER_CALL_LOG, so this file can assert the FULL
# call sequence contains no `compose ... up`, `network create`, `rm`, or
# `network rm` before the process exits nonzero — proving the refusal
# happens strictly before any state-mutating call, exactly like
# run.sh's/run-ha.sh's own phase3_preflight_no_ha_collision/
# ha_preflight_no_phase3_collision (run.sh:69-85, run-ha.sh:90-106).
#
# Diagnostics below print only call-log LINE COUNTS and the matched
# forbidden-pattern name — never the raw call-log content, a credential, or
# a response body.

if [ -z "${SCRIPT_DIR:-}" ] || [ -z "${RUN_TMP_DIR:-}" ]; then
    printf 'FAIL: wirecapture-collision-preflight.sh -- expected SCRIPT_DIR/RUN_TMP_DIR to already be set by lib-tests.sh\n'
    FAILURES=$((FAILURES + 1))
    return 0 2>/dev/null || exit 1
fi

# run_wirecap_collision_case CASE_NAME SCRIPT_PATH HIT_PATTERN [SCRIPT_ARGS...]
#
# Runs SCRIPT_PATH as a real subprocess with a stub `docker` on PATH that
# reports a hit (a nonempty `docker ps -a --filter name=...` /
# `docker network ls --filter name=...` result) for exactly HIT_PATTERN,
# and asserts:
#   1. the script exits nonzero (it `die`d on the collision);
#   2. its Docker call log contains no `compose ... up`, `network create`,
#      `rm`, or `network rm` call.
run_wirecap_collision_case() {
    local case_name="$1" script_path="$2" hit_pattern="$3"
    shift 3
    local script_args=("$@")
    local stub_dir fresh_tmp call_log out rc

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/collision-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Logs every invocation verbatim, then answers `ps -a --filter
# name=X`/`network ls --filter name=X` with a hit only when X contains
# $STUB_HIT_PATTERN (docker's own --filter name= substring semantics) —
# everything else (including every mutating subcommand) exits 0 with no
# output, so a script that reaches past the targeted preflight would
# proceed uneventfully rather than erroring for an unrelated reason.
printf '%s\n' "$*" >>"$DOCKER_CALL_LOG"

if [ "$1" = "ps" ] && [ "$2" = "-a" ]; then
    filt=""
    for a in "$@"; do
        case "$a" in
            name=*) filt="${a#name=}" ;;
        esac
    done
    case "$filt" in
        *"$STUB_HIT_PATTERN"*) printf 'fake-container-hit\n' ;;
    esac
    exit 0
fi

if [ "$1" = "network" ] && [ "$2" = "ls" ]; then
    filt=""
    for a in "$@"; do
        case "$a" in
            name=*) filt="${a#name=}" ;;
        esac
    done
    case "$filt" in
        *"$STUB_HIT_PATTERN"*) printf '%s\n' "$filt" ;;
    esac
    exit 0
fi

exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/collision-run-tmp.XXXXXX")"
    call_log="$fresh_tmp/docker-calls.log"
    : >"$call_log"

    out="$(PATH="$stub_dir:$PATH" \
        TMPDIR="$fresh_tmp" \
        DOCKER_CALL_LOG="$call_log" \
        STUB_HIT_PATTERN="$hit_pattern" \
        bash "$script_path" "${script_args[@]}" 2>&1)"
    rc=$?

    if [ "$rc" -ne 0 ]; then
        pass "$case_name: dies on the collision (nonzero exit)"
    else
        fail "$case_name: dies on the collision (nonzero exit)" "expected nonzero exit, got 0"
    fi

    case "$out" in
    *"preflight:"*"$hit_pattern"*) pass "$case_name: die message names the colliding fixture" ;;
    *) fail "$case_name: die message names the colliding fixture" "expected a 'preflight: ...' message naming '$hit_pattern'" ;;
    esac

    local log_lines
    log_lines="$(grep -c . "$call_log" 2>/dev/null || true)"

    if grep -qE '^compose( .*)? up([[:space:]]|$)' "$call_log"; then
        fail "$case_name: no 'compose ... up' issued before the die" "found in $log_lines logged call(s)"
    else
        pass "$case_name: no 'compose ... up' issued before the die"
    fi

    if grep -q 'network create' "$call_log"; then
        fail "$case_name: no 'network create' issued before the die" "found in $log_lines logged call(s)"
    else
        pass "$case_name: no 'network create' issued before the die"
    fi

    if grep -qE '^rm([[:space:]]|$)' "$call_log" || grep -q 'network rm' "$call_log"; then
        fail "$case_name: no 'rm'/'network rm' issued before the die" "found in $log_lines logged call(s)"
    else
        pass "$case_name: no 'rm'/'network rm' issued before the die"
    fi

    rm -rf "$stub_dir" "$fresh_tmp"
}

# ---- the five pairwise refusals (plan §16's mutual-exclusion table) ----

run_wirecap_collision_case \
    "run.sh vs ch-wirecap" \
    "$SCRIPT_DIR/run.sh" \
    "ch-wirecap"

run_wirecap_collision_case \
    "run-ha.sh vs ch-wirecap" \
    "$SCRIPT_DIR/run-ha.sh" \
    "ch-wirecap"

run_wirecap_collision_case \
    "capture-ldap-wire.sh vs ch-phase3" \
    "$SCRIPT_DIR/capture-ldap-wire.sh" \
    "ch-phase3" \
    --mode generate --output "$RUN_TMP_DIR/collision-unused-output-phase3"

run_wirecap_collision_case \
    "capture-ldap-wire.sh vs ch-phase5-ha" \
    "$SCRIPT_DIR/capture-ldap-wire.sh" \
    "ch-phase5-ha" \
    --mode generate --output "$RUN_TMP_DIR/collision-unused-output-ha"

run_wirecap_collision_case \
    "capture-ldap-wire.sh vs stale ch-wirecap" \
    "$SCRIPT_DIR/capture-ldap-wire.sh" \
    "ch-wirecap" \
    --mode generate --output "$RUN_TMP_DIR/collision-unused-output-stale"
