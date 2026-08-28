#!/usr/bin/env bash
# integration/clickhouse/tests/lib-tests.sh
#
# Self-contained, Docker-daemon-free unit tests for the bash helper
# libraries under integration/clickhouse/lib/*.sh — specifically the review
# pass 1 fixes on issue #19 phase 3:
#
#   1. die() paths in lib/oauth.sh and lib/expectations.sh must never
#      interpolate the raw, possibly-credential-bearing $CH_LAST_BODY —
#      only safe metadata (length/digest/artifact path) via the new
#      oauth_body_diagnostics.
#   2. scenarios/80-leak-scan.sh must issue its auth-failure probes BEFORE
#      the final compose-logs/on-disk-log/transcript snapshot, so the
#      probes' own log side effects land inside the scanned corpus.
#   3. lib/leakscan.sh's leakscan_capture_auth_failure_bodies must reject
#      (via `die`) a curl transport failure or an unexpected HTTP 200
#      rather than silently accepting whatever body resulted.
#   4. lib/common.sh's container_name_for must be version-neutral
#      (`compose ps -q` + `docker inspect`, never `compose ps --format`,
#      which classic docker-compose v1 does not support).
#   5. scenarios/60-local-precedence.sh (scenario G) must assert its
#      currentUser()/currentRoles() response with a single whole-body
#      oauth_expect_exact_body call, never by `read`-parsing CH_LAST_BODY
#      into intermediate shell variables that then reach die() — a
#      response-derived value flowing into die() defeats
#      oauth_body_diagnostics' leak protection, and a single-line `read`
#      only ever examines the first line, silently accepting an
#      unexpected trailing row.
#   6. run.sh's `trap cleanup EXIT` must be installed immediately after
#      RUN_TMP_DIR is allocated — before the tee, the env file, and the
#      PHASE3_CH_IMAGE validation, all of which can die() — so a rejected
#      digest or untagged image reference still removes RUN_TMP_DIR
#      instead of leaking it (contradicting the README's "deleted by the
#      EXIT trap on every exit path" claim).
#
# ...and review pass 2's findings:
#
#   7. run.sh's ENV_FILE must be assigned BEFORE `trap cleanup EXIT` is
#      installed, not merely before the PHASE3_CH_IMAGE die()s — cleanup()
#      calls compose(), which expands `--env-file "$ENV_FILE"`
#      unconditionally, so a SIGINT landing between the old trap-install
#      point and the old ENV_FILE assignment died on "ENV_FILE: unbound
#      variable" inside cleanup() itself, before `rm -rf "$RUN_TMP_DIR"`.
#
# ...and a ChatGPT review finding beyond those two passes:
#
#   T11 (issue #19 phase 5, plan §17.1-17.3): a daemon-free shim test of
#   run.sh's bring_up_fixture_fallback (service-set/config parity with
#   compose.yml, --alias on every hand-connect, correct auth-net/cluster-net
#   aliases, and that only ch-oauth-ldap/clickhouse-remote are disconnected
#   from the shared network); array-driven leak-scan completeness tests
#   (normal defaults still yield exactly the legacy six required files; a
#   missing/empty artifact for an HA-shaped LEAKSCAN_COMPOSE_SERVICES/
#   LEAKSCAN_NODES/LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS set is a hard failure);
#   and a sourcing-guard idempotence test proving a second `source` of
#   lib/common.sh or lib/leakscan.sh does not reset a caller's
#   PHASE3_SERVICES/LEAKSCAN_NODES/LEAKSCAN_COMPOSE_SERVICES reassignment.
#
#   8. Findings 6 and 7 above only moved the trap earlier relative to
#      RUN_TMP_DIR/ENV_FILE — they never closed the window BEFORE
#      RUN_TMP_DIR itself exists. `mktemp -d` ran, then `chmod`, then
#      ENV_FILE was created/chmod'd, and only THEN was `trap cleanup EXIT`
#      installed, so a SIGINT anywhere in that whole interval exited with
#      NO trap registered at all, leaking the just-created
#      `ch-phase3-run.*` directory outright (reproduced with an injected
#      sleep + process-group SIGINT → exit 130, directory surviving). The
#      fix installs the trap FIRST — right after cleanup() is defined,
#      itself placed right after COMPOSE_FILE/COMPOSE_PROJECT_NAME are set
#      and strictly before `mktemp -d` ever runs — and makes cleanup()
#      tolerate running with RUN_TMP_DIR, ENV_FILE, and/or
#      FALLBACK_NETWORKS_CREATED all still unset (each guarded with
#      `${VAR:-}`). This supersedes findings 6/7's "trap right after
#      RUN_TMP_DIR"/"ENV_FILE before trap" orderings: the trap now precedes
#      RUN_TMP_DIR's own creation, not merely ENV_FILE's.
#
# ...and a review-pass-1 (second round) finding on top of finding 8:
#
#   9. Finding 8 closed the window BEFORE the trap existed, but left a
#      narrower one AFTER it: `RUN_TMP_DIR="$(mktemp -d ...)"` still runs
#      mktemp as a separate process, so a SIGINT landing between mktemp's
#      own mkdir(2) creating the directory and this shell finishing the
#      command substitution and assigning the path into RUN_TMP_DIR left
#      RUN_TMP_DIR unset in cleanup() (its `[ -n "${RUN_TMP_DIR:-}" ]`
#      guard skips the rm -rf), leaking the just-created directory even
#      though the trap was already live (reproduced: exit 130, directory
#      survives). The fix pre-computes a collision-resistant candidate
#      path and assigns it into RUN_TMP_DIR BEFORE calling `mkdir -m 700`
#      on it (with collision retry, since `mkdir`, unlike `mktemp -d`,
#      isn't itself atomic-with-name-choice) — a plain variable assignment
#      is a single in-process bash statement, so cleanup() knows the path
#      no matter when a signal lands relative to the external `mkdir` call.
#
# This does NOT bring up the real four-service fixture — that remains
# run.sh's job (see integration/clickhouse/README.md: "manual, local
# gate"). It DOES source the real lib/*.sh files, so it needs the same
# `docker`/`docker-compose` CLI *presence* on PATH that lib/common.sh's own
# sourcing-time detect_compose_cmd already requires (no daemon needed —
# every Docker/compose call in these tests is stubbed) — findings 6, 7, 8,
# and 9's tests below run the real run.sh (findings 7, 8, and 9: a working
# copy of it, see those tests' own comments) as a subprocess but with a
# stub `docker` shim placed first on PATH, so they stay just as
# daemon-free as everything else in this file. The T11 bring_up_fixture_
# fallback test uses the same technique with a more elaborate stub `docker`
# that also recognizes `compose ps -q`/`up`/`network create`/`connect`/
# `disconnect` well enough to let that function run to completion and
# record what it did.
#
# After the inline test cases below, this file also sources every
# integration/clickhouse/tests/cases/*.sh file (an empty glob is fine —
# unlike scenarios/*.sh, cases/ starts out empty and later sub-tasks add
# files there rather than growing this file indefinitely), so
# `bash lib-tests.sh` stays the single entry point for this suite's shell
# unit tests.
#
# Run directly:
#   bash integration/clickhouse/tests/lib-tests.sh
#
# Exits 0 only if every test passes.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FAILURES=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() {
    printf 'FAIL: %s -- %s\n' "$1" "$2"
    FAILURES=$((FAILURES + 1))
}

# A private per-test-run scratch dir standing in for $RUN_TMP_DIR, matching
# the real fixture's own private/0700 discipline (see run.sh).
TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
TEST_TMP_DIR="$(mktemp -d "$TMPDIR/ch-phase3-libtest.XXXXXX")"
chmod 700 "$TEST_TMP_DIR"
cleanup_test_tmp_dir() { rm -rf "$TEST_TMP_DIR"; }
trap cleanup_test_tmp_dir EXIT

RUN_TMP_DIR="$TEST_TMP_DIR"

# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=../lib/oauth.sh
source "$SCRIPT_DIR/lib/oauth.sh"
# shellcheck source=../lib/expectations.sh
source "$SCRIPT_DIR/lib/expectations.sh"
# shellcheck source=../lib/leakscan.sh
source "$SCRIPT_DIR/lib/leakscan.sh"

# run_and_capture CODE — evals CODE in a subshell (so a `die`'s `exit 1`
# never kills this test script) and records its combined stdout+stderr in
# $CAPTURE_OUT and its exit code in $CAPTURE_RC.
run_and_capture() {
    CAPTURE_OUT="$(eval "$1" 2>&1)"
    CAPTURE_RC=$?
}

# ── Finding 1: die() paths must never leak the raw body ──────────────────
#
# assert_die_is_leak_safe TEST_NAME CODE SECRET — CODE must `die` (nonzero
# exit); its combined output must NOT contain SECRET verbatim, but must
# reference a sha256=... digest and an artifact= path whose file on disk
# DOES contain SECRET (proving the real body was preserved for live
# debugging, merely relocated off the tee'd log path rather than lost).
assert_die_is_leak_safe() {
    local test_name="$1" code="$2" secret="$3"
    run_and_capture "$code"
    if [ "$CAPTURE_RC" -eq 0 ]; then
        fail "$test_name" "expected the assertion helper to die (nonzero exit); got 0. Output: $CAPTURE_OUT"
        return
    fi
    case "$CAPTURE_OUT" in
    *"$secret"*)
        fail "$test_name" "die() message leaked the raw credential-bearing body verbatim: $CAPTURE_OUT"
        return
        ;;
    esac
    case "$CAPTURE_OUT" in
    *"sha256="*) : ;;
    *)
        fail "$test_name" "die() message missing expected safe body metadata (sha256=...): $CAPTURE_OUT"
        return
        ;;
    esac
    local artifact
    artifact="$(printf '%s' "$CAPTURE_OUT" | sed -n 's/.*saved to \([^ ,]*\).*/\1/p')"
    if [ -z "$artifact" ] || [ ! -f "$artifact" ]; then
        fail "$test_name" "could not locate an on-disk artifact referenced by the die() message: $CAPTURE_OUT"
        return
    fi
    case "$(cat "$artifact")" in
    *"$secret"*) pass "$test_name" ;;
    *) fail "$test_name" "on-disk artifact '$artifact' does not contain the real body — diagnostics would be useless" ;;
    esac
}

SECRET='FAKE-JWT-payload.abcdef0123456789.signature-should-never-appear-in-logs'

assert_die_is_leak_safe \
    "oauth_expect_status never leaks body" \
    "CH_LAST_STATUS=401; CH_LAST_BODY='leak-marker: $SECRET'; oauth_expect_status 200 unit-test" \
    "$SECRET"

assert_die_is_leak_safe \
    "oauth_expect_exact_body never leaks body" \
    "CH_LAST_BODY='leak-marker: $SECRET'; oauth_expect_exact_body 'something-else' unit-test" \
    "$SECRET"

assert_die_is_leak_safe \
    "oauth_expect_not_contains never leaks body" \
    "CH_LAST_BODY='leak-marker: $SECRET ch_readonly'; oauth_expect_not_contains ch_readonly unit-test" \
    "$SECRET"

assert_die_is_leak_safe \
    "oauth_expect_auth_failure never leaks body" \
    "CH_LAST_STATUS=200; CH_LAST_BODY='leak-marker: $SECRET'; oauth_expect_auth_failure unit-test" \
    "$SECRET"

assert_die_is_leak_safe \
    "expect_remote_access_denied (wrong status) never leaks body" \
    "CH_LAST_STATUS=403; CH_LAST_BODY='leak-marker: $SECRET'; expect_remote_access_denied unit-test" \
    "$SECRET"

assert_die_is_leak_safe \
    "expect_remote_access_denied (missing ACCESS_DENIED) never leaks body" \
    "CH_LAST_STATUS=500; CH_LAST_BODY='leak-marker: $SECRET'; expect_remote_access_denied unit-test" \
    "$SECRET"

assert_die_is_leak_safe \
    "expect_remote_access_denied (missing remote marker) never leaks body" \
    "CH_LAST_STATUS=500; CH_LAST_BODY='ACCESS_DENIED leak-marker: $SECRET'; expect_remote_access_denied unit-test" \
    "$SECRET"

# Happy-path sanity: a matching status must NOT die.
run_and_capture "CH_LAST_STATUS=200; CH_LAST_BODY=''; oauth_expect_status 200 unit-test"
if [ "$CAPTURE_RC" -eq 0 ]; then
    pass "oauth_expect_status happy path does not die"
else
    fail "oauth_expect_status happy path does not die" "expected exit 0, got $CAPTURE_RC. Output: $CAPTURE_OUT"
fi

# ── Finding 3: leakscan_capture_auth_failure_bodies rc/status gating ─────

test_leakscan_capture_rejects_transport_failure() {
    local dir out rc
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-test.XXXXXX")"
    out="$({
        ch_http_query_as() { CH_HTTP_STATUS=""; printf 'curl: (7) Failed to connect\n'; return 7; }
        TEST_CRED_TRANSPORT="$SECRET"
        leakscan_capture_auth_failure_bodies "$dir" TEST_CRED_TRANSPORT
    } 2>&1)"
    rc=$?
    rm -rf "$dir"
    if [ "$rc" -eq 0 ]; then
        fail "leakscan_capture_auth_failure_bodies rejects transport failure" "expected die (nonzero exit) on curl rc=7, got 0. Output: $out"
        return
    fi
    case "$out" in
    *"$SECRET"*)
        fail "leakscan_capture_auth_failure_bodies rejects transport failure" "die() message leaked the raw credential: $out"
        ;;
    *"transport level"*) pass "leakscan_capture_auth_failure_bodies rejects transport failure" ;;
    *) fail "leakscan_capture_auth_failure_bodies rejects transport failure" "die() message did not explain the transport failure: $out" ;;
    esac
}
test_leakscan_capture_rejects_transport_failure

test_leakscan_capture_rejects_unexpected_200() {
    local dir out rc
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-test.XXXXXX")"
    out="$({
        ch_http_query_as() { CH_HTTP_STATUS="200"; printf '1\n'; return 0; }
        TEST_CRED_200="$SECRET"
        leakscan_capture_auth_failure_bodies "$dir" TEST_CRED_200
    } 2>&1)"
    rc=$?
    rm -rf "$dir"
    if [ "$rc" -eq 0 ]; then
        fail "leakscan_capture_auth_failure_bodies rejects unexpected 200" "expected die (nonzero exit) on HTTP 200, got 0. Output: $out"
        return
    fi
    case "$out" in
    *"$SECRET"*)
        fail "leakscan_capture_auth_failure_bodies rejects unexpected 200" "die() message leaked the raw credential: $out"
        ;;
    *"UNEXPECTEDLY SUCCEEDED"*) pass "leakscan_capture_auth_failure_bodies rejects unexpected 200" ;;
    *) fail "leakscan_capture_auth_failure_bodies rejects unexpected 200" "die() message did not explain the unexpected success: $out" ;;
    esac
}
test_leakscan_capture_rejects_unexpected_200

test_leakscan_capture_accepts_genuine_failure() {
    local dir out rc body_file
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-test.XXXXXX")"
    out="$({
        ch_http_query_as() { CH_HTTP_STATUS="401"; printf 'Code: 516. DB::Exception: AUTHENTICATION_FAILED\n'; return 0; }
        TEST_CRED_OK="$SECRET"
        leakscan_capture_auth_failure_bodies "$dir" TEST_CRED_OK
    } 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "leakscan_capture_auth_failure_bodies accepts genuine auth failure" "expected exit 0 for a genuine non-200 failure, got $rc. Output: $out"
        rm -rf "$dir"
        return
    fi
    body_file="$dir/auth-failure-01.txt"
    if [ ! -s "$body_file" ]; then
        fail "leakscan_capture_auth_failure_bodies accepts genuine auth failure" "expected artifact '$body_file' to exist and be non-empty"
        rm -rf "$dir"
        return
    fi
    case "$(cat "$body_file")" in
    *AUTHENTICATION_FAILED*) pass "leakscan_capture_auth_failure_bodies accepts genuine auth failure" ;;
    *) fail "leakscan_capture_auth_failure_bodies accepts genuine auth failure" "artifact content unexpected: $(cat "$body_file")" ;;
    esac
    rm -rf "$dir"
}
test_leakscan_capture_accepts_genuine_failure

# ── Finding 5: scenario G whole-body match, not field-parse-then-die ─────
#
# Scenario G's real assertion is a single
#   oauth_expect_exact_body $'admin@example.com\tch_local_admin' LABEL
# call — exercise that exact shape here (rather than re-deriving a parser)
# against the two malformed-response sub-cases the review flagged, proving
# both are rejected via the already leak-safe oauth_expect_exact_body path
# instead of ever binding a response-derived value into a variable that
# reaches die().

PHASE3_G_EXPECTED=$'admin@example.com\tch_local_admin'

assert_die_is_leak_safe \
    "scenario G rejects a credential echoed into the first/second field" \
    "CH_LAST_BODY=\$'$SECRET\tch_local_admin'; oauth_expect_exact_body \"\$PHASE3_G_EXPECTED\" 'scenario G unit-test'" \
    "$SECRET"

assert_die_is_leak_safe \
    "scenario G rejects a correct first line plus an unexpected trailing row" \
    "CH_LAST_BODY=\$'admin@example.com\tch_local_admin\n$SECRET-trailing-row'; oauth_expect_exact_body \"\$PHASE3_G_EXPECTED\" 'scenario G unit-test'" \
    "$SECRET"

# Happy-path sanity: the real expected two-field body must NOT die.
run_and_capture "CH_LAST_BODY=\$'admin@example.com\tch_local_admin'; oauth_expect_exact_body \"\$PHASE3_G_EXPECTED\" 'scenario G unit-test'"
if [ "$CAPTURE_RC" -eq 0 ]; then
    pass "scenario G accepts the exact expected two-field body"
else
    fail "scenario G accepts the exact expected two-field body" "expected exit 0, got $CAPTURE_RC. Output: $CAPTURE_OUT"
fi

# ── Finding 2: scenario I must probe before the final snapshot ───────────

test_leak_scan_probe_before_collect_order() {
    local file="$SCRIPT_DIR/scenarios/80-leak-scan.sh" collect_line probe_line
    collect_line="$(awk '/^leakscan_collect_artifacts /{print NR; exit}' "$file")"
    probe_line="$(awk '/^leakscan_capture_auth_failure_bodies /{print NR; exit}' "$file")"
    if [ -z "${collect_line:-}" ] || [ -z "${probe_line:-}" ]; then
        fail "scenario I probes before final snapshot" "could not locate both calls in $file (collect_line='${collect_line:-}' probe_line='${probe_line:-}')"
        return
    fi
    if [ "$probe_line" -lt "$collect_line" ]; then
        pass "scenario I probes before final snapshot"
    else
        fail "scenario I probes before final snapshot" "leakscan_capture_auth_failure_bodies (line $probe_line) must run BEFORE leakscan_collect_artifacts (line $collect_line) so the probes' own log side effects land in the scanned corpus"
    fi
}
test_leak_scan_probe_before_collect_order

# ── Finding 4: container_name_for must be version-neutral ────────────────

test_container_name_for_version_neutral() {
    local out rc
    out="$(
        compose() {
            if [ "$1" = "ps" ] && [ "$2" = "-q" ] && [ "$3" = "clickhouse-origin" ]; then
                printf 'deadbeef0001\n'
                return 0
            fi
            if [ "$1" = "ps" ] && [ "$2" = "--format" ]; then
                # Classic docker-compose v1 has no `ps --format`; the fix
                # must never reach this branch.
                printf 'STUB-ERROR: called compose ps --format, unsupported by docker-compose v1\n' >&2
                return 1
            fi
            return 1
        }
        docker() {
            if [ "$1" = "inspect" ]; then
                printf '/ch-phase3-clickhouse-origin-1\n'
                return 0
            fi
            return 1
        }
        container_name_for clickhouse-origin
    )"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "container_name_for version-neutral" "unexpected nonzero exit ($rc); output: $out"
        return
    fi
    if [ "$out" = "ch-phase3-clickhouse-origin-1" ]; then
        pass "container_name_for version-neutral"
    else
        fail "container_name_for version-neutral" "expected 'ch-phase3-clickhouse-origin-1', got '$out'"
    fi
}
test_container_name_for_version_neutral

test_container_name_for_missing_service_returns_empty() {
    local out rc
    out="$(
        compose() { return 1; }
        docker() { return 1; }
        container_name_for no-such-service
    )"
    rc=$?
    if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
        pass "container_name_for missing service returns empty, not error"
    else
        fail "container_name_for missing service returns empty, not error" "expected exit 0 and empty output, got rc=$rc output='$out'"
    fi
}
test_container_name_for_missing_service_returns_empty

# ── Finding 6: run.sh cleanup trap must precede PHASE3_CH_IMAGE die() ────
#
# assert_run_sh_early_die_cleans_up TEST_NAME IMAGE EXPECT_SUBSTR — runs
# the REAL run.sh as a subprocess with a fake `docker` shim placed first on
# PATH (so `docker compose version` succeeds, selecting COMPOSE_CMD="docker
# compose", and cleanup()'s later `compose down ...` call resolves to the
# same no-op shim rather than a real daemon — keeping this test exactly as
# Docker-daemon-free as the rest of this file) and a fresh, private TMPDIR,
# then asserts: run.sh exits nonzero, its die() message mentions
# EXPECT_SUBSTR, and — the actual regression this guards — no
# ch-phase3-run.* directory is left behind under that fresh TMPDIR
# afterward, proving the EXIT trap fired even though IMAGE was rejected
# before the fixture bring-up ever started.
assert_run_sh_early_die_cleans_up() {
    local test_name="$1" image="$2" expect_substr="$3"
    local stub_dir fresh_tmp out rc leftover

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/run-early-fail-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Always succeeds. `docker compose version` (detect_compose_cmd) sees a
# zero exit and picks "docker compose"; every later `docker compose ...`
# call from cleanup()'s `compose down -v --remove-orphans` resolves back
# to this same no-op, so nothing here ever touches a real daemon.
exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/run-early-fail-tmp.XXXXXX")"
    out="$(PATH="$stub_dir:$PATH" PHASE3_CH_IMAGE="$image" TMPDIR="$fresh_tmp" bash "$SCRIPT_DIR/run.sh" 2>&1)"
    rc=$?
    leftover=("$fresh_tmp"/ch-phase3-run.*)
    # Record whether a leak actually happened BEFORE the rm -rf below
    # touches fresh_tmp — checking `-e` on the leftover path afterward
    # would always read false regardless of the real outcome, since the
    # rm -rf already deleted anything the glob matched (a false-negative
    # bug review pass 2 found in this exact test).
    local leaked=0
    [ -e "${leftover[0]}" ] && leaked=1
    rm -rf "$stub_dir" "$fresh_tmp"

    if [ "$rc" -eq 0 ]; then
        fail "$test_name" "expected run.sh to die (nonzero exit) for image '$image', got 0. Output: $out"
        return
    fi
    if [ "$leaked" -eq 1 ]; then
        fail "$test_name" "RUN_TMP_DIR '${leftover[0]}' survived the early die() — the cleanup trap did not run before exit. Output: $out"
        return
    fi
    case "$out" in
    *"$expect_substr"*) pass "$test_name" ;;
    *) fail "$test_name" "die() message did not mention the expected reason ('$expect_substr'): $out" ;;
    esac
}

assert_run_sh_early_die_cleans_up \
    "run.sh cleans up RUN_TMP_DIR on an early die from a digest PHASE3_CH_IMAGE" \
    "ghcr.io/example/clickhouse-server@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" \
    "digest reference"

assert_run_sh_early_die_cleans_up \
    "run.sh cleans up RUN_TMP_DIR on an early die from an untagged PHASE3_CH_IMAGE" \
    "untagged-image-no-colon" \
    "has no tag"

# ── Review pass 2, finding 1: SIGINT delivered right after the trap is ────
# ── installed must not abort cleanup on an unset ENV_FILE ─────────────────
#
# Before this fix, ENV_FILE was assigned AFTER `trap cleanup EXIT` (past
# RUN_LOG and the `exec > >(tee ...)` redirection), so a signal landing in
# that gap ran cleanup() with ENV_FILE still unset; cleanup()'s `compose
# down` expands `--env-file "$ENV_FILE"`, and under `set -u` that is a
# fatal "unbound variable" that aborts cleanup() itself before it reaches
# `rm -rf "$RUN_TMP_DIR"` — a real, reproducible-with-SIGINT regression
# (exit 130, RUN_TMP_DIR left on disk), even though it generates no
# credential and even though the digest/untagged-image die() case above
# (already covered) stays safe (ENV_FILE is set before those specific
# die()s can fire). ENV_FILE is now assigned before the trap is installed
# at all, so this exact gap no longer exists in the real script.
#
# assert_run_sh_sigint_right_after_trap_install_cleans_up runs a working
# copy of run.sh — symlinked back to the real lib/ and compose.yml so its
# own SCRIPT_DIR-relative sourcing still resolves — with one `sleep`
# injected immediately after the real `trap cleanup EXIT` line, so a SIGINT
# deterministically lands squarely where the old gap used to begin, rather
# than racing a real, sub-millisecond window. It then asserts run.sh exits
# nonzero and — the regression this guards — leaves no ch-phase3-run.*
# directory behind.
#
# NOTE (findings 8/9, below): `trap cleanup EXIT` now precedes RUN_TMP_DIR's
# own creation (see run.sh), so the injection point this test targets no
# longer sits between RUN_TMP_DIR and ENV_FILE — it sits before either
# exists. That still exercises a real case (cleanup() firing with NEITHER
# set) and this test is kept for that reason, but it no longer covers the
# window around RUN_TMP_DIR's own creation that findings 8 and 9 fix;
# assert_run_sh_sigint_right_after_rundir_created_cleans_up and
# assert_run_sh_sigint_during_rundir_mkdir_cleans_up below cover those
# specifically.
assert_run_sh_sigint_right_after_trap_install_cleans_up() {
    local test_name="run.sh cleans up RUN_TMP_DIR on SIGINT delivered right after the cleanup trap is installed"
    local stub_dir fresh_tmp work_dir out rc leftover leaked run_pid

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/run-sigint-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Always succeeds — see assert_run_sh_early_die_cleans_up's identical stub
# above for why this keeps detect_compose_cmd and cleanup()'s later
# `compose down` both daemon-free.
exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/run-sigint-tmp.XXXXXX")"

    work_dir="$fresh_tmp/run-sh-copy"
    mkdir -p "$work_dir"
    ln -s "$SCRIPT_DIR/lib" "$work_dir/lib"
    ln -s "$SCRIPT_DIR/compose.yml" "$work_dir/compose.yml"
    awk '
        { print }
        $0 == "trap cleanup EXIT" && !done {
            print "sleep 5  # lib-tests.sh test-injected delay, see assert_run_sh_sigint_right_after_trap_install_cleans_up"
            done = 1
        }
    ' "$SCRIPT_DIR/run.sh" >"$work_dir/run.sh"
    if ! grep -q 'test-injected delay' "$work_dir/run.sh"; then
        fail "$test_name" "internal test error: failed to inject the test delay into the run.sh copy — did the exact 'trap cleanup EXIT' line change?"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    chmod +x "$work_dir/run.sh"

    # Monitor mode (job control), on just long enough to background the
    # process: without it, a non-interactive script's background jobs stay
    # in THIS script's own process group rather than becoming their own
    # group leader, so there would be no separate group to signal below —
    # a real terminal's Ctrl-C always delivers SIGINT to the whole
    # foreground process group, which is what this test needs to
    # reproduce.
    set -m
    PATH="$stub_dir:$PATH" TMPDIR="$fresh_tmp" bash "$work_dir/run.sh" >"$fresh_tmp/out.log" 2>&1 &
    run_pid=$!
    set +m

    # Generous margin for the process to source lib/common.sh, allocate
    # RUN_TMP_DIR, set ENV_FILE, and reach the injected `sleep 5` — every
    # step before it is either a pure bash builtin or one stubbed,
    # instant-exit `docker` call.
    sleep 1
    # Signal the whole process group (`-$run_pid`: with monitor mode above,
    # the backgrounded job is its own group leader, so its pgid equals its
    # pid), not just the bash PID — signalling only the bash PID leaves the
    # foreground `sleep 5` child alive, and bash defers acting on the
    # pending SIGINT until that child exits on its own, which would make
    # this test take the full 5s and prove nothing about signal-time
    # behavior.
    kill -INT -- "-$run_pid" 2>/dev/null

    wait "$run_pid"
    rc=$?
    out="$(cat "$fresh_tmp/out.log" 2>/dev/null)"

    leftover=("$fresh_tmp"/ch-phase3-run.*)
    leaked=0
    [ -e "${leftover[0]}" ] && leaked=1
    rm -rf "$stub_dir" "$fresh_tmp"

    if [ "$rc" -eq 0 ]; then
        fail "$test_name" "expected run.sh to exit nonzero after SIGINT, got 0. Output: $out"
        return
    fi
    if [ "$leaked" -eq 1 ]; then
        fail "$test_name" "RUN_TMP_DIR '${leftover[0]}' survived a SIGINT delivered right after the cleanup trap was installed — cleanup() aborted before its final rm -rf. Output: $out"
        return
    fi
    pass "$test_name"
}
assert_run_sh_sigint_right_after_trap_install_cleans_up

# ── Finding 8: SIGINT delivered right after RUN_TMP_DIR is created (before ─
# ── ENV_FILE/anything else exists) must still clean up ────────────────────
#
# The pre-trap interrupt window: before this fix, `trap cleanup EXIT` was
# installed only after RUN_TMP_DIR was `mktemp -d`'d and `chmod`'d AND
# ENV_FILE was created/`chmod 600`'d, so a SIGINT anywhere in that whole
# interval — including immediately after RUN_TMP_DIR's directory is
# allocated — exited with NO trap registered at all, leaking the
# just-created `ch-phase3-run.*` directory outright. Neither test above
# catches this: assert_run_sh_early_die_cleans_up only exercises die()
# paths that fire well after the trap is installed, and
# assert_run_sh_sigint_right_after_trap_install_cleans_up injects its delay
# strictly AFTER the (now much earlier) trap line, which today lands before
# RUN_TMP_DIR even exists.
#
# assert_run_sh_sigint_right_after_rundir_created_cleans_up mirrors that
# test's technique exactly — a working copy of run.sh, symlinked back to
# the real lib/ and compose.yml, run under `set -m` so a process-group
# SIGINT can be delivered deterministically — but injects its `sleep`
# immediately after the loop's `unset _run_tmp_candidate _run_tmp_attempt`
# line (i.e. right when RUN_TMP_DIR's directory has just been created and
# the loop is about to `break`), matched via `index()` on that exact
# substring rather than a regex (no shell metacharacters to escape). It
# then asserts run.sh exits nonzero and — the regression this guards —
# leaves no ch-phase3-run.* directory behind, proving the trap (which
# precedes this loop entirely) was already live at the moment RUN_TMP_DIR
# was created. Sabotage-checked against the pre-finding-8 ordering (trap
# moved back below the loop/ENV_FILE in a scratch copy): fails there
# (directory leaked), confirming it actually exercises the fix.
assert_run_sh_sigint_right_after_rundir_created_cleans_up() {
    local test_name="run.sh cleans up RUN_TMP_DIR on SIGINT delivered right after its directory is created (before ENV_FILE exists)"
    local stub_dir fresh_tmp work_dir out rc leftover leaked run_pid

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/run-sigint-rundir-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Always succeeds — see assert_run_sh_early_die_cleans_up's identical stub
# above for why this keeps detect_compose_cmd and cleanup()'s later
# `compose down` both daemon-free.
exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/run-sigint-rundir-tmp.XXXXXX")"

    work_dir="$fresh_tmp/run-sh-copy"
    mkdir -p "$work_dir"
    ln -s "$SCRIPT_DIR/lib" "$work_dir/lib"
    ln -s "$SCRIPT_DIR/compose.yml" "$work_dir/compose.yml"
    awk '
        { print }
        index($0, "unset _run_tmp_candidate _run_tmp_attempt") > 0 && !done {
            print "sleep 5  # lib-tests.sh test-injected delay, see assert_run_sh_sigint_right_after_rundir_created_cleans_up"
            done = 1
        }
    ' "$SCRIPT_DIR/run.sh" >"$work_dir/run.sh"
    if ! grep -q 'test-injected delay' "$work_dir/run.sh"; then
        fail "$test_name" "internal test error: failed to inject the test delay into the run.sh copy — did the RUN_TMP_DIR creation loop change?"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    chmod +x "$work_dir/run.sh"

    # Monitor mode (job control), on just long enough to background the
    # process: without it, a non-interactive script's background jobs stay
    # in THIS script's own process group rather than becoming their own
    # group leader, so there would be no separate group to signal below —
    # a real terminal's Ctrl-C always delivers SIGINT to the whole
    # foreground process group, which is what this test needs to
    # reproduce.
    set -m
    PATH="$stub_dir:$PATH" TMPDIR="$fresh_tmp" bash "$work_dir/run.sh" >"$fresh_tmp/out.log" 2>&1 &
    run_pid=$!
    set +m

    # Generous margin for the process to source lib/common.sh, install the
    # trap, and reach the injected `sleep 5` right after RUN_TMP_DIR's
    # directory is created — every step before it is either a pure bash
    # builtin or one stubbed, instant-exit `docker`/`openssl` call.
    sleep 1
    # Signal the whole process group (`-$run_pid`: with monitor mode above,
    # the backgrounded job is its own group leader, so its pgid equals its
    # pid), not just the bash PID — signalling only the bash PID leaves the
    # foreground `sleep 5` child alive, and bash defers acting on the
    # pending SIGINT until that child exits on its own, which would make
    # this test take the full 5s and prove nothing about signal-time
    # behavior.
    kill -INT -- "-$run_pid" 2>/dev/null

    wait "$run_pid"
    rc=$?
    out="$(cat "$fresh_tmp/out.log" 2>/dev/null)"

    leftover=("$fresh_tmp"/ch-phase3-run.*)
    # Record whether a leak actually happened BEFORE the rm -rf below
    # touches fresh_tmp — checking `-e` on the leftover path afterward
    # would always read false regardless of the real outcome, since the
    # rm -rf already deleted anything the glob matched.
    leaked=0
    [ -e "${leftover[0]}" ] && leaked=1
    rm -rf "$stub_dir" "$fresh_tmp"

    if [ "$rc" -eq 0 ]; then
        fail "$test_name" "expected run.sh to exit nonzero after SIGINT, got 0. Output: $out"
        return
    fi
    if [ "$leaked" -eq 1 ]; then
        fail "$test_name" "RUN_TMP_DIR '${leftover[0]}' survived a SIGINT delivered right after RUN_TMP_DIR was created — no trap was live yet (or cleanup() aborted before its final rm -rf). Output: $out"
        return
    fi
    pass "$test_name"
}
assert_run_sh_sigint_right_after_rundir_created_cleans_up

# ── Finding 9: SIGINT delivered WHILE the `mkdir` creating RUN_TMP_DIR is ──
# ── still running (directory already exists on disk, external command ────
# ── has not yet returned) must still clean up ──────────────────────────────
#
# The narrower gap finding 8 left open: `RUN_TMP_DIR="$(mktemp -d ...)"`
# still ran mktemp as a separate process, so a SIGINT landing between
# mktemp's own mkdir(2) syscall creating the directory and this shell
# finishing the command substitution and assigning the path left
# RUN_TMP_DIR unset in cleanup() — the trap was live (finding 8), but it
# had nothing to remove yet, so the just-created directory still leaked
# (reproduced: exit 130, directory survives). assert_run_sh_sigint_right_
# after_rundir_created_cleans_up above cannot catch this: its injected
# sleep fires only after RUN_TMP_DIR is already known, which is exactly the
# state finding 9 did not previously guarantee.
#
# The fix assigns RUN_TMP_DIR to a pre-computed candidate path BEFORE
# calling `mkdir` on it (see run.sh), so RUN_TMP_DIR is known even while
# the external `mkdir` command is still running. This test proves that
# specific ordering rather than merely re-running the finding-8 scenario:
# it runs the REAL, unmodified run.sh (no awk injection into run.sh itself)
# with a stub `mkdir` placed first on PATH that, only for a
# `ch-phase3-run.*` target, invokes the real `mkdir` (so the directory is
# genuinely created on disk) and THEN sleeps 5s before returning — landing
# the SIGINT while the directory already exists but the `mkdir` command
# itself has not yet handed control back to run.sh. Any other `mkdir` call
# (e.g. run.sh's own `mkdir -p "$TMPDIR"`) passes straight through to the
# real binary via `command -p mkdir`, untouched.
#
# Sabotage-checked against an ordering that assigns RUN_TMP_DIR only AFTER
# `mkdir` succeeds (`if mkdir -m 700 "$candidate"; then RUN_TMP_DIR=...`,
# the shape finding 9 forbids) in a scratch copy: with that ordering, bash
# is still blocked waiting for the stubbed `mkdir` process (mid-sleep) to
# exit when SIGINT arrives, so the `if`'s body — and therefore the
# RUN_TMP_DIR assignment — never runs; cleanup() sees RUN_TMP_DIR unset and
# the directory the stub already created on disk leaks. The real ordering
# below does not have this problem because the assignment happens as its
# own statement strictly before `mkdir` is ever invoked.
assert_run_sh_sigint_during_rundir_mkdir_cleans_up() {
    local test_name="run.sh cleans up RUN_TMP_DIR on SIGINT delivered while the mkdir creating it is still running"
    local stub_dir fresh_tmp out rc leftover leaked run_pid dir_existed

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/run-sigint-mkdir-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Always succeeds — see assert_run_sh_early_die_cleans_up's identical stub
# above for why this keeps detect_compose_cmd and cleanup()'s later
# `compose down` both daemon-free.
exit 0
STUB
    chmod +x "$stub_dir/docker"

    cat >"$stub_dir/mkdir" <<'STUB'
#!/usr/bin/env bash
# Pass every call through to the real mkdir untouched EXCEPT one targeting
# run.sh's own ch-phase3-run.* directory, which we let actually happen
# (via `command -p`, so this stub itself isn't found again) and then hold
# open with a sleep — simulating a SIGINT landing after the directory
# exists on disk but before this external `mkdir` process has returned
# control to run.sh.
for arg in "$@"; do
    case "$arg" in
        *ch-phase3-run.*)
            command -p mkdir "$@"
            rc=$?
            sleep 5
            exit "$rc"
            ;;
    esac
done
exec command -p mkdir "$@"
STUB
    chmod +x "$stub_dir/mkdir"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/run-sigint-mkdir-tmp.XXXXXX")"

    # Monitor mode (job control) — see the identical comment on
    # assert_run_sh_sigint_right_after_rundir_created_cleans_up above for
    # why this is required to deliver a real process-group SIGINT.
    set -m
    PATH="$stub_dir:$PATH" TMPDIR="$fresh_tmp" bash "$SCRIPT_DIR/run.sh" >"$fresh_tmp/out.log" 2>&1 &
    run_pid=$!
    set +m

    # Generous margin for the process to source lib/common.sh, install the
    # trap, and reach the stubbed `mkdir`'s post-creation sleep — every
    # step before it is either a pure bash builtin or a stubbed,
    # instant-exit `docker`/`openssl` call.
    sleep 1
    kill -INT -- "-$run_pid" 2>/dev/null

    wait "$run_pid"
    rc=$?
    out="$(cat "$fresh_tmp/out.log" 2>/dev/null)"

    leftover=("$fresh_tmp"/ch-phase3-run.*)
    dir_existed=0
    [ -e "${leftover[0]}" ] && dir_existed=1
    leaked="$dir_existed"
    rm -rf "$stub_dir" "$fresh_tmp"

    if [ "$rc" -eq 0 ]; then
        fail "$test_name" "expected run.sh to exit nonzero after SIGINT, got 0. Output: $out"
        return
    fi
    if [ "$leaked" -eq 1 ]; then
        fail "$test_name" "RUN_TMP_DIR '${leftover[0]}' survived a SIGINT delivered while its mkdir was still running — RUN_TMP_DIR was not known to cleanup() at that point. Output: $out"
        return
    fi
    pass "$test_name"
}
assert_run_sh_sigint_during_rundir_mkdir_cleans_up

# ── T11: bring_up_fixture_fallback shim test (plan §17.3) ─────────────────
#
# The functions below extract facts from a docker-compose YAML file's text
# well enough to compare run.sh's generated fallback template against the
# real compose.yml, without needing a real `docker compose config`/
# `docker-compose config` call (which would need PHASE3_CLUSTER_SECRET and
# DOCKER_NETWORK resolved the same way for both files, and would mix in
# whichever compose engine happens to be installed on the test host). Both
# files use the identical 2/4/6-space indent convention (compose.yml is
# hand-written that way; the fallback's printf calls in run.sh emit the
# same indentation on purpose), so the same extraction logic applies to
# both unchanged.

# extract_compose_service_names FILE — the top-level service keys under
# "services:" (2-space indent, ending in ':'), one per line, until
# "networks:" or EOF.
extract_compose_service_names() {
    awk '
        /^services:/ { in_services = 1; next }
        /^networks:/ { in_services = 0 }
        in_services && /^  [A-Za-z0-9_-]+:$/ {
            line = $0
            sub(/^  /, "", line)
            sub(/:$/, "", line)
            print line
        }
    ' "$1"
}

# extract_compose_service_block FILE SERVICE — SERVICE's own lines
# (strictly between its "  SERVICE:" header and the next 2-space-indent
# service header or "networks:"), indentation preserved.
extract_compose_service_block() {
    local file="$1" svc="$2"
    awk -v header="  ${svc}:" '
        $0 == header { grab = 1; next }
        grab && /^  [A-Za-z0-9_-]+:$/ { grab = 0 }
        grab && /^networks:/ { grab = 0 }
        grab { print }
    ' "$file"
}

# compose_scalar BLOCK KEY — the value of a "    KEY: value" line (4-space
# indent) within BLOCK, e.g. "image" or "command".
compose_scalar() {
    printf '%s\n' "$1" | awk -v key="    $2:" '
        index($0, key) == 1 {
            line = $0
            sub(key, "", line)
            sub(/^ */, "", line)
            print line
            exit
        }
    '
}

# compose_nested_scalar BLOCK KEY — the value of a "      KEY: value" line
# (6-space indent, one level deeper than compose_scalar), e.g. the "test:"
# line under a service's "healthcheck:".
compose_nested_scalar() {
    printf '%s\n' "$1" | awk -v key="      $2:" '
        index($0, key) == 1 {
            line = $0
            sub(key, "", line)
            sub(/^ */, "", line)
            print line
            exit
        }
    '
}

# compose_sub_list BLOCK KEY — every "      - item" bullet line (6-space
# indent) under a "    KEY:" heading (4-space indent) within BLOCK,
# stopping at the next 4-space or 2-space heading.
compose_sub_list() {
    printf '%s\n' "$1" | awk -v key="    $2:" '
        $0 == key { grab = 1; next }
        grab && /^    [A-Za-z]/ { grab = 0 }
        grab && /^  [A-Za-z]/ { grab = 0 }
        grab && /^      - / { print }
    '
}

# compose_volume_dst_mode_list BLOCK — compose_sub_list BLOCK volumes,
# stripped down to "DST:MODE" per bullet (dropping the bind-mount SOURCE,
# which legitimately differs between compose.yml's relative "./..." paths
# and the fallback's absolute $SCRIPT_DIR/$repo_root-based ones — neither
# source ever contains a literal ':', so "everything after the first
# colon" is exactly "DST:MODE" either way), sorted.
compose_volume_dst_mode_list() {
    compose_sub_list "$1" volumes | while IFS= read -r line; do
        line="${line#- }"
        printf '%s\n' "${line#*:}"
    done | sort
}

# normalize_compose_image VALUE — compose.yml's two ClickHouse-node
# services keep their image as compose's own `${PHASE3_CH_IMAGE:-DEFAULT}`
# variable reference (resolved by the compose engine at up-time), while
# run.sh's fallback template bakes in the already-resolved literal value
# via printf (see bring_up_fixture_fallback) — semantically the same image
# whenever PHASE3_CH_IMAGE is unset, as it is for this test, but textually
# different. Strip the `${PHASE3_CH_IMAGE:-...}` wrapper down to its
# DEFAULT so both forms compare equal; a plain literal (every other
# service's image) passes through unchanged.
normalize_compose_image() {
    local v="$1"
    case "$v" in
        '${PHASE3_CH_IMAGE:-'*'}')
            v="${v#\$\{PHASE3_CH_IMAGE:-}"
            v="${v%\}}"
            ;;
    esac
    printf '%s' "$v"
}

# compose_env_keys BLOCK — the KEY names (never the values — the two
# files' PHASE3_CLUSTER_SECRET require-error MESSAGE text legitimately
# differs) of every "      KEY: value" line under a service's
# "    environment:" heading, sorted.
compose_env_keys() {
    printf '%s\n' "$1" | awk '
        $0 == "    environment:" { grab = 1; next }
        grab && /^    [A-Za-z]/ { grab = 0 }
        grab && /^  [A-Za-z]/ { grab = 0 }
        grab && /^      [A-Za-z0-9_]+:/ {
            line = $0
            sub(/^      /, "", line)
            sub(/:.*/, "", line)
            print line
        }
    ' | sort
}

# test_bring_up_fixture_fallback — runs the REAL run.sh as a subprocess
# with PHASE3_TEST_INVOKE_FALLBACK=1 (see run.sh's own comment on that
# hook) and a stub `docker` shim on PATH that records every Docker/Compose
# operation bring_up_fixture_fallback issues and answers just enough of
# `compose version/up/ps -q`, `network inspect/create/connect/disconnect`,
# and `inspect -f '{{.Name}}'` for that function to run to completion with
# no real daemon involved, then asserts: the generated fallback compose
# file's service set and per-service image/command/ports/healthcheck/
# volumes/environment-keys match compose.yml; every `docker network
# connect` call carries `--alias`; the auth-net/cluster-net aliases are
# exactly the services the plan requires; and only ch-oauth-ldap and
# clickhouse-remote are ever disconnected from the shared network.
test_bring_up_fixture_fallback() {
    local prefix="bring_up_fixture_fallback"
    local stub_dir fresh_tmp call_log compose_copy out rc shared_net

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/fallback-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Records selected Docker CLI invocations to $DOCKER_CALL_LOG and returns
# fixed, deterministic responses so bring_up_fixture_fallback (run.sh) can
# run to completion with no real Docker daemon involved. See
# test_bring_up_fixture_fallback (lib-tests.sh) for what each response
# encodes and asserts.
log_call() { printf '%s\n' "$*" >>"$DOCKER_CALL_LOG"; }

if [ "$1" = "compose" ]; then
    shift
    # compose() (lib/common.sh) always prepends "-p PROJECT -f FILE
    # --env-file FILE" before the real subcommand; skip those three
    # flag/value pairs to find it.
    rest=()
    skip=0
    for a in "$@"; do
        if [ "$skip" -eq 1 ]; then
            skip=0
            continue
        fi
        case "$a" in
            -p|-f|--env-file)
                skip=1
                continue
                ;;
        esac
        rest+=("$a")
    done
    case "${rest[0]:-}" in
        version)
            exit 0
            ;;
        up)
            log_call "compose up"
            exit 0
            ;;
        ps)
            # rest = (ps -q SERVICE)
            log_call "compose ps -q ${rest[2]:-}"
            printf 'cid-%s\n' "${rest[2]:-}"
            exit 0
            ;;
        *)
            log_call "compose ${rest[*]:-}"
            exit 0
            ;;
    esac
fi

if [ "$1" = "network" ]; then
    case "$2" in
        inspect)
            # Always report "does not exist" so bring_up_fixture_fallback's
            # `docker network inspect || create` branch always creates.
            exit 1
            ;;
        create)
            log_call "network create net=$3"
            exit 0
            ;;
        connect)
            # docker network connect --alias ALIAS NET CNAME — require the
            # literal --alias flag at $3 rather than assuming it by
            # position, so a caller that drops --alias (leaving $3=NET,
            # $4=CNAME) is recorded distinguishably instead of being
            # mis-parsed into a line that still happens to contain the
            # substring "alias=".
            if [ "$3" = "--alias" ]; then
                log_call "network connect alias=$4 net=$5 cname=$6"
            else
                log_call "network connect NO-ALIAS-FLAG args=$*"
            fi
            exit 0
            ;;
        disconnect)
            # docker network disconnect NET CNAME
            log_call "network disconnect net=$3 cname=$4"
            exit 0
            ;;
        *)
            log_call "network $*"
            exit 0
            ;;
    esac
fi

if [ "$1" = "inspect" ]; then
    # docker inspect -f '{{.Name}}' CID — CID is our own synthetic
    # "cid-<service>" minted by the `compose ps -q` branch above.
    cid="${*: -1}"
    printf '/fake-container-%s\n' "${cid#cid-}"
    exit 0
fi

log_call "UNHANDLED: $*"
exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/fallback-run-tmp.XXXXXX")"
    call_log="$fresh_tmp/docker-calls.log"
    compose_copy="$fresh_tmp/fallback-compose-copy.yml"
    : >"$call_log"
    shared_net="ch-phase3-libtest-shared"

    out="$(PATH="$stub_dir:$PATH" \
        TMPDIR="$fresh_tmp" \
        DOCKER_NETWORK="$shared_net" \
        DOCKER_CALL_LOG="$call_log" \
        PHASE3_TEST_INVOKE_FALLBACK=1 \
        PHASE3_TEST_FALLBACK_COMPOSE_COPY="$compose_copy" \
        bash "$SCRIPT_DIR/run.sh" 2>&1)"
    rc=$?

    if [ "$rc" -ne 0 ]; then
        fail "$prefix: hook completes daemon-free" "expected exit 0, got $rc. Output: $out"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    pass "$prefix: hook completes daemon-free"

    if [ ! -s "$compose_copy" ]; then
        fail "$prefix: generated fallback compose captured" "no non-empty file at $compose_copy. Output: $out"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    pass "$prefix: generated fallback compose captured"

    # ---- service set parity ----
    local real_services fb_services
    real_services="$(extract_compose_service_names "$SCRIPT_DIR/compose.yml" | sort)"
    fb_services="$(extract_compose_service_names "$compose_copy" | sort)"
    if [ "$real_services" = "$fb_services" ]; then
        pass "$prefix: generated service set matches compose.yml"
    else
        fail "$prefix: generated service set matches compose.yml" "compose.yml=[$real_services] fallback=[$fb_services]"
    fi

    # ---- per-service config parity ----
    local svc real_block fb_block mismatch=0 detail="" real_v fb_v
    for svc in synthetic-idp ch-oauth-ldap clickhouse-origin clickhouse-remote; do
        real_block="$(extract_compose_service_block "$SCRIPT_DIR/compose.yml" "$svc")"
        fb_block="$(extract_compose_service_block "$compose_copy" "$svc")"

        real_v="$(normalize_compose_image "$(compose_scalar "$real_block" image)")"
        fb_v="$(normalize_compose_image "$(compose_scalar "$fb_block" image)")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail image[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_scalar "$real_block" command)"
        fb_v="$(compose_scalar "$fb_block" command)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail command[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_sub_list "$real_block" ports | sort)"
        fb_v="$(compose_sub_list "$fb_block" ports | sort)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail ports[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_nested_scalar "$real_block" test)"
        fb_v="$(compose_nested_scalar "$fb_block" test)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail healthcheck[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_volume_dst_mode_list "$real_block")"
        fb_v="$(compose_volume_dst_mode_list "$fb_block")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail volumes[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_env_keys "$real_block")"
        fb_v="$(compose_env_keys "$fb_block")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail env-keys[$svc]:'$real_v'!='$fb_v' "; }
    done
    if [ "$mismatch" -eq 0 ]; then
        pass "$prefix: per-service image/command/ports/healthcheck/volumes/env-keys match compose.yml"
    else
        fail "$prefix: per-service image/command/ports/healthcheck/volumes/env-keys match compose.yml" "$detail"
    fi

    # ---- every network connect carries --alias ----
    local connect_lines total_connects
    connect_lines="$(grep '^network connect ' "$call_log" || true)"
    total_connects="$(printf '%s\n' "$connect_lines" | grep -c . || true)"
    if [ "$total_connects" -eq 5 ] && ! printf '%s\n' "$connect_lines" | grep -q 'NO-ALIAS-FLAG'; then
        pass "$prefix: every docker network connect carries --alias"
    else
        fail "$prefix: every docker network connect carries --alias" "expected 5 connect calls all with alias=; got: $connect_lines"
    fi

    # ---- auth-net aliases ----
    local auth_ok=1 auth_svc
    for auth_svc in synthetic-idp ch-oauth-ldap clickhouse-origin; do
        grep -qF "network connect alias=$auth_svc net=ch-phase3-auth-net cname=fake-container-$auth_svc" "$call_log" || auth_ok=0
    done
    if [ "$auth_ok" -eq 1 ]; then
        pass "$prefix: auth-net aliases are synthetic-idp/ch-oauth-ldap/clickhouse-origin"
    else
        fail "$prefix: auth-net aliases are synthetic-idp/ch-oauth-ldap/clickhouse-origin" "call log: $(cat "$call_log")"
    fi

    # ---- cluster-net aliases ----
    local cluster_ok=1 cluster_svc
    for cluster_svc in clickhouse-origin clickhouse-remote; do
        grep -qF "network connect alias=$cluster_svc net=ch-phase3-cluster-net cname=fake-container-$cluster_svc" "$call_log" || cluster_ok=0
    done
    if [ "$cluster_ok" -eq 1 ]; then
        pass "$prefix: cluster-net aliases are clickhouse-origin/clickhouse-remote"
    else
        fail "$prefix: cluster-net aliases are clickhouse-origin/clickhouse-remote" "call log: $(cat "$call_log")"
    fi

    # ---- only ch-oauth-ldap + clickhouse-remote disconnected from shared ----
    local disc_ok=1
    grep -qF "network disconnect net=$shared_net cname=fake-container-ch-oauth-ldap" "$call_log" || disc_ok=0
    grep -qF "network disconnect net=$shared_net cname=fake-container-clickhouse-remote" "$call_log" || disc_ok=0
    if grep -qF "network disconnect net=$shared_net cname=fake-container-synthetic-idp" "$call_log"; then disc_ok=0; fi
    if grep -qF "network disconnect net=$shared_net cname=fake-container-clickhouse-origin" "$call_log"; then disc_ok=0; fi
    if [ "$disc_ok" -eq 1 ]; then
        pass "$prefix: only ch-oauth-ldap and clickhouse-remote are disconnected from the shared network"
    else
        fail "$prefix: only ch-oauth-ldap and clickhouse-remote are disconnected from the shared network" "call log: $(cat "$call_log")"
    fi

    rm -rf "$stub_dir" "$fresh_tmp"
}
test_bring_up_fixture_fallback

# ── T11: array-driven leak-scan completeness (plan §17.2) ─────────────────

test_leakscan_completeness_normal_defaults() {
    local dir out rc
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-normal.XXXXXX")"
    printf 'x\n' >"$dir/compose-ch-oauth-ldap.log"
    printf 'x\n' >"$dir/compose-clickhouse-origin.log"
    printf 'x\n' >"$dir/compose-clickhouse-remote.log"
    printf 'x\n' >"$dir/clickhouse-origin-clickhouse-server.log"
    printf 'x\n' >"$dir/clickhouse-remote-clickhouse-server.log"
    printf 'x\n' >"$dir/run-transcript.log"
    printf '' >"$dir/clickhouse-origin-clickhouse-server.err.log"
    printf '' >"$dir/clickhouse-remote-clickhouse-server.err.log"
    printf 'x\n' >"$dir/auth-failure-01.txt"

    out="$(leakscan_require_artifacts_complete "$dir" 2>&1)"
    rc=$?
    rm -rf "$dir"
    if [ "$rc" -ne 0 ]; then
        fail "leakscan completeness: normal defaults unchanged (happy path)" "expected exit 0, got $rc. Output: $out"
        return
    fi
    case "$out" in
        *"6 required"*"0 extra"*) pass "leakscan completeness: normal defaults unchanged (happy path)" ;;
        *) fail "leakscan completeness: normal defaults unchanged (happy path)" "expected the legacy six-artifact/zero-extra corpus size in the log: $out" ;;
    esac
}
test_leakscan_completeness_normal_defaults

test_leakscan_completeness_normal_defaults_missing_file_dies() {
    local dir out rc
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-normal-missing.XXXXXX")"
    printf 'x\n' >"$dir/compose-ch-oauth-ldap.log"
    printf 'x\n' >"$dir/compose-clickhouse-origin.log"
    # compose-clickhouse-remote.log deliberately omitted.
    printf 'x\n' >"$dir/clickhouse-origin-clickhouse-server.log"
    printf 'x\n' >"$dir/clickhouse-remote-clickhouse-server.log"
    printf 'x\n' >"$dir/run-transcript.log"
    printf '' >"$dir/clickhouse-origin-clickhouse-server.err.log"
    printf '' >"$dir/clickhouse-remote-clickhouse-server.err.log"
    printf 'x\n' >"$dir/auth-failure-01.txt"

    out="$(leakscan_require_artifacts_complete "$dir" 2>&1)"
    rc=$?
    rm -rf "$dir"
    if [ "$rc" -eq 0 ]; then
        fail "leakscan completeness: normal defaults still catch a missing legacy artifact" "expected die (nonzero exit), got 0. Output: $out"
        return
    fi
    case "$out" in
        *"compose-clickhouse-remote.log"*) pass "leakscan completeness: normal defaults still catch a missing legacy artifact" ;;
        *) fail "leakscan completeness: normal defaults still catch a missing legacy artifact" "die() message did not name the missing file: $out" ;;
    esac
}
test_leakscan_completeness_normal_defaults_missing_file_dies

# build_ha_leakscan_corpus DIR — writes every file the HA-shaped arrays
# below (run_ha_leakscan_completeness) require, all non-empty. The
# "compose-ch-oauth-ldap.log" entry stands for the HAProxy frontend, which
# the plan's HA topology keeps under the same "ch-oauth-ldap" compose
# service name the normal fixture uses for the single helper (see §17.2).
build_ha_leakscan_corpus() {
    local dir="$1" f
    for f in compose-ch-oauth-ldap.log compose-ch-oauth-ldap-a.log compose-ch-oauth-ldap-b.log \
        compose-clickhouse-origin.log compose-clickhouse-remote.log \
        clickhouse-origin-clickhouse-server.log clickhouse-remote-clickhouse-server.log \
        clickhouse-origin-clickhouse-server.err.log clickhouse-remote-clickhouse-server.err.log \
        run-transcript.log session-probe.log auth-failure-01.txt; do
        printf 'synthetic artifact content\n' >"$dir/$f"
    done
}

# run_ha_leakscan_completeness DIR — runs leakscan_require_artifacts_complete
# against DIR with the plan's HA-shaped arrays, in a subshell so the array
# reassignment never escapes into this test file's own shell. Sets
# CAPTURE_OUT/CAPTURE_RC.
run_ha_leakscan_completeness() {
    local dir="$1"
    CAPTURE_OUT="$(
        LEAKSCAN_COMPOSE_SERVICES=(ch-oauth-ldap ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-origin clickhouse-remote)
        LEAKSCAN_NODES=(clickhouse-origin clickhouse-remote)
        LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS=(session-probe.log)
        leakscan_require_artifacts_complete "$dir" 2>&1
    )"
    CAPTURE_RC=$?
}

test_leakscan_completeness_ha_shaped_happy_path() {
    local dir
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-ha-happy.XXXXXX")"
    build_ha_leakscan_corpus "$dir"
    run_ha_leakscan_completeness "$dir"
    rm -rf "$dir"
    if [ "$CAPTURE_RC" -ne 0 ]; then
        fail "leakscan completeness: HA-shaped arrays accept a complete corpus" "expected exit 0, got $CAPTURE_RC. Output: $CAPTURE_OUT"
        return
    fi
    case "$CAPTURE_OUT" in
        *"9 required"*"1 extra"*) pass "leakscan completeness: HA-shaped arrays accept a complete corpus" ;;
        *) fail "leakscan completeness: HA-shaped arrays accept a complete corpus" "expected a 9-required/1-extra corpus size in the log: $CAPTURE_OUT" ;;
    esac
}
test_leakscan_completeness_ha_shaped_happy_path

# assert_ha_leakscan_fails FILENAME MODE — builds a complete HA corpus,
# then removes (MODE=missing) or truncates (MODE=empty) FILENAME, and
# asserts leakscan_require_artifacts_complete dies naming that file — the
# plan's "missing/empty A/B/HAProxy/probe artifact is a hard failure"
# requirement (§17.2/§25).
assert_ha_leakscan_fails() {
    local filename="$1" mode="$2" dir test_name
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-ha-neg.XXXXXX")"
    build_ha_leakscan_corpus "$dir"
    case "$mode" in
        missing) rm -f "$dir/$filename" ;;
        empty) : >"$dir/$filename" ;;
    esac
    run_ha_leakscan_completeness "$dir"
    rm -rf "$dir"
    test_name="leakscan completeness: HA-shaped arrays fail on $mode $filename"
    if [ "$CAPTURE_RC" -eq 0 ]; then
        fail "$test_name" "expected die (nonzero exit), got 0. Output: $CAPTURE_OUT"
        return
    fi
    case "$CAPTURE_OUT" in
        *"$filename"*) pass "$test_name" ;;
        *) fail "$test_name" "die() message did not name '$filename': $CAPTURE_OUT" ;;
    esac
}

for _ha_neg_file in compose-ch-oauth-ldap-a.log compose-ch-oauth-ldap-b.log compose-ch-oauth-ldap.log session-probe.log; do
    assert_ha_leakscan_fails "$_ha_neg_file" missing
    assert_ha_leakscan_fails "$_ha_neg_file" empty
done
unset _ha_neg_file

# ── T11: sourcing-guard idempotence (plan §17.1) ──────────────────────────

test_common_sh_sourcing_guard_preserves_reassignment() {
    local rc
    (
        PHASE3_SERVICES=(guard-test-a guard-test-b)
        # shellcheck source=../lib/common.sh
        source "$SCRIPT_DIR/lib/common.sh"
        [ "${PHASE3_SERVICES[*]}" = "guard-test-a guard-test-b" ]
    )
    rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "lib/common.sh: re-sourcing does not reset a reassigned PHASE3_SERVICES"
    else
        fail "lib/common.sh: re-sourcing does not reset a reassigned PHASE3_SERVICES" "PHASE3_SERVICES was reset by the second source"
    fi
}
test_common_sh_sourcing_guard_preserves_reassignment

test_leakscan_sh_sourcing_guard_preserves_reassignment() {
    local rc
    (
        LEAKSCAN_NODES=(guard-node-a guard-node-b guard-node-c)
        LEAKSCAN_COMPOSE_SERVICES=(guard-svc-a guard-svc-b)
        LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS=(guard-extra.log)
        # shellcheck source=../lib/leakscan.sh
        source "$SCRIPT_DIR/lib/leakscan.sh"
        [ "${LEAKSCAN_NODES[*]}" = "guard-node-a guard-node-b guard-node-c" ] \
            && [ "${LEAKSCAN_COMPOSE_SERVICES[*]}" = "guard-svc-a guard-svc-b" ] \
            && [ "${LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS[*]}" = "guard-extra.log" ]
    )
    rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "lib/leakscan.sh: re-sourcing does not reset reassigned LEAKSCAN_NODES/LEAKSCAN_COMPOSE_SERVICES/LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS"
    else
        fail "lib/leakscan.sh: re-sourcing does not reset reassigned LEAKSCAN_NODES/LEAKSCAN_COMPOSE_SERVICES/LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS" "one or more arrays were reset by the second source"
    fi
}
test_leakscan_sh_sourcing_guard_preserves_reassignment

# ── T11: cases/ auto-discovery hook ────────────────────────────────────────
#
# T12b (and later sub-tasks) add self-contained case files under
# integration/clickhouse/tests/cases/*.sh rather than growing this file
# indefinitely. Each is sourced — not exec'd — so it sees every function
# and variable already defined above (SCRIPT_DIR, RUN_TMP_DIR, pass/fail/
# run_and_capture, the sourced lib/*.sh functions), exactly like a
# scenarios/*.sh file sees run.sh's; a case file signals its own failures
# via fail(), which is already reflected in $FAILURES below. Unlike
# scenarios/*.sh, an empty cases/ directory is the expected steady state
# until a case-adding sub-task lands, so nullglob makes a zero-file glob a
# normal, explicitly-logged outcome rather than an error.
shopt -s nullglob
case_files=("$SCRIPT_DIR"/tests/cases/*.sh)
shopt -u nullglob
if [ "${#case_files[@]}" -eq 0 ]; then
    printf 'cases/ hook: no integration/clickhouse/tests/cases/*.sh files found (0 files) — nothing to auto-discover yet\n'
else
    printf 'cases/ hook: sourcing %d file(s) from integration/clickhouse/tests/cases/\n' "${#case_files[@]}"
    for f in "${case_files[@]}"; do
        printf 'cases/ hook: sourcing %s\n' "$f"
        # shellcheck disable=SC1090
        source "$f"
    done
fi

# ── Summary ────────────────────────────────────────────────────────────────

if [ "$FAILURES" -eq 0 ]; then
    printf '\nall tests passed\n'
    exit 0
else
    printf '\n%d test(s) failed\n' "$FAILURES"
    exit 1
fi
