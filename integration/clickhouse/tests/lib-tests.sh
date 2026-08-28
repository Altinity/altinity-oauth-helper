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
#
# This does NOT bring up the real four-service fixture — that remains
# run.sh's job (see integration/clickhouse/README.md: "manual, local
# gate"). It DOES source the real lib/*.sh files, so it needs the same
# `docker`/`docker-compose` CLI *presence* on PATH that lib/common.sh's own
# sourcing-time detect_compose_cmd already requires (no daemon needed —
# every Docker/compose call in these tests is stubbed).
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

# ── Summary ────────────────────────────────────────────────────────────────

if [ "$FAILURES" -eq 0 ]; then
    printf '\nall tests passed\n'
    exit 0
else
    printf '\n%d test(s) failed\n' "$FAILURES"
    exit 1
fi
