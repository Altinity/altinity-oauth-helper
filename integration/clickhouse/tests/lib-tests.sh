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
# This does NOT bring up the real four-service fixture — that remains
# run.sh's job (see integration/clickhouse/README.md: "manual, local
# gate"). It DOES source the real lib/*.sh files, so it needs the same
# `docker`/`docker-compose` CLI *presence* on PATH that lib/common.sh's own
# sourcing-time detect_compose_cmd already requires (no daemon needed —
# every Docker/compose call in these tests is stubbed) — finding 6 and 7's
# tests below run the real run.sh (finding 7: a working copy of it, see
# that test's own comment) as a subprocess but with a stub `docker` shim
# placed first on PATH, so they stay just as daemon-free as everything
# else in this file.
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

# ── Summary ────────────────────────────────────────────────────────────────

if [ "$FAILURES" -eq 0 ]; then
    printf '\nall tests passed\n'
    exit 0
else
    printf '\n%d test(s) failed\n' "$FAILURES"
    exit 1
fi
