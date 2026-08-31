#!/usr/bin/env bash
# integration/clickhouse/tests/cases/wirecapture-fixture-freeze.sh
#
# Proves, daemon-free, that capture-ldap-wire.sh's committed-fixture freeze
# is mechanical rather than documentary: `--mode generate` refuses, BEFORE
# any state-mutating Docker/Compose call, to promote into an --output
# directory that already holds a directory for a tracked line it would
# capture — and, symmetrically, does NOT refuse when the only pre-existing
# directories belong to lines outside BUILDS.
#
# Why this test exists. Issue #33 phase 4 froze wire generation outright.
# Adding the 26.3/26.8 tracked lines narrowed that freeze to what it was
# actually protecting — "no COMMITTED fixture is ever regenerated or
# promoted" — because an outright freeze makes BUILDS unable to ever grow
# again: the four-way tracked-line equality contract requires a fixture
# directory per line, and a line that can never be captured can never
# satisfy it. A narrowed policy that lives only in prose is one careless
# `--output internal/ldap/testdata/clickhouse-wire` away from silently
# rewriting the committed corpus, which is exactly the thing the original
# freeze existed to prevent. So the narrowing is enforced here.
#
# Sourced by tests/lib-tests.sh's cases/ auto-discovery hook — see that
# file's header and wirecapture-collision-preflight.sh's — so it inherits
# SCRIPT_DIR, RUN_TMP_DIR, and pass/fail. It defines only its own helpers.
#
# Proof technique matches wirecapture-collision-preflight.sh: a stub
# `docker` on PATH that logs every invocation verbatim and answers every
# subcommand with a clean exit and no output. That default makes all three
# of capture-ldap-wire.sh's ch-* collision preflights pass (no hits ever
# reported), so the ONLY refusal a run can hit is the freeze guard under
# test — and the logged call sequence proves nothing was mutated first.
#
# Diagnostics below print call-log LINE COUNTS only, never the raw log.

if [ -z "${SCRIPT_DIR:-}" ] || [ -z "${RUN_TMP_DIR:-}" ]; then
    printf 'FAIL: wirecapture-fixture-freeze.sh -- expected SCRIPT_DIR/RUN_TMP_DIR to already be set by lib-tests.sh\n'
    FAILURES=$((FAILURES + 1))
    return 0 2>/dev/null || exit 1
fi

# wirecap_freeze_stub_dir — a stub `docker` that logs every call and never
# reports a collision hit, so no ch-* preflight can fire.
wirecap_freeze_stub_dir() {
    local stub_dir
    stub_dir="$(mktemp -d "$RUN_TMP_DIR/freeze-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_CALL_LOG"
exit 0
STUB
    chmod +x "$stub_dir/docker"
    printf '%s' "$stub_dir"
}

# run_wirecap_freeze_case CASE_NAME EXPECT_DIE PRE_EXISTING_LINE...
#
# Creates a fresh --output directory pre-seeded with a directory per
# PRE_EXISTING_LINE, runs capture-ldap-wire.sh --mode generate against it,
# and asserts the die/no-die outcome plus (when dying) that no mutating
# Docker call was issued first.
run_wirecap_freeze_case() {
    local case_name="$1" expect_die="$2"
    shift 2
    local pre_lines=("$@")
    local stub_dir fresh_tmp call_log out_dir out rc line

    stub_dir="$(wirecap_freeze_stub_dir)"
    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/freeze-run-tmp.XXXXXX")"
    call_log="$fresh_tmp/docker-calls.log"
    : >"$call_log"

    out_dir="$fresh_tmp/output"
    mkdir -p "$out_dir"
    for line in "${pre_lines[@]}"; do
        mkdir -p "$out_dir/$line"
    done

    out="$(PATH="$stub_dir:$PATH" \
        TMPDIR="$fresh_tmp" \
        DOCKER_CALL_LOG="$call_log" \
        bash "$SCRIPT_DIR/capture-ldap-wire.sh" --mode generate --output "$out_dir" 2>&1)"
    rc=$?

    if [ "$expect_die" = "yes" ]; then
        if [ "$rc" -ne 0 ]; then
            pass "$case_name: refuses (nonzero exit)"
        else
            fail "$case_name: refuses (nonzero exit)" "expected nonzero exit, got 0"
        fi

        case "$out" in
        *"refusing to regenerate committed fixture"*)
            pass "$case_name: die message names the freeze"
            ;;
        *)
            fail "$case_name: die message names the freeze" "expected a 'refusing to regenerate committed fixture' message"
            ;;
        esac

        for line in "${pre_lines[@]}"; do
            case "$out" in
            *"$line"*) pass "$case_name: die message names the colliding line $line" ;;
            *) fail "$case_name: die message names the colliding line $line" "line '$line' absent from the refusal message" ;;
            esac
        done

        local log_lines
        log_lines="$(grep -c . "$call_log" 2>/dev/null || true)"

        if grep -qE '^compose( .*)? up([[:space:]]|$)' "$call_log"; then
            fail "$case_name: no 'compose ... up' before the die" "found in $log_lines logged call(s)"
        else
            pass "$case_name: no 'compose ... up' before the die"
        fi

        if grep -q 'network create' "$call_log"; then
            fail "$case_name: no 'network create' before the die" "found in $log_lines logged call(s)"
        else
            pass "$case_name: no 'network create' before the die"
        fi
    else
        case "$out" in
        *"refusing to regenerate committed fixture"*)
            fail "$case_name: does not trip the freeze" "the freeze guard fired for a line with no committed fixture directory"
            ;;
        *)
            pass "$case_name: does not trip the freeze"
            ;;
        esac

        # Asserting only the ABSENCE of the refusal message would pass
        # vacuously if the run died before ever reaching the guard (a
        # missing image, a preflight, an argument error). Require the
        # guard's own positive log line too, so this case proves the guard
        # ran and declined rather than proving nothing at all.
        case "$out" in
        *"preflight: no committed fixture would be overwritten"*)
            pass "$case_name: freeze guard actually ran"
            ;;
        *)
            fail "$case_name: freeze guard actually ran" "the guard's positive log line is absent — the run never reached the freeze check, so the absence of a refusal proves nothing"
            ;;
        esac
    fi

    rm -rf "$stub_dir" "$fresh_tmp"
}

# Every line currently in BUILDS must be refused when already present.
# Derived from run-all-builds.sh rather than hardcoded, so this test keeps
# covering the real tracked set as BUILDS grows.
wirecap_freeze_tracked_lines() {
    awk '
        /^BUILDS=\(/ { inblock=1; next }
        inblock && /^\)/ { inblock=0; next }
        inblock { print }
    ' "$SCRIPT_DIR/run-all-builds.sh" \
        | grep -oE '"[^"]+"' | tr -d '"' \
        | sed 's/.*://' | awk -F. '{print $1"."$2}' | sort -u
}

wirecap_freeze_lines=()
while IFS= read -r wirecap_freeze_line; do
    [ -n "$wirecap_freeze_line" ] || continue
    wirecap_freeze_lines+=("$wirecap_freeze_line")
done < <(wirecap_freeze_tracked_lines)
unset wirecap_freeze_line

if [ "${#wirecap_freeze_lines[@]}" -eq 0 ]; then
    fail "wirecapture-fixture-freeze: derive tracked lines" "parsed zero lines from run-all-builds.sh's BUILDS"
else
    # One pre-existing committed line is enough to refuse the whole run.
    run_wirecap_freeze_case \
        "freeze: single committed line ${wirecap_freeze_lines[0]}" \
        yes \
        "${wirecap_freeze_lines[0]}"

    # All committed lines present — the "--output pointed straight at the
    # committed corpus" mistake this guard exists to stop.
    run_wirecap_freeze_case \
        "freeze: every committed line present" \
        yes \
        "${wirecap_freeze_lines[@]}"
fi

# A directory for a line NOT in BUILDS must not trip the guard: capturing a
# brand-new tracked line into a fresh output directory is the supported
# path, and over-refusing would make BUILDS ungrowable again.
run_wirecap_freeze_case \
    "freeze: untracked line directory does not refuse" \
    no \
    "1.0"
