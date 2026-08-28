#!/usr/bin/env bash
# integration/clickhouse/lib/leakscan.sh
#
# JWT leak-scan helpers for acceptance scenario I (see "Acceptance scenario
# I — JWT leak assertion" and "Leak-scanner self-test" in the phase-3
# plan). This file is SOURCED — never executed directly — by
# scenarios/80-leak-scan.sh, after integration/clickhouse/lib/common.sh and
# integration/clickhouse/lib/oauth.sh. It assumes everything those two
# files' own headers document: run.sh's `set -euo pipefail` / `umask 077`,
# common.sh's log/die/compose/RUN_TMP_DIR, and oauth.sh's
# OAUTH_RETAINED_TOKEN_NAMES registry (a plain array of VARIABLE NAMES, not
# values — see oauth.sh's "Retained-token registry" section).
#
# ── The core invariant this file exists to prove ─────────────────────────
# No raw signed JWT this run ever minted may appear, as a literal
# substring, in any artifact this phase's own integration logs are allowed
# to cover: the helper's own logs, either ClickHouse node's logs (compose-
# captured and on-disk), the runner's own transcript, or a captured HTTP
# authentication-failure body. Every function below is written so that
# PROVING that is itself safe — none of them ever print a token's VALUE to
# stdout/stderr (which would create a fresh leak in the very artifact this
# file captures, namely the runner transcript RUN_LOG tees itself into).
# Only token NAMES, byte counts, and artifact FILE NAMES are ever logged.
#
# ── Functions this file provides ──────────────────────────────────────────
#   leakscan_collect_artifacts
#       Gathers every artifact type acceptance scenario I lists into a
#       fresh, private (mode 0700) directory under $RUN_TMP_DIR and prints
#       that directory's path to stdout (caller must capture it — this is
#       the ONLY thing this function writes to stdout):
#         - `compose logs --no-color` for ch-oauth-ldap, clickhouse-origin,
#           clickhouse-remote;
#         - each ClickHouse node's own on-disk
#           /var/log/clickhouse-server/clickhouse-server{,.err}.log, read
#           via `compose exec -T <node> cat <path>` (no bind mount exists
#           for these — see compose.yml — so this is the only way to reach
#           them);
#         - a copy of $RUN_LOG, the runner's own captured stdout+stderr
#           transcript (see run.sh: it tees itself there from the top);
#       Deliberately does NOT collect the private per-request curl
#       credential configs ch_http_query_as writes under $RUN_TMP_DIR — the
#       plan is explicit that those are "intentional short-lived credential
#       input channels" that "must already have been deleted" by the time
#       this runs (ch_http_query_as deletes its own before returning), so
#       there is nothing there to collect even if this tried.
#   leakscan_capture_auth_failure_bodies DEST_DIR NAME...
#       For each NAME (a variable holding one retained signed JWT), issues
#       one fresh HTTP Basic-authenticated request via ch_http_query_as
#       with that JWT as the password and a fixed, deliberately-mismatched
#       username ("leakscan-probe@example.com", which no minted token's
#       email claim ever equals) — guaranteeing a genuine, generic
#       ClickHouse-side authentication failure every time regardless of
#       which scenario originally minted the token or whether it was
#       itself a positive or negative case. Each response body is written
#       to its own file under DEST_DIR. This is the plan's "captured HTTP
#       authentication-failure bodies" artifact.
#   leakscan_scan_artifacts DIR NAME...
#       Fixed-string (never regex — see `grep -F` below) scan of every
#       regular file under DIR (recursively) for each NAME's token value.
#       Returns 0 ("clean", no leak) if none of the tokens appear anywhere
#       under DIR; returns 1 if at least one does. On a match, logs which
#       retained-token NAME and which FILENAME(s) matched — never the
#       token value, and `grep -l` (list filenames only) is used
#       specifically so the matching line's content — which would contain
#       the leaked token — never reaches this function's own stdout.
#   leakscan_self_test VARNAME
#       The plan's mandatory pre-flight before trusting
#       leakscan_scan_artifacts at all: creates a private synthetic
#       artifact directory under $RUN_TMP_DIR, writes VARNAME's token value
#       into one synthetic file inside it, requires
#       leakscan_scan_artifacts to report a leak there, then removes the
#       synthetic directory. Calls `die` (aborting the whole suite) if the
#       deliberate plant is NOT detected — per the plan, an undetected
#       plant means the scanner itself is not a valid proof, so nothing it
#       reports afterward can be trusted either.
#
# Every function above takes token VARIABLE NAMES as arguments, resolving
# each to its value only internally via bash indirect expansion
# (`"${!name}"`), exactly like oauth.sh's own documented
# OAUTH_RETAINED_TOKEN_NAMES contract — callers should pass
# `"${OAUTH_RETAINED_TOKEN_NAMES[@]}"` through, never a token value
# directly.
# Guards only the `readonly` declaration below against a second `source`
# of this file within the same shell (harmless either way here, since
# run.sh's scenarios/*.sh files each source their own libraries once — see
# lib/common.sh's sourcing-contract header — but this matches lib/oauth.sh's
# own idempotent-sourcing discipline rather than assuming it). The function
# definitions below are always safe to redefine, so they are not guarded.
if [ -z "${LEAKSCAN_SH_LOADED:-}" ]; then
    LEAKSCAN_SH_LOADED=1
    readonly LEAKSCAN_PROBE_USERNAME="leakscan-probe@example.com"
fi

# leakscan_collect_artifacts — see contract above.
leakscan_collect_artifacts() {
    local dir
    dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-artifacts.XXXXXX")"
    chmod 700 "$dir"

    local svc
    for svc in ch-oauth-ldap clickhouse-origin clickhouse-remote; do
        compose logs --no-color "$svc" >"$dir/compose-${svc}.log" 2>&1 || true
    done

    local node
    for node in clickhouse-origin clickhouse-remote; do
        compose exec -T "$node" cat /var/log/clickhouse-server/clickhouse-server.log \
            >"$dir/${node}-server.log" 2>/dev/null || true
        compose exec -T "$node" cat /var/log/clickhouse-server/clickhouse-server.err.log \
            >"$dir/${node}-server.err.log" 2>/dev/null || true
    done

    if [ -n "${RUN_LOG:-}" ] && [ -f "$RUN_LOG" ]; then
        cp "$RUN_LOG" "$dir/run-transcript.log"
    fi

    chmod 600 "$dir"/* 2>/dev/null || true
    printf '%s\n' "$dir"
}

# leakscan_capture_auth_failure_bodies DEST_DIR NAME... — see contract
# above. LEAKSCAN_PROBE_USERNAME (declared above) is fixed and never equal
# to any minted token's email claim, so every one of these requests fails
# ClickHouse's own authentication generically (username/token mismatch),
# independent of what the named token itself carries.
leakscan_capture_auth_failure_bodies() {
    local dest_dir="$1"
    shift
    local name token body_file idx=0
    for name in "$@"; do
        token="${!name:-}"
        [ -n "$token" ] || continue
        idx=$((idx + 1))
        body_file="$dest_dir/auth-failure-$(printf '%02d' "$idx").txt"
        ch_http_query_as "$LEAKSCAN_PROBE_USERNAME" "$token" "SELECT 1" \
            >"$body_file" 2>&1 || true
        chmod 600 "$body_file"
    done
}

# leakscan_scan_artifacts DIR NAME... — see contract above.
leakscan_scan_artifacts() {
    local dir="$1"
    shift
    local name token matches found=0

    for name in "$@"; do
        token="${!name:-}"
        [ -n "$token" ] || continue

        # -r: recurse; -l: filenames only, never the matching line itself
        # (which would contain the leaked token); -F: literal fixed-string
        # match, never a regex (a raw JWT's '.' separators must not be
        # treated as regex metacharacters).
        matches="$(grep -rlF -- "$token" "$dir" 2>/dev/null || true)"
        if [ -n "$matches" ]; then
            found=1
            log "leak-scan: LEAK DETECTED — retained token '$name' found in: $matches"
        fi
    done

    [ "$found" -eq 0 ]
}

# leakscan_self_test VARNAME — see contract above.
leakscan_self_test() {
    local varname="$1"
    local token synth_dir synth_file

    token="${!varname:-}"
    [ -n "$token" ] || die "leak-scan self-test: '$varname' has no token value to plant"

    synth_dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-selftest.XXXXXX")"
    chmod 700 "$synth_dir"
    synth_file="$synth_dir/planted-artifact.log"
    # The planted line deliberately mimics a real log line's shape (a
    # message plus a key=value pair) without actually being one — this is
    # a synthetic artifact for the scanner's own self-test, never a real
    # captured log.
    printf 'synthetic self-test artifact: leaked_value=%s\n' "$token" >"$synth_file"
    chmod 600 "$synth_file"

    if leakscan_scan_artifacts "$synth_dir" "$varname"; then
        rm -rf "$synth_dir"
        die "leak-scan self-test: the scanner did NOT detect a deliberately planted token ('$varname') — the scanner is not a valid proof, aborting the suite (see the plan's Leak-scanner self-test)"
    fi

    rm -rf "$synth_dir"
    log "leak-scan self-test: deliberate plant of '$varname' was correctly detected — scanner is trustworthy"
}
