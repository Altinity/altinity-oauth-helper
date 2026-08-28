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
# No raw signed JWT (or other retained credential) this run ever minted may
# appear, as a literal substring, in any artifact this phase's own
# integration logs are allowed to cover: the helper's own logs, either
# ClickHouse node's logs (compose-captured and on-disk), the runner's own
# transcript, or a captured HTTP authentication-failure body. Every
# function below is written so that PROVING that is itself safe — none of
# them ever print a credential's VALUE to stdout/stderr (which would create
# a fresh leak in the very artifact this file captures, namely the runner
# transcript RUN_LOG tees itself into), and none of them ever place a
# credential on an external process's argv (visible in `ps`/process
# accounting for the life of that process) — `grep` is fed its patterns
# through a private mode-0600 pattern FILE written by the `printf` builtin,
# never as a `grep PATTERN` argument. Only credential NAMES, byte counts,
# and artifact FILE NAMES are ever logged.
#
# ── Functions this file provides ──────────────────────────────────────────
#   leakscan_collect_artifacts DEST_DIR
#       Gathers every artifact type acceptance scenario I lists into
#       DEST_DIR (a private, mode-0700 directory the CALLER creates under
#       $RUN_TMP_DIR — created by the caller, not here, so that this
#       function runs in the caller's own shell and its `die` calls
#       genuinely abort the suite rather than merely killing a `$(...)`
#       subshell):
#         - `compose logs --no-color` for ch-oauth-ldap, clickhouse-origin,
#           clickhouse-remote — the compose invocation itself MUST succeed;
#         - each ClickHouse node's own on-disk
#           /var/log/clickhouse-server/clickhouse-server{,.err}.log, read
#           via `compose exec -T <node> cat <path>` (no bind mount exists
#           for these — see compose.yml — so this is the only way to reach
#           them) — the `cat` MUST succeed (a missing file is a real
#           failure of the artifact corpus, never silently treated as
#           "nothing to scan");
#         - a copy of $RUN_LOG, the runner's own captured stdout+stderr
#           transcript (see run.sh: it tees itself there from the top).
#       Deliberately does NOT collect the private per-request curl
#       credential configs ch_http_query_as writes under $RUN_TMP_DIR — the
#       plan is explicit that those are "intentional short-lived credential
#       input channels" that "must already have been deleted" by the time
#       this runs (ch_http_query_as deletes its own before returning), so
#       there is nothing there to collect even if this tried.
#   leakscan_capture_auth_failure_bodies DEST_DIR NAME...
#       For each NAME (a variable holding one retained credential), issues
#       one fresh HTTP Basic-authenticated request via ch_http_query_as
#       with that credential as the password and a fixed, deliberately-
#       mismatched username ("leakscan-probe@example.com", which no minted
#       token's email claim ever equals and which is not a local user) —
#       guaranteeing a genuine, generic ClickHouse-side authentication
#       failure every time regardless of which scenario originally minted
#       the credential. Each response body is written to its own file
#       under DEST_DIR. This is the plan's "captured HTTP authentication-
#       failure bodies" artifact. Per ch_http_query_as's own contract
#       (lib/common.sh) a non-zero return means a curl TRANSPORT failure,
#       never a query/auth outcome — this function checks that return code
#       AND requires $CH_HTTP_STATUS != "200" before accepting the body as
#       a genuine artifact, `die`-ing otherwise (a transport failure or an
#       unexpected 200 — e.g. a cache-key/identity-policy regression that
#       let the mismatched probe username authenticate — must never be
#       silently accepted as "the intended failure body", since neither
#       exercises the failure-path leak surface this artifact exists to
#       scan). Never echoes the captured body in a `die` message.
#   leakscan_require_artifacts_complete DEST_DIR
#       The completeness gate: `die`s unless every artifact the scan is
#       about to trust actually exists AND is non-empty. The required
#       corpus is built from the ACTIVE arrays, not a hardcoded list, so it
#       automatically widens for an HA-shaped caller instead of trivially
#       passing over a corpus that quietly dropped a service's logs:
#         - one compose log per LEAKSCAN_COMPOSE_SERVICES entry;
#         - one on-disk clickhouse-server.log per LEAKSCAN_NODES entry;
#         - the runner transcript (always required, exactly one);
#         - one file per LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS entry (empty by
#           default in phase-3 normal mode; an HA caller populates it, e.g.
#           with the persistent session probe's captured output).
#       Phase-3's own unreassigned defaults yield exactly the same six
#       required files this function has always required (three compose
#       logs, two node server logs, the transcript) — this refactor changes
#       WHERE the required set comes from, not what it evaluates to for the
#       caller that never touches the arrays. A scan over an empty corpus
#       is trivially "clean" and proves nothing, so an empty artifact is a
#       hard failure, not a pass. The one deliberate exception, logged
#       explicitly rather than silently: a node's on-disk
#       clickhouse-server.err.log MAY legitimately be zero bytes when the
#       server emitted no warnings/errors during the run (the file itself
#       must still have been readable — see leakscan_collect_artifacts).
#   leakscan_scan_artifacts DIR NAME...
#       Fixed-string (never regex — see `grep -F` below) scan of every
#       regular file under DIR (recursively) for each NAME's credential
#       value, supplied to grep via a private pattern file (`grep -f`),
#       never argv. Returns 0 ("clean", no leak) if none of the values
#       appear anywhere under DIR; returns 1 if at least one does. On a
#       match, logs which retained NAME and which FILENAME(s) matched —
#       never the value, and `grep -l` (list filenames only) is used
#       specifically so the matching line's content — which would contain
#       the leaked value — never reaches this function's own stdout.
#   leakscan_self_test VARNAME
#       The plan's mandatory pre-flight before trusting
#       leakscan_scan_artifacts at all: creates a private synthetic
#       artifact directory under $RUN_TMP_DIR, writes VARNAME's value into
#       one synthetic file inside it (via the `printf` builtin), requires
#       leakscan_scan_artifacts — the SAME pattern-file code path the real
#       scan uses — to report a leak there, then removes the synthetic
#       directory. Calls `die` (aborting the whole suite) if the deliberate
#       plant is NOT detected — per the plan, an undetected plant means the
#       scanner itself is not a valid proof, so nothing it reports
#       afterward can be trusted either.
#
#   LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS
#       Caller-populated array of additional filenames (relative to the
#       artifact DEST_DIR, e.g. "session-probe.log") that
#       leakscan_require_artifacts_complete must also require non-empty,
#       beyond the compose logs/node logs/transcript it already derives
#       from LEAKSCAN_COMPOSE_SERVICES/LEAKSCAN_NODES. Empty by default
#       (phase-3 normal mode requires nothing extra); an HA run reassigns
#       it (e.g. to hold the persistent session probe's captured output)
#       the same way it reassigns LEAKSCAN_NODES/LEAKSCAN_COMPOSE_SERVICES
#       below — see the sourcing-guard note on those two arrays.
#
# Every function above takes credential VARIABLE NAMES as arguments,
# resolving each to its value only internally via bash indirect expansion
# (`"${!name}"`), exactly like oauth.sh's own documented
# OAUTH_RETAINED_TOKEN_NAMES contract — callers should pass
# `"${OAUTH_RETAINED_TOKEN_NAMES[@]}"` through, never a value directly.
# Guards the `readonly` declaration AND the three arrays below (LEAKSCAN_
# NODES, LEAKSCAN_COMPOSE_SERVICES, LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS)
# against a second `source` of this file within the same shell — this
# matters in practice, not just in theory: scenarios/80-leak-scan.sh
# sources this file itself (see its own header), so a caller such as
# run-ha.sh — which sources this file once and then reassigns these
# three arrays to its HA-shaped values — would otherwise have that
# reassignment silently wiped back to the phase-3 defaults the moment
# 80-leak-scan.sh's own `source lib/leakscan.sh` line runs later in the
# same shell. Guarding the assignment (rather than, say, only sourcing this
# file once ever) is what lets a caller reassign the arrays AFTER its own
# first source and have that reassignment survive every subsequent source.
# The function definitions below are always safe to redefine, so they stay
# unguarded, matching lib/oauth.sh's own idempotent-sourcing discipline.
if [ -z "${LEAKSCAN_SH_LOADED:-}" ]; then
    LEAKSCAN_SH_LOADED=1
    readonly LEAKSCAN_PROBE_USERNAME="leakscan-probe@example.com"
    LEAKSCAN_NODES=(clickhouse-origin clickhouse-remote)
    LEAKSCAN_COMPOSE_SERVICES=(ch-oauth-ldap clickhouse-origin clickhouse-remote)
    LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS=()
fi

# leakscan_collect_artifacts DEST_DIR — see contract above.
leakscan_collect_artifacts() {
    local dir="$1"
    [ -d "$dir" ] || die "leak-scan: artifact directory '$dir' does not exist (the caller must create it under \$RUN_TMP_DIR)"

    local svc rc
    for svc in "${LEAKSCAN_COMPOSE_SERVICES[@]}"; do
        set +e
        compose logs --no-color "$svc" >"$dir/compose-${svc}.log" 2>&1
        rc=$?
        set -e
        [ "$rc" -eq 0 ] || die "leak-scan: 'compose logs $svc' failed (rc=$rc) — cannot build a trustworthy artifact corpus"
    done

    local node path base
    for node in "${LEAKSCAN_NODES[@]}"; do
        for path in /var/log/clickhouse-server/clickhouse-server.log /var/log/clickhouse-server/clickhouse-server.err.log; do
            base="${path##*/}"
            set +e
            compose exec -T "$node" cat "$path" >"$dir/${node}-${base}" 2>"$dir/${node}-${base}.stderr"
            rc=$?
            set -e
            if [ "$rc" -ne 0 ]; then
                die "leak-scan: reading $path from $node failed (rc=$rc): $(cat "$dir/${node}-${base}.stderr" 2>/dev/null) — a missing/unreadable on-disk log is a real gap in the artifact corpus, not 'nothing to scan'"
            fi
            rm -f "$dir/${node}-${base}.stderr"
        done
    done

    [ -n "${RUN_LOG:-}" ] && [ -f "$RUN_LOG" ] \
        || die "leak-scan: RUN_LOG ('${RUN_LOG:-unset}') is not a readable file — the runner transcript is a required artifact"
    cp "$RUN_LOG" "$dir/run-transcript.log"

    chmod 600 "$dir"/*
}

# leakscan_capture_auth_failure_bodies DEST_DIR NAME... — see contract
# above. LEAKSCAN_PROBE_USERNAME (declared above) is fixed and never equal
# to any minted token's email claim, so every one of these requests fails
# ClickHouse's own authentication generically (username/credential
# mismatch), independent of what the named credential itself carries.
leakscan_capture_auth_failure_bodies() {
    local dest_dir="$1"
    shift
    local name value body_file idx=0 rc status
    for name in "$@"; do
        value="${!name:-}"
        [ -n "$value" ] || continue
        idx=$((idx + 1))
        body_file="$dest_dir/auth-failure-$(printf '%02d' "$idx").txt"
        set +e
        ch_http_query_as "$LEAKSCAN_PROBE_USERNAME" "$value" "SELECT 1" \
            >"$body_file" 2>&1
        rc=$?
        set -e
        status="$CH_HTTP_STATUS"
        chmod 600 "$body_file"
        # Never interpolate the captured body into this die() message —
        # only the artifact PATH, matching oauth_body_diagnostics'
        # discipline elsewhere in this suite.
        [ "$rc" -eq 0 ] \
            || die "leak-scan: auth-failure probe for retained credential '$name' failed at the curl transport level (rc=$rc) — an infrastructure failure, not the intended ClickHouse-side authentication-failure response, so it cannot be trusted as part of the leak-scan corpus; see $body_file for captured diagnostics"
        [ "$status" != "200" ] \
            || die "leak-scan: auth-failure probe for retained credential '$name' UNEXPECTEDLY SUCCEEDED (HTTP 200) against mismatched probe username '$LEAKSCAN_PROBE_USERNAME' — the credential authenticated as an unrelated identity instead of failing generically, which points at a cache-key/identity-policy regression, not a usable auth-failure artifact; investigate before trusting this leak-scan run"
    done
}

# leakscan_require_artifacts_complete DEST_DIR — see contract above.
leakscan_require_artifacts_complete() {
    local dir="$1"
    local f svc node extra
    local -a required=()

    for svc in "${LEAKSCAN_COMPOSE_SERVICES[@]}"; do
        required+=("$dir/compose-${svc}.log")
    done
    for node in "${LEAKSCAN_NODES[@]}"; do
        required+=("$dir/${node}-clickhouse-server.log")
    done
    required+=("$dir/run-transcript.log")
    # The `:-` default here is the standard workaround for pre-4.4 bash
    # treating `"${arr[@]}"` on a declared-but-empty array as an unbound
    # variable under `set -u` — LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS is empty
    # by default (phase-3 normal mode), unlike LEAKSCAN_COMPOSE_SERVICES/
    # LEAKSCAN_NODES which are never intentionally empty. The `-n` guard
    # below then skips the single empty-string element that idiom yields
    # when the array truly has nothing in it.
    for extra in "${LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS[@]:-}"; do
        [ -n "$extra" ] || continue
        required+=("$dir/$extra")
    done

    for f in "${required[@]}"; do
        [ -f "$f" ] || die "leak-scan: required artifact '$f' was not collected"
        [ -s "$f" ] || die "leak-scan: required artifact '$f' is EMPTY (0 bytes) — a scan over an empty artifact is trivially clean and proves nothing; refusing to continue"
    done
    for node in "${LEAKSCAN_NODES[@]}"; do
        f="$dir/${node}-clickhouse-server.err.log"
        [ -f "$f" ] || die "leak-scan: expected on-disk error log capture '$f' was not collected"
        if [ ! -s "$f" ]; then
            log "leak-scan: note — $(basename "$f") is 0 bytes (this build emitted no warnings/errors to its error log during the run); it was readable and is included in the scan, but there is nothing in it to match against"
        fi
    done
    local body_count=0
    for f in "$dir"/auth-failure-*.txt; do
        [ -f "$f" ] || continue
        body_count=$((body_count + 1))
        [ -s "$f" ] || die "leak-scan: captured auth-failure body '$f' is EMPTY — the probe request produced no response body to scan"
    done
    [ "$body_count" -gt 0 ] || die "leak-scan: no auth-failure bodies were captured"
    log "leak-scan: artifact corpus complete — ${#required[@]} required log artifacts non-empty (${#LEAKSCAN_COMPOSE_SERVICES[@]} compose logs, ${#LEAKSCAN_NODES[@]} node server logs, 1 run transcript, ${#LEAKSCAN_REQUIRED_EXTRA_ARTIFACTS[@]} extra), $body_count auth-failure bodies captured"
}

# leakscan_scan_artifacts DIR NAME... — see contract above.
leakscan_scan_artifacts() {
    local dir="$1"
    shift
    local name value matches pattern_file found=0

    for name in "$@"; do
        value="${!name:-}"
        [ -n "$value" ] || continue

        # The credential reaches grep ONLY through this private pattern file
        # (written by the printf builtin — no external process ever sees
        # the value on its command line), never as an argv pattern.
        pattern_file="$(mktemp "$RUN_TMP_DIR/leakscan-pattern.XXXXXX")"
        chmod 600 "$pattern_file"
        printf '%s\n' "$value" >"$pattern_file"

        # -r: recurse; -l: filenames only, never the matching line itself
        # (which would contain the leaked value); -F: literal fixed-string
        # match, never a regex (a raw JWT's '.' separators must not be
        # treated as regex metacharacters); -f: patterns from the file.
        matches="$(grep -rlF -f "$pattern_file" -- "$dir" 2>/dev/null || true)"
        rm -f "$pattern_file"

        if [ -n "$matches" ]; then
            found=1
            log "leak-scan: LEAK DETECTED — retained credential '$name' found in: $matches"
        fi
    done

    [ "$found" -eq 0 ]
}

# leakscan_self_test VARNAME — see contract above.
leakscan_self_test() {
    local varname="$1"
    local value synth_dir synth_file

    value="${!varname:-}"
    [ -n "$value" ] || die "leak-scan self-test: '$varname' has no value to plant"

    synth_dir="$(mktemp -d "$RUN_TMP_DIR/leakscan-selftest.XXXXXX")"
    chmod 700 "$synth_dir"
    synth_file="$synth_dir/planted-artifact.log"
    # The planted line deliberately mimics a real log line's shape (a
    # message plus a key=value pair) without actually being one — this is
    # a synthetic artifact for the scanner's own self-test, never a real
    # captured log. Written by the printf builtin — no argv exposure.
    printf 'synthetic self-test artifact: leaked_value=%s\n' "$value" >"$synth_file"
    chmod 600 "$synth_file"

    if leakscan_scan_artifacts "$synth_dir" "$varname"; then
        rm -rf "$synth_dir"
        die "leak-scan self-test: the scanner did NOT detect a deliberately planted credential ('$varname') — the scanner is not a valid proof, aborting the suite (see the plan's Leak-scanner self-test)"
    fi

    rm -rf "$synth_dir"
    log "leak-scan self-test: deliberate plant of '$varname' was correctly detected via the pattern-file scan path — scanner is trustworthy"
}
