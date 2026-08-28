#!/usr/bin/env bash
# integration/clickhouse/lib/oauth.sh
#
# OAuth-client discipline shared by every acceptance scenario under
# integration/clickhouse/scenarios/*.sh (B onward). This file is SOURCED —
# never executed directly — after integration/clickhouse/lib/common.sh, and
# assumes everything common.sh's own header documents (run.sh's
# `set -euo pipefail` / `umask 077`, and common.sh's idp_sign/
# ch_http_query_as/log/die). It layers three things on top of common.sh:
#
#   1. Token-lifetime discipline ("Token lifetime discipline" in the
#      phase-3 plan): a mint helper for POSITIVE tokens that hardcodes
#      `exp=3600` itself rather than trusting a caller to remember it or
#      relying on the synthetic IdP's 300-second default, plus a separate,
#      explicitly-named helper for the one sanctioned exception (a
#      deliberately expired token, scenario E).
#   2. A thin, exact-match-friendly query/assert layer on top of
#      ch_http_query_as, so every scenario file makes the same shape of
#      assertion (fresh HTTP connection, exact HTTP status, exact trimmed
#      body) rather than each re-deriving its own comparison logic.
#   3. A retained-credential NAME registry for the JWT-leak-scan scenario
#      (acceptance scenario I, scenarios/80-leak-scan.sh) — see
#      "Retained-token registry" below.
#
# Every function here inherits ch_http_query_as's existing credential
# discipline (see common.sh's own header and "Administrative versus OAuth
# client paths" in the plan): the JWT/password is a function parameter
# only, is written to a private mode-0600 single-use curl config under
# $RUN_TMP_DIR that ch_http_query_as deletes before returning, SQL travels
# over stdin, the request sends `Connection: close`, and the JWT is never
# placed in argv, an exported variable, or a Docker `-e` argument. Nothing
# in this file re-implements that plumbing — it all funnels through
# ch_http_query_as.
#
# ── Mint helpers ───────────────────────────────────────────────────────────
#   oauth_mint EMAIL [ROLE...]           mint a POSITIVE token: exp=3600
#                                         (hardcoded here, never left to a
#                                         caller or the IdP's default),
#                                         aud=clickhouse, plus zero or more
#                                         repeated `role=` params. Prints
#                                         the signed JWT to stdout. Caller
#                                         MUST capture it into a local,
#                                         unexported variable — never
#                                         `export` it.
#   oauth_mint_with_exp EMAIL EXP [ROLE...]
#                                         mint with an EXPLICIT exp value
#                                         instead of the hardcoded 3600.
#                                         This is the plan's one sanctioned
#                                         exception to "every positive
#                                         token must explicitly request
#                                         exp=3600" — used ONLY for
#                                         scenario E's deliberately expired
#                                         token (exp=-120). Do not reach
#                                         for this to mint an ordinary
#                                         positive token; use oauth_mint.
#
# ── Query/assert helpers ───────────────────────────────────────────────────
#   oauth_run USERNAME PASSWORD SQL      runs one fresh HTTP Basic-
#                                         authenticated request via
#                                         ch_http_query_as and stores the
#                                         result in CH_LAST_STATUS (numeric
#                                         HTTP status) and CH_LAST_BODY
#                                         (response body with exactly one
#                                         trailing newline stripped, if
#                                         present). Every call is a
#                                         distinct curl process / distinct
#                                         HTTP connection, matching "Each
#                                         authentication uses a distinct
#                                         curl process... Connection:
#                                         close" in the plan.
#   oauth_expect_status STATUS LABEL     dies unless CH_LAST_STATUS equals
#                                         STATUS exactly.
#   oauth_expect_exact_body TEXT LABEL   dies unless CH_LAST_BODY equals
#                                         TEXT exactly (not a contains-only
#                                         check — see "Do not use a
#                                         contains-only assertion" in
#                                         acceptance scenario C).
#   oauth_expect_not_contains TEXT LABEL dies if CH_LAST_BODY contains TEXT
#                                         as a substring. Used as a belt-
#                                         and-suspenders check alongside an
#                                         exact-body assertion (e.g.
#                                         scenario F's "must not contain
#                                         ch_readonly").
#   oauth_expect_auth_failure LABEL      dies if CH_LAST_STATUS is the
#                                         success status (200) — i.e.
#                                         requires the request to have
#                                         failed generically, without
#                                         asserting anything about which
#                                         status code ClickHouse chose.
#                                         The plan is explicit that a
#                                         mismatch/invalid/expired
#                                         credential's client-visible
#                                         failure "must not disclose"
#                                         which specific reason applied
#                                         (scenario D), so callers must
#                                         not compare CH_LAST_BODY against
#                                         a specific error string either.
#   oauth_body_diagnostics               prints a SAFE, credential-free
#                                         summary of $CH_LAST_BODY (byte
#                                         length, sha256 digest, and the
#                                         path of a private mode-0600 copy
#                                         written under $RUN_TMP_DIR) —
#                                         never the raw body itself. Every
#                                         oauth_expect_*/
#                                         expect_remote_access_denied
#                                         failure below interpolates THIS
#                                         into its die() message instead of
#                                         $CH_LAST_BODY directly: die()
#                                         logs via log(), and run.sh tees
#                                         that into BOTH the private
#                                         $RUN_LOG under $RUN_TMP_DIR AND
#                                         the caller's own inherited
#                                         stdout/stderr — a stream that
#                                         survives this run's own
#                                         $RUN_TMP_DIR cleanup and that
#                                         scenario I's leak scan never gets
#                                         a chance to check, because a
#                                         `die` aborts the suite before
#                                         scenario I (which runs last) ever
#                                         runs. If a regression under test
#                                         ever echoes a JWT/password back
#                                         in an HTTP error body, that is
#                                         exactly the value CH_LAST_BODY
#                                         would hold — so it must never be
#                                         interpolated directly into a
#                                         log/die call.
#
# ── Retained-token registry ────────────────────────────────────────────────
# Acceptance scenario I (the JWT-leak scan, scenarios/80-leak-scan.sh)
# needs every generated credential this phase mints — reader/unprovisioned,
# mismatch, expired, both reconnect tokens, local-precedence (both the
# external JWT and the runtime-generated local password), both
# distributed tokens, and (phase 5) scenario G's 257-role Search-limit
# token — so it can fixed-string-scan the captured artifacts for each one.
# Every scenario file retains its credentials by NAME the moment it mints
# or receives them, so the leak-scan scenario can consume them without
# re-deriving or re-minting anything.
#
# Phase 5's scenario G' (integration/clickhouse/scenarios/
# 65-ldap-search-limits.sh) is not special-cased anywhere in this file: it
# mints its one token via the same oauth_mint helper below (the 257
# repeated `role=` params it passes are just a longer argument list to the
# same function) and calls oauth_retain on it immediately after minting,
# exactly like every other scenario — the mechanism here is scenario-count-
# and role-count-agnostic by design.
#
# The registry stores VARIABLE NAMES, never values: OAUTH_RETAINED_TOKEN_NAMES
# is a plain (unexported) indexed array of the names of other unexported
# shell variables that each hold one signed JWT. run.sh sources every
# scenario file into its own shell (see common.sh's sourcing-contract
# header), so a name registered by scenario B is still resolvable by name
# when a later scenario file (e.g. the future leak-scan scenario) runs,
# via bash indirect expansion:
#
#   for name in "${OAUTH_RETAINED_TOKEN_NAMES[@]}"; do
#       token="${!name}"   # the JWT itself, resolved only when needed
#       ...
#   done
#
# Never iterate this registry to print a token — only to feed it to the
# leak scanner's own fixed-string search.
#
#   oauth_retain VARNAME                 registers the name of an already-
#                                         set, unexported shell variable
#                                         holding one signed JWT into
#                                         OAUTH_RETAINED_TOKEN_NAMES.
#
# ── Sourcing ────────────────────────────────────────────────────────────────
# run.sh itself sources only lib/common.sh; it does not know about
# lib/oauth.sh (or lib/expectations.sh / lib/leakscan.sh). Each scenario
# file that needs these helpers therefore sources this file itself, near
# the top:
#
#   source "$SCRIPT_DIR/lib/oauth.sh"
#
# Because run.sh sources every scenarios/*.sh file into its OWN shell in
# lexical order (see common.sh's sourcing-contract header), this file's
# own state (OAUTH_RETAINED_TOKEN_NAMES, CH_LAST_STATUS, CH_LAST_BODY)
# would be silently reset to empty if a later scenario file's `source`
# re-ran unguarded initialization — destroying token names an earlier
# scenario file had already registered. The guard below makes sourcing
# this file idempotent: the first source in a run initializes state, and
# every subsequent source (one per scenario file, by design, so each
# scenario file works even if run standalone against an already-sourced
# common.sh) is a safe no-op for state while still (harmlessly)
# re-defining the functions below.
if [ -z "${OAUTH_SH_LOADED:-}" ]; then
    OAUTH_SH_LOADED=1
    declare -ag OAUTH_RETAINED_TOKEN_NAMES=()
    CH_LAST_STATUS=""
    CH_LAST_BODY=""
fi

# oauth_looks_like_jwt TOKEN — a light shape check (three non-empty
# dot-separated segments) so a mint helper fails fast and loudly on an
# unexpected /sign response shape rather than letting a malformed value
# silently flow into an authentication attempt and surface as a confusing
# downstream assertion failure.
oauth_looks_like_jwt() {
    local token="$1"
    local -a parts
    IFS='.' read -r -a parts <<<"$token"
    [ "${#parts[@]}" -eq 3 ] || return 1
    local p
    for p in "${parts[@]}"; do
        [ -n "$p" ] || return 1
    done
    return 0
}

# oauth_mint EMAIL [ROLE...] — see contract above.
oauth_mint() {
    local email="$1"
    shift
    local qs="email=${email}&aud=clickhouse&exp=3600"
    local role
    for role in "$@"; do
        qs="${qs}&role=${role}"
    done
    local token
    token="$(idp_sign "$qs")"
    oauth_looks_like_jwt "$token" || die "oauth_mint: synthetic-idp /sign did not return a well-formed JWT for email=${email}"
    printf '%s' "$token"
}

# oauth_mint_with_exp EMAIL EXP [ROLE...] — see contract above; the one
# sanctioned exception to hardcoded exp=3600 (scenario E's expired token).
oauth_mint_with_exp() {
    local email="$1" exp="$2"
    shift 2
    local qs="email=${email}&aud=clickhouse&exp=${exp}"
    local role
    for role in "$@"; do
        qs="${qs}&role=${role}"
    done
    local token
    token="$(idp_sign "$qs")"
    oauth_looks_like_jwt "$token" || die "oauth_mint_with_exp: synthetic-idp /sign did not return a well-formed JWT for email=${email} exp=${exp}"
    printf '%s' "$token"
}

# oauth_retain VARNAME — see "Retained-token registry" above.
oauth_retain() {
    local varname="$1"
    OAUTH_RETAINED_TOKEN_NAMES+=("$varname")
}

# oauth_run USERNAME PASSWORD SQL — see contract above. Deliberately does
# NOT swallow ch_http_query_as's own return code: a non-zero return there
# means curl itself failed at the transport level (DNS/connect/timeout),
# which is an infrastructure failure this suite should abort on (via
# `set -e`), not an authentication-failure test case. An HTTP-level
# authentication/query failure (a received non-2xx response) still returns
# 0 from ch_http_query_as and is what CH_LAST_STATUS/CH_LAST_BODY are for.
#
# Deliberately does NOT capture ch_http_query_as's stdout via `$(...)`:
# command substitution forks a subshell, and ch_http_query_as communicates
# its HTTP status back to the caller as a side-effecting global variable
# ($CH_HTTP_STATUS, per common.sh's own documented contract) — an
# assignment made inside that subshell would vanish the instant the
# subshell exits, leaving $CH_HTTP_STATUS unset in this shell. Redirecting
# the function's stdout straight to a private temp file instead calls it
# in THIS shell, so its $CH_HTTP_STATUS assignment is visible here too.
oauth_run() {
    local username="$1" password="$2" sql="$3"
    local outfile
    outfile="$(mktemp "$RUN_TMP_DIR/oauth-run-body.XXXXXX")"
    chmod 600 "$outfile"
    ch_http_query_as "$username" "$password" "$sql" >"$outfile"
    CH_LAST_STATUS="$CH_HTTP_STATUS"
    CH_LAST_BODY="$(cat "$outfile")"
    rm -f "$outfile"
}

oauth_expect_status() {
    local expected="$1" label="$2"
    [ "$CH_LAST_STATUS" = "$expected" ] \
        || die "$label: expected HTTP $expected, got HTTP $CH_LAST_STATUS ($(oauth_body_diagnostics))"
}

oauth_expect_exact_body() {
    local expected="$1" label="$2"
    [ "$CH_LAST_BODY" = "$expected" ] \
        || die "$label: expected body exactly '$expected'; actual ($(oauth_body_diagnostics))"
}

oauth_expect_not_contains() {
    local forbidden="$1" label="$2"
    case "$CH_LAST_BODY" in
    *"$forbidden"*) die "$label: body unexpectedly contains '$forbidden' ($(oauth_body_diagnostics))" ;;
    esac
}

# oauth_expect_auth_failure LABEL — see contract above. Intentionally
# checks only "not the success status", never a specific status code or
# error string, so this suite itself never encodes an assumption about
# which generic failure reason ClickHouse chose to report.
oauth_expect_auth_failure() {
    local label="$1"
    [ "$CH_LAST_STATUS" != "200" ] \
        || die "$label: expected authentication/query failure, got HTTP 200 ($(oauth_body_diagnostics))"
}

# oauth_body_diagnostics — see contract above. Never echoes $CH_LAST_BODY;
# prints only length/digest/artifact-path metadata about it.
oauth_body_diagnostics() {
    local artifact len digest
    artifact="$(mktemp "$RUN_TMP_DIR/body-diag.XXXXXX")"
    chmod 600 "$artifact"
    printf '%s' "$CH_LAST_BODY" >"$artifact"
    len=$(printf '%s' "$CH_LAST_BODY" | wc -c | tr -d '[:space:]')
    digest=$(printf '%s' "$CH_LAST_BODY" | sha256_hex)
    printf 'body: %s bytes, sha256=%s, saved to %s — deleted like everything else under RUN_TMP_DIR at run end; inspect it from another shell while this run is still alive if you need the raw content' \
        "$len" "$digest" "$artifact"
}
