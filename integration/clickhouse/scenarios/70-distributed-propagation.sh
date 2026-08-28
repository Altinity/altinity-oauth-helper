#!/usr/bin/env bash
# integration/clickhouse/scenarios/70-distributed-propagation.sh
#
# Acceptance scenario H — distributed external-role propagation (see the
# phase-3 plan). This is the proof that:
#
#   1. an externally-mapped role (idp-distributed -> ch_distributed_reader)
#      reaches clickhouse-remote across a secret-authenticated interserver
#      query, carrying the initiating user's identity with it;
#   2. that propagated role is what actually authorizes the remote read —
#      not some broader grant the fixture accidentally left in place
#      (bootstrap/remote.sql grants SELECT on the probe table/view to
#      ch_distributed_reader ONLY, and run.sh's scenario A.13/A.14
#      preflight asserts that exclusivity against the LIVE servers, so
#      this is what the negative/positive pair below actually exercises);
#   3. clickhouse-remote never independently re-authenticates the JWT over
#      LDAP — it has no auth-net route to ch-oauth-ldap at all (see "Why
#      the remote node has the LDAP directory but not helper connectivity"
#      in the plan), and the exact target's AlwaysAllowCredentials
#      interserver path materializes the initiating username without a
#      Basic LDAP Bind. This is proved by the helper's own Bind-log delta:
#      exactly the intentionally fresh origin HTTP authentications this
#      scenario performs after taking its baseline, and nothing else.
#
# This oracle deliberately reads a DIRECT BASE TABLE
# (phase3.distributed_probe -> phase3.remote_probe, bootstrap/origin.sql /
# remote.sql), not a view — see lib/expectations.sh's header for why: a
# VIEW-based oracle reproduces a SEPARATE, independent ClickHouse defect
# (StorageView's context clone drops the pushed external role) even on a
# build where propagation itself works. That defect gets its own dedicated,
# expected-fail scenario (scenarios/75-distributed-propagation-view.sh) so
# it doesn't mask or get confused with THIS scenario's actual subject: does
# a pushed external role authorize a remote distributed read at all.
#
# ── Why every denial here must come FROM THE REMOTE ──────────────────────
# On the issue's 24.8 baseline BOTH arms of this scenario expect a denial
# (the negative control by design, the positive control as a tracked
# KNOWN LIMITATION — see lib/expectations.sh). A denial alone therefore
# proves nothing on that build: if origin itself denied (a lost
# `GRANT ... ON phase3.distributed_probe`, an origin-side role-mapping
# regression), both arms would still "pass". Two things close that hole:
#   - an ORIGIN-SIDE positive check first: as alice, with the very token
#     used below, `currentRoles()` on origin must be exactly
#     ch_distributed_reader — proving the token/role mapping works on
#     origin, so any later ACCESS_DENIED is attributable to the remote;
#   - both arms require the specific remote-denial shape (HTTP 500,
#     ACCESS_DENIED, and ClickHouse's own "Received from
#     clickhouse-remote:9000" relay marker) via expect_remote_access_denied
#     / expect_known_access_denied, never a generic "not 200".
#
# Whether the positive control below is required to succeed or is a
# documented, asserted KNOWN LIMITATION depends on which ClickHouse build
# this run targets — see lib/expectations.sh's H_base_table_propagation
# entry and assert_propagation_outcome's contract. The negative control is
# NOT build-dependent: with propagation disabled, nothing is pushed at all,
# so the ephemeral, locally-ungranted alice@example.com has zero authority
# on the remote on either build — that's the unaffected base case both
# known ClickHouse defects sit on top of, not a symptom of either one.
#
# A FRESH token is minted here (not reused from an earlier scenario) so
# this scenario's own Bind-count reasoning is self-contained. The helper
# Bind BASELINE is taken AFTER the origin-side check above (which is itself
# one fresh Bind), so the delta this scenario asserts stays "the two
# distributed-query authentications, plus one per transient retry" rather
# than having to fold the origin check into the arithmetic.

source "$SCRIPT_DIR/lib/oauth.sh"
source "$SCRIPT_DIR/lib/expectations.sh"

log "scenario H: distributed external-role propagation (base-table oracle)"

oauth_retry_reset_extra_attempts

# ── Bind-log counting helpers ─────────────────────────────────────────────
# ch-oauth-ldap's own Bind handler (internal/ldap/bind.go) logs exactly one
# of two fixed message strings per simple-Bind attempt:
#   "ldap bind succeeded" (with username=<normalized email> among its
#     fields)
#   "ldap bind failed" (generic — never names the attempted username, by
#     design; see bind.go's invalidCredentialsDiagnostic non-disclosure
#     discipline)
# "total Bind result records" below is therefore succeeded + failed.
#
# phase3_h_strip_ansi strips SGR escape sequences (\x1b[...m) from stdin.
# ch-oauth-ldap's zerolog console writer colorizes each `key=` token and
# each value SEPARATELY (verified against the real, captured raw bytes: a
# line reads literally `...\x1b[36musername=\x1b[0malice@example.com...`,
# i.e. an SGR reset sequence is spliced directly between `=` and the value)
# — so a fixed-string match for `username=alice@example.com` never matches
# the raw captured log without stripping color codes first. Every counting
# helper below strips first, for consistency, even where the fixed message
# text itself happens not to straddle an escape today.
phase3_h_strip_ansi() {
    sed -E $'s/\x1b\\[[0-9;]*m//g'
}
# Every stage of these pipelines is forced to exit 0 (`|| true` around each
# grep, which exits 1 on "no match"), so they are safe under
# `set -euo pipefail` on any bash version: with pipefail a pipeline's exit
# status is that of the LAST stage to exit non-zero, so a first-stage grep
# with no match would otherwise make the whole pipeline non-zero even when
# the final `grep -c` prints a perfectly valid 0. (An earlier version only
# guarded the last stage and relied on a bash-5 errexit quirk to survive.)
phase3_h_bind_success_total() {
    phase3_h_strip_ansi <"$1" | { grep -c -F 'ldap bind succeeded' || true; }
}
phase3_h_bind_failed_total() {
    phase3_h_strip_ansi <"$1" | { grep -c -F 'ldap bind failed' || true; }
}
phase3_h_bind_success_alice() {
    { grep -F 'ldap bind succeeded' "$1" || true; } | phase3_h_strip_ansi | { grep -c -F 'username=alice@example.com' || true; }
}

# ── Fresh token ───────────────────────────────────────────────────────────
PHASE3_TOKEN_H_ALICE_DISTRIBUTED="$(oauth_mint alice@example.com idp-distributed)"
oauth_retain PHASE3_TOKEN_H_ALICE_DISTRIBUTED

# ── Origin-side positive check (see the header) ───────────────────────────
# One fresh origin authentication, BEFORE the Bind baseline is taken. If
# this fails, the problem is on origin (token, helper, role mapping, or
# the origin-side grant), and neither distributed arm below could say
# anything meaningful about propagation.
oauth_run alice@example.com "$PHASE3_TOKEN_H_ALICE_DISTRIBUTED" \
    "SELECT arrayStringConcat(arraySort(currentRoles()), ',')"
oauth_expect_status 200 "scenario H (origin-side role check)"
oauth_expect_exact_body "ch_distributed_reader" "scenario H (origin-side role check)"
log "scenario H: origin-side check — alice@example.com's currentRoles() on origin = ch_distributed_reader (exact match) — OK"

# ── Record helper Bind baseline (AFTER the origin check, before either
# distributed query) ──────────────────────────────────────────────────────
# `compose logs` always returns the full buffered log for the service, not
# just what's new since the last call — so "delta" here means re-deriving
# the same counts from a fresh full capture after H's distributed queries
# and subtracting, not resetting any counter. See "Record helper Bind
# baseline" in the plan.
PHASE3_H_BASELINE_LOG="$(mktemp "$RUN_TMP_DIR/h-helper-baseline.XXXXXX.log")"
chmod 600 "$PHASE3_H_BASELINE_LOG"
compose logs --no-color ch-oauth-ldap >"$PHASE3_H_BASELINE_LOG" 2>&1

PHASE3_H_BASELINE_SUCCESS="$(phase3_h_bind_success_total "$PHASE3_H_BASELINE_LOG")"
PHASE3_H_BASELINE_FAILED="$(phase3_h_bind_failed_total "$PHASE3_H_BASELINE_LOG")"
PHASE3_H_BASELINE_ALICE="$(phase3_h_bind_success_alice "$PHASE3_H_BASELINE_LOG")"
PHASE3_H_BASELINE_TOTAL=$((PHASE3_H_BASELINE_SUCCESS + PHASE3_H_BASELINE_FAILED))
rm -f "$PHASE3_H_BASELINE_LOG"

log "scenario H: helper Bind baseline — total=$PHASE3_H_BASELINE_TOTAL successful_alice=$PHASE3_H_BASELINE_ALICE failed=$PHASE3_H_BASELINE_FAILED"

# A short, server-generated (never user-input-derived) marker embedded as a
# SQL comment in the ORIGIN-side query text only — this is what "Assert
# remote identity separately, not via a view" resolves to here: the marker
# lets us find THIS exact request's auto-assigned query_id in origin's own
# system.query_log after the fact (comment survives verbatim in the literal
# HTTP request body ClickHouse received and logged for the ORIGIN query),
# then use that query_id to look up the REMOTE-side execution by
# initial_query_id — a mechanism ClickHouse itself propagates across the
# interserver boundary for exactly this kind of cross-node correlation,
# rather than assuming the comment text itself survives verbatim into the
# remote sub-query's own logged text (unverified, and not needed).
PHASE3_H_MARKER="phase3h$(openssl rand -hex 8)"
PHASE3_H_QUERY="/* ${PHASE3_H_MARKER} */ SELECT sum(n) FROM phase3.distributed_probe SETTINGS push_external_roles_in_interserver_queries"

# ── Negative propagation control ──────────────────────────────────────────
# Remote may materialize alice@example.com via the secret-authenticated
# interserver path (AlwaysAllowCredentials), but WITHOUT the propagated
# external role she has no locally recognized role there at all — the
# remote probe table grants SELECT to ch_distributed_reader only (see
# bootstrap/remote.sql, asserted live by scenario A.13), so this must fail
# authorization ON THE REMOTE on EVERY build, independent of either tracked
# ClickHouse defect (see this file's own header). If it instead succeeds,
# the fixture over-grants and scenario H fails (see the plan: "If this
# succeeds, the fixture grants too much authority and H fails"). If it
# fails for any OTHER reason (origin-side denial, transport, SQL),
# expect_remote_access_denied rejects that too — see lib/expectations.sh.
oauth_run_retry_transient alice@example.com "$PHASE3_TOKEN_H_ALICE_DISTRIBUTED" "${PHASE3_H_QUERY} = 0"
expect_remote_access_denied "scenario H (negative propagation control, setting=0)"
log "scenario H: negative control (push_external_roles_in_interserver_queries=0) correctly denied BY THE REMOTE — OK"

# ── Positive propagation control ──────────────────────────────────────────
# Same fresh JWT, another distinct fresh HTTP connection/authentication.
# On a build where H_base_table_propagation is must_pass, this proves in
# one shot that the external role reached the remote, is locally
# recognized there, and actually authorizes the remote-only data (1+2+3
# from bootstrap/remote.sql's phase3.remote_probe). On a build recorded as
# expected_fail, assert_propagation_outcome asserts the SPECIFIC known
# remote-denial shape instead and logs it loudly as a tracked limitation —
# see lib/expectations.sh.
oauth_run_retry_transient alice@example.com "$PHASE3_TOKEN_H_ALICE_DISTRIBUTED" "${PHASE3_H_QUERY} = 1"
assert_propagation_outcome H_base_table_propagation \
    "scenario H (positive propagation control, setting=1)" "6"

# ── Remote identity check (only meaningful when the read actually ran) ────
# Assert the remote query's user/initial_user separately from the
# authorization result above — this is deliberately NOT folded into the
# authorization oracle itself (contrast the OLD view-based design, which
# read currentUser()/currentRoles() as query RESULT columns and thereby
# accidentally made a normal view load-bearing for the propagation proof;
# see scenarios/75 and lib/expectations.sh for why that's now its own,
# separately-tracked scenario). Only runs when the positive control
# actually succeeded — an expected_fail build has no successful remote
# execution to inspect here.
if [ "$(expectation_for H_base_table_propagation)" = "must_pass" ] && [ "$CH_LAST_STATUS" = "200" ]; then
    ch_admin_query clickhouse-origin "SYSTEM FLUSH LOGS" >/dev/null

    PHASE3_H_ORIGIN_QID="$(ch_admin_query clickhouse-origin \
        "SELECT query_id FROM system.query_log WHERE query LIKE '%${PHASE3_H_MARKER}%' AND type = 'QueryFinish' ORDER BY event_time DESC LIMIT 1")"
    [ -n "$PHASE3_H_ORIGIN_QID" ] \
        || die "scenario H: no origin system.query_log entry found for marker ${PHASE3_H_MARKER}"
    # The query_id is ClickHouse-generated (a UUID) and about to be
    # interpolated into SQL below — hard-validate its shape first so this
    # can never become an injection vector even if that assumption changes.
    case "$PHASE3_H_ORIGIN_QID" in
    *[!0-9a-f-]*) die "scenario H: origin query_id '$PHASE3_H_ORIGIN_QID' is not of the expected [0-9a-f-] shape; refusing to interpolate it into SQL" ;;
    esac

    ch_admin_query clickhouse-remote "SYSTEM FLUSH LOGS" >/dev/null

    PHASE3_H_REMOTE_ROW="$(ch_admin_query clickhouse-remote \
        "SELECT user, initial_user FROM system.query_log WHERE initial_query_id = '${PHASE3_H_ORIGIN_QID}' AND type = 'QueryFinish' LIMIT 1")"
    [ -n "$PHASE3_H_REMOTE_ROW" ] \
        || die "scenario H: no remote system.query_log entry found for initial_query_id ${PHASE3_H_ORIGIN_QID}"

    PHASE3_H_REMOTE_USER="$(printf '%s' "$PHASE3_H_REMOTE_ROW" | cut -f1)"
    PHASE3_H_REMOTE_INITIAL_USER="$(printf '%s' "$PHASE3_H_REMOTE_ROW" | cut -f2)"

    [ "$PHASE3_H_REMOTE_USER" = "alice@example.com" ] \
        || die "scenario H: remote system.query_log user = '$PHASE3_H_REMOTE_USER', expected alice@example.com"
    [ "$PHASE3_H_REMOTE_INITIAL_USER" = "alice@example.com" ] \
        || die "scenario H: remote system.query_log initial_user = '$PHASE3_H_REMOTE_INITIAL_USER', expected alice@example.com"

    log "scenario H: remote system.query_log confirms user=initial_user=alice@example.com for initial_query_id=${PHASE3_H_ORIGIN_QID} — OK"
else
    log "scenario H: skipping remote system.query_log identity check — this build's positive control is a documented KNOWN LIMITATION, not a successful remote execution to inspect"
fi

# ── Prove remote did not independently authenticate the JWT ──────────────
# Re-capture the full helper log and re-derive the same three counts;
# their DELTA against the baseline above must be exactly the two
# intentionally fresh origin HTTP authentications performed above (one per
# distributed control), PLUS one per transient-transport retry
# oauth_run_retry_transient had to make (each retry is itself a fresh,
# successful origin Bind — see lib/expectations.sh) — and no OTHER Bind
# caused by remote execution (see "Prove remote did not independently
# authenticate the JWT" in the plan). This holds regardless of
# build/expectation: clickhouse-remote has no auth-net route to
# ch-oauth-ldap at all, so it cannot independently Bind either way.
PHASE3_H_AFTER_LOG="$(mktemp "$RUN_TMP_DIR/h-helper-after.XXXXXX.log")"
chmod 600 "$PHASE3_H_AFTER_LOG"
compose logs --no-color ch-oauth-ldap >"$PHASE3_H_AFTER_LOG" 2>&1

PHASE3_H_AFTER_SUCCESS="$(phase3_h_bind_success_total "$PHASE3_H_AFTER_LOG")"
PHASE3_H_AFTER_FAILED="$(phase3_h_bind_failed_total "$PHASE3_H_AFTER_LOG")"
PHASE3_H_AFTER_ALICE="$(phase3_h_bind_success_alice "$PHASE3_H_AFTER_LOG")"
PHASE3_H_AFTER_TOTAL=$((PHASE3_H_AFTER_SUCCESS + PHASE3_H_AFTER_FAILED))
rm -f "$PHASE3_H_AFTER_LOG"

PHASE3_H_DELTA_TOTAL=$((PHASE3_H_AFTER_TOTAL - PHASE3_H_BASELINE_TOTAL))
PHASE3_H_DELTA_ALICE=$((PHASE3_H_AFTER_ALICE - PHASE3_H_BASELINE_ALICE))
PHASE3_H_DELTA_FAILED=$((PHASE3_H_AFTER_FAILED - PHASE3_H_BASELINE_FAILED))
PHASE3_H_EXPECTED_NEW_BINDS=$((2 + OAUTH_RETRY_EXTRA_ATTEMPTS))

if [ "$OAUTH_RETRY_EXTRA_ATTEMPTS" -gt 0 ]; then
    log "scenario H: $OAUTH_RETRY_EXTRA_ATTEMPTS transient-transport retr(y/ies) occurred; expected new-Bind count adjusted from 2 to $PHASE3_H_EXPECTED_NEW_BINDS"
fi
log "scenario H: helper Bind delta — total=$PHASE3_H_DELTA_TOTAL successful_alice=$PHASE3_H_DELTA_ALICE failed=$PHASE3_H_DELTA_FAILED (expected $PHASE3_H_EXPECTED_NEW_BINDS / $PHASE3_H_EXPECTED_NEW_BINDS / 0)"

[ "$PHASE3_H_DELTA_TOTAL" -eq "$PHASE3_H_EXPECTED_NEW_BINDS" ] \
    || die "scenario H: expected exactly $PHASE3_H_EXPECTED_NEW_BINDS new helper Bind attempts total, got $PHASE3_H_DELTA_TOTAL — an unaccounted Bind implies remote independently attempted LDAP authentication (see the plan's Remote interserver-materialization contingency)"
[ "$PHASE3_H_DELTA_ALICE" -eq "$PHASE3_H_EXPECTED_NEW_BINDS" ] \
    || die "scenario H: expected exactly $PHASE3_H_EXPECTED_NEW_BINDS new successful alice@example.com Binds, got $PHASE3_H_DELTA_ALICE"
[ "$PHASE3_H_DELTA_FAILED" -eq 0 ] \
    || die "scenario H: expected zero new failed Binds, got $PHASE3_H_DELTA_FAILED"

log "scenario H: helper Bind delta matches exactly the fresh origin authentications this scenario made ($PHASE3_H_EXPECTED_NEW_BINDS successful alice, 0 failed) — clickhouse-remote never independently re-authenticated the JWT — OK"
