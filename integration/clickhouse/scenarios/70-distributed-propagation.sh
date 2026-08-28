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
#      ch_distributed_reader ONLY, so this is what the negative/positive
#      pair below actually exercises);
#   3. clickhouse-remote never independently re-authenticates the JWT over
#      LDAP — it has no auth-net route to ch-oauth-ldap at all (see "Why
#      the remote node has the LDAP directory but not helper connectivity"
#      in the plan), and the exact target's AlwaysAllowCredentials
#      interserver path materializes the initiating username without a
#      Basic LDAP Bind. This is proved by the helper's own Bind-log delta:
#      exactly the two intentionally fresh origin HTTP authentications
#      below, and nothing else.
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
# Whether the positive control below is required to succeed or is a
# documented, asserted KNOWN LIMITATION depends on which ClickHouse build
# this run targets — see lib/expectations.sh's H_base_table_propagation
# entry and assert_propagation_outcome's contract. The negative control is
# NOT build-dependent: with propagation disabled, nothing is pushed at all,
# so the ephemeral, locally-ungranted alice@example.com has zero authority
# on either build — that's the unaffected base case both known ClickHouse
# defects sit on top of, not a symptom of either one.
#
# A FRESH token is minted here (not reused from an earlier scenario) so
# this scenario's own Bind-count reasoning is self-contained: the "exactly
# two new Binds" assertion below only holds if H mints and authenticates
# its own token pair, not a token some earlier scenario already bound.

source "$SCRIPT_DIR/lib/oauth.sh"
source "$SCRIPT_DIR/lib/expectations.sh"

log "scenario H: distributed external-role propagation (base-table oracle)"

# ── Record helper Bind baseline (before either H query) ──────────────────
# `compose logs` always returns the full buffered log for the service, not
# just what's new since the last call — so "delta" here means re-deriving
# the same counts from a fresh full capture after H's two queries and
# subtracting, not resetting any counter. See "Record helper Bind
# baseline" in the plan.
#
# ch-oauth-ldap's own Bind handler (internal/ldap/bind.go) logs exactly one
# of two fixed message strings per simple-Bind attempt:
#   "ldap bind succeeded" (with username=<normalized email> among its
#     fields)
#   "ldap bind failed" (generic — never names the attempted username, by
#     design; see bind.go's invalidCredentialsDiagnostic non-disclosure
#     discipline)
# "total Bind result records" below is therefore succeeded + failed.
phase3_h_bind_success_total() {
    grep -c -F 'ldap bind succeeded' "$1" || true
}
phase3_h_bind_failed_total() {
    grep -c -F 'ldap bind failed' "$1" || true
}
# phase3_h_strip_ansi strips SGR escape sequences (\x1b[...m) from stdin.
# ch-oauth-ldap's zerolog console writer colorizes each `key=` token and
# each value SEPARATELY (verified against the real, captured raw bytes: a
# line reads literally `...\x1b[36musername=\x1b[0malice@example.com...`,
# i.e. an SGR reset sequence is spliced directly between `=` and the value)
# — so a fixed-string match for `username=alice@example.com` never matches
# the raw captured log without stripping color codes first, regardless of
# which key/value pair is being searched for.
phase3_h_strip_ansi() {
    sed -E $'s/\x1b\\[[0-9;]*m//g'
}
phase3_h_bind_success_alice() {
    # The trailing `|| true` on the SECOND stage is what makes this safe
    # under `set -o pipefail`: with pipefail, a pipeline's exit status is
    # the last command to exit non-zero, or zero if the last command
    # exits zero — forcing the last stage's own exit to 0 makes the whole
    # pipeline 0 regardless of whether the first grep matched anything.
    grep -F 'ldap bind succeeded' "$1" | phase3_h_strip_ansi | { grep -c -F 'username=alice@example.com' || true; }
}

PHASE3_H_BASELINE_LOG="$(mktemp "$RUN_TMP_DIR/h-helper-baseline.XXXXXX.log")"
chmod 600 "$PHASE3_H_BASELINE_LOG"
compose logs --no-color ch-oauth-ldap >"$PHASE3_H_BASELINE_LOG" 2>&1

PHASE3_H_BASELINE_SUCCESS="$(phase3_h_bind_success_total "$PHASE3_H_BASELINE_LOG")"
PHASE3_H_BASELINE_FAILED="$(phase3_h_bind_failed_total "$PHASE3_H_BASELINE_LOG")"
PHASE3_H_BASELINE_ALICE="$(phase3_h_bind_success_alice "$PHASE3_H_BASELINE_LOG")"
PHASE3_H_BASELINE_TOTAL=$((PHASE3_H_BASELINE_SUCCESS + PHASE3_H_BASELINE_FAILED))
rm -f "$PHASE3_H_BASELINE_LOG"

log "scenario H: helper Bind baseline — total=$PHASE3_H_BASELINE_TOTAL successful_alice=$PHASE3_H_BASELINE_ALICE failed=$PHASE3_H_BASELINE_FAILED"

# ── Fresh token, immediately before H (see "Acceptance scenario H") ──────
PHASE3_TOKEN_H_ALICE_DISTRIBUTED="$(oauth_mint alice@example.com idp-distributed)"
oauth_retain PHASE3_TOKEN_H_ALICE_DISTRIBUTED

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
# bootstrap/remote.sql), so this must fail authorization on EVERY build,
# independent of either tracked ClickHouse defect (see this file's own
# header). If it instead succeeds, the fixture over-grants and scenario H
# fails (see the plan: "If this succeeds, the fixture grants too much
# authority and H fails").
oauth_run alice@example.com "$PHASE3_TOKEN_H_ALICE_DISTRIBUTED" "${PHASE3_H_QUERY} = 0"
oauth_expect_auth_failure "scenario H (negative propagation control, setting=0)"
log "scenario H: negative control (push_external_roles_in_interserver_queries=0) correctly denied — OK"

# ── Positive propagation control ──────────────────────────────────────────
# Same fresh JWT, a second distinct fresh HTTP connection/authentication.
# On a build where H_base_table_propagation is must_pass, this proves in
# one shot that the external role reached the remote, is locally
# recognized there, and actually authorizes the remote-only data (1+2+3
# from bootstrap/remote.sql's phase3.remote_probe). On a build recorded as
# expected_fail, assert_propagation_outcome asserts the SPECIFIC known
# failure shape instead and logs it loudly as a tracked limitation — see
# lib/expectations.sh.
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
# intentionally fresh origin HTTP authentications performed above — no
# third Bind caused by remote execution (see "Prove remote did not
# independently authenticate the JWT" in the plan). This holds regardless
# of build/expectation: clickhouse-remote has no auth-net route to
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

log "scenario H: helper Bind delta — total=$PHASE3_H_DELTA_TOTAL successful_alice=$PHASE3_H_DELTA_ALICE failed=$PHASE3_H_DELTA_FAILED"

[ "$PHASE3_H_DELTA_TOTAL" -eq 2 ] \
    || die "scenario H: expected exactly 2 new helper Bind attempts total, got $PHASE3_H_DELTA_TOTAL — a third Bind implies remote independently attempted LDAP authentication (see the plan's Remote interserver-materialization contingency)"
[ "$PHASE3_H_DELTA_ALICE" -eq 2 ] \
    || die "scenario H: expected exactly 2 new successful alice@example.com Binds, got $PHASE3_H_DELTA_ALICE"
[ "$PHASE3_H_DELTA_FAILED" -eq 0 ] \
    || die "scenario H: expected zero new failed Binds, got $PHASE3_H_DELTA_FAILED"

log "scenario H: helper Bind delta matches exactly the two fresh origin authentications (2 successful alice, 0 failed, 2 total) — clickhouse-remote never independently re-authenticated the JWT — OK"
