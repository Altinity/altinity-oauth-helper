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
# A FRESH token is minted here (not reused from an earlier scenario) so
# this scenario's own Bind-count reasoning is self-contained: the "exactly
# two new Binds" assertion below only holds if H mints and authenticates
# its own token pair, not a token some earlier scenario already bound.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario H: distributed external-role propagation"

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
phase3_h_bind_success_alice() {
    # The trailing `|| true` on the SECOND stage is what makes this safe
    # under `set -o pipefail`: with pipefail, a pipeline's exit status is
    # the last command to exit non-zero, or zero if the last command
    # exits zero — forcing the last stage's own exit to 0 makes the whole
    # pipeline 0 regardless of whether the first grep matched anything.
    grep -F 'ldap bind succeeded' "$1" | { grep -c -F 'username=alice@example.com' || true; }
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

PHASE3_H_QUERY="SELECT remote_user, remote_roles, sum(n) FROM phase3.distributed_auth_probe GROUP BY remote_user, remote_roles SETTINGS push_external_roles_in_interserver_queries"

# ── Negative propagation control ──────────────────────────────────────────
# Remote may materialize alice@example.com via the secret-authenticated
# interserver path (AlwaysAllowCredentials), but WITHOUT the propagated
# external role she has no locally recognized role there at all — the
# remote probe table/view grant SELECT to ch_distributed_reader only (see
# bootstrap/remote.sql), so this must fail authorization. If it instead
# succeeds, the fixture over-grants and scenario H fails (see the plan:
# "If this succeeds, the fixture grants too much authority and H fails").
oauth_run alice@example.com "$PHASE3_TOKEN_H_ALICE_DISTRIBUTED" "${PHASE3_H_QUERY} = 0"
oauth_expect_auth_failure "scenario H (negative propagation control, setting=0)"
log "scenario H: negative control (push_external_roles_in_interserver_queries=0) correctly denied — OK"

# ── Positive propagation control ──────────────────────────────────────────
# Same fresh JWT, a second distinct fresh HTTP connection/authentication.
# Requires the EXACT semantic result the plan specifies: remote_user =
# alice@example.com, remote_roles = ch_distributed_reader, sum(n) = 6 —
# proving in one shot that the remote session's initiating/current user is
# Alice (not default), the external role reached the remote, that role is
# locally recognized there, and it actually authorizes the remote-only
# data (1+2+3 from bootstrap/remote.sql's phase3.remote_probe).
oauth_run alice@example.com "$PHASE3_TOKEN_H_ALICE_DISTRIBUTED" "${PHASE3_H_QUERY} = 1"
oauth_expect_status 200 "scenario H (positive propagation control, setting=1)"
oauth_expect_exact_body "$(printf 'alice@example.com\tch_distributed_reader\t6')" \
    "scenario H (positive propagation control, setting=1)"
log "scenario H: positive control (push_external_roles_in_interserver_queries=1) -> remote_user=alice@example.com remote_roles=ch_distributed_reader sum(n)=6 (exact match) — OK"

# ── Prove remote did not independently authenticate the JWT ──────────────
# Re-capture the full helper log and re-derive the same three counts;
# their DELTA against the baseline above must be exactly the two
# intentionally fresh origin HTTP authentications performed above — no
# third Bind caused by remote execution (see "Prove remote did not
# independently authenticate the JWT" in the plan).
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
