#!/usr/bin/env bash
# integration/clickhouse/scenarios/40-invalid-expired.sh
#
# Acceptance scenario E — invalid and expired JWTs (see the phase-3 plan).
#
# Two independent negative cases, each its own fresh HTTP request:
#
#   1. A malformed, non-cryptographic value ("not-a-jwt") presented as
#      alice@example.com's password. No token is minted for this case —
#      it never touches the synthetic IdP at all.
#   2. A cryptographically signed but already-expired token (exp=-120,
#      well beyond the helper's configured 60s verifier leeway — see
#      helper/config.yaml's oauth.verifier_leeway), minted via
#      oauth_mint_with_exp (the plan's one sanctioned exception to the
#      hardcoded exp=3600 positive-token discipline). Retained (name
#      only) for the later JWT-leak-scan scenario.
#
# Both must fail generically (oauth_expect_auth_failure), matching
# scenario D's discipline of never asserting on a specific status code or
# error string.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario E: invalid and expired JWTs"

oauth_run alice@example.com "not-a-jwt" "SELECT 1"
oauth_expect_auth_failure "scenario E (malformed token)"
log "scenario E: malformed 'not-a-jwt' password correctly rejected — OK"

PHASE3_TOKEN_E_ALICE_EXPIRED="$(oauth_mint_with_exp alice@example.com -120 idp-readers)"
oauth_retain PHASE3_TOKEN_E_ALICE_EXPIRED

oauth_run alice@example.com "$PHASE3_TOKEN_E_ALICE_EXPIRED" "SELECT 1"
oauth_expect_auth_failure "scenario E (expired token)"
log "scenario E: signed but expired (exp=-120) token correctly rejected — OK"
