#!/usr/bin/env bash
# integration/clickhouse/scenarios/50-role-refresh.sh
#
# Acceptance scenario F — role refresh on reconnect (see the phase-3
# plan).
#
# Mints two distinct one-hour tokens for alice@example.com carrying
# different IdP role claims, each authenticated on its own fresh HTTP
# connection (distinct curl process, distinct private curl config,
# `Connection: close` — all via oauth_run/ch_http_query_as):
#
#   Token A: role=idp-readers   -> must map to EXACTLY ch_readonly
#   Token B: role=idp-engineers -> must map to EXACTLY ch_engineer, and
#                                   the response must NOT contain
#                                   ch_readonly
#
# Because ldap.xml sets verification_cooldown=0, each fresh authentication
# reaches ch-oauth-ldap again rather than reusing a cached Bind result, so
# token B's different role claim genuinely changes the mapped local role
# on the new connection — this proves refresh happens on new
# authentication, not mutation inside one still-open session. Both tokens
# are retained (name only) for the later JWT-leak-scan scenario.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario F: role refresh on reconnect"

PHASE3_TOKEN_F_ALICE_A="$(oauth_mint alice@example.com idp-readers)"
oauth_retain PHASE3_TOKEN_F_ALICE_A

oauth_run alice@example.com "$PHASE3_TOKEN_F_ALICE_A" \
    "SELECT arrayStringConcat(arraySort(currentRoles()), ',')"
oauth_expect_status 200 "scenario F (token A)"
oauth_expect_exact_body "ch_readonly" "scenario F (token A)"
log "scenario F: token A (idp-readers) -> currentRoles() = ch_readonly (exact match) — OK"

PHASE3_TOKEN_F_ALICE_B="$(oauth_mint alice@example.com idp-engineers)"
oauth_retain PHASE3_TOKEN_F_ALICE_B

oauth_run alice@example.com "$PHASE3_TOKEN_F_ALICE_B" \
    "SELECT arrayStringConcat(arraySort(currentRoles()), ',')"
oauth_expect_status 200 "scenario F (token B)"
oauth_expect_exact_body "ch_engineer" "scenario F (token B)"
oauth_expect_not_contains "ch_readonly" "scenario F (token B)"
log "scenario F: token B (idp-engineers) -> currentRoles() = ch_engineer (exact match, no stale ch_readonly) — OK"
