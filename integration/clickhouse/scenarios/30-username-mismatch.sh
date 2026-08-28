#!/usr/bin/env bash
# integration/clickhouse/scenarios/30-username-mismatch.sh
#
# Acceptance scenario D — username/token mismatch (see the phase-3 plan).
#
# Mints a valid token for bob@example.com, then presents it as the HTTP
# Basic password while requesting ClickHouse username alice@example.com.
# Requires a generic authentication failure — the plan is explicit that
# the client-visible failure "must not disclose whether the underlying
# reason was username mismatch, signature policy, issuer policy, or
# another credential detail," so this only asserts non-success (via
# oauth_expect_auth_failure), never a specific status code or error
# string.
#
# The generated token is retained (name only) for the later JWT-leak-scan
# scenario.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario D: username/token mismatch"

PHASE3_TOKEN_D_BOB="$(oauth_mint bob@example.com idp-readers)"
oauth_retain PHASE3_TOKEN_D_BOB

oauth_run alice@example.com "$PHASE3_TOKEN_D_BOB" "SELECT 1"
oauth_expect_auth_failure "scenario D"

log "scenario D: bob@example.com's token presented as alice@example.com was correctly rejected — OK"
