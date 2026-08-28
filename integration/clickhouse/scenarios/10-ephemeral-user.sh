#!/usr/bin/env bash
# integration/clickhouse/scenarios/10-ephemeral-user.sh
#
# Acceptance scenario B — ephemeral external user and currentUser() (see
# the phase-3 plan). Sourced by run.sh after the health gate, RBAC/data
# bootstrap, and the full scenario-A preflight have all passed (see
# lib/common.sh's sourcing-contract header) — so alice@example.com is
# already proven absent from persistent ClickHouse user configuration
# (scenario A.6) before this file mints her first token.
#
# Mints a token for alice@example.com carrying BOTH a mapped role
# (idp-readers -> ch_readonly) and the deliberately unmapped-to-nothing
# role (idp-unprovisioned -> ch_unprovisioned, which bootstrap/common.sql
# never creates in ClickHouse) — scenario C (20-dynamic-roles.sh) reuses
# this same token/claims on a fresh HTTP request to prove the
# unprovisioned mapped role carries no authority. The token is retained
# (name only) for the later JWT-leak-scan scenario.
#
# Authenticates to origin over HTTP Basic (username = alice@example.com,
# password = the JWT) and requires `SELECT currentUser()` to return
# EXACTLY "alice@example.com" — proving the otherwise-undefined external-
# user path end to end through real ClickHouse LDAP delegation to
# ch-oauth-ldap.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario B: ephemeral external user / currentUser()"

# Shared across 10-/20- (scenario B and C use the same claims — see the
# plan's "Using the same claims on a fresh request" for scenario C).
# Unexported; never printed. Retained by name only for the leak scan.
PHASE3_TOKEN_B_ALICE_READER="$(oauth_mint alice@example.com idp-readers idp-unprovisioned)"
oauth_retain PHASE3_TOKEN_B_ALICE_READER

oauth_run alice@example.com "$PHASE3_TOKEN_B_ALICE_READER" "SELECT currentUser()"
oauth_expect_status 200 "scenario B"
oauth_expect_exact_body "alice@example.com" "scenario B"

log "scenario B: currentUser() = alice@example.com (exact match) — OK"
