#!/usr/bin/env bash
# integration/clickhouse/scenarios/20-dynamic-roles.sh
#
# Acceptance scenario C — dynamic roles and local-RBAC authority (see the
# phase-3 plan). Depends on 10-ephemeral-user.sh (scenario B) having
# already sourced lib/oauth.sh and minted PHASE3_TOKEN_B_ALICE_READER —
# guaranteed by run.sh's lexical-order auto-sourcing of scenarios/*.sh
# (see lib/common.sh's sourcing-contract header: "10" sorts before "20").
#
# Reuses alice's SAME claims (idp-readers + idp-unprovisioned) on a FRESH
# HTTP request — a new curl process / new HTTP connection, so this is a
# genuinely new authentication (verification_cooldown=0 means ClickHouse
# reaches ch-oauth-ldap again rather than trusting a cached Bind), not a
# state check inside scenario B's own connection.
#
# helper/config.yaml's roles_mapping sends BOTH:
#   idp-readers       -> ch_readonly       (created in bootstrap/common.sql)
#   idp-unprovisioned -> ch_unprovisioned  (NEVER created in ClickHouse)
#
# Requiring `currentRoles()` to be EXACTLY "ch_readonly" (not merely
# "contains ch_readonly") proves both halves of the invariant at once:
# token-derived role mapping reached ClickHouse, AND the helper cannot
# manufacture authorization merely by naming a role that has no local
# ClickHouse definition.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario C: dynamic currentRoles() / local-RBAC authority"

: "${PHASE3_TOKEN_B_ALICE_READER:?scenario C requires 10-ephemeral-user.sh (scenario B) to have run first and minted this token}"

oauth_run alice@example.com "$PHASE3_TOKEN_B_ALICE_READER" \
    "SELECT arrayStringConcat(arraySort(currentRoles()), ',')"
oauth_expect_status 200 "scenario C"
oauth_expect_exact_body "ch_readonly" "scenario C"

log "scenario C: currentRoles() = ch_readonly (exact match; ch_unprovisioned has no authority) — OK"
