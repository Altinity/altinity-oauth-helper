#!/usr/bin/env bash
# integration/clickhouse/scenarios/60-local-precedence.sh
#
# Acceptance scenario G — local-user precedence (see the phase-3 plan).
#
# bootstrap/origin.sql already created a genuinely LOCAL ClickHouse user
# `admin@example.com` (password-hash authenticated, DEFAULT ROLE
# ch_local_admin) before any of this file runs — deliberately NOT the
# literal `admin`, since helper/config.yaml's identity.denied_usernames
# rejects exactly that literal, and a precedence test built on a
# helper-denied name would pass vacuously rather than actually exercising
# ClickHouse's local-user-before-LDAP precedence.
#
# Two checks:
#
#   1. A valid EXTERNAL token for admin@example.com (which the helper
#      would otherwise accept — she is not on the deny list) presented as
#      that local user's password. Because ClickHouse finds an exact local
#      user definition first, it must never fall through to LDAP/the
#      helper at all, so this must fail generically exactly like any other
#      wrong password would. Retained (name only) for the later
#      JWT-leak-scan scenario.
#   2. The REAL runtime-generated local password (CH_LOCAL_ADMIN_PASSWORD
#      — set by run.sh from the same bootstrap step, per lib/common.sh's
#      documented contract; never argv, never exported, never printed)
#      must succeed and report EXACTLY currentUser() = admin@example.com
#      and currentRoles() = ch_local_admin — and specifically NOT
#      ch_readonly, proving this session's authority came from the local
#      user definition, not from any LDAP-mapped role.

source "$SCRIPT_DIR/lib/oauth.sh"

log "scenario G: local-user precedence"

: "${CH_LOCAL_ADMIN_PASSWORD:?scenario G requires the run.sh origin.sql bootstrap step to have set CH_LOCAL_ADMIN_PASSWORD}"

# The plaintext local-admin password is a credential that travels the same
# HTTP Basic path as every JWT below, so it joins the leak-scan corpus
# (scenario I) too — by NAME, exactly like the tokens.
oauth_retain CH_LOCAL_ADMIN_PASSWORD

PHASE3_TOKEN_G_ADMIN_EXTERNAL="$(oauth_mint admin@example.com idp-readers)"
oauth_retain PHASE3_TOKEN_G_ADMIN_EXTERNAL

oauth_run admin@example.com "$PHASE3_TOKEN_G_ADMIN_EXTERNAL" "SELECT 1"
oauth_expect_auth_failure "scenario G (JWT presented to local user)"
log "scenario G: valid external JWT correctly rejected as admin@example.com's password (local user definition took precedence) — OK"

oauth_run admin@example.com "$CH_LOCAL_ADMIN_PASSWORD" \
    "SELECT currentUser(), arrayStringConcat(arraySort(currentRoles()), ',')"
oauth_expect_status 200 "scenario G (real local auth)"

# Whole-body exact match via the shared leak-safe helper (see "Do not use a
# contains-only assertion" in acceptance scenario C, and oauth.sh's own
# contract for oauth_expect_exact_body) rather than parsing CH_LAST_BODY
# into intermediate shell variables ourselves: a `read` split here would
# (a) let a response-derived value flow straight into a die() message —
# exactly the credential-echo path oauth_body_diagnostics exists to avoid
# — and (b) only ever examine the first line, silently accepting an
# unexpected trailing row after a correct first line. A single whole-body
# equality check rejects both malformed shapes at once.
oauth_expect_exact_body $'admin@example.com\tch_local_admin' "scenario G (real local auth)"
oauth_expect_not_contains "ch_readonly" "scenario G (real local auth)"

log "scenario G: real local password -> currentUser()=admin@example.com, currentRoles()=ch_local_admin (exact match, no ch_readonly) — OK"
