#!/usr/bin/env bash
# integration/clickhouse/scenarios/65-ldap-search-limits.sh
#
# Acceptance scenario G' — LDAP Search-limit compatibility (issue #19 phase
# 5, plan §8.4). Filename-numbered 65 so it sorts between
# 60-local-precedence.sh (scenario G) and 70-distributed-propagation.sh
# (scenario H) — see lib/common.sh's sourcing-contract header for the
# numbering convention. Existing H/H'/I names are unchanged; this is an
# ADDITIONAL scenario, not a renumbering.
#
# ── What this proves ───────────────────────────────────────────────────────
# integration/clickhouse/clickhouse/common/config.d/ldap.xml now makes
# ClickHouse's Search size limit explicit:
#
#     <search_limit>256</search_limit>
#
# This scenario mints a token whose mapped roles EXCEED that limit by one
# (257 grant-less, locally-existing-but-ungranted roles) and requires:
#   1. the helper's own Search actually hit the limit — 256 entries
#      emitted, final LDAP result 4 (sizeLimitExceeded) — proved from
#      ch-oauth-ldap's own T2 telemetry log fields, not inferred from
#      ClickHouse's HTTP response;
#   2. ClickHouse's own CONSEQUENCE of that non-success Search result is
#      exactly what was measured live for this build (see
#      lib/expectations.sh's search_limit_overflow_expectation_for) — never
#      assumed. Per the phase-5 plan's "Per-build outcome, not assumption"
#      process, this scenario was FIRST run in a temporary, permissive
#      characterization form against both required Altinity Stable images
#      to OBSERVE what each build actually does with a sizeLimitExceeded
#      Search result, before lib/expectations.sh's two dedicated functions
#      were populated with those measured outcomes and this file was
#      finalized into the enforcing form below — there is no runtime
#      characterization toggle left in this file; the characterization was
#      a one-time measurement step whose result now lives entirely in
#      lib/expectations.sh;
#   3. the 257 temporary roles are gone from clickhouse-origin before this
#      scenario lets the suite continue toward scenario H, so this
#      scenario's own principal/roles cannot contaminate H's negative/
#      positive propagation controls (see "G' cannot contaminate H" in the
#      phase-5 plan's invariant map — A.13/A.14 already ran before any
#      sourced scenario, these roles exist on origin ONLY and carry no
#      grants, and this scenario uses its own separate principal/token, so
#      the one thing left for this file itself to guarantee is that
#      nothing it created outlives it).
#
# ── A7 first-wave probe (recorded result) ─────────────────────────────────
# Before this scenario was written, the plan's A7 amendment required
# confirming that synthetic-idp's /sign endpoint (cmd/synthetic-idp/
# main.go:128-176) actually accepts a 257-way repeated `role=` query
# string within its request-size limits, since /sign reads roles via
# `r.URL.Query()["role"]` and the server sets only ReadHeaderTimeout (no
# MaxHeaderBytes override, so Go's net/http DefaultMaxHeaderBytes, 1 MiB,
# governs the combined request-line + header size).
#
# CONFIRMED live in this environment: a direct HTTP GET to a locally-built
# synthetic-idp's /sign with 257 repeated `role=` params (query string
# ~4.9 KiB, well under the 1 MiB ceiling) returned HTTP 200 with a
# well-formed three-segment JWT whose decoded payload carried all 257
# roles intact (verified by base64-decoding the payload and counting the
# "roles" array — 257 entries, first "ch_slimit_000", last
# "ch_slimit_256"). No fallback (JSON body / fewer roles) is needed; the
# plain repeated-`role=` query string oauth_mint already uses for every
# other scenario works unchanged here, just with 257 roles instead of one
# or two.
#
# ── Why a distinct principal and grant-less origin-only roles ────────────
# limit@example.com is used nowhere else in this suite. The 257 mapped
# role names (ch_slimit_000 .. ch_slimit_256, matching the fixture's
# restrictive `^ch_[A-Za-z0-9_]+$` roles_filter) are created on
# clickhouse-origin ONLY, via the administrative (no-JWT) path — never on
# clickhouse-remote, and never with any GRANT — so even if a bug let this
# scenario's roles survive, they would confer no authority anywhere and
# would not exist on the node scenario H's distributed queries target.
# None of these role names appear in helper/config.yaml's roles_mapping:
# the helper's unmapped-group pass-through (see "Roles" in the phase-5
# plan: "unmapped groups pass through before filter") means the raw group
# name reaches roles_filter directly, which already accepts anything
# matching ^ch_[A-Za-z0-9_]+$ — no fixture mapping entry is required.

source "$SCRIPT_DIR/lib/oauth.sh"
source "$SCRIPT_DIR/lib/expectations.sh"

log "scenario G': LDAP Search-limit compatibility (257 mapped roles vs configured <search_limit>256</search_limit>)"

# phase3_g2_strip_ansi — identical technique to scenario H's
# phase3_h_strip_ansi (see that file's header for why: ch-oauth-ldap's
# zerolog console writer splices an SGR reset between `key=` and its value,
# so a fixed-string match against the raw captured log never matches
# without stripping color codes first).
phase3_g2_strip_ansi() {
    sed -E $'s/\x1b\\[[0-9;]*m//g'
}

# phase3_g2_search_size_limit_exceeded_total — counts ch-oauth-ldap's own
# fixed "ldap search size limit exceeded" message (internal/ldap/
# search.go's finishSearch), which is logged if and only if a Search on
# this connection hit sizeLimit and returned result 4. See phase3_h_*'s own
# `|| true` discipline in scenario H for why every stage of this pipeline
# is forced to exit 0 under `set -euo pipefail`.
phase3_g2_search_size_limit_exceeded_total() {
    phase3_g2_strip_ansi <"$1" | { grep -c -F 'ldap search size limit exceeded' || true; }
}

# ── 1. Create 257 grant-less roles on origin ONLY ─────────────────────────
PHASE3_G2_ROLE_COUNT=257
PHASE3_G2_ROLES=()
for ((_g2_i = 0; _g2_i < PHASE3_G2_ROLE_COUNT; _g2_i++)); do
    printf -v _g2_role 'ch_slimit_%03d' "$_g2_i"
    PHASE3_G2_ROLES+=("$_g2_role")
done
unset _g2_i _g2_role

PHASE3_G2_CREATE_SQL=""
for _g2_role in "${PHASE3_G2_ROLES[@]}"; do
    PHASE3_G2_CREATE_SQL+="CREATE ROLE IF NOT EXISTS ${_g2_role};"$'\n'
done
unset _g2_role
ch_admin_query clickhouse-origin "$PHASE3_G2_CREATE_SQL" >/dev/null

PHASE3_G2_CREATED_COUNT="$(ch_admin_query clickhouse-origin \
    "SELECT count() FROM system.roles WHERE name LIKE 'ch_slimit_%'")"
[ "$PHASE3_G2_CREATED_COUNT" = "$PHASE3_G2_ROLE_COUNT" ] \
    || die "scenario G': expected $PHASE3_G2_ROLE_COUNT grant-less ch_slimit_* roles on origin after creation, found $PHASE3_G2_CREATED_COUNT"
log "scenario G': created $PHASE3_G2_CREATED_COUNT grant-less roles (ch_slimit_000..ch_slimit_256) on clickhouse-origin only"

# ── 2 & 3. Mint the token, retain it IMMEDIATELY (before any assertion
# that could die and skip the retain — see "G' token reaches leak scan" in
# the phase-5 plan's invariant map) ───────────────────────────────────────
PHASE3_TOKEN_G2_LIMIT="$(oauth_mint limit@example.com "${PHASE3_G2_ROLES[@]}")"
oauth_retain PHASE3_TOKEN_G2_LIMIT

# ── Helper Bind/Search baseline (before the fresh auth below) ─────────────
PHASE3_G2_BASELINE_LOG="$(mktemp "$RUN_TMP_DIR/g2-helper-baseline.XXXXXX.log")"
chmod 600 "$PHASE3_G2_BASELINE_LOG"
compose logs --no-color ch-oauth-ldap >"$PHASE3_G2_BASELINE_LOG" 2>&1
PHASE3_G2_BASELINE_COUNT="$(phase3_g2_search_size_limit_exceeded_total "$PHASE3_G2_BASELINE_LOG")"
rm -f "$PHASE3_G2_BASELINE_LOG"

# ── 4. One fresh ClickHouse HTTP authentication ───────────────────────────
# The SQL is fixed to exactly this text: assert_search_limit_overflow_outcome
# (lib/expectations.sh) requires it verbatim for the truncated-roles
# success branch.
oauth_run limit@example.com "$PHASE3_TOKEN_G2_LIMIT" "SELECT length(currentRoles())"
log "scenario G': fresh authentication attempt completed — HTTP $CH_LAST_STATUS ($(oauth_body_diagnostics))"

# ── 5. Require helper evidence of 256 emitted entries / result 4 ─────────
# (A7: die fail-closed if the required T2 telemetry fields are absent —
# never assume the Search-limit fix is present just because the delta
# count below happens to work out.)
PHASE3_G2_AFTER_LOG="$(mktemp "$RUN_TMP_DIR/g2-helper-after.XXXXXX.log")"
chmod 600 "$PHASE3_G2_AFTER_LOG"
compose logs --no-color ch-oauth-ldap >"$PHASE3_G2_AFTER_LOG" 2>&1
PHASE3_G2_AFTER_COUNT="$(phase3_g2_search_size_limit_exceeded_total "$PHASE3_G2_AFTER_LOG")"
PHASE3_G2_DELTA=$((PHASE3_G2_AFTER_COUNT - PHASE3_G2_BASELINE_COUNT))

[ "$PHASE3_G2_DELTA" -eq 1 ] \
    || die "scenario G': expected exactly 1 new 'ldap search size limit exceeded' helper log event for this scenario's Search (delta-from-baseline, exactly like scenario H's Bind counting), got delta=$PHASE3_G2_DELTA (baseline=$PHASE3_G2_BASELINE_COUNT after=$PHASE3_G2_AFTER_COUNT) — either the fixture's <search_limit>256</search_limit> is not reaching the helper as sizeLimit=256, or ClickHouse's LDAP client never issued this scenario's Search at all"

PHASE3_G2_EVIDENCE_LINE="$(phase3_g2_strip_ansi <"$PHASE3_G2_AFTER_LOG" | { grep -F 'ldap search size limit exceeded' || true; } | tail -n 1)"
rm -f "$PHASE3_G2_AFTER_LOG"
[ -n "$PHASE3_G2_EVIDENCE_LINE" ] \
    || die "scenario G': delta indicated a new size-limit-exceeded Search event but no matching line could be extracted from the helper log — internal inconsistency"

# Fail-closed presence checks (A7) — die if the required numeric telemetry
# fields are missing from the evidence line, rather than silently letting
# an absent field pass an exact-value check that a shell substring match
# would never even attempt.
case "$PHASE3_G2_EVIDENCE_LINE" in
*'size_limit='*) : ;;
*) die "scenario G': helper Search evidence line is missing the required size_limit= telemetry field — refusing to assume the phase-5 sizeLimit fix/telemetry is present: $PHASE3_G2_EVIDENCE_LINE" ;;
esac
case "$PHASE3_G2_EVIDENCE_LINE" in
*'entries='*) : ;;
*) die "scenario G': helper Search evidence line is missing the required entries= telemetry field: $PHASE3_G2_EVIDENCE_LINE" ;;
esac
case "$PHASE3_G2_EVIDENCE_LINE" in
*'result='*) : ;;
*) die "scenario G': helper Search evidence line is missing the required result= telemetry field: $PHASE3_G2_EVIDENCE_LINE" ;;
esac

# Exact-value checks: sizeLimit=256 (the fixture's configured value must
# actually be what ClickHouse sent), exactly 256 entries emitted, final
# LDAP result 4 (sizeLimitExceeded).
case "$PHASE3_G2_EVIDENCE_LINE" in
*'size_limit=256'*) : ;;
*) die "scenario G': expected size_limit=256 in helper Search evidence (the fixture's configured <search_limit>), got: $PHASE3_G2_EVIDENCE_LINE" ;;
esac
case "$PHASE3_G2_EVIDENCE_LINE" in
*'entries=256'*) : ;;
*) die "scenario G': expected entries=256 in helper Search evidence, got: $PHASE3_G2_EVIDENCE_LINE" ;;
esac
case "$PHASE3_G2_EVIDENCE_LINE" in
*'result=4'*) : ;;
*) die "scenario G': expected result=4 (sizeLimitExceeded) in helper Search evidence, got: $PHASE3_G2_EVIDENCE_LINE" ;;
esac

log "scenario G': helper evidence confirmed — size_limit=256, entries=256, result=4 (recorded wire tuple for build $EXPECTED_CH_VERSION: $(search_limit_overflow_wire_tuple)) — OK"

# ── 6 (partial: classification happens after cleanup, per step 7 below;
# CH_LAST_STATUS/CH_LAST_BODY from the auth above are preserved unchanged
# by everything from here through the enforcement call) ──────────────────

# ── 7 & 8. Drop all 257 temporary roles BEFORE any assertion that can
# terminate the scenario, then assert cleanup succeeded ──────────────────
# This runs regardless of whether the classification/enforcement step
# below would pass or die — see "G' cannot contaminate H" in the phase-5
# plan's invariant map: even a die() in enforcement below must not leave
# these roles behind on origin for scenario H to inherit (H sources right
# after this file in run.sh's lexical scenario order).
PHASE3_G2_DROP_SQL=""
for _g2_role in "${PHASE3_G2_ROLES[@]}"; do
    PHASE3_G2_DROP_SQL+="DROP ROLE IF EXISTS ${_g2_role};"$'\n'
done
unset _g2_role
ch_admin_query clickhouse-origin "$PHASE3_G2_DROP_SQL" >/dev/null

PHASE3_G2_REMAINING_COUNT="$(ch_admin_query clickhouse-origin \
    "SELECT count() FROM system.roles WHERE name LIKE 'ch_slimit_%'")"
[ "$PHASE3_G2_REMAINING_COUNT" = "0" ] \
    || die "scenario G': cleanup failed — $PHASE3_G2_REMAINING_COUNT of the $PHASE3_G2_ROLE_COUNT temporary ch_slimit_* roles remain on clickhouse-origin after DROP ROLE; refusing to let the suite continue toward scenario H with these roles still present"
log "scenario G': all $PHASE3_G2_ROLE_COUNT temporary roles removed from clickhouse-origin — system.roles count for ch_slimit_* is 0 — OK (safe to proceed toward scenario H)"

# ── 6/9. Classify ClickHouse's actual outcome and enforce the recorded
# per-build expectation (lib/expectations.sh) ─────────────────────────────
assert_search_limit_overflow_outcome "scenario G' (Search-limit overflow consequence)"

log "scenario G': LDAP Search-limit compatibility complete"
