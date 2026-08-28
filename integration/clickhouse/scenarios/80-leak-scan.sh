#!/usr/bin/env bash
# integration/clickhouse/scenarios/80-leak-scan.sh
#
# Acceptance scenario I — JWT leak assertion (see the phase-3 plan). Runs
# LAST (lexically after every other scenarios/*.sh file), so
# lib/oauth.sh's OAUTH_RETAINED_TOKEN_NAMES registry already holds every
# signed JWT this run minted: Alice reader/unprovisioned (scenario B),
# Bob mismatch (D), expired Alice (E), reconnect A and B (F),
# local-precedence (G), and distributed (H, both oracles) — the seven the
# plan names in "Acceptance scenario I" plus the view-oracle token — and,
# beyond the plan's minimum, the runtime-generated plaintext password of
# the local-precedence user (scenario G retains CH_LOCAL_ADMIN_PASSWORD),
# which travels the same HTTP Basic path and is just as much a credential.
#
# Order matters here (see the plan's "Leak-scanner self-test"): the
# self-test MUST run and MUST detect its own deliberate plant before this
# file trusts leakscan_scan_artifacts against anything real. If the
# self-test fails to detect the plant, lib/leakscan.sh's leakscan_self_test
# calls `die` itself — this file never reaches the real scan in that case.

source "$SCRIPT_DIR/lib/oauth.sh"
source "$SCRIPT_DIR/lib/leakscan.sh"

log "scenario I: JWT leak assertion"

[ "${#OAUTH_RETAINED_TOKEN_NAMES[@]}" -gt 0 ] \
    || die "scenario I: OAUTH_RETAINED_TOKEN_NAMES is empty — no earlier scenario retained a token for this scan to check, which means either an earlier scenario file failed to run or the registry itself is broken"

log "scenario I: retained-token registry has ${#OAUTH_RETAINED_TOKEN_NAMES[@]} entries"

# ── Leak-scanner self-test ────────────────────────────────────────────────
# Uses the first retained token (an arbitrary but real, already-minted
# JWT) as the deliberate plant — see "Leak-scanner self-test" in the plan.
log "scenario I: leak-scanner self-test (plant one real JWT into a synthetic artifact, require detection)"
leakscan_self_test "${OAUTH_RETAINED_TOKEN_NAMES[0]}"

# ── Probe FIRST, then snapshot ────────────────────────────────────────────
# The artifact directory is created HERE (not inside
# leakscan_collect_artifacts) so that function runs in this shell and its
# `die` calls abort the suite for real — see lib/leakscan.sh.
#
# Order matters: leakscan_capture_auth_failure_bodies fires a genuinely NEW
# HTTP Basic-auth request per retained credential, which can itself add
# lines to the helper's and both ClickHouse nodes' logs. Taking the compose
# logs / on-disk server logs / run transcript snapshot BEFORE issuing these
# probes would let whatever the probes themselves cause ClickHouse to log
# escape the very corpus this scenario scans — so the probes run first, and
# the snapshot is taken only once they have all completed.
PHASE3_I_ARTIFACT_DIR="$(mktemp -d "$RUN_TMP_DIR/leakscan-artifacts.XXXXXX")"
chmod 700 "$PHASE3_I_ARTIFACT_DIR"

log "scenario I: issuing auth-failure probes for all ${#OAUTH_RETAINED_TOKEN_NAMES[@]} retained tokens (before the final snapshot below)"
leakscan_capture_auth_failure_bodies "$PHASE3_I_ARTIFACT_DIR" "${OAUTH_RETAINED_TOKEN_NAMES[@]}"

log "scenario I: collecting real artifacts (helper/origin/remote compose logs, on-disk ClickHouse server/error logs, runner transcript) — taken AFTER the probes above so their own log side-effects are included"
leakscan_collect_artifacts "$PHASE3_I_ARTIFACT_DIR"

# ── Completeness gate ─────────────────────────────────────────────────────
# A scan over a missing or empty artifact is trivially "clean" and proves
# nothing, so every artifact the scan is about to trust must exist and be
# non-empty (see leakscan_require_artifacts_complete for the one logged
# exception, an error log a quiet build never wrote to).
leakscan_require_artifacts_complete "$PHASE3_I_ARTIFACT_DIR"

# ── Scan real artifacts ────────────────────────────────────────────────────
# Do NOT scan the private per-request curl credential configs
# ch_http_query_as writes: those are deleted by ch_http_query_as itself
# before it ever returns (see lib/common.sh), and leakscan_collect_artifacts
# never copies them — there is nothing there to scan, per the plan ("Do not
# scan the private curl credential files themselves").
log "scenario I: scanning real artifacts for all ${#OAUTH_RETAINED_TOKEN_NAMES[@]} retained tokens"
if leakscan_scan_artifacts "$PHASE3_I_ARTIFACT_DIR" "${OAUTH_RETAINED_TOKEN_NAMES[@]}"; then
    rm -rf "$PHASE3_I_ARTIFACT_DIR"
    log "scenario I: zero JWT matches across all real artifacts — OK"
else
    rm -rf "$PHASE3_I_ARTIFACT_DIR"
    die "scenario I: at least one retained JWT was found verbatim in a captured artifact (see the leak-scan log line above for which retained token and which artifact file) — phase 3 fails"
fi

log "scenario I: JWT leak assertion complete"
