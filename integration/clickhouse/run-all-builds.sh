#!/usr/bin/env bash
# integration/clickhouse/run-all-builds.sh
#
# Runs the full phase-3 acceptance suite (run.sh) sequentially against
# every ClickHouse build lib/expectations.sh has recorded per-build
# behavioral expectations for, printing a final build -> result summary and
# exiting non-zero if any build's run itself exits non-zero.
#
# Sequential is not a performance choice: this fixture is single-instance
# per Docker daemon (fixed COMPOSE_PROJECT_NAME and, on the sandbox
# fallback path, fixed fallback network names in run.sh — see
# "Concurrency" in integration/clickhouse/README.md), so two of its runs
# against the same daemon at once would collide.
#
# A build whose run.sh exits 0 is a PASS for that build even when one of
# its scenarios logged a KNOWN LIMITATION line (an expected_fail case that
# failed for the recorded, tracked reason) — that is run.sh working
# correctly, not a suite failure. A build only shows FAIL here when run.sh
# itself died: a genuine infrastructure problem, an assertion outside the
# expectation machinery, or assert_propagation_outcome's own "BEHAVIOR
# CHANGED" die (an expected_fail case that unexpectedly succeeded — see
# lib/expectations.sh).
#
# Single-build invocation (`./integration/clickhouse/run.sh`, optionally
# with PHASE3_CH_IMAGE set) is unaffected by this script and keeps working
# exactly as before.
#
# Usage:
#   ./integration/clickhouse/run-all-builds.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The four images this suite is actually run against: the issue's pinned
# 24.8 baseline, the 25.8 build on which distributed external-role
# propagation is proven to work, and the 26.3/26.8 lines added when the
# tracked set was extended.
#
# This array is the tracked-line AUTHORITY, not just a convenience list.
# docs/clickhouse-ldap-wire-profile.md §1 defines "tracked" as exactly the
# images here, and internal/securitytest/wire_profile_contract_test.go's
# TestWireProfileContract_TrackedLineFourWayEquality holds four sources
# equal to it: this array, the wire doc's §1/§2.1/§2.2 tables, the fixture
# directories under internal/ldap/testdata/clickhouse-wire/, and every
# committed profile.json's "line" field. Adding an image here therefore
# also requires audited source provenance and a captured wire corpus for
# its line — it is never a one-line edit.
#
# 26.8 is deliberately the UPSTREAM clickhouse/clickhouse-server image:
# no Altinity Stable 26.8 build exists (see the wire doc §2.1). Every
# other tracked line is an Altinity Stable build. What this array requires
# is a TAGGED image whose tag equals the server's version() string, which
# both registries satisfy — run.sh enforces that pin itself.
#
# lib/expectations.sh additionally records per-build outcomes for the 25.3
# line (from a one-off LTS sweep, see its header and
# integration/clickhouse/README.md), so a 25.3 image can be run ad hoc via
# PHASE3_CH_IMAGE without adding it here. A build added here (or run ad
# hoc) WITHOUT a matching expectation entry makes run.sh die loudly at the
# first expectation lookup, never silently pass.
BUILDS=(
    "altinity/clickhouse-server:24.8.11.51285.altinitystable"
    "altinity/clickhouse-server:25.8.28.10001.altinitystable"
    "altinity/clickhouse-server:26.3.16.10001.altinitystable"
    "clickhouse/clickhouse-server:26.8.1.2041"
)

declare -A RESULTS

overall_rc=0
for image in "${BUILDS[@]}"; do
    printf '\n==== running against %s ====\n' "$image" >&2
    if PHASE3_CH_IMAGE="$image" "$SCRIPT_DIR/run.sh"; then
        RESULTS["$image"]="PASS"
    else
        RESULTS["$image"]="FAIL"
        overall_rc=1
    fi
done

printf '\n==== build summary ====\n' >&2
for image in "${BUILDS[@]}"; do
    printf '  %-70s %s\n' "$image" "${RESULTS[$image]}" >&2
done

exit "$overall_rc"
