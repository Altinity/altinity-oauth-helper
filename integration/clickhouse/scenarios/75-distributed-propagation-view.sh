#!/usr/bin/env bash
# integration/clickhouse/scenarios/75-distributed-propagation-view.sh
#
# Acceptance scenario H's expected-fail sibling: distributed external-role
# propagation through a NORMAL VIEW (phase3.distributed_auth_probe ->
# phase3.remote_auth_probe, bootstrap/origin.sql / remote.sql — the
# ORIGINAL scenario-H objects, before scenarios/70 was reshaped to use a
# direct base table instead). This is NOT a duplicate of scenario H — it
# tracks a SEPARATE, independent upstream ClickHouse defect than the one
# scenario H (scenarios/70) proves is fixed on a suitable build.
#
# ── The bug (verified live, not just read from source) ───────────────────
#
# Even on a ClickHouse build where a direct base-table distributed read
# with a pushed external role succeeds (confirmed:
# altinity/clickhouse-server:25.8.28.10001.altinitystable), the IDENTICAL
# query through a normal view fails with the same ACCESS_DENIED shape
# scenario H's own known limitation reproduces on an unfixed build. Root
# cause (source-derived, cross-checked against the live failure):
#
#   - `StorageView::getViewContext()` builds the view's inner-query context
#     via `Context::createCopy(context)` for a view with no explicit
#     SQL SECURITY definer/override.
#   - `ContextData`'s copy constructor copies `current_roles` and the
#     already-calculated `access` object, but does NOT copy
#     `external_roles`.
#   - `StorageView` then calls `setSettings()` on the copy, which sets
#     `need_recalculate_access = true`.
#   - The next access-rights calculation therefore runs with no
#     `external_roles` to reconstruct the pushed role from — the
#     ephemeral, locally-ungranted alice@example.com has no ordinary local
#     role grant either, so the view read is denied exactly like the
#     unfixed-build case in scenario H, even though the SAME role, on the
#     SAME connection, DOES authorize a direct base-table read one query
#     earlier.
#
# This is why scenario H itself was reshaped away from a view-based oracle
# (see scenarios/70's own header and lib/expectations.sh): the original
# design conflated "does a pushed role authorize a distributed read" with
# "does a pushed role survive a normal view's context-copy path," which
# are different properties. This scenario keeps the second property
# separately tracked and asserted, so it can flip from expected_fail to
# must_pass the moment ClickHouse fixes the underlying context-copy defect,
# without touching scenario H's own pass/fail logic at all.
#
# Filed upstream: ClickHouse/ClickHouse#116840 (the copy-constructor
# omission of external_roles in Context.cpp's ContextData is the first
# place to patch and regression-test, per the ad hoc consultation that
# diagnosed this). Confirmed reproducing on every LTS line swept so far
# (24.8, 25.3, 25.8, 26.3) — see lib/expectations.sh's H_view_propagation
# entry.
#
# A FRESH token is minted here (not reused from scenario H) so this
# scenario's own reasoning is self-contained, matching every other
# scenario file's convention.

source "$SCRIPT_DIR/lib/oauth.sh"
source "$SCRIPT_DIR/lib/expectations.sh"

log "scenario H (view oracle): distributed external-role propagation through a normal view"

PHASE3_TOKEN_H_VIEW="$(oauth_mint alice@example.com idp-distributed)"
oauth_retain PHASE3_TOKEN_H_VIEW

PHASE3_H_VIEW_QUERY="SELECT remote_user, remote_roles, sum(n) FROM phase3.distributed_auth_probe GROUP BY remote_user, remote_roles SETTINGS push_external_roles_in_interserver_queries"

# ── Negative propagation control ──────────────────────────────────────────
# Build-independent, exactly like scenario H's own negative control: with
# propagation disabled, nothing is pushed, so the ephemeral
# alice@example.com has zero authority regardless of either tracked
# ClickHouse defect.
oauth_run alice@example.com "$PHASE3_TOKEN_H_VIEW" "${PHASE3_H_VIEW_QUERY} = 0"
oauth_expect_auth_failure "scenario H view oracle (negative propagation control, setting=0)"
log "scenario H (view oracle): negative control (push_external_roles_in_interserver_queries=0) correctly denied — OK"

# ── Positive propagation control ──────────────────────────────────────────
# Tracked as expected_fail on EVERY currently known build (see
# lib/expectations.sh's H_view_propagation entry) — assert_propagation_outcome
# asserts the specific known ACCESS_DENIED failure shape and logs it loudly
# as a tracked limitation. If a future ClickHouse build fixes the
# underlying ContextData copy-constructor omission, this will die with a
# "BEHAVIOR CHANGED" message rather than silently passing — update
# lib/expectations.sh's H_view_propagation entry to must_pass for that
# build and change the assertion below to require the exact
# "alice@example.com\tch_distributed_reader\t6" body, matching scenario H's
# own must_pass shape, when that happens.
oauth_run_retry_transient alice@example.com "$PHASE3_TOKEN_H_VIEW" "${PHASE3_H_VIEW_QUERY} = 1"
assert_propagation_outcome H_view_propagation \
    "scenario H view oracle (positive propagation control, setting=1)" \
    "$(printf 'alice@example.com\tch_distributed_reader\t6')"
