#!/usr/bin/env bash
# integration/clickhouse/lib/expectations.sh
#
# Per-ClickHouse-build behavioral expectations for known, tracked upstream
# ClickHouse limitations that acceptance scenario H's two authorization
# oracles (scenarios/70-distributed-propagation.sh,
# scenarios/75-distributed-propagation-view.sh) probe. Sourced by whichever
# scenario file needs it, the same way scenario files source lib/oauth.sh —
# run.sh itself does not know about this file. Assumes lib/common.sh (for
# `die`/`log`) and EXPECTED_CH_VERSION (set by run.sh, derived from
# PHASE3_CH_IMAGE) are already in scope.
#
# ── Why this exists ────────────────────────────────────────────────────────
# Two independent, real upstream ClickHouse defects were found while
# implementing acceptance scenario H (verified live against real
# containers, not inferred from reading source alone):
#
#   1. ClickHouse #78791 / fixed by #79099 ("Fix passing of external roles
#      in interserver query"): on a build without that fix,
#      Context::setExternalRolesWithLock stores a pushed external role's
#      UUID in `current_roles` rather than a separate `external_roles`
#      field. Access-rights calculation filters `current_roles` against the
#      (ephemeral, locally-ungranted) user's own local grants, so the
#      pushed role never actually authorizes anything, even though the
#      remote server's own log line ("... has external_roles applied: ...")
#      makes it look like the role WAS honored. The issue's stated baseline
#      build, `altinity/clickhouse-server:24.8.11.51285.altinitystable`
#      (released 2025-01-31), predates the fix (merged 2025-06-09) and has
#      no later 24.8.x Altinity Stable release backporting it as of this
#      writing. `altinity/clickhouse-server:25.8.28.10001.altinitystable`
#      (confirmed via git ancestry to already contain the fix commit) does
#      NOT exhibit this bug for a direct base-table read.
#   2. A second, distinct bug: even on a build with #79099, a NORMAL VIEW
#      loses the propagated role. `ContextData`'s copy constructor (used by
#      `StorageView::getViewContext`'s `Context::createCopy`) copies
#      `current_roles`/the cached `access` object, but not
#      `external_roles`. `StorageView` then calls `setSettings()` on the
#      copy, which sets `need_recalculate_access = true` — so the NEXT
#      access-rights calculation runs with no `external_roles` to
#      reconstruct the pushed role from, and the read is denied exactly
#      like case 1, even on a build where a direct base-table read
#      succeeds. Verified live: identical ACCESS_DENIED failure persisted
#      on 25.8.28.10001.altinitystable when the authorization oracle was a
#      view, while the equivalent direct-base-table query on the SAME
#      container succeeded. Filed upstream as
#      ClickHouse/ClickHouse#116840.
#
# A broader LTS-line sweep (24.8, 25.3, 25.8, 26.3) confirmed the pattern
# holds across all four: base-table propagation (case 1) fails on
# 24.8/25.3 (both predate #79099) and passes on 25.8/26.3 (both contain
# it), while the view-context-copy defect (case 2) reproduces on every one
# of the four, including 25.8/26.3 where the base-table oracle already
# passes.
#
# Both are real ClickHouse defects, not fixture misconfiguration — manually
# granting the exact privilege the error names, directly to the role, does
# not help in either case; the only thing that has been observed to make
# the query succeed regardless of these bugs is an unconditional static
# LDAP `<roles>` list, which would also defeat scenario H's negative
# control (see the scenario files' own header comments). Treat both as
# EXPECTED failures on the builds where they're known to reproduce, rather
# than either silently skipping the assertion or failing the whole suite —
# and treat an unexpected SUCCESS as loudly as an unexpected failure, since
# that means ClickHouse's behavior changed and this file's expectations (and
# the corresponding scenario's assertions) need to be updated to match.
#
# ── Functions ───────────────────────────────────────────────────────────────
#   ch_build_prefix VERSION        prints VERSION's "MAJOR.MINOR" prefix
#                                    (e.g. "24.8.11.51285.altinitystable" ->
#                                    "24.8"). Expectations are keyed at this
#                                    granularity because the tracked bugs
#                                    above are properties of the ClickHouse
#                                    minor-version line, not a specific
#                                    patch/build number.
#   expectation_for KEY             prints "must_pass" or "expected_fail" for
#                                    KEY against $EXPECTED_CH_VERSION's build
#                                    prefix. Dies loudly for an unrecognized
#                                    (KEY, prefix) pair — a new build must
#                                    get an explicit expectation added here
#                                    before it can run this suite, never
#                                    silently inherit one.
#   expectation_reason KEY          prints the recorded human-readable
#                                    reason for KEY's expected_fail case
#                                    (used in log lines and die messages).
#   expect_remote_access_denied LABEL
#                                    asserts the ONE failure shape this suite
#                                    accepts as "the REMOTE node denied the
#                                    distributed read": HTTP 500, body
#                                    containing "ACCESS_DENIED", AND body
#                                    containing "Received from
#                                    clickhouse-remote:9000" (the same
#                                    remote-origin marker run.sh's scenario
#                                    A.3 preflight already keys on) — against
#                                    $CH_LAST_STATUS/$CH_LAST_BODY. Used for
#                                    both oracles' NEGATIVE controls. This
#                                    is deliberately much stricter than
#                                    oauth_expect_auth_failure's generic
#                                    "not 200": a transport failure
#                                    (ALL_CONNECTION_TRIES_FAILED), a SQL
#                                    error, or an ORIGIN-side ACCESS_DENIED
#                                    (e.g. a lost origin grant, or origin-
#                                    side role mapping regressing) all also
#                                    return non-200, and none of them prove
#                                    "remote denied because no role was
#                                    pushed". Requiring the remote marker is
#                                    what stops scenario H from passing
#                                    vacuously on a build where both arms
#                                    expect denial.
#   expect_known_access_denied LABEL
#                                    the SPECIFIC known-limitation failure
#                                    shape this suite has actually observed
#                                    for both bugs above. Identical to
#                                    expect_remote_access_denied (500 +
#                                    ACCESS_DENIED + remote marker): the
#                                    tracked defects both manifest as the
#                                    REMOTE denying the read, so an
#                                    origin-side denial is never mistaken
#                                    for the tracked one either.
#   oauth_retry_reset_extra_attempts
#                                    resets OAUTH_RETRY_EXTRA_ATTEMPTS to 0.
#                                    Call once at the top of every scenario
#                                    that uses oauth_run_retry_transient and
#                                    reasons about helper Bind counts.
#   oauth_run_retry_transient USERNAME PASSWORD SQL [MAX_ATTEMPTS]
#                                    like oauth_run, but retries (after a
#                                    short sleep) when $CH_LAST_BODY
#                                    indicates a TRANSPORT-level interserver
#                                    connection failure
#                                    (ALL_CONNECTION_TRIES_FAILED) rather
#                                    than a real query/authorization
#                                    result — observed intermittently in
#                                    this sandbox between clickhouse-origin
#                                    and clickhouse-remote even after
#                                    scenario A's own preflight already
#                                    proved connectivity earlier in the
#                                    same run. Does NOT retry on any other
#                                    failure shape, including the tracked
#                                    ACCESS_DENIED case both authorization
#                                    oracles' controls use this for — only
#                                    this specific transient transport
#                                    error, so a genuine authorization
#                                    result is never masked by a retry
#                                    loop. Gives up and returns the last
#                                    (still-transient) result after
#                                    MAX_ATTEMPTS (default 3).
#                                    EVERY retry is a fresh HTTP request and
#                                    therefore a fresh, successful helper
#                                    Bind on origin (origin authenticates
#                                    the JWT before the distributed step
#                                    fails), so each retry increments
#                                    OAUTH_RETRY_EXTRA_ATTEMPTS by one —
#                                    scenario H's "exactly N new Binds"
#                                    delta proof must add that counter to
#                                    its expected value, or a retry that did
#                                    its job would still fail the run with a
#                                    misleading "remote re-authenticated"
#                                    diagnosis.
#   assert_propagation_outcome KEY LABEL EXPECTED_BODY
#                                    call after oauth_run has already set
#                                    $CH_LAST_STATUS/$CH_LAST_BODY for the
#                                    scenario's positive propagation-control
#                                    query. Branches on expectation_for KEY:
#                                      must_pass:     assert HTTP 200 and
#                                                       body exactly
#                                                       EXPECTED_BODY.
#                                      expected_fail: if the query
#                                                       UNEXPECTEDLY
#                                                       returned 200, `die`
#                                                       with a "behavior
#                                                       changed, update this
#                                                       file" message (never
#                                                       silently treat an
#                                                       upstream fix as a
#                                                       failure); otherwise
#                                                       assert
#                                                       expect_known_access_denied
#                                                       and log a
#                                                       "KNOWN LIMITATION"
#                                                       line.

# ch_build_prefix VERSION — see contract above.
ch_build_prefix() {
    local version="$1"
    printf '%s' "$version" | cut -d. -f1-2
}

# expectation_for KEY — see contract above. Keep in sync with
# expectation_reason below: every expected_fail case here must have a
# matching reason case there.
expectation_for() {
    local key="$1"
    local prefix
    prefix="$(ch_build_prefix "$EXPECTED_CH_VERSION")"
    case "${key}:${prefix}" in
    # Full matrix confirmed live: 24.8 and 25.3 predate ClickHouse #79099
    # (base-table propagation fails on both); 25.8 and 26.3 contain the fix
    # (base-table propagation passes on both). The view-context-copy defect
    # (H_view_propagation) reproduces on every one of these four lines,
    # including 25.8/26.3 where the base-table oracle already passes.
    H_base_table_propagation:24.8) printf 'expected_fail' ;;
    H_base_table_propagation:25.3) printf 'expected_fail' ;;
    H_base_table_propagation:25.8) printf 'must_pass' ;;
    H_base_table_propagation:26.3) printf 'must_pass' ;;
    H_view_propagation:24.8) printf 'expected_fail' ;;
    H_view_propagation:25.3) printf 'expected_fail' ;;
    H_view_propagation:25.8) printf 'expected_fail' ;;
    H_view_propagation:26.3) printf 'expected_fail' ;;
    *)
        die "expectation_for: no recorded expectation for scenario key '$key' against ClickHouse build prefix '$prefix' (full version: $EXPECTED_CH_VERSION) — add one to integration/clickhouse/lib/expectations.sh before running this suite against this build"
        ;;
    esac
}

# expectation_reason KEY — see contract above.
expectation_reason() {
    local key="$1"
    case "$key" in
    H_base_table_propagation)
        printf 'ClickHouse #78791, fixed upstream by #79099 ("Fix passing of external roles in interserver query", not backported to this build — confirmed on both 24.8 and 25.3): a pushed external role is stored in current_roles and filtered against the ephemeral users own (empty) local grants, so it never authorizes anything'
        ;;
    H_view_propagation)
        printf 'ContextData copy constructor omits external_roles when StorageView clones the query context for a normal view; the subsequent setSettings() call forces access-rights recalculation with no external_roles to reconstruct the pushed role from — reproduces on every build tested (24.8, 25.3, 25.8, 26.3), including ones where the base-table oracle already passes. Filed upstream as ClickHouse/ClickHouse#116840'
        ;;
    *)
        die "expectation_reason: no reason text recorded for key '$key'"
        ;;
    esac
}

# OAUTH_RETRY_EXTRA_ATTEMPTS — see oauth_run_retry_transient's contract
# above. Initialized here (idempotently) so a scenario that never retries
# can still read it as 0; reset per scenario via
# oauth_retry_reset_extra_attempts.
: "${OAUTH_RETRY_EXTRA_ATTEMPTS:=0}"

# oauth_retry_reset_extra_attempts — see contract above.
oauth_retry_reset_extra_attempts() {
    OAUTH_RETRY_EXTRA_ATTEMPTS=0
}

# oauth_run_retry_transient USERNAME PASSWORD SQL [MAX_ATTEMPTS] — see
# contract above.
oauth_run_retry_transient() {
    local username="$1" password="$2" sql="$3" max_attempts="${4:-3}"
    local attempt=1
    while :; do
        oauth_run "$username" "$password" "$sql"
        case "$CH_LAST_BODY" in
        *ALL_CONNECTION_TRIES_FAILED*)
            if [ "$attempt" -ge "$max_attempts" ]; then
                log "oauth_run_retry_transient: still ALL_CONNECTION_TRIES_FAILED after $attempt attempts, giving up and returning this result"
                return 0
            fi
            log "oauth_run_retry_transient: transient ALL_CONNECTION_TRIES_FAILED on attempt $attempt/$max_attempts, retrying after a short delay (this retry is one extra successful origin Bind; OAUTH_RETRY_EXTRA_ATTEMPTS accounts for it)"
            sleep 2
            attempt=$((attempt + 1))
            OAUTH_RETRY_EXTRA_ATTEMPTS=$((OAUTH_RETRY_EXTRA_ATTEMPTS + 1))
            ;;
        *)
            return 0
            ;;
        esac
    done
}

# PHASE3_REMOTE_DENIAL_MARKER is the substring ClickHouse puts in an
# exception that was raised on the remote shard and relayed by the
# initiator — the same text run.sh's scenario A.3 preflight keys on to prove
# origin actually reached clickhouse-remote:9000.
PHASE3_REMOTE_DENIAL_MARKER="Received from clickhouse-remote:9000"

# expect_remote_access_denied LABEL — see contract above.
expect_remote_access_denied() {
    local label="$1"
    [ "$CH_LAST_STATUS" = "500" ] \
        || die "$label: expected a remote ACCESS_DENIED failure shape (HTTP 500), got HTTP $CH_LAST_STATUS (body: $CH_LAST_BODY)"
    case "$CH_LAST_BODY" in
    *ACCESS_DENIED*) : ;;
    *) die "$label: expected body to contain ACCESS_DENIED, got: $CH_LAST_BODY" ;;
    esac
    case "$CH_LAST_BODY" in
    *"$PHASE3_REMOTE_DENIAL_MARKER"*) : ;;
    *) die "$label: expected the denial to have been raised on the REMOTE node (body must contain '$PHASE3_REMOTE_DENIAL_MARKER') — an origin-side denial, a transport failure, or a SQL error proves nothing about role propagation. Got: $CH_LAST_BODY" ;;
    esac
}

# expect_known_access_denied LABEL — see contract above.
expect_known_access_denied() {
    expect_remote_access_denied "$1"
}

# assert_propagation_outcome KEY LABEL EXPECTED_BODY — see contract above.
assert_propagation_outcome() {
    local key="$1" label="$2" expected_body="$3"
    local outcome prefix
    outcome="$(expectation_for "$key")"
    prefix="$(ch_build_prefix "$EXPECTED_CH_VERSION")"
    case "$outcome" in
    must_pass)
        oauth_expect_status 200 "$label"
        oauth_expect_exact_body "$expected_body" "$label"
        log "$label: must_pass expectation met on build $prefix — OK"
        ;;
    expected_fail)
        if [ "$CH_LAST_STATUS" = "200" ]; then
            die "$label: BEHAVIOR CHANGED — build $prefix unexpectedly succeeded where '$key' is recorded as expected_fail (tracked reason: $(expectation_reason "$key")). ClickHouse may have fixed this; update expectation_for in lib/expectations.sh to must_pass for this build and flip this scenario's assertions to require success, rather than silently accepting a stale expectation."
        fi
        expect_known_access_denied "$label"
        log "$label: KNOWN LIMITATION ($(expectation_reason "$key")) — failing as expected on build $prefix"
        ;;
    *)
        die "$label: expectation_for returned unrecognized outcome '$outcome' for key '$key'"
        ;;
    esac
}
