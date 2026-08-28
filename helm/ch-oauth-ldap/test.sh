#!/usr/bin/env bash
# helm/ch-oauth-ldap/test.sh
#
# Committed acceptance gate for the ch-oauth-ldap chart (issue #19 phase 4,
# plan sections 27, 28, 29, 36, 50, 52, 53, 54, 55, 56, A1, A4, A6, and 3).
# This is the single composed entry point a human or CI runs; it sources
# the three sibling assertion libraries under ci/lib/ and adds the checks
# that only make sense as final, integration-level proof:
#
#   * §36  helm lint (structural only -- does NOT prove required/fail);
#   * §37/§38/§41-46 (via ci/lib/chart-assertions.sh)  render matrix;
#   * §39/§40/§47    (via ci/lib/embedded-assertions.sh) structural
#                     config.yaml/ldap.xml verification;
#   * §48/§49/§29/§51 (via ci/lib/image-assertions.sh) Dockerfile/script/
#                     workflow static checks + the REAL script's own
#                     SIGINT regression + a pinned-actionlint validity gate
#                     on build-ch-oauth-ldap.yml (with an informational-only
#                     pass over build-ch-jwt-verify.yml and a negative case
#                     proving the check inspects expressions inside `run:`
#                     comments);
#   * §52  helm package + archive-content proof (test.sh/ci/ excluded);
#   * §53  documentation checks across both READMEs, CLAUDE.md, and the
#          (skip-if-absent, per amendment A6) repo-footguns.md;
#   * §54  the standard Go gate (build/vet/test) plus cross-compilation;
#   * §55  the OLD helm/ch-jwt-verify chart's lint/template smoke, proving
#          this phase did not disturb it;
#   * §56  a base-ref-aware proof that a ch-oauth-ldap change leaves the
#          ch-jwt-verify sidecar surface untouched, both in committed
#          history and in the current working tree;
#   * §50/§29 this script's OWN deterministic SIGINT regression, run
#          against a real, unmodified copy of itself.
#
# Requires: Bash, Helm, Go, network access for kubeconform install/schema
# fetch (unless KUBECONFORM_SCHEMA_LOCATION points at a local mirror) and for
# actionlint install (unless a PATH `actionlint` already reports the pinned
# ACTIONLINT_VERSION), and ordinary POSIX text utilities. Prefers `rg` (via
# ci/lib/common.sh's matcher) but never requires it. Never requires yq,
# kubectl, a Docker daemon, registry credentials, or a Kubernetes cluster.
#
# This script only reads chart/lib/doc/workflow files and writes under its
# own $RUN_TMP_DIR (plus, transiently, the two cross-compiled binaries it
# also writes there) -- it never modifies any lib, chart, image, or doc
# file. If a check here fails because one of those files is wrong, the
# fix belongs in that file, not in this gate.

set -uo pipefail
# NOT `set -e`: every check below is wrapped in an explicit `if`/status
# check specifically so one failing assertion doesn't abort the run before
# later, independent sections get a chance to report their own results.
# The overall exit code is decided once, at the very end, from the shared
# $GATE_FAILURES counter (see ci/lib/common.sh).

# ==============================================================================
# Lifecycle (plan §27/§28) -- identical pattern to
# scripts/build-ch-oauth-ldap-image.sh and integration/clickhouse/run.sh.
# ==============================================================================

# Per-run private state lives under $TMPDIR, never /tmp: sandboxed hosts in
# this repo's own CI/dev environment block /tmp for exactly this kind of
# owned scratch state. Most hosts leave TMPDIR unset, so default it to
# $HOME/tmp rather than refusing to run.
TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR
umask 077

# RUN_TMP_DIR is declared, and the cleanup trap installed, before any other
# per-run state exists -- this closes the "SIGINT before the trap exists at
# all" window outright. cleanup() below tolerates running with RUN_TMP_DIR
# still unset (the guard immediately inside it).
RUN_TMP_DIR=""

cleanup() {
    local rc=$?
    set +e
    if [ -n "${RUN_TMP_DIR:-}" ]; then
        rm -rf -- "$RUN_TMP_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# RUN_TMP_DIR is deliberately NOT assigned from a directory-creating
# temp-file-utility invocation run via command substitution: that utility
# runs as a separate process, so there is an unavoidable gap between the
# moment its mkdir(2) syscall creates the directory and the moment this
# shell finishes the command substitution and assigns the path into
# RUN_TMP_DIR -- a SIGINT landing in exactly that gap would leave
# RUN_TMP_DIR unset in cleanup() even though the trap is already live,
# leaking the just-created directory. Instead, pre-compute a
# collision-resistant candidate path (via printf -v + several $RANDOM
# values -- a pure bash builtin operation, no filesystem state, no forked
# process) and assign it into RUN_TMP_DIR BEFORE calling `mkdir` on it.
# That assignment is a single in-process bash statement -- bash only acts
# on a pending signal between simple commands, never mid-statement -- so by
# the time the external `mkdir` runs, cleanup() already knows the path
# regardless of whether mkdir has created the directory yet, is
# interrupted mid-syscall, or never gets to run at all. Because the name is
# no longer handed out atomically, plain `mkdir` can fail with EEXIST on a
# genuine collision; clear RUN_TMP_DIR and retry with a fresh candidate
# rather than assuming the first name is free.
for _gate_attempt in {1..10}; do
    printf -v _gate_suffix '%04x%04x%04x%04x' "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM"
    _gate_candidate="$TMPDIR/ch-oauth-ldap-chart-gate.$_gate_suffix"
    RUN_TMP_DIR="$_gate_candidate"
    if mkdir -m 700 "$RUN_TMP_DIR" 2>/dev/null; then
        unset _gate_suffix _gate_candidate _gate_attempt
        break
    fi
    RUN_TMP_DIR=""
done
if [ -z "$RUN_TMP_DIR" ]; then
    echo "test.sh: failed to create a unique run directory under $TMPDIR (ch-oauth-ldap-chart-gate.*) after 10 attempts" >&2
    exit 1
fi

# ==============================================================================
# Locate the repo/chart, source the libraries, print the reproducibility header.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CHART_DIR="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=ci/lib/common.sh
source "$CHART_DIR/ci/lib/common.sh"
# shellcheck source=ci/lib/chart-assertions.sh
source "$CHART_DIR/ci/lib/chart-assertions.sh"
# shellcheck source=ci/lib/embedded-assertions.sh
source "$CHART_DIR/ci/lib/embedded-assertions.sh"
# shellcheck source=ci/lib/image-assertions.sh
source "$CHART_DIR/ci/lib/image-assertions.sh"

export REPO_ROOT CHART_DIR RUN_TMP_DIR

echo "===================================================================="
echo "ch-oauth-ldap committed acceptance gate"
echo "REPO_ROOT=$REPO_ROOT"
echo "CHART_DIR=$CHART_DIR"
echo "RUN_TMP_DIR=$RUN_TMP_DIR"
print_gate_pins
note "remote kubeconform schema retrieval needs network access unless KUBECONFORM_SCHEMA_LOCATION points at a local mirror"
echo "===================================================================="

# ==============================================================================
# §A4 -- resolve/install the pinned kubeconform once, up front, and put its
# bin dir on PATH so the assertion libraries' own ensure_kubeconform calls
# find it already resolved instead of reinstalling. Same pattern for the
# pinned actionlint (workflow-validity gate): resolve it once, up front, so
# ci/lib/image-assertions.sh's actionlint checks find $ACTIONLINT_BIN
# already set. Fails closed (via `fail`, no silent skip) if either pinned
# tool cannot be resolved on PATH or installed.
# ==============================================================================

ensure_kubeconform "$RUN_TMP_DIR/bin"
ensure_actionlint "$RUN_TMP_DIR/bin"
export PATH="$RUN_TMP_DIR/bin:$PATH"

# ==============================================================================
# §36 -- helm lint (production CI values, and dev values layered on top).
# Lint is structural only: Helm 3 and 4.1.4 both make `required`/`fail`
# calls non-fatal in lint mode, so a lint pass here proves nothing about
# the chart's fail-closed validation -- that proof lives entirely in
# run_chart_assertions' negative `helm template` matrix below.
# ==============================================================================

run_lint_checks() {
    note "helm lint does not enforce required/fail on Helm 3 or 4.1.4; treat lint here as structural-only, never as the fail-closed validation proof (see run_chart_assertions' negative matrix for that)"

    if helm lint "$CHART_DIR" -f "$CHART_DIR/ci/valid-values.yaml" \
        >"$RUN_TMP_DIR/lint-prod.out" 2>"$RUN_TMP_DIR/lint-prod.err"; then
        pass "lint(prod): helm lint $CHART_DIR -f ci/valid-values.yaml succeeded"
    else
        fail "lint(prod): helm lint $CHART_DIR -f ci/valid-values.yaml FAILED: $(cat "$RUN_TMP_DIR/lint-prod.err")"
    fi

    if helm lint "$CHART_DIR" -f "$CHART_DIR/ci/valid-values.yaml" -f "$CHART_DIR/values-dev.yaml" \
        >"$RUN_TMP_DIR/lint-dev.out" 2>"$RUN_TMP_DIR/lint-dev.err"; then
        pass "lint(dev): helm lint $CHART_DIR -f ci/valid-values.yaml -f values-dev.yaml succeeded"
    else
        fail "lint(dev): helm lint $CHART_DIR -f ci/valid-values.yaml -f values-dev.yaml FAILED: $(cat "$RUN_TMP_DIR/lint-dev.err")"
    fi
}

run_lint_checks

# ==============================================================================
# The three sibling assertion libraries. Each is delta-based: it reports
# its own PASS/FAIL against how many NEW entries it added to the shared
# $GATE_FAILURES counter, not the counter's absolute value, so an earlier
# section's failure never masks a later section's own clean result.
# ==============================================================================

_gate_delta_report() {
    local label="$1" before="$2" after="$3"
    if [ "$after" -eq "$before" ]; then
        pass "$label: section passed"
    else
        # A summary NOTE, deliberately not another `fail`: each failure above
        # is already counted exactly once in $GATE_FAILURES, so the final
        # "GATE RESULT: FAIL (N failure(s))" line is the true assertion count.
        note "$label: section FAILED -- $((after - before)) failure(s) recorded above"
    fi
}

note "chart: running render/negative-matrix/rendered-Kubernetes assertions (ci/lib/chart-assertions.sh)"
_before=$GATE_FAILURES
run_chart_assertions || true
_gate_delta_report "chart" "$_before" "$GATE_FAILURES"

note "embedded: running structural config.yaml/ldap.xml verification (ci/lib/embedded-assertions.sh)"
_before=$GATE_FAILURES
run_embedded_assertions || true
_gate_delta_report "embedded" "$_before" "$GATE_FAILURES"

note "image: running Dockerfile/script/workflow static checks + the real script's SIGINT regression (ci/lib/image-assertions.sh)"
_before=$GATE_FAILURES
run_image_assertions || true
_gate_delta_report "image" "$_before" "$GATE_FAILURES"

# ==============================================================================
# §52 -- chart packaging hygiene: test.sh and ci/ must never ship.
# ==============================================================================

run_package_check() {
    local before=$GATE_FAILURES
    local pkg_dir="$RUN_TMP_DIR/package"
    mkdir -p "$pkg_dir"

    if ! helm package "$CHART_DIR" --destination "$pkg_dir" \
        >"$RUN_TMP_DIR/package.out" 2>"$RUN_TMP_DIR/package.err"; then
        fail "package: helm package $CHART_DIR FAILED: $(cat "$RUN_TMP_DIR/package.err")"
        _gate_delta_report "package" "$before" "$GATE_FAILURES"
        return
    fi

    local tgz
    tgz=$(command find "$pkg_dir" -maxdepth 1 -name '*.tgz' 2>/dev/null | command head -n1)
    if [ -z "$tgz" ]; then
        fail "package: helm package succeeded but no .tgz was found under $pkg_dir"
        _gate_delta_report "package" "$before" "$GATE_FAILURES"
        return
    fi

    local listing="$RUN_TMP_DIR/package-listing.txt"
    tar tzf "$tgz" >"$listing" 2>"$RUN_TMP_DIR/package-listing.err"

    assert_not_match "$listing" 'test\.sh' E
    assert_not_match "$listing" '/ci/' F
    assert_match "$listing" 'Chart.yaml' F
    assert_match "$listing" 'values.yaml' F
    assert_match "$listing" 'values-dev.yaml' F
    assert_match "$listing" 'README.md' F
    assert_match "$listing" 'templates/' F

    _gate_delta_report "package" "$before" "$GATE_FAILURES"
}

run_package_check

# ==============================================================================
# §53 -- documentation checks.
# ==============================================================================

run_docs_checks() {
    local before=$GATE_FAILURES
    local chart_readme="$CHART_DIR/README.md"
    local root_readme="$REPO_ROOT/README.md"
    local claude_md="$REPO_ROOT/CLAUDE.md"
    local footguns="$REPO_ROOT/skills/ship/references/repo-footguns.md"
    local s

    note "docs: the six stable security strings, required in BOTH READMEs"
    local security_strings=(
        'clear text'
        'LDAP simple-bind password'
        'ADR #16'
        'BorisTyshkevich'
        'internal-only'
        'NetworkPolicy is not transport confidentiality'
    )
    for s in "${security_strings[@]}"; do
        assert_match "$chart_readme" "$s" F
        assert_match "$root_readme" "$s" F
    done

    note "docs: chart-README-only tokens"
    local chart_only=(
        'ldap.listen'
        'user_base_dn'
        'group_base_dn'
        'user_rdn_attribute'
        '64 KiB'
        '256'
        '30 seconds'
        '512'
        'clusterDomain'
        'imagePullSecrets'
        'helm lint'
        'helm template'
        'immutable'
        'values-dev.yaml'
        'replicaCount: 1'
        'anti-affinity'
        'preStop'
        '/bin/sleep'
        'CNI-dependent'
        'networkPolicy.enabled=false'
    )
    for s in "${chart_only[@]}"; do
        assert_match "$chart_readme" "$s" F
    done

    note "docs: root-README tokens (both deployment models, both build pipelines, tag scheme, new layout paths)"
    local root_only=(
        'sidecar'
        'environment-level'
        'build-ch-jwt-verify.yml'
        'build-ch-oauth-ldap.yml'
        'ldap-<short-sha>'
        'helm/ch-oauth-ldap/'
        'Dockerfile.ch-oauth-ldap'
        'scripts/build-ch-oauth-ldap-image.sh'
        '.github/workflows/build-ch-oauth-ldap.yml'
    )
    for s in "${root_only[@]}"; do
        assert_match "$root_readme" "$s" F
    done

    note "docs: the old, inaccurate 'same tag always refers to the same manifest' promise must be gone (review Finding 2) -- publication now REFUSES tag re-use, but a rebuild of the same commit is not byte-reproducible"
    assert_not_match "$chart_readme" 'the same tag always refers to the same manifest' F
    assert_not_match "$root_readme" 'the same tag always refers to the same manifest' F

    note "docs: CLAUDE.md mentions of chart/image/gate/workflow"
    assert_match "$claude_md" 'helm/ch-oauth-ldap/' F
    assert_match "$claude_md" 'Dockerfile.ch-oauth-ldap' F
    assert_match "$claude_md" 'build-ch-oauth-ldap.yml' F
    assert_match "$claude_md" 'helm/ch-oauth-ldap/test.sh' F

    note "docs: repo-footguns.md (A6: skip-if-absent, never a hard dependency of this gate)"
    if [ -f "$footguns" ]; then
        assert_not_match "$footguns" 'only workflow' F
        assert_match "$footguns" 'build-ch-oauth-ldap.yml' F
    else
        skip "footguns doc not present, skipping"
    fi

    _gate_delta_report "docs" "$before" "$GATE_FAILURES"
}

run_docs_checks

# ==============================================================================
# §54 -- the standard Go gate, plus cross-compilation to the owned temp dir.
# ==============================================================================

run_go_gate() {
    local before=$GATE_FAILURES
    local log="$RUN_TMP_DIR/gate.log"

    note "go-gate: go build/vet/test, captured to $log"
    if ( cd "$REPO_ROOT" && go build ./... && go vet ./... && go test ./... ) >"$log" 2>&1; then
        pass "go-gate: go build/vet/test all succeeded"
    else
        fail "go-gate: go build/vet/test FAILED -- tail of $log follows"
        command tail -n 40 "$log" >&2
    fi

    local arch
    for arch in amd64 arm64; do
        mkdir -p "$RUN_TMP_DIR/xc/$arch"
        local xc_log="$RUN_TMP_DIR/xc-$arch.log"
        if ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -o "$RUN_TMP_DIR/xc/$arch/ch-oauth-ldap" ./cmd/ch-oauth-ldap ) \
            >"$xc_log" 2>&1; then
            pass "go-gate: cross-compile linux/$arch OK ($RUN_TMP_DIR/xc/$arch/ch-oauth-ldap)"
        else
            fail "go-gate: cross-compile linux/$arch FAILED -- $(command tail -n 20 "$xc_log")"
        fi
    done

    _gate_delta_report "go-gate" "$before" "$GATE_FAILURES"
}

run_go_gate

# ==============================================================================
# §55 -- existing chart smoke: prove this phase did not disturb the old
# ch-jwt-verify sidecar chart. Read-only; never modifies that chart.
# ==============================================================================

run_old_chart_smoke() {
    local before=$GATE_FAILURES
    local old_chart="$REPO_ROOT/helm/ch-jwt-verify"

    if helm lint "$old_chart" >"$RUN_TMP_DIR/old-chart-lint.out" 2>"$RUN_TMP_DIR/old-chart-lint.err"; then
        pass "old-chart: helm lint helm/ch-jwt-verify succeeded"
    else
        fail "old-chart: helm lint helm/ch-jwt-verify FAILED: $(cat "$RUN_TMP_DIR/old-chart-lint.err")"
    fi

    if helm template regression "$old_chart" >/dev/null 2>"$RUN_TMP_DIR/old-chart-template.err"; then
        pass "old-chart: helm template regression helm/ch-jwt-verify succeeded"
    else
        fail "old-chart: helm template regression helm/ch-jwt-verify FAILED: $(cat "$RUN_TMP_DIR/old-chart-template.err")"
    fi

    _gate_delta_report "old-chart" "$before" "$GATE_FAILURES"
}

run_old_chart_smoke

# ==============================================================================
# §56 -- base-ref-aware untouched-path proof.
#
# This gate's real invariant is narrower than "no Go changes": a
# ch-oauth-ldap change must never touch the ch-jwt-verify SIDECAR surface,
# since that sidecar is the only cryptographic gate on its auth path (see
# CLAUDE.md's "Sidecar trust model is load-bearing"). It previously also
# listed cmd/, internal/, third_party/, integration/, and .gitignore, which
# was correct only for the phase-4 PR that introduced this gate (a chart-only
# change with literally no Go diff) -- as a standing repository gate that set
# was wrong, since any real ch-oauth-ldap change legitimately touches those
# paths (e.g. cmd/ch-jwt-verify/verify_test.go, internal/securitytest,
# integration fixtures). Scoped down to just the sidecar's own files/dirs.
#
# cmd/ch-jwt-verify/ is included (production Go included, *_test.go files
# excluded via the ":(exclude)" pathspec below): the sidecar's PRODUCTION
# code must never move for a ch-oauth-ldap change, but its TESTS may -- e.g.
# phase 5 adds a shared redaction-proof matrix that legitimately touches
# cmd/ch-jwt-verify/verify_test.go. Both `git diff --stat` (committed
# history) and `git status --porcelain` (working tree) below are checked
# against this same pathspec set.
# ==============================================================================

UNTOUCHED_PATHS=(
    ".github/workflows/build-ch-jwt-verify.yml"
    "helm/ch-jwt-verify/"
    "Dockerfile"
    "scripts/build-image.sh"
    "examples/"
    "cmd/ch-jwt-verify/"
    ":(exclude)cmd/ch-jwt-verify/*_test.go"
)

run_untouched_path_proof() {
    local before=$GATE_FAILURES
    local base_ref="${BASE_REF:-origin/main}"

    note "untouched-paths: BASE_REF=$base_ref"

    if ( cd "$REPO_ROOT" && git rev-parse --verify "${base_ref}^{commit}" >/dev/null 2>&1 ); then
        # Diff against the real merge-base, not the base ref's tip: a
        # tip-vs-tip diff would report every change the base branch itself
        # received since this branch forked as if this branch had made it
        # (or, worse, would cancel a real change here out against an
        # opposite one there).
        local merge_base diff_out
        merge_base=$(cd "$REPO_ROOT" && git merge-base "$base_ref" HEAD 2>/dev/null)
        if [ -z "$merge_base" ]; then
            fail "untouched-paths: git merge-base $base_ref HEAD failed (unrelated histories or a shallow checkout?)"
        else
            note "untouched-paths: merge-base($base_ref, HEAD)=$merge_base"
            diff_out=$(cd "$REPO_ROOT" && git diff --stat "$merge_base" HEAD -- "${UNTOUCHED_PATHS[@]}")
            if [ -z "$diff_out" ]; then
                pass "untouched-paths: git diff --stat $merge_base..HEAD is empty over the committed ch-jwt-verify sidecar surface"
            else
                fail "untouched-paths: git diff --stat $merge_base..HEAD is NOT empty over the committed ch-jwt-verify sidecar surface: $diff_out"
            fi
        fi
    else
        skip "untouched-paths: BASE_REF '$base_ref' does not resolve to a commit in this checkout; committed sidecar-surface scope could not be proven from local history here (a shallow checkout must not be treated as a false implementation failure -- obtain the real base comparison before certification)"
    fi

    local status_out
    status_out=$(cd "$REPO_ROOT" && git status --porcelain -- "${UNTOUCHED_PATHS[@]}")
    if [ -z "$status_out" ]; then
        pass "untouched-paths: working tree has no staged/unstaged/untracked changes under the ch-jwt-verify sidecar surface"
    else
        fail "untouched-paths: working tree HAS changes under the ch-jwt-verify sidecar surface: $status_out"
    fi

    _gate_delta_report "untouched-paths" "$before" "$GATE_FAILURES"
}

run_untouched_path_proof

# ==============================================================================
# §50/§29 -- this script's OWN deterministic SIGINT regression, run against
# a real, unmodified copy of itself (never a special test mode), through the
# same common.sh harness (gate_sigint_regression) image-assertions.sh uses
# against scripts/build-ch-oauth-ldap-image.sh -- here with this script's
# own ch-oauth-ldap-chart-gate.* run-directory prefix.
# ==============================================================================

run_self_sigint_regression() {
    local before=$GATE_FAILURES

    local self_dir="$RUN_TMP_DIR/self"
    local self_script="$self_dir/test.sh"
    mkdir -p "$self_dir"
    cp "$SCRIPT_DIR/test.sh" "$self_script"
    chmod +x "$self_script"
    # A copy of ci/ travels alongside so a child that gets far enough to
    # source the assertion libraries can do so; in practice the SIGINT
    # lands during this child's own run-directory `mkdir`, strictly before
    # it ever reaches that sourcing step.
    if [ -d "$CHART_DIR/ci" ]; then
        cp -R "$CHART_DIR/ci" "$self_dir/ci"
    fi

    gate_sigint_regression "self-sigint" "$self_script" "ch-oauth-ldap-chart-gate." "$RUN_TMP_DIR/sigint-gate"

    _gate_delta_report "self-sigint" "$before" "$GATE_FAILURES"
}

run_self_sigint_regression

# ==============================================================================
# Final invariant + PASS/FAIL summary.
# ==============================================================================

if [ -e "$REPO_ROOT/ch-oauth-ldap" ]; then
    fail "repository root contains a 'ch-oauth-ldap' artifact after the gate ran ($REPO_ROOT/ch-oauth-ldap)"
else
    pass "repository root has no 'ch-oauth-ldap' artifact after the gate ran"
fi

echo "===================================================================="
if [ "$GATE_FAILURES" -eq 0 ]; then
    echo "GATE RESULT: PASS (0 failures)"
    _gate_exit=0
else
    echo "GATE RESULT: FAIL ($GATE_FAILURES failure(s))"
    _gate_exit=1
fi
echo "===================================================================="

exit "$_gate_exit"
