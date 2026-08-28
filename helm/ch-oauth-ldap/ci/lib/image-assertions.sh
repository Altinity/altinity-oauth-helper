#!/usr/bin/env bash
# helm/ch-oauth-ldap/ci/lib/image-assertions.sh
#
# Sourced-only assertion library for the ch-oauth-ldap image/build surface:
# Dockerfile.ch-oauth-ldap, scripts/build-ch-oauth-ldap-image.sh, and
# .github/workflows/build-ch-oauth-ldap.yml (plan sections 29, 48, 49, 51).
#
# THIS FILE IS A LIBRARY. It must be `source`d (after helm/ch-oauth-ldap/
# ci/lib/common.sh, whose pass/fail/note/skip/assert_* primitives and
# $GATE_FAILURES counter this file depends on), never executed directly.
#
# Contract this file provides:
#   run_image_assertions
#     Reads $REPO_ROOT, $CHART_DIR, $RUN_TMP_DIR (all required; the function
#     fails loudly if any is unset) and runs every static/live check listed
#     below against the REAL, UNMODIFIED build artifacts. It never edits
#     Dockerfile.ch-oauth-ldap, scripts/build-ch-oauth-ldap-image.sh, or
#     .github/workflows/build-ch-oauth-ldap.yml -- only common.sh's
#     pass/fail/note/skip report defects, via $GATE_FAILURES, back to the
#     caller. Returns 0 if every check passed (i.e. $GATE_FAILURES is
#     unchanged by this run), 1 otherwise.
#
#   Checks performed:
#     - Dockerfile.ch-oauth-ldap (plan section 48): pinned base image, CA
#       certificates, the /bin/sleep executable guard the preStop hook
#       depends on, OCI source metadata, non-root USER, EXPOSE 3389, the
#       LDAP entrypoint, the world-executable-mode guard on the copied
#       binary placed between `COPY` and `USER` (the image runs as UID
#       65532, not the root owner of the file), and UID/GID equality
#       between the Dockerfile's `USER` and the chart's rendered
#       `runAsUser`/`runAsGroup` (rendered from $CHART_DIR with
#       $CHART_DIR/ci/valid-values.yaml).
#     - scripts/build-ch-oauth-ldap-image.sh (plan sections 49, A2): `bash
#       -n` syntax, the $TMPDIR/$HOME/tmp contract, the
#       ch-oauth-ldap-image. run-directory prefix, trap-before-mkdir and
#       candidate-assigned-before-mkdir ordering, no `mktemp -d`, no
#       checkout-root binary output, the main.version stamp, the default
#       "ldap" tag prefix, amd64/arm64, a temporary (non-checkout-root)
#       Docker build context, the explicit `chmod 0755` of the compiled
#       binary ordered after `go build` and before `docker build` (the
#       script's own `umask 077` would otherwise leave it 0700), and the A2
#       per-arch `docker pull --platform` of the pinned base image ordered
#       before that arch's `docker build` plus the post-build `docker image
#       inspect ... .Architecture` equality check.
#     - the real script's deterministic SIGINT regression (plan section
#       29), via common.sh's gate_sigint_regression: the actual, unmodified
#       script -- never a special test mode -- interrupted during its
#       run-directory `mkdir` itself, strictly before any `go build`/`docker`
#       step runs, so the real script's docker/push path is never exercised.
#     - .github/workflows/build-ch-oauth-ldap.yml (plan sections 51, A7):
#       image path, `main`-only push plus workflow_dispatch with
#       tag_prefix reaching the shell only through `env:` (never inlined in
#       `run:`), no pull_request trigger, all seven path filters, the
#       main.version stamp, amd64/arm64, immutable-tag-only (no `:main` /
#       `:latest`), per-arch $RUNNER_TEMP/runner.temp context and Docker
#       build `context:` that is never checkout root, the binary chmod
#       0755, and cancel-in-progress concurrency.
#     - a final `test ! -e "$REPO_ROOT/ch-oauth-ldap"` proving none of the
#       above checks (nor anything else already on disk) left a compiled
#       LDAP binary in the repository root.
#
# This library performs no `docker build`/`docker push`/network image
# operation of its own; the only external command with real side effects
# it runs is `helm template` (read-only, into $RUN_TMP_DIR) for the UID/GID
# equality check, and the deterministic SIGINT regression against the real
# script (which is interrupted before its own docker/push path runs).

# --- sourced-only guard -----------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "image-assertions.sh: this file is a library; source it, do not execute it" >&2
    exit 1
fi

# --- paths (filled in by run_image_assertions, read by every _ia_ helper) --
_IA_DOCKERFILE=""
_IA_SCRIPT=""
_IA_WORKFLOW=""

# _ia_require_file LABEL PATH
# Returns 0 (and notes nothing) if PATH exists and is a regular file.
# Otherwise records a single `fail` for LABEL and returns 1, so callers can
# `_ia_require_file ... || return` out of a whole section in one line
# rather than growing an existence check into every individual assertion.
_ia_require_file() {
    local label="$1" path="$2"
    if [ -f "$path" ]; then
        return 0
    fi
    fail "$label: required file not found at $path"
    return 1
}

# =============================================================================
# Section 48 -- Dockerfile.ch-oauth-ldap
# =============================================================================

_ia_dockerfile_assertions() {
    local dockerfile="$_IA_DOCKERFILE"

    _ia_require_file "Dockerfile.ch-oauth-ldap" "$dockerfile" || return

    assert_match "$dockerfile" 'FROM alpine:3.24'
    assert_match "$dockerfile" 'ca-certificates'
    assert_match "$dockerfile" 'RUN test -x /bin/sleep'
    assert_match "$dockerfile" 'org.opencontainers.image.source'
    assert_match "$dockerfile" 'USER 65532:65532'
    assert_match "$dockerfile" 'EXPOSE 3389'
    assert_match "$dockerfile" 'ENTRYPOINT ["/bin/ch-oauth-ldap"]'

    _ia_dockerfile_binary_mode_guard "$dockerfile"
    _ia_uid_gid_equality "$dockerfile"
}

# _ia_dockerfile_binary_mode_guard DOCKERFILE
# The image runs as UID 65532 while COPY leaves the binary root-owned with
# the build context's mode, so a 0700 binary (what a `umask 077` build host
# produces) builds fine and fails to exec at container start. Require:
#   * the `COPY ch-oauth-ldap /bin/ch-oauth-ldap` line,
#   * a `RUN stat ... /bin/ch-oauth-ldap ... grep` mode guard on a LATER
#     line that requires the others-execute bit,
#   * `USER 65532:65532` on a line after BOTH (so the guard still runs as
#     root, where stat cannot be denied, and the drop happens last),
#   * the file-mode concern documented in a comment.
_ia_dockerfile_binary_mode_guard() {
    local dockerfile="$1"
    local copy_line guard_line user_line

    copy_line=$(command grep -nE '^COPY[[:space:]]+ch-oauth-ldap[[:space:]]+/bin/ch-oauth-ldap[[:space:]]*$' "$dockerfile" | command head -n1 | command cut -d: -f1)
    # Fixed-string match on the exact guard line (the regex it contains is
    # data here, not a pattern).
    guard_line=$(command grep -nF "RUN stat -c '%a' /bin/ch-oauth-ldap | grep -Eq '^[0-7]?[0-7][0-7][5-7]\$'" "$dockerfile" | command head -n1 | command cut -d: -f1)
    user_line=$(command grep -nE '^USER[[:space:]]+65532:65532[[:space:]]*$' "$dockerfile" | command head -n1 | command cut -d: -f1)

    if [ -z "$copy_line" ]; then
        fail "$dockerfile: no 'COPY ch-oauth-ldap /bin/ch-oauth-ldap' line found"
        return
    fi
    if [ -z "$guard_line" ]; then
        fail "$dockerfile: no 'RUN stat -c %a /bin/ch-oauth-ldap | grep -Eq <others-exec mode regex>' guard found after COPY"
        return
    fi
    if [ -z "$user_line" ]; then
        fail "$dockerfile: no 'USER 65532:65532' line found"
        return
    fi
    if [ "$copy_line" -lt "$guard_line" ] && [ "$guard_line" -lt "$user_line" ]; then
        pass "$dockerfile: COPY (line $copy_line) < binary mode guard (line $guard_line) < USER 65532:65532 (line $user_line)"
    else
        fail "$dockerfile: expected COPY (line $copy_line) < binary mode guard (line $guard_line) < USER 65532:65532 (line $user_line)"
    fi

    assert_match "$dockerfile" 'COPY preserves the context file'
    assert_match "$dockerfile" '0755'
    assert_match "$dockerfile" 'umask 077'
}

# _ia_uid_gid_equality DOCKERFILE
# Extracts the Dockerfile's `USER uid:gid` and compares it against the
# chart's rendered `runAsUser`/`runAsGroup` (rendered from $CHART_DIR with
# $CHART_DIR/ci/valid-values.yaml). helm and the chart are hard requirements
# of this gate, so their absence is a failure, never a skip.
_ia_uid_gid_equality() {
    local dockerfile="$1"
    local valid_values="$CHART_DIR/ci/valid-values.yaml"

    if ! command -v helm >/dev/null 2>&1; then
        fail "Dockerfile/chart UID-GID equality: helm not on PATH"
        return
    fi
    if [ ! -d "$CHART_DIR" ] || [ ! -f "$valid_values" ]; then
        fail "Dockerfile/chart UID-GID equality: chart or ci/valid-values.yaml not present at $CHART_DIR"
        return
    fi

    local rendered="$RUN_TMP_DIR/image-assertions.chart-render.yaml"
    local render_err="$RUN_TMP_DIR/image-assertions.chart-render.err"
    if ! helm template ia-uidgid-check "$CHART_DIR" -f "$valid_values" >"$rendered" 2>"$render_err"; then
        fail "Dockerfile/chart UID-GID equality: helm template failed ($(command head -n1 "$render_err" 2>/dev/null))"
        return
    fi

    local user_line dockerfile_uid dockerfile_gid
    user_line=$(command grep -E '^[[:space:]]*USER[[:space:]]+[0-9]+:[0-9]+[[:space:]]*$' "$dockerfile" | command tail -n1)
    if [ -z "$user_line" ]; then
        fail "Dockerfile/chart UID-GID equality: no 'USER uid:gid' line found in $dockerfile"
        return
    fi
    dockerfile_uid=$(printf '%s' "$user_line" | command grep -oE '[0-9]+:[0-9]+' | command cut -d: -f1)
    dockerfile_gid=$(printf '%s' "$user_line" | command grep -oE '[0-9]+:[0-9]+' | command cut -d: -f2)

    local chart_uid chart_gid
    chart_uid=$(command grep -m1 -E 'runAsUser:[[:space:]]*[0-9]+' "$rendered" | command grep -oE '[0-9]+')
    chart_gid=$(command grep -m1 -E 'runAsGroup:[[:space:]]*[0-9]+' "$rendered" | command grep -oE '[0-9]+')

    if [ -z "$chart_uid" ] || [ -z "$chart_gid" ]; then
        fail "Dockerfile/chart UID-GID equality: rendered chart has no runAsUser/runAsGroup"
        return
    fi

    assert_eq "$dockerfile_uid" "$chart_uid" "Dockerfile USER uid vs chart runAsUser"
    assert_eq "$dockerfile_gid" "$chart_gid" "Dockerfile USER gid vs chart runAsGroup"
}

# =============================================================================
# Section 49 (+ A2) -- scripts/build-ch-oauth-ldap-image.sh, static checks
# =============================================================================

_ia_script_static_assertions() {
    local script="$_IA_SCRIPT"

    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    local syntax_err="$RUN_TMP_DIR/image-assertions.script-syntax.err"
    if bash -n "$script" 2>"$syntax_err"; then
        pass "bash -n $script"
    else
        fail "bash -n $script failed: $(command head -n1 "$syntax_err" 2>/dev/null)"
    fi

    # $TMPDIR/$HOME/tmp contract (plan section 27) and the owned
    # run-directory prefix (plan section 27/28).
    assert_match "$script" 'TMPDIR="${TMPDIR:-$HOME/tmp}"'
    assert_match "$script" 'ch-oauth-ldap-image.'

    # No mktemp -d for the owned run directory (plan section 28).
    assert_not_match "$script" 'mktemp -d'

    # No repository-root build artifact: never `-o ch-oauth-ldap` as a
    # bare/root-relative build output (plan sections 24, 49). Checked as a
    # forbidden bare form rather than requiring one exact quoting of the
    # (variable-derived) owned output path, since the real script may -- and
    # does -- route the path through an intermediate per-arch context
    # variable rather than interpolating $RUN_TMP_DIR directly at the -o
    # flag.
    assert_not_match "$script" '-o ch-oauth-ldap'
    # Positive complement: some path derived from $RUN_TMP_DIR/ is actually
    # used as a build context/output root (plan section 24: "Per
    # architecture: $RUN_TMP_DIR/<arch>/ch-oauth-ldap").
    assert_match "$script" '$RUN_TMP_DIR/'

    # Version stamping (plan section 23).
    assert_match "$script" 'main.version='

    # Default "ldap" tag prefix (plan section 24).
    assert_match "$script" ':-ldap}'

    # Both architectures (plan section 24).
    assert_match "$script" 'amd64'
    assert_match "$script" 'arm64'

    _ia_script_trap_and_candidate_ordering "$script"
    _ia_script_no_bare_dot_context "$script"
    _ia_script_arch_parity "$script"
    _ia_script_binary_mode "$script"
}

# _ia_script_binary_mode SCRIPT
# The script runs under `umask 077` (its run directory must be private), so
# `go build` writes a 0700 binary; COPY preserves that mode and the image
# runs as UID 65532, which then cannot exec it. Require an explicit
# `chmod 0755 "$ctx/ch-oauth-ldap"` ordered strictly after the `go build`
# and before the arch's `docker build`, plus a 0644 on the copied
# Dockerfile.
_ia_script_binary_mode() {
    local script="$1"
    local build_line chmod_line docker_line

    # Commands only (line-anchored, optional leading whitespace and env
    # assignments) -- the script's header comments also mention `go build`
    # and `docker build` in prose.
    build_line=$(command grep -nE '^[[:space:]]*([A-Z_]+=[^[:space:]]*[[:space:]]+)*go build' "$script" | command head -n1 | command cut -d: -f1)
    chmod_line=$(command grep -nF 'chmod 0755 "$ctx/ch-oauth-ldap"' "$script" | command head -n1 | command cut -d: -f1)
    docker_line=$(command grep -nE '^[[:space:]]*([A-Z_]+=[^[:space:]]*[[:space:]]+)*docker[a-zA-Z]*[[:space:]]+(image[[:space:]]+)?build' "$script" | command head -n1 | command cut -d: -f1)

    if [ -z "$chmod_line" ]; then
        fail "$script: no 'chmod 0755 \"\$ctx/ch-oauth-ldap\"' found -- under umask 077 the binary would be 0700 and UID 65532 could not exec it"
        return
    fi
    if [ -z "$build_line" ] || [ -z "$docker_line" ]; then
        fail "$script: could not locate both 'go build' and 'docker build' to order the chmod against"
        return
    fi
    if [ "$build_line" -lt "$chmod_line" ] && [ "$chmod_line" -lt "$docker_line" ]; then
        pass "$script: go build (line $build_line) < chmod 0755 binary (line $chmod_line) < docker build (line $docker_line)"
    else
        fail "$script: expected go build (line $build_line) < chmod 0755 binary (line $chmod_line) < docker build (line $docker_line)"
    fi

    assert_match "$script" 'chmod 0644 "$ctx/Dockerfile"'
}

# _ia_script_trap_and_candidate_ordering SCRIPT
# Plan section 28/49: the EXIT trap must be installed, and the run-directory
# candidate path assigned into RUN_TMP_DIR, strictly before the first
# `mkdir -m 700` call that actually creates the owned run directory.
_ia_script_trap_and_candidate_ordering() {
    local script="$1"
    local trap_line mkdir_line

    trap_line=$(command grep -nE 'trap[[:space:]]+[^[:space:]]+[[:space:]]+.*EXIT' "$script" | command head -n1 | command cut -d: -f1)
    mkdir_line=$(command grep -nE 'mkdir[[:space:]]+-m[[:space:]]*700' "$script" | command head -n1 | command cut -d: -f1)

    if [ -z "$trap_line" ]; then
        fail "$script: no 'trap ... EXIT' line found"
    elif [ -z "$mkdir_line" ]; then
        fail "$script: no 'mkdir -m 700' line found"
    elif [ "$trap_line" -lt "$mkdir_line" ]; then
        pass "$script: trap ... EXIT (line $trap_line) precedes first mkdir -m 700 (line $mkdir_line)"
    else
        fail "$script: trap ... EXIT (line $trap_line) does not precede first mkdir -m 700 (line $mkdir_line)"
    fi

    if [ -z "$mkdir_line" ]; then
        return
    fi

    # Find every line that assigns RUN_TMP_DIR (excluding the initial
    # RUN_TMP_DIR="" / RUN_TMP_DIR='' declaration) before the mkdir line,
    # i.e. a real candidate path -- not just the empty initializer --
    # assigned to RUN_TMP_DIR before mkdir runs.
    local assign_lines ln content found=0
    assign_lines=$(command grep -nE '^[[:space:]]*RUN_TMP_DIR=' "$script" | command cut -d: -f1)
    for ln in $assign_lines; do
        if [ "$ln" -ge "$mkdir_line" ]; then
            continue
        fi
        content=$(command sed -n "${ln}p" "$script")
        case "$content" in
            *'RUN_TMP_DIR=""'* | *"RUN_TMP_DIR=''"*) ;;
            *) found=1 ;;
        esac
    done

    if [ "$found" -eq 1 ]; then
        pass "$script: RUN_TMP_DIR is assigned a real candidate path before mkdir -m 700 (line $mkdir_line)"
    else
        fail "$script: no RUN_TMP_DIR candidate assignment found before mkdir -m 700 (line $mkdir_line); only an empty initializer (or none) precedes it"
    fi
}

# _ia_script_no_bare_dot_context SCRIPT
# Plan sections 24, 49: `docker build`/`docker buildx build` must never run
# against a bare `.` context (i.e. the checkout root).
_ia_script_no_bare_dot_context() {
    local script="$1"
    local bad
    bad=$(command grep -nE 'docker[a-zA-Z]*[[:space:]]+(image[[:space:]]+)?build' "$script" | command grep -E '[[:space:]]\.[[:space:]]*$')
    if [ -n "$bad" ]; then
        fail "$script: docker build invoked against a bare '.' (checkout-root) context: $bad"
    else
        pass "$script: no docker build invocation uses a bare '.' context"
    fi
}

# _ia_script_arch_parity SCRIPT
# Plan amendment A2: a per-arch `docker pull --platform` of the pinned base
# image must run before that arch's `docker build`, and the post-build
# `docker image inspect ... .Architecture` equality check must be present.
# This is checked as ordering + presence rather than single-line text,
# since the real script pulls a pinned-base variable rather than the
# literal "alpine:3.24" string at the point of the `docker pull` call
# itself.
_ia_script_arch_parity() {
    local script="$1"
    local pull_line build_line inspect_line

    pull_line=$(command grep -nE 'docker pull --platform' "$script" | command head -n1 | command cut -d: -f1)
    build_line=$(command grep -nE 'docker[a-zA-Z]*[[:space:]]+(image[[:space:]]+)?build.*--platform' "$script" | command head -n1 | command cut -d: -f1)

    if [ -z "$pull_line" ]; then
        fail "$script: no per-arch 'docker pull --platform' found (A2 parity)"
    elif [ -z "$build_line" ]; then
        fail "$script: no per-arch 'docker build --platform' found to compare against the pull (A2 parity)"
    elif [ "$pull_line" -lt "$build_line" ]; then
        pass "$script: 'docker pull --platform' (line $pull_line) precedes 'docker build --platform' (line $build_line) -- avoids a stale cached wrong-arch base"
    else
        fail "$script: 'docker pull --platform' (line $pull_line) does not precede 'docker build --platform' (line $build_line)"
    fi

    assert_match "$script" 'alpine:3.24'
    assert_not_match "$script" 'alpine:latest'

    inspect_line=$(command grep -nE 'docker image inspect' "$script" | command head -n1 | command cut -d: -f1)
    if [ -z "$inspect_line" ]; then
        fail "$script: no 'docker image inspect' arch equality check found (A2 parity)"
    else
        assert_match "$script" '.Architecture'
        pass "$script: docker image inspect .Architecture equality check present (line $inspect_line)"
    fi
}

# =============================================================================
# Section 29 -- deterministic SIGINT regression against the real script
# =============================================================================

# _ia_script_sigint_regression SCRIPT
# See the file header and plan section 29. Delegates to common.sh's
# gate_sigint_regression (shared with test.sh's self-regression) against
# the real, unmodified script with its `ch-oauth-ldap-image.` run-directory
# prefix; the script is a hard requirement, so its absence fails.
_ia_script_sigint_regression() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return
    gate_sigint_regression "SIGINT regression" "$script" "ch-oauth-ldap-image." "$RUN_TMP_DIR/sigint-image"
}

# =============================================================================
# Section 51 (+ A7) -- .github/workflows/build-ch-oauth-ldap.yml
# =============================================================================

_ia_workflow_assertions() {
    local workflow="$_IA_WORKFLOW"

    _ia_require_file ".github/workflows/build-ch-oauth-ldap.yml" "$workflow" || return

    # Image path (plan section 21/25).
    assert_match "$workflow" 'altinity/ch-oauth-ldap'

    # main push plus workflow_dispatch with tag_prefix; no pull_request
    # (plan sections 25, A7).
    assert_match "$workflow" 'branches: [main]'
    assert_match "$workflow" 'workflow_dispatch'
    assert_match "$workflow" 'tag_prefix'
    assert_not_match "$workflow" 'pull_request'

    # The dispatch input reaches the shell only through `env:` -- exactly
    # one `${{ inputs.` reference in the whole file (the env mapping), and
    # never the inlined `prefix="${{ inputs.tag_prefix }}"` form -- and is
    # shape-checked before use.
    assert_count "$workflow" '${{ inputs.' 1 F
    assert_match "$workflow" 'TAG_PREFIX: ${{ inputs.tag_prefix }}'
    assert_not_match "$workflow" 'prefix="${{'
    assert_match "$workflow" '"$prefix" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,40}$'

    # The compiled binary is chmod 0755 before it enters the build context
    # (COPY preserves mode; the image runs as UID 65532).
    assert_match "$workflow" 'chmod 0755 "$RUNNER_TEMP/ch-oauth-ldap-${{ matrix.arch }}/ch-oauth-ldap"'

    # All seven path filters (plan section 25).
    assert_match "$workflow" 'cmd/ch-oauth-ldap/**'
    assert_match "$workflow" 'internal/**'
    assert_match "$workflow" 'third_party/**'
    assert_match "$workflow" 'go.mod'
    assert_match "$workflow" 'go.sum'
    assert_match "$workflow" 'Dockerfile.ch-oauth-ldap'
    assert_match "$workflow" '.github/workflows/build-ch-oauth-ldap.yml'

    # Version stamp, both architectures (plan sections 23, 25).
    assert_match "$workflow" 'main.version='
    assert_match "$workflow" 'amd64'
    assert_match "$workflow" 'arm64'

    # Immutable tag only -- no mutable main/latest alias (plan section 21).
    assert_not_match "$workflow" ':main'
    assert_not_match "$workflow" ':latest'

    # Per-arch $RUNNER_TEMP/runner.temp context; Docker context never
    # checkout root; go build -o points into runner temp (plan section 25).
    assert_match "$workflow" 'RUNNER_TEMP'
    assert_match "$workflow" 'runner.temp'
    assert_not_match "$workflow" 'context: .'
    assert_match "$workflow" '-o "$RUNNER_TEMP/'

    # Concurrency (plan amendment A7).
    assert_match "$workflow" 'cancel-in-progress: true'
}

# =============================================================================
# Entry point
# =============================================================================

# run_image_assertions
# See the file header. Requires $REPO_ROOT, $CHART_DIR, $RUN_TMP_DIR.
run_image_assertions() {
    : "${REPO_ROOT:?run_image_assertions: REPO_ROOT must be set}"
    : "${CHART_DIR:?run_image_assertions: CHART_DIR must be set}"
    : "${RUN_TMP_DIR:?run_image_assertions: RUN_TMP_DIR must be set}"

    if ! command -v pass >/dev/null 2>&1 || ! command -v fail >/dev/null 2>&1; then
        echo "run_image_assertions: helm/ch-oauth-ldap/ci/lib/common.sh must be sourced first" >&2
        return 1
    fi

    _IA_DOCKERFILE="$REPO_ROOT/Dockerfile.ch-oauth-ldap"
    _IA_SCRIPT="$REPO_ROOT/scripts/build-ch-oauth-ldap-image.sh"
    _IA_WORKFLOW="$REPO_ROOT/.github/workflows/build-ch-oauth-ldap.yml"

    note "run_image_assertions: Dockerfile=$_IA_DOCKERFILE script=$_IA_SCRIPT workflow=$_IA_WORKFLOW"

    local before="${GATE_FAILURES:-0}"

    _ia_dockerfile_assertions
    _ia_script_static_assertions
    _ia_script_sigint_regression "$_IA_SCRIPT"
    _ia_workflow_assertions

    if [ -e "$REPO_ROOT/ch-oauth-ldap" ]; then
        fail "repository root contains a 'ch-oauth-ldap' artifact after image/build assertions ran ($REPO_ROOT/ch-oauth-ldap)"
    else
        pass "no 'ch-oauth-ldap' artifact in repository root after image/build assertions ran"
    fi

    local after="${GATE_FAILURES:-0}"
    if [ "$after" -eq "$before" ]; then
        pass "run_image_assertions: all checks passed"
        return 0
    fi
    note "run_image_assertions: $((after - before)) failure(s) recorded"
    return 1
}
