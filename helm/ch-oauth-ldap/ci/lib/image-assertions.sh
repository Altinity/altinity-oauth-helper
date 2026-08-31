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
#       65532, not the root owner of the file), a BEHAVIORAL check that the
#       guard's own regex actually requires the others-execute bit (extracts
#       the real regex from the Dockerfile and runs it, via `grep -Eq`,
#       against sample modes including 0756 -- others=rw-, no execute --
#       which an earlier `[5-7]` final digit wrongly accepted), and UID/GID
#       equality between the Dockerfile's `USER` and the chart's rendered
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
#       REPO is pointed at a throwaway clean git repo for this one (never
#       the real checkout, whose tree is routinely dirty exactly when a
#       developer runs this gate), so the dirty-tree guard below never
#       intercepts it before the mkdir this regression targets.
#     - the real script's dirty-working-tree regression: the actual,
#       unmodified script, pointed (via REPO=) at three throwaway git
#       repos -- clean, a tracked-but-uncommitted change, and an untracked
#       file -- proving canonical publication is refused in the latter two
#       cases BEFORE any go build/docker step, and that a clean tree is not
#       wrongly refused by the guard itself.
#     - the real script's dirty-working-tree guard BYPASS (review Finding
#       1): a throwaway repo proving the `--untracked-files=all` status
#       pre-check still refuses a `status.showUntrackedFiles=no`-hidden
#       untracked .go file, which a bare `git status --porcelain` (the
#       pre-fix check) let through silently. A SECOND throwaway repo proves
#       the deliberate NON-bypass added in review pass 3: a .gitignore'd .go
#       file is no longer refused (the pre-pass-3 `--ignored=matching` flag
#       is gone), because `git archive HEAD` -- the actual build input --
#       can never see a gitignored file regardless of what `git status`
#       reports, so refusing on it was a false positive with no correctness
#       payoff, not a bypass to close.
#     - a HEAD-export BEHAVIORAL proof (review Finding 1's actual fix): the
#       real, unmodified script run against a throwaway repo whose tracked
#       .go file is tampered under `git update-index --assume-unchanged`
#       (invisible to every `git status` flag combination, so the guard
#       above cannot catch it), with a PATH-stubbed `docker` (records args,
#       satisfies every preflight, exits 0) and a PATH-stubbed `go` that
#       never compiles -- it records whether the tampered/HEAD marker
#       strings are present under its own build cwd. Proves the compile
#       input is `git archive HEAD`'s export, not the working tree: the
#       tampered marker must be absent and the committed HEAD marker
#       present.
#     - a REALISTIC RE-EXEC BEHAVIORAL proof (fix for the self re-exec's own
#       REPO-recomputation bug): the real, unmodified script run from a
#       throwaway checkout's own root, invoked as `bash
#       scripts/build-ch-oauth-ldap-image.sh` with NO `REPO` set in the
#       environment -- the realistic invocation shape, unlike every other
#       test above which sets `REPO=` explicitly and so cannot see this bug
#       -- across three scenarios (tag-already-published refusal, a full
#       stubbed-docker success, and a stubbed `docker pull` failure
#       mid-build). Proves REPO survives the self re-exec (the run reaches
#       real `docker` calls rather than failing the Dockerfile precheck
#       against a `$TMPDIR/..`-derived wrong REPO) and that the self
#       re-exec's own temp copy is removed under every one of those exit
#       paths, never left behind under $TMPDIR.
#     - a SELF-TAMPER BEHAVIORAL proof (review pass 3 Finding 2): the exact
#       same threat, applied to the script's OWN on-disk bytes rather than a
#       .go file -- a throwaway repo commits the REAL script content
#       (copied from $_IA_SCRIPT, never a hand-duplicated copy that could
#       drift), then the on-disk copy is tampered under `--assume-unchanged`
#       to neutralize the tag-republish guard's `exit 1`. Runs the real,
#       tampered-on-disk script (a PATH-stubbed `docker manifest inspect`
#       reports the tag as already existing) and proves the run still
#       refuses -- proving the guard that actually ran was the committed
#       HEAD copy (via the self re-exec), not the neutralized on-disk one.
#     - static proof (review Finding 1) that `git archive --format=tar
#       HEAD` precedes `go build`, and that the compile/Dockerfile-copy
#       paths read from that export ($SRC_DIR), never from $REPO.
#     - static proof (review Finding 2) that the manual script's `docker
#       manifest inspect` tag-existence check precedes its first `docker
#       push`, with no force-override knob.
#     - a TAG-IMMUTABILITY FAIL-CLOSED behavioral proof (review pass 4): the
#       real, unmodified script run against a throwaway repo with a
#       PATH-stubbed `docker manifest inspect` that exits nonzero with a
#       generic (non-"not found") error, reproducing the review's own
#       rc=2 case -- proves the run aborts via the new fail-closed refusal,
#       distinctly from the ordinary "tag already exists" refusal, and
#       never reaches a single `docker pull`/`build`/`push` call.
#     - static proof (review pass 4) that a `check_tag_absent` recheck of
#       each tag runs a SECOND time, immediately before the mutating call
#       that actually publishes it (`docker push` per arch, `docker
#       manifest create` for the shared final tag) -- not just once, in the
#       batch check before any build/push work.
#     - an ENV-MARKER INJECTION behavioral proof (review pass 4, Finding 2):
#       (a) a caller-supplied `_CH_OAUTH_LDAP_IMAGE_SELF_COPY` pointing at an
#       unrelated file is never deleted by the cleanup trap, proven on an
#       early exit that predates the point the self re-exec section would
#       legitimately reassign that variable; (b) a caller-forged
#       `_CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED=1` does not skip the self
#       re-exec from HEAD -- proven against a throwaway repo whose on-disk
#       script is tampered with a PLAIN (non-`--assume-unchanged`) edit
#       neutralizing both the dirty-tree and tag-republish guards, where
#       the genuine (HEAD) guard still correctly refuses.
#     - .github/workflows/build-ch-oauth-ldap.yml (plan sections 51, A7):
#       image path, `main`-only push plus workflow_dispatch with
#       tag_prefix reaching the shell only through `env:` (never inlined in
#       `run:`), no pull_request trigger, all six path filters, the
#       main.version stamp, amd64/arm64, immutable-tag-only (no `:main` /
#       `:latest`), per-arch $RUNNER_TEMP/runner.temp context and Docker
#       build `context:` that is never checkout root, the binary chmod
#       0755, cancel-in-progress concurrency, (review Finding 2) that its
#       `docker buildx imagetools inspect` tag-existence check precedes the
#       build-push action with no force-override input, and (review pass 4)
#       that both the per-arch guard and the manifest job's own final
#       recheck (immediately before `docker buildx imagetools create`) use
#       the same fail-closed "not found" disambiguation as the manual
#       script's check_tag_absent, rather than a bare nonzero-exit check.
#     - a BEHAVIORAL proof that both guard steps are errexit-safe (the
#       confirmed defect: GitHub-hosted runners execute `run:` blocks with
#       `bash --noprofile --norc -eo pipefail`, so a bare `OUT=$(...);
#       RC=$?` capture dies at the assignment under `-e` for the normal
#       first-publication case -- a genuinely absent tag -- before `RC=$?`
#       or the not-found classifier ever runs, blocking every first
#       publication). Extracts each guard step's literal `run:` body from
#       the real workflow YAML with a generated gopkg.in/yaml.v3 Go
#       verifier (run with cwd=$REPO_ROOT, exactly like
#       embedded-assertions.sh's verifier) and executes it under that exact
#       invocation shape, with a PATH-stubbed `docker` and the step's real
#       `env:` variables set, across three scenarios: tag absent (must
#       proceed, exit 0), tag present (must refuse with "already exists"),
#       and an ambiguous inspect failure (must refuse with "could not
#       determine"). Also a STATIC assertion that no `run:` body in the
#       whole workflow contains the exact anti-pattern (an `UPPER_VAR=$(`
#       assignment immediately followed by a `$?` read on the next line).
#     - actionlint validity gate (added after a literal `${{ }}` inside a
#       `run:` bash comment made build-ch-oauth-ldap.yml an invalid workflow
#       file on main -- GitHub Actions evaluates `${{ ... }}` expressions
#       anywhere inside a `run:` string, comments included, before bash ever
#       runs, and an empty expression is a parse error): runs the pinned
#       actionlint (ensure_actionlint in common.sh; fails closed, no silent
#       skip, if it cannot be resolved) with `-no-color` against
#       build-ch-oauth-ldap.yml and requires exit 0 with empty output; runs
#       it AGAIN, informationally only, against build-ch-jwt-verify.yml
#       (out of this scope -- never fails the gate on that file's findings,
#       only notes them); and a NEGATIVE case that copies the real
#       (already-valid) workflow, injects a literal `${{ }}` into a `run:`
#       comment, and asserts actionlint FAILS on the copy -- proving this
#       check actually inspects expressions inside comments rather than
#       trivially passing everything.
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
_IA_WORKFLOW_JWT=""

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
    _ia_dockerfile_binary_mode_regex_behavior "$dockerfile"
    _ia_uid_gid_equality "$dockerfile"
}

# _ia_dockerfile_binary_mode_regex_behavior DOCKERFILE
# The guard's own regex, not just its presence, must actually require the
# others-execute bit: an earlier `[5-7]` final digit wrongly accepted mode
# 6 (`rw-`, no execute) alongside 5 (`r-x`) and 7 (`rwx`). Extract the exact
# regex the Dockerfile's `RUN stat ... | grep -Eq '...'` line applies (never
# a hand-copied duplicate, which could silently drift out of sync with the
# real guard) and run it, via the real `grep -Eq`, against sample modes.
_ia_dockerfile_binary_mode_regex_behavior() {
    local dockerfile="$1"
    local guard_regex

    guard_regex=$(command grep -F 'grep -Eq' "$dockerfile" | command head -n1 | command sed -E "s/.*grep -Eq '([^']*)'.*/\1/")
    if [ -z "$guard_regex" ]; then
        fail "$dockerfile: could not extract the binary-mode guard's grep -Eq regex for behavioral testing"
        return
    fi

    # mode:expect pairs. 0756 is the exact regression this guards: others=6
    # (rw-) has no execute bit, but the pre-fix `[5-7]` final digit matched
    # 5, 6, AND 7, wrongly accepting it.
    local cases=("0700:reject" "0755:accept" "0757:accept" "0756:reject" "0754:reject")
    local c mode want got
    for c in "${cases[@]}"; do
        mode="${c%%:*}"
        want="${c##*:}"
        if printf '%s\n' "$mode" | command grep -Eq "$guard_regex"; then
            got=accept
        else
            got=reject
        fi
        if [ "$got" = "$want" ]; then
            pass "$dockerfile: binary-mode guard regex correctly ${want}s mode $mode"
        else
            fail "$dockerfile: binary-mode guard regex ${got}ed mode $mode, expected to $want it (regex: $guard_regex)"
        fi
    done
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
    guard_line=$(command grep -nF "RUN stat -c '%a' /bin/ch-oauth-ldap | grep -Eq '^[0-7]?[0-7][0-7][57]\$'" "$dockerfile" | command head -n1 | command cut -d: -f1)
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
    _ia_script_dirty_tree_guard_static "$script"
    _ia_script_head_export_static "$script"
    _ia_script_tag_republish_static "$script"
    _ia_script_tag_immutability_recheck_static "$script"
}

# _ia_script_head_export_static SCRIPT
# Static proof of the review's Finding 1 fix: `git archive --format=tar
# HEAD` (exporting exactly the HEAD commit's tree into the script's own
# temp dir) must run strictly before the compile step, and the compile /
# Dockerfile-copy paths must read from that export, never from $REPO's
# working tree. A bare `git status --porcelain` check -- even the
# strengthened form checked by _ia_script_dirty_tree_guard_static -- cannot
# see a tracked file hidden by `--assume-unchanged`/`--skip-worktree`; the
# archive export is what actually makes the compile input immune to that
# (proven behaviorally by _ia_script_head_export_behavioral below).
_ia_script_head_export_static() {
    local script="$1"
    local archive_line build_line

    assert_match "$script" 'git archive --format=tar HEAD' F
    assert_match "$script" 'SRC_DIR='
    assert_match "$script" 'cp "$SRC_DIR/Dockerfile.ch-oauth-ldap"' F
    assert_not_match "$script" 'cp "$REPO/Dockerfile.ch-oauth-ldap"' F

    archive_line=$(command grep -nF 'git archive --format=tar HEAD' "$script" | command head -n1 | command cut -d: -f1)
    # Anchored to an actual command line (optional leading whitespace/env
    # assignments), matching _ia_script_binary_mode's convention -- never
    # the header prose, which also says "go build" in passing.
    build_line=$(command grep -nE '^[[:space:]]*([A-Z_]+=[^[:space:]]*[[:space:]]+)*go build' "$script" | command head -n1 | command cut -d: -f1)

    if [ -z "$archive_line" ] || [ -z "$build_line" ]; then
        fail "$script: could not locate both 'git archive --format=tar HEAD' and 'go build' to order them"
        return
    fi
    if [ "$archive_line" -lt "$build_line" ]; then
        pass "$script: git archive --format=tar HEAD (line $archive_line) precedes go build (line $build_line)"
    else
        fail "$script: expected git archive --format=tar HEAD (line $archive_line) to precede go build (line $build_line)"
    fi

    # The go build invocation itself must run scoped to $SRC_DIR (never
    # $REPO), so the exported tree -- not the working tree -- is what
    # actually gets compiled.
    assert_match "$script" 'cd "$SRC_DIR" &&' F
}

# _ia_script_tag_republish_static SCRIPT
# Static proof of the review's Finding 2 fix in the manual script: the
# `docker manifest inspect` existence check must run before the first
# `docker push`, checked before any build/push work, with no force-override
# knob.
_ia_script_tag_republish_static() {
    local script="$1"
    local inspect_line push_line

    assert_match "$script" 'docker manifest inspect' F

    inspect_line=$(command grep -nF 'docker manifest inspect' "$script" | command head -n1 | command cut -d: -f1)
    push_line=$(command grep -nE '^[[:space:]]*docker push' "$script" | command head -n1 | command cut -d: -f1)

    if [ -z "$inspect_line" ] || [ -z "$push_line" ]; then
        fail "$script: could not locate both 'docker manifest inspect' and 'docker push' to order them"
        return
    fi
    if [ "$inspect_line" -lt "$push_line" ]; then
        pass "$script: docker manifest inspect existence check (line $inspect_line) precedes the first docker push (line $push_line)"
    else
        fail "$script: expected the docker manifest inspect existence check (line $inspect_line) to precede the first docker push (line $push_line)"
    fi

    assert_not_match "$script" 'FORCE' F
}

# _ia_script_tag_immutability_recheck_static SCRIPT
# Static proof of review pass 4's non-atomicity fix: the batch
# check_tag_absent loop at the top of the script (before any build/push
# work) is not the only place the tag is checked -- a second recheck of the
# SAME tag must run immediately before each point that actually mutates the
# registry (the per-arch `docker push`, and `docker manifest create` for
# the shared final tag), narrowing the window a concurrent publisher could
# slip through while this run's own per-arch builds (which can each take a
# while) are in flight.
_ia_script_tag_immutability_recheck_static() {
    local script="$1"
    local push_line create_line recheck_arch_line recheck_final_line

    assert_match "$script" 'check_tag_absent()' F

    # Fails open with a fixed count of 2 rather than "at least 2": the batch
    # check and the mutation-site recheck are the only two legitimate call
    # sites for each tag form -- a third occurrence would mean either a
    # dangling leftover from a previous edit or a check that stopped being
    # where this test expects it.
    assert_count "$script" 'check_tag_absent "${FULL}:${TAG}-${arch}"' 2 F
    assert_count "$script" 'check_tag_absent "${FULL}:${TAG}"' 2 F

    push_line=$(command grep -nF 'docker push "${FULL}:${TAG}-${arch}"' "$script" | command tail -n1 | command cut -d: -f1)
    recheck_arch_line=$(command grep -nF 'check_tag_absent "${FULL}:${TAG}-${arch}"' "$script" | command tail -n1 | command cut -d: -f1)
    if [ -z "$push_line" ] || [ -z "$recheck_arch_line" ]; then
        fail "$script: could not locate both the per-arch docker push and a check_tag_absent recheck to order them"
    elif [ "$recheck_arch_line" -lt "$push_line" ]; then
        pass "$script: a check_tag_absent recheck (line $recheck_arch_line) immediately precedes the per-arch docker push (line $push_line)"
    else
        fail "$script: expected a check_tag_absent recheck to precede the per-arch docker push (line $push_line) -- found the closest check_tag_absent call for this tag form at line $recheck_arch_line"
    fi

    create_line=$(command grep -nF 'docker manifest create "${FULL}:${TAG}"' "$script" | command tail -n1 | command cut -d: -f1)
    recheck_final_line=$(command grep -nF 'check_tag_absent "${FULL}:${TAG}"' "$script" | command tail -n1 | command cut -d: -f1)
    if [ -z "$create_line" ] || [ -z "$recheck_final_line" ]; then
        fail "$script: could not locate both 'docker manifest create' and a check_tag_absent recheck to order them"
    elif [ "$recheck_final_line" -lt "$create_line" ]; then
        pass "$script: a check_tag_absent recheck (line $recheck_final_line) immediately precedes docker manifest create (line $create_line)"
    else
        fail "$script: expected a check_tag_absent recheck to precede docker manifest create (line $create_line) -- found the closest check_tag_absent call for this tag form at line $recheck_final_line"
    fi
}

# _ia_script_dirty_tree_guard_static SCRIPT
# Static complement to _ia_script_dirty_tree_guard's behavioral regression:
# the refusal must be wired in ahead of `git rev-parse --short=7 HEAD`, so a
# dirty tree is caught before SHA/TAG (and everything derived from them) is
# even computed. Also statically proves the review pass 3 fix: the actual
# `git status` invocation must not pass the gitignored-path flag, since git
# archive HEAD (the actual build input) can never see a gitignored file
# regardless of what git status reports about it -- flagging one is a
# false-positive cost with no correctness payoff, confirmed behaviorally by
# _ia_script_dirty_tree_guard_bypasses below.
#
# The invocation itself is located by its unique
# `DIRTY_STATUS="$(git status --porcelain` anchor, never the bare substring
# `git status --porcelain` -- the header comment above ALSO contains that
# bare substring (in prose, describing the very check below), so a bare
# substring search would silently pick up the comment instead of the real
# invocation, and the flag-absence check would then be proving nothing.
_ia_script_dirty_tree_guard_static() {
    local script="$1"
    local porcelain_line rev_parse_line invocation

    assert_match "$script" 'git status --porcelain'

    porcelain_line=$(command grep -nF 'DIRTY_STATUS="$(git status --porcelain' "$script" | command head -n1 | command cut -d: -f1)
    rev_parse_line=$(command grep -nE 'git rev-parse --short=7 HEAD' "$script" | command head -n1 | command cut -d: -f1)

    if [ -n "$porcelain_line" ]; then
        invocation=$(command sed -n "${porcelain_line}p" "$script")
        case "$invocation" in
            *'--ignored=matching'*)
                fail "$script: line $porcelain_line still passes --ignored=matching to git status -- review pass 3 dropped this flag because git archive HEAD (the actual build input) can never see a gitignored file regardless of what git status reports"
                ;;
            *)
                pass "$script: the dirty-tree guard's git status invocation (line $porcelain_line) does not pass --ignored=matching"
                ;;
        esac
    fi

    if [ -z "$porcelain_line" ] || [ -z "$rev_parse_line" ]; then
        fail "$script: could not locate both the dirty-tree check and 'git rev-parse --short=7 HEAD' to order them"
        return
    fi
    if [ "$porcelain_line" -lt "$rev_parse_line" ]; then
        pass "$script: dirty-tree check (line $porcelain_line) precedes SHA computation (line $rev_parse_line)"
    else
        fail "$script: expected the dirty-tree check (line $porcelain_line) to precede SHA computation (line $rev_parse_line)"
    fi
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

    # The dirty-tree guard added below (_ia_script_dirty_tree_guard) makes
    # the real script refuse to proceed past `git status --porcelain`,
    # strictly before the run-directory `mkdir` this regression targets --
    # so REPO must point at a clean, disposable git repo rather than the
    # real checkout, whose working tree is routinely dirty precisely when a
    # developer is running this gate (mid-edit, before committing). This
    # regression is only about the mkdir/SIGINT/cleanup sequence and needs
    # nothing from the real checkout beyond the one placeholder file the
    # script requires to exist up front; the guard's own early-exit
    # behavior is exercised separately by _ia_script_dirty_tree_guard.
    if ! command -v git >/dev/null 2>&1; then
        fail "SIGINT regression: git not on PATH (needed for the clean throwaway REPO)"
        return
    fi
    local sigint_repo="$RUN_TMP_DIR/sigint-image-repo"
    _ia_dtg_new_repo "$sigint_repo"

    # This throwaway repo's HEAD has no tag published against it, so the
    # tag-existence check reaches a real `docker manifest inspect` against
    # the script's default ghcr.io/altinity/ch-oauth-ldap -- a live,
    # unauthenticated network call. Review pass 4 made that check fail
    # closed on anything that isn't an unambiguous "not found" response,
    # and ghcr.io itself answers "denied" (ambiguous) rather than
    # not-found for an unauthenticated inspect of a genuinely absent tag,
    # so without a stub the script would now abort at that check --
    # before ever reaching the run-directory `mkdir` this regression
    # targets. Stub `docker` with the same deterministic "not found"
    # answer used elsewhere in this file, so this regression stays about
    # the mkdir/SIGINT/cleanup sequence, not registry/network state.
    local sigint_stub="$RUN_TMP_DIR/sigint-image-stub"
    command mkdir -p "$sigint_stub"
    cat >"$sigint_stub/docker" <<'DOCKER_STUB'
#!/bin/bash
if [ "$1" = "manifest" ] && [ "$2" = "inspect" ]; then
    echo "no such manifest: stubbed" >&2
    exit 1
fi
exit 0
DOCKER_STUB
    command chmod +x "$sigint_stub/docker"

    REPO="$sigint_repo" PATH="$sigint_stub:$PATH" gate_sigint_regression "SIGINT regression" "$script" "ch-oauth-ldap-image." "$RUN_TMP_DIR/sigint-image"
}

# _ia_dtg_new_repo DIR
# Helper for _ia_script_dirty_tree_guard: a minimal, standalone git repo
# (never the real checkout) containing only the one file the real script
# requires to exist before it will `cd` into REPO and reach the guard.
_ia_dtg_new_repo() {
    local dir="$1"
    command mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" config user.email gate@example.invalid
    git -C "$dir" config user.name gate
    printf 'FROM scratch\n' >"$dir/Dockerfile.ch-oauth-ldap"
    git -C "$dir" add -A
    git -C "$dir" commit -q -m init
}

# _ia_script_dirty_tree_guard SCRIPT
# Runs the REAL, unmodified script (never a special test mode) against
# three throwaway git repos, proving the review finding's fix: a modified
# tracked file, or an untracked file, must be refused BEFORE any
# go build/docker step -- and a genuinely clean tree must not be refused by
# the guard itself. REPO is pointed at each throwaway repo, never the real
# checkout; ARCHES is left at its default (amd64 arm64) rather than "" (bash
# parameter expansion's `:-` treats an empty override the same as unset), so
# the clean-tree case is left to fail the FIRST `go build` for an unrelated
# reason (no cmd/ch-oauth-ldap package in the throwaway repo, no go.mod) --
# fast, and needs no network or Docker. The assertion for that case is
# therefore scoped to "the guard's own refusal text is absent", not "the
# script exited 0"; only the tracked/untracked cases require exit-nonzero.
_ia_script_dirty_tree_guard() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    if ! command -v git >/dev/null 2>&1; then
        fail "dirty-tree guard: git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/dirty-tree-guard"
    local refusal_marker="refusing to publish"
    command mkdir -p "$base/tmp" "$base/stub"

    local clean_dir="$base/clean" tracked_dir="$base/tracked" untracked_dir="$base/untracked"
    _ia_dtg_new_repo "$clean_dir"
    _ia_dtg_new_repo "$tracked_dir"
    _ia_dtg_new_repo "$untracked_dir"

    # tracked-dirty: modify the already-committed file without committing.
    printf 'FROM scratch\n# dirty\n' >"$tracked_dir/Dockerfile.ch-oauth-ldap"
    # untracked-dirty: add a brand-new file, never `git add`ed.
    printf 'stray\n' >"$untracked_dir/stray.txt"

    # The clean-tree case (only) survives the dirty-tree guard and reaches
    # the real script's tag-existence check, which -- since REPO/IMAGE are
    # left at their real ghcr.io/altinity/ch-oauth-ldap default here -- would
    # otherwise be a live, unauthenticated network call. Review pass 4 made
    # that check fail closed on anything that isn't an unambiguous "not
    # found" response, and an unauthenticated `docker manifest inspect`
    # against ghcr.io answers "denied" even for a genuinely absent tag, so
    # this scenario would flip from "fails later at go build" (the
    # documented expectation below) to "refused by the tag-existence check"
    # for a reason that has nothing to do with the dirty-tree guard under
    # test. Stub `docker` to give the same deterministic "not found" answer
    # the rest of this file's behavioral tests use, so this check never
    # depends on network reachability or registry auth state.
    cat >"$base/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
if [ "$1" = "manifest" ] && [ "$2" = "inspect" ]; then
    echo "no such manifest: stubbed" >&2
    exit 1
fi
exit 0
DOCKER_STUB
    command chmod +x "$base/stub/docker"

    local status

    REPO="$clean_dir" TMPDIR="$base/tmp" PATH="$base/stub:$PATH" bash "$script" \
        >"$base/clean.out" 2>"$base/clean.err"
    status=$?
    if command grep -qF "$refusal_marker" "$base/clean.err"; then
        fail "dirty-tree guard: clean tree in $clean_dir was refused by the dirty-tree guard (exit $status): $(command head -n3 "$base/clean.err")"
    else
        pass "dirty-tree guard: clean tree in $clean_dir is not refused by the dirty-tree guard (exit $status came from something else, e.g. no cmd/ch-oauth-ldap package to build -- expected in this throwaway repo)"
    fi

    REPO="$tracked_dir" TMPDIR="$base/tmp" bash "$script" \
        >"$base/tracked.out" 2>"$base/tracked.err"
    status=$?
    if [ "$status" -ne 0 ] && command grep -qF "$refusal_marker" "$base/tracked.err"; then
        pass "dirty-tree guard: tracked-but-uncommitted change in $tracked_dir is refused (exit $status)"
    else
        fail "dirty-tree guard: tracked-but-uncommitted change in $tracked_dir was NOT refused as expected (exit $status) -- a modified tracked source file could be baked into a tag silently: $(command head -n3 "$base/tracked.err")"
    fi

    REPO="$untracked_dir" TMPDIR="$base/tmp" bash "$script" \
        >"$base/untracked.out" 2>"$base/untracked.err"
    status=$?
    if [ "$status" -ne 0 ] && command grep -qF "$refusal_marker" "$base/untracked.err"; then
        pass "dirty-tree guard: untracked file in $untracked_dir is refused (exit $status)"
    else
        fail "dirty-tree guard: untracked file in $untracked_dir was NOT refused as expected (exit $status) -- an added untracked source file could be baked into a tag silently: $(command head -n3 "$base/untracked.err")"
    fi
}

# _ia_script_dirty_tree_guard_bypasses SCRIPT
# Extends _ia_script_dirty_tree_guard with two specific scenarios a bare
# `git status --porcelain` (the pre-Finding-1 check) could not tell apart:
#   1. `git config status.showUntrackedFiles no` hides an untracked .go
#      file from a bare `git status --porcelain` entirely -- this remains a
#      real bypass and `--untracked-files=all` must still refuse it.
#   2. A .gitignore'd .go file is never reported by `git status --porcelain`
#      regardless of flags. Review pass 1 treated this as a bypass to close
#      (via `--ignored=matching`); review pass 3 corrected that: since `git
#      archive HEAD` (not the working tree) is the actual build input, a
#      gitignored file can never reach the build no matter what `git
#      status` reports about it, so refusing on it is a false positive with
#      zero correctness payoff, not a bypass. This case now proves the
#      OPPOSITE of what it proved before pass 3: the guard must NOT refuse.
# The remaining bypass no `git status` invocation can ever see
# (`--assume-unchanged`/`--skip-worktree`) is proven separately,
# behaviorally, against the archive export, by
# _ia_script_head_export_behavioral below (and, for this script's own
# bytes, by _ia_script_self_tamper_behavioral).
_ia_script_dirty_tree_guard_bypasses() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    if ! command -v git >/dev/null 2>&1; then
        fail "dirty-tree guard bypasses: git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/dirty-tree-guard-bypasses"
    local refusal_marker="refusing to publish"
    command mkdir -p "$base/tmp" "$base/stub"

    # Case 2 below is a clean-tree-per-guard scenario (same shape as
    # _ia_script_dirty_tree_guard's "clean" case) that reaches the real
    # script's tag-existence check with REGISTRY/IMAGE left at their real
    # ghcr.io/altinity/ch-oauth-ldap default -- stub `docker` so that check
    # never depends on live network reachability or registry auth state
    # (see the matching comment in _ia_script_dirty_tree_guard for why this
    # matters now that check_tag_absent, added in review pass 4, fails
    # closed on anything but an unambiguous "not found" response).
    cat >"$base/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
if [ "$1" = "manifest" ] && [ "$2" = "inspect" ]; then
    echo "no such manifest: stubbed" >&2
    exit 1
fi
exit 0
DOCKER_STUB
    command chmod +x "$base/stub/docker"

    local show_untracked_dir="$base/show-untracked-no" gitignored_dir="$base/gitignored"
    _ia_dtg_new_repo "$show_untracked_dir"
    _ia_dtg_new_repo "$gitignored_dir"

    # Case 1 (real bypass, must still be refused): status.showUntrackedFiles=no.
    git -C "$show_untracked_dir" config status.showUntrackedFiles no
    command mkdir -p "$show_untracked_dir/cmd/ch-oauth-ldap"
    printf 'package main\nfunc main(){}\n' >"$show_untracked_dir/cmd/ch-oauth-ldap/extra.go"

    # Case 2 (deliberate non-bypass, must NOT be refused): a committed
    # .gitignore excluding *.go, then an untracked (ignored) .go file added
    # afterward. No go.mod exists in this throwaway repo, so -- exactly like
    # _ia_script_dirty_tree_guard's "clean" case above -- an unrefused run
    # is left to fail later for the unrelated reason of having no
    # cmd/ch-oauth-ldap package to build; the assertion below only checks
    # that the dirty-tree guard's OWN refusal text is absent.
    printf '*.go\n' >"$gitignored_dir/.gitignore"
    git -C "$gitignored_dir" add .gitignore
    git -C "$gitignored_dir" commit -q -m "add gitignore"
    command mkdir -p "$gitignored_dir/cmd/ch-oauth-ldap"
    printf 'package main\nfunc main(){}\n' >"$gitignored_dir/cmd/ch-oauth-ldap/extra.go"

    local status

    REPO="$show_untracked_dir" TMPDIR="$base/tmp" bash "$script" \
        >"$base/show-untracked.out" 2>"$base/show-untracked.err"
    status=$?
    if [ "$status" -ne 0 ] && command grep -qF "$refusal_marker" "$base/show-untracked.err"; then
        pass "dirty-tree guard bypasses: status.showUntrackedFiles=no + untracked .go in $show_untracked_dir is refused (exit $status) -- the explicit --untracked-files=all flag overrides the config"
    else
        fail "dirty-tree guard bypasses: status.showUntrackedFiles=no + untracked .go in $show_untracked_dir was NOT refused (exit $status): $(command head -n3 "$base/show-untracked.err")"
    fi

    REPO="$gitignored_dir" TMPDIR="$base/tmp" PATH="$base/stub:$PATH" bash "$script" \
        >"$base/gitignored.out" 2>"$base/gitignored.err"
    status=$?
    if command grep -qF "$refusal_marker" "$base/gitignored.err"; then
        fail "dirty-tree guard bypasses: .gitignore'd .go file in $gitignored_dir was refused by the dirty-tree guard (exit $status) -- review pass 3 dropped --ignored=matching precisely because git archive HEAD can never see a gitignored file regardless of git status, so this is a false-positive refusal, not correct bypass-closing: $(command head -n3 "$base/gitignored.err")"
    else
        pass "dirty-tree guard bypasses: .gitignore'd .go file in $gitignored_dir is NOT refused by the dirty-tree guard (exit $status came from something else, e.g. no go.mod/cmd package to build in this throwaway repo -- expected, same as the clean-tree case above)"
    fi
}

# _ia_script_head_export_behavioral SCRIPT
# Behavioral proof for the review's third bypass (`--assume-unchanged` /
# `--skip-worktree`), which NO `git status` flag combination can detect: a
# tracked .go file is tampered after `git update-index --assume-unchanged`,
# then the REAL, unmodified script is run against that repo with a
# PATH-stubbed `docker` (records args, answers every preflight the script
# performs -- manifest/image inspect, pull, build, push -- without ever
# touching a real daemon) and a PATH-stubbed `go` that never compiles
# anything: it inspects its own $PWD for the tampered-vs-HEAD marker
# strings and records the verdict, then fabricates the requested `-o`
# output file so the rest of the script (chmod, docker build/push)
# proceeds normally. Proves the compile input is the exported HEAD tree,
# not the working tree: the tampered marker must be ABSENT from the stub's
# build cwd and the committed HEAD marker must be PRESENT.
_ia_script_head_export_behavioral() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    if ! command -v git >/dev/null 2>&1; then
        fail "HEAD-export behavioral proof: git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/head-export-behavioral"
    local repo="$base/repo"
    command mkdir -p "$repo/cmd/ch-oauth-ldap" "$base/stub" "$base/tmp"

    git -C "$repo" init -q
    git -C "$repo" config user.email gate@example.invalid
    git -C "$repo" config user.name gate
    printf 'FROM scratch\n' >"$repo/Dockerfile.ch-oauth-ldap"
    printf 'module example.com/ia-head-export\n\ngo 1.22\n' >"$repo/go.mod"
    printf 'package main\n\n// MARKER: IA_HEAD_CONTENT_MARKER\nfunc main() {}\n' \
        >"$repo/cmd/ch-oauth-ldap/main.go"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m init

    # Tamper the tracked file under --assume-unchanged: invisible to every
    # `git status` flag combination, including this script's own
    # strengthened --untracked-files=all --ignored=matching convenience
    # pre-check.
    git -C "$repo" update-index --assume-unchanged cmd/ch-oauth-ldap/main.go
    printf 'package main\n\n// MARKER: IA_TAMPERED_CONTENT_MARKER\nfunc main() {}\n' \
        >"$repo/cmd/ch-oauth-ldap/main.go"

    cat >"$base/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
echo "docker $*" >>"$IA_DOCKER_LOG"
case "$1" in
    manifest)
        if [ "$2" = "inspect" ]; then
            # An unambiguous "not found" signature -- the real script's
            # check_tag_absent (review pass 4) now requires this before
            # treating a nonzero exit as "tag absent" rather than aborting
            # as an ambiguous inspection failure.
            echo "no such manifest: stubbed" >&2
            exit 1
        fi
        exit 0
        ;;
    image)
        if [ "$2" = "inspect" ]; then
            echo "$IA_STUB_ARCH"
            exit 0
        fi
        exit 0
        ;;
    *) exit 0 ;;
esac
DOCKER_STUB
    command chmod +x "$base/stub/docker"

    cat >"$base/stub/go" <<'GO_STUB'
#!/bin/bash
if [ "$1" != "build" ]; then
    exit 0
fi
shift
out=""
prev=""
for a in "$@"; do
    if [ "$prev" = "-o" ]; then out="$a"; fi
    prev="$a"
done
{
    if command grep -RqF "$IA_TAMPER_MARKER" . 2>/dev/null; then
        echo "TAMPER:PRESENT"
    else
        echo "TAMPER:ABSENT"
    fi
    if command grep -RqF "$IA_HEAD_MARKER" . 2>/dev/null; then
        echo "HEAD:PRESENT"
    else
        echo "HEAD:ABSENT"
    fi
    echo "CWD:$(pwd)"
} >>"$IA_GO_RESULT"
command mkdir -p "$(dirname "$out")"
printf 'stub-binary\n' >"$out"
exit 0
GO_STUB
    command chmod +x "$base/stub/go"

    local docker_log="$base/docker.log" go_result="$base/go-result.log"
    : >"$docker_log"
    : >"$go_result"

    REPO="$repo" \
        TMPDIR="$base/tmp" \
        ARCHES="amd64" \
        PATH="$base/stub:$PATH" \
        IA_DOCKER_LOG="$docker_log" \
        IA_STUB_ARCH="amd64" \
        IA_TAMPER_MARKER="IA_TAMPERED_CONTENT_MARKER" \
        IA_HEAD_MARKER="IA_HEAD_CONTENT_MARKER" \
        IA_GO_RESULT="$go_result" \
        bash "$script" >"$base/run.out" 2>"$base/run.err"
    local status=$?

    if [ "$status" -ne 0 ]; then
        fail "HEAD-export behavioral proof: script exited $status against the assume-unchanged-tampered/stubbed repo (expected 0 -- this tamper is NOT caught by the status pre-check, only silently excluded from the build by the archive export): $(command tail -n5 "$base/run.err")"
        return
    fi

    if [ ! -s "$go_result" ]; then
        fail "HEAD-export behavioral proof: the stub go was never invoked with 'build' -- see $base/run.out / $base/run.err"
        return
    fi

    if command grep -qF 'TAMPER:PRESENT' "$go_result"; then
        fail "HEAD-export behavioral proof: the tampered (--assume-unchanged) marker WAS visible to the stub go's build cwd -- the compile input is still the working tree, not an exported HEAD: $(cat "$go_result")"
    else
        pass "HEAD-export behavioral proof: tampered (--assume-unchanged) content is absent from the compile input"
    fi

    if command grep -qF 'HEAD:PRESENT' "$go_result"; then
        pass "HEAD-export behavioral proof: committed HEAD content is present in the compile input"
    else
        fail "HEAD-export behavioral proof: committed HEAD content is NOT present in the compile input (see $go_result) -- the export may not be running at all"
    fi
}

# _ia_script_self_tamper_behavioral SCRIPT
# Behavioral proof for review pass 3's Finding 2: the same
# `--assume-unchanged` threat _ia_script_head_export_behavioral proves
# against a .go file, applied instead to the script's OWN on-disk bytes.
# Without the self re-exec fix, every check below the point bash first loads
# this file -- the dirty-tree guard, the tag-republish guard, the archive
# export itself -- would run from whatever bytes are actually on disk, not
# HEAD, exactly the gap the source-tree export closes for cmd/**/*.go.
#
# Commits the REAL, unmodified script content (copied from SCRIPT itself,
# never a hand-duplicated copy that could silently drift from the actual
# guard logic) into a throwaway repo at the same relative path the self
# re-exec logic looks for, marks it `--assume-unchanged`, then tampers the
# on-disk copy to neutralize the tag-republish guard's `exit 1` into a
# no-op. Runs that tampered on-disk copy directly (SCRIPT's own
# self-detection auto-resolves REPO to this throwaway repo from the
# invoked path, exactly like a real checkout) against a PATH-stubbed
# `docker manifest inspect` that reports the tag as already published, and
# proves the run still refuses -- proving the guard that actually executed
# was the committed HEAD copy (via the self re-exec), not the neutralized
# on-disk one.
_ia_script_self_tamper_behavioral() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    if ! command -v git >/dev/null 2>&1; then
        fail "self-tamper behavioral proof: git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/self-tamper-behavioral"
    local repo="$base/repo"
    command mkdir -p "$repo/scripts" "$repo/cmd/ch-oauth-ldap" "$base/stub" "$base/tmp"

    git -C "$repo" init -q
    git -C "$repo" config user.email gate@example.invalid
    git -C "$repo" config user.name gate
    printf 'FROM scratch\n' >"$repo/Dockerfile.ch-oauth-ldap"
    printf 'module example.com/ia-self-tamper\n\ngo 1.22\n' >"$repo/go.mod"
    printf 'package main\n\nfunc main() {}\n' >"$repo/cmd/ch-oauth-ldap/main.go"

    command cp "$script" "$repo/scripts/build-ch-oauth-ldap-image.sh"
    command chmod +x "$repo/scripts/build-ch-oauth-ldap-image.sh"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m init

    # Tamper the ON-DISK copy under --assume-unchanged: invisible to every
    # `git status` flag combination, including this script's own
    # --untracked-files=all convenience pre-check. Neutralize the
    # tag-republish guard's `exit 1` (the line immediately following its
    # unique "no force override" refusal text) into a no-op, simulating an
    # operator -- or attacker -- quietly disabling the immutability check on
    # their own machine while a `git status` on the repo stays clean.
    git -C "$repo" update-index --assume-unchanged scripts/build-ch-oauth-ldap-image.sh
    local anchor_line exit_line
    anchor_line=$(command grep -nF 'There is no force override.' "$repo/scripts/build-ch-oauth-ldap-image.sh" | command head -n1 | command cut -d: -f1)
    if [ -z "$anchor_line" ]; then
        fail "self-tamper behavioral proof: could not locate the tag-republish guard's refusal text in the committed script to tamper"
        return
    fi
    exit_line=$((anchor_line + 1))
    command awk -v n="$exit_line" '
        NR == n { sub(/exit 1/, ": # tampered: guard neutralized") }
        { print }
    ' "$repo/scripts/build-ch-oauth-ldap-image.sh" >"$repo/scripts/build-ch-oauth-ldap-image.sh.tampered"
    command mv "$repo/scripts/build-ch-oauth-ldap-image.sh.tampered" "$repo/scripts/build-ch-oauth-ldap-image.sh"
    command chmod +x "$repo/scripts/build-ch-oauth-ldap-image.sh"
    if ! command grep -qF 'tampered: guard neutralized' "$repo/scripts/build-ch-oauth-ldap-image.sh"; then
        fail "self-tamper behavioral proof: failed to tamper the on-disk script's tag-republish guard (line $exit_line was not the expected 'exit 1')"
        return
    fi

    cat >"$base/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
if [ "$1" = "manifest" ] && [ "$2" = "inspect" ]; then
    exit 0
fi
exit 0
DOCKER_STUB
    command chmod +x "$base/stub/docker"

    REPO="$repo" \
        TMPDIR="$base/tmp" \
        PATH="$base/stub:$PATH" \
        bash "$repo/scripts/build-ch-oauth-ldap-image.sh" \
        >"$base/run.out" 2>"$base/run.err"
    local status=$?

    if [ "$status" -eq 0 ]; then
        fail "self-tamper behavioral proof: script exited 0 against a tag that already exists in the registry (stubbed) -- the on-disk tag-republish guard was neutralized via --assume-unchanged and the self re-exec from HEAD did not override it: $(command tail -n5 "$base/run.out")"
        return
    fi

    if command grep -qF "refusing to publish" "$base/run.err"; then
        pass "self-tamper behavioral proof: the committed (HEAD) tag-republish guard still refuses even though the on-disk copy of the script itself was tampered via --assume-unchanged -- the self re-exec from 'git show HEAD:...' is what enforces this"
    else
        fail "self-tamper behavioral proof: script exited nonzero ($status) but not via the expected tag-republish refusal -- see $base/run.err: $(command tail -n5 "$base/run.err")"
    fi
}

# _ia_script_realistic_reexec_behavioral SCRIPT
# Behavioral proof that the realistic, no-`REPO`-env invocation of the real
# script -- cwd is a checkout root, invoked as `bash
# scripts/build-ch-oauth-ldap-image.sh`, exactly how a developer or CI
# actually runs it -- survives the self re-exec added alongside the
# self-tamper fix above. The self-tamper proof above always sets `REPO=`
# explicitly, which masks a real defect: without an exported REPO, the
# re-exec'd child re-derives REPO from ITS OWN location (a temp copy under
# $TMPDIR), not the real checkout, and would fail the Dockerfile precheck
# with a wrong-REPO message before ever reaching a single `docker` call.
#
# Three scenarios, run from a single throwaway repo that commits the REAL
# script content (copied from SCRIPT, never a hand-duplicated copy), each
# under its own isolated $TMPDIR with a PATH-stubbed `docker` and no `REPO`
# in the environment:
#   refusal -- stubbed `docker manifest inspect` reports the tag as already
#     published; the script must refuse via the tag-republish guard.
#   success -- stubbed `docker` answers every preflight/build/push call
#     (single arch, so no manifest-assembly step); the real `go build`
#     compiles a trivial package; the script must exit 0.
#   failure -- stubbed `docker manifest inspect` reports "not found" (so the
#     script proceeds into build_one and a real `go build` runs), then
#     stubbed `docker pull` fails outright, aborting the script under
#     `set -e` well after the self re-exec and after RUN_TMP_DIR exists.
# Every scenario asserts: (a) the run reached at least the shared-tag
# `docker manifest inspect` call (proof REPO survived the self re-exec far
# enough to pass the Dockerfile precheck, `cd "$REPO"`, the dirty-tree
# guard, and SHA/TAG computation -- not just that some docker call
# happened, but that it is not the pre-fix "not found at $TMPDIR/.." wrong
# REPO refusal), (b) the Dockerfile-precheck's own wrong-REPO refusal text
# is absent, and (c) no `ch-oauth-ldap-image-self.*` temp copy remains under
# that scenario's own $TMPDIR after the run exits, on every exit path
# (success, refusal, and mid-run failure alike).
_ia_script_realistic_reexec_behavioral() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    if ! command -v git >/dev/null 2>&1; then
        fail "realistic re-exec proof: git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/realistic-reexec"
    local repo="$base/repo"
    command mkdir -p "$repo/scripts" "$repo/cmd/ch-oauth-ldap"

    git -C "$repo" init -q
    git -C "$repo" config user.email gate@example.invalid
    git -C "$repo" config user.name gate
    printf 'FROM scratch\n' >"$repo/Dockerfile.ch-oauth-ldap"
    printf 'module example.com/ia-realistic-reexec\n\ngo 1.22\n' >"$repo/go.mod"
    printf 'package main\n\nfunc main() {}\n' >"$repo/cmd/ch-oauth-ldap/main.go"
    command cp "$script" "$repo/scripts/build-ch-oauth-ldap-image.sh"
    command chmod +x "$repo/scripts/build-ch-oauth-ldap-image.sh"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m init

    local wrong_repo_marker="does not look like an altinity-oauth-helper checkout"
    local refusal_marker="refusing to publish"

    # --- scenario: refusal (tag already exists) -----------------------------
    local rdir="$base/refusal"
    command mkdir -p "$rdir/stub" "$rdir/tmp"
    cat >"$rdir/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
echo "docker $*" >>"$IA_DOCKER_LOG"
exit 0
DOCKER_STUB
    command chmod +x "$rdir/stub/docker"
    ( cd "$repo" && env -u REPO \
        TMPDIR="$rdir/tmp" \
        PATH="$rdir/stub:$PATH" \
        IA_DOCKER_LOG="$rdir/docker.log" \
        bash scripts/build-ch-oauth-ldap-image.sh \
        >"$rdir/out" 2>"$rdir/err" )
    local refusal_status=$?

    if [ "$refusal_status" -ne 0 ] && command grep -qF "$refusal_marker" "$rdir/err"; then
        pass "realistic re-exec proof (refusal): no-REPO-env, relative invocation is refused via the tag-republish guard (exit $refusal_status), not some other error"
    else
        fail "realistic re-exec proof (refusal): expected a tag-republish refusal (exit nonzero, '$refusal_marker' in stderr), got exit $refusal_status: $(command tail -n5 "$rdir/err")"
    fi
    if command grep -qF "$wrong_repo_marker" "$rdir/err"; then
        fail "realistic re-exec proof (refusal): script failed the Dockerfile precheck with a wrong-REPO message -- REPO did NOT survive the self re-exec: $(command tail -n5 "$rdir/err")"
    else
        pass "realistic re-exec proof (refusal): no wrong-REPO Dockerfile-precheck failure"
    fi
    if [ -s "$rdir/docker.log" ] && command grep -qF 'manifest inspect' "$rdir/docker.log"; then
        pass "realistic re-exec proof (refusal): script reached 'docker manifest inspect' -- REPO survived the self re-exec past the Dockerfile precheck, cd, and dirty-tree guard"
    else
        fail "realistic re-exec proof (refusal): script never reached 'docker manifest inspect' -- see $rdir/err: $(command tail -n5 "$rdir/err")"
    fi
    if command find "$rdir/tmp" -maxdepth 1 -name 'ch-oauth-ldap-image-self.*' 2>/dev/null | command grep -q .; then
        fail "realistic re-exec proof (refusal): a ch-oauth-ldap-image-self.* temp copy leaked under $rdir/tmp"
    else
        pass "realistic re-exec proof (refusal): no ch-oauth-ldap-image-self.* temp copy left under $rdir/tmp"
    fi

    # --- scenario: success (single arch, everything stubbed to succeed) -----
    local sdir="$base/success"
    command mkdir -p "$sdir/stub" "$sdir/tmp"
    cat >"$sdir/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
echo "docker $*" >>"$IA_DOCKER_LOG"
case "$1" in
    manifest)
        if [ "$2" = "inspect" ]; then
            # Unambiguous "not found" signature -- see check_tag_absent
            # (review pass 4) in the real script.
            echo "no such manifest: stubbed" >&2
            exit 1
        fi
        exit 0
        ;;
    image)
        if [ "$2" = "inspect" ]; then
            echo "$IA_STUB_ARCH"
            exit 0
        fi
        exit 0
        ;;
    *) exit 0 ;;
esac
DOCKER_STUB
    command chmod +x "$sdir/stub/docker"
    ( cd "$repo" && env -u REPO \
        ARCHES="amd64" \
        TMPDIR="$sdir/tmp" \
        PATH="$sdir/stub:$PATH" \
        IA_DOCKER_LOG="$sdir/docker.log" \
        IA_STUB_ARCH="amd64" \
        bash scripts/build-ch-oauth-ldap-image.sh \
        >"$sdir/out" 2>"$sdir/err" )
    local success_status=$?

    if [ "$success_status" -eq 0 ]; then
        pass "realistic re-exec proof (success): no-REPO-env, relative invocation completes (exit 0) end to end with a stubbed docker"
    else
        fail "realistic re-exec proof (success): expected exit 0, got $success_status: $(command tail -n5 "$sdir/err")"
    fi
    if command grep -qF "$wrong_repo_marker" "$sdir/err"; then
        fail "realistic re-exec proof (success): script failed the Dockerfile precheck with a wrong-REPO message -- REPO did NOT survive the self re-exec: $(command tail -n5 "$sdir/err")"
    fi
    if [ -s "$sdir/docker.log" ] && command grep -qF 'push' "$sdir/docker.log"; then
        pass "realistic re-exec proof (success): script reached 'docker push' -- REPO survived the self re-exec through the full build_one path"
    else
        fail "realistic re-exec proof (success): script never reached 'docker push' -- see $sdir/err: $(command tail -n5 "$sdir/err")"
    fi
    if command find "$sdir/tmp" -maxdepth 1 -name 'ch-oauth-ldap-image-self.*' 2>/dev/null | command grep -q .; then
        fail "realistic re-exec proof (success): a ch-oauth-ldap-image-self.* temp copy leaked under $sdir/tmp"
    else
        pass "realistic re-exec proof (success): no ch-oauth-ldap-image-self.* temp copy left under $sdir/tmp"
    fi
    if command find "$sdir/tmp" -maxdepth 1 -name 'ch-oauth-ldap-image.*' 2>/dev/null | command grep -q .; then
        fail "realistic re-exec proof (success): a ch-oauth-ldap-image.* run directory leaked under $sdir/tmp"
    else
        pass "realistic re-exec proof (success): no ch-oauth-ldap-image.* run directory left under $sdir/tmp"
    fi

    # --- scenario: failure (docker pull fails mid-build) ---------------------
    local fdir="$base/failure"
    command mkdir -p "$fdir/stub" "$fdir/tmp"
    cat >"$fdir/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
echo "docker $*" >>"$IA_DOCKER_LOG"
case "$1" in
    manifest)
        if [ "$2" = "inspect" ]; then
            # Unambiguous "not found" signature -- see check_tag_absent
            # (review pass 4) in the real script.
            echo "no such manifest: stubbed" >&2
            exit 1
        fi
        exit 0
        ;;
    pull)
        exit 1
        ;;
    *) exit 0 ;;
esac
DOCKER_STUB
    command chmod +x "$fdir/stub/docker"
    ( cd "$repo" && env -u REPO \
        ARCHES="amd64" \
        TMPDIR="$fdir/tmp" \
        PATH="$fdir/stub:$PATH" \
        IA_DOCKER_LOG="$fdir/docker.log" \
        bash scripts/build-ch-oauth-ldap-image.sh \
        >"$fdir/out" 2>"$fdir/err" )
    local failure_status=$?

    if [ "$failure_status" -ne 0 ] && ! command grep -qF "$refusal_marker" "$fdir/err"; then
        pass "realistic re-exec proof (failure): a real mid-build docker failure (docker pull) aborts the script (exit $failure_status), distinct from the tag-republish refusal"
    else
        fail "realistic re-exec proof (failure): expected a non-refusal nonzero exit from the stubbed 'docker pull' failure, got exit $failure_status: $(command tail -n5 "$fdir/err")"
    fi
    if command grep -qF "$wrong_repo_marker" "$fdir/err"; then
        fail "realistic re-exec proof (failure): script failed the Dockerfile precheck with a wrong-REPO message -- REPO did NOT survive the self re-exec: $(command tail -n5 "$fdir/err")"
    fi
    if [ -s "$fdir/docker.log" ] && command grep -qF 'pull' "$fdir/docker.log"; then
        pass "realistic re-exec proof (failure): script reached 'docker pull' before the stubbed failure -- REPO survived the self re-exec into build_one (go build ran for real)"
    else
        fail "realistic re-exec proof (failure): script never reached 'docker pull' -- see $fdir/err: $(command tail -n5 "$fdir/err")"
    fi
    if command find "$fdir/tmp" -maxdepth 1 -name 'ch-oauth-ldap-image-self.*' 2>/dev/null | command grep -q .; then
        fail "realistic re-exec proof (failure): a ch-oauth-ldap-image-self.* temp copy leaked under $fdir/tmp after a mid-build failure"
    else
        pass "realistic re-exec proof (failure): no ch-oauth-ldap-image-self.* temp copy left under $fdir/tmp after a mid-build failure"
    fi
    if command find "$fdir/tmp" -maxdepth 1 -name 'ch-oauth-ldap-image.*' 2>/dev/null | command grep -q .; then
        fail "realistic re-exec proof (failure): a ch-oauth-ldap-image.* run directory leaked under $fdir/tmp after a mid-build failure"
    else
        pass "realistic re-exec proof (failure): no ch-oauth-ldap-image.* run directory left under $fdir/tmp after a mid-build failure"
    fi
}

# _ia_script_tag_immutability_fail_closed_behavioral SCRIPT
# Behavioral proof of review pass 4's Finding 1: a `docker manifest
# inspect` failure that is NOT an unambiguous "not found" response (an
# auth/transport/registry error -- reproduced here the same way the review
# did, with an inspect that exits nonzero and prints an unrelated error) must
# abort the whole run before any build/push work, not be silently treated as
# "tag absent". Runs the real, unmodified script against a throwaway repo
# with a PATH-stubbed `docker` whose `manifest inspect` always exits 2 with
# a generic (non-"not found") error, and asserts: (a) the run fails, (b) the
# failure text is the new ambiguous-inspection-failure refusal, distinct
# from the ordinary "tag already exists" refusal, and (c) the run never
# reaches `docker pull`/`docker build`/`docker push` -- fail-closed means no
# build work happens on doubt, not just "eventually fails at push time".
_ia_script_tag_immutability_fail_closed_behavioral() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    if ! command -v git >/dev/null 2>&1; then
        fail "tag-immutability fail-closed proof: git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/tag-immutability-fail-closed"
    local repo="$base/repo"
    command mkdir -p "$repo/cmd/ch-oauth-ldap" "$base/stub" "$base/tmp"

    git -C "$repo" init -q
    git -C "$repo" config user.email gate@example.invalid
    git -C "$repo" config user.name gate
    printf 'FROM scratch\n' >"$repo/Dockerfile.ch-oauth-ldap"
    printf 'module example.com/ia-fail-closed\n\ngo 1.22\n' >"$repo/go.mod"
    printf 'package main\n\nfunc main() {}\n' >"$repo/cmd/ch-oauth-ldap/main.go"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m init

    local docker_log="$base/docker.log"
    : >"$docker_log"
    cat >"$base/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
echo "docker $*" >>"$IA_DOCKER_LOG"
if [ "$1" = "manifest" ] && [ "$2" = "inspect" ]; then
    # Neither "success" (tag exists) nor a recognized "not found" response --
    # simulates an auth/transport/registry error, exactly the class the
    # review reproduced with rc=2.
    echo "docker: error requesting authorization" >&2
    exit 2
fi
exit 0
DOCKER_STUB
    command chmod +x "$base/stub/docker"

    REPO="$repo" \
        TMPDIR="$base/tmp" \
        PATH="$base/stub:$PATH" \
        IA_DOCKER_LOG="$docker_log" \
        bash "$script" \
        >"$base/run.out" 2>"$base/run.err"
    local status=$?

    if [ "$status" -eq 0 ]; then
        fail "tag-immutability fail-closed proof: script exited 0 despite an inspect failure that is neither a match nor a recognized \"not found\" response -- an ambiguous registry-inspection error was silently treated as \"tag absent\": $(command tail -n5 "$base/run.out")"
        return
    fi

    if command grep -qF "could not determine whether" "$base/run.err"; then
        pass "tag-immutability fail-closed proof: an ambiguous docker manifest inspect failure (exit 2, non-\"not found\" text) aborts the run via the new fail-closed refusal (exit $status)"
    else
        fail "tag-immutability fail-closed proof: script exited nonzero ($status) but not via the expected fail-closed refusal -- see $base/run.err: $(command tail -n5 "$base/run.err")"
    fi

    if command grep -qF "already exist in the registry" "$base/run.err"; then
        fail "tag-immutability fail-closed proof: the ambiguous inspect failure was reported as the ordinary \"tag already exists\" refusal, not distinguished as an inspection failure: $(command tail -n5 "$base/run.err")"
    else
        pass "tag-immutability fail-closed proof: the ambiguous inspect failure is reported distinctly from the ordinary \"tag already exists\" refusal"
    fi

    if command grep -qE '^docker (pull|build|push)' "$docker_log"; then
        fail "tag-immutability fail-closed proof: the run reached a docker pull/build/push call despite the ambiguous inspect failure -- fail-closed must stop before any build/push work, not just fail later: $(cat "$docker_log")"
    else
        pass "tag-immutability fail-closed proof: no docker pull/build/push call was reached -- the run stopped before any build/push work"
    fi
}

# _ia_script_env_marker_injection_behavioral SCRIPT
# Behavioral proof of review pass 4's Finding 2: neither
# _CH_OAUTH_LDAP_IMAGE_SELF_COPY nor _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED may
# be trusted when inherited from an external caller's environment.
#
# Part (a) -- arbitrary file deletion: a caller sets ONLY
# _CH_OAUTH_LDAP_IMAGE_SELF_COPY to an unrelated "victim" file and points
# REPO at a directory that fails the very first check the real script
# performs (a missing Dockerfile.ch-oauth-ldap) -- deliberately BEFORE the
# self re-exec section would ever reassign that variable to its own
# legitimate temp-file path, isolating exactly the vulnerable window the
# review reproduced (their own repro used only the trap/cleanup lines in
# isolation; this drives the real, complete script to the same place). The
# victim file must survive.
#
# Part (b) -- provenance-bypass: a throwaway repo commits the REAL script
# content (copied from SCRIPT, never a hand-duplicated copy), then the
# on-disk copy is tampered with a PLAIN edit (deliberately NOT
# --assume-unchanged, which _ia_script_self_tamper_behavioral already
# covers as a separate vector) neutralizing both the dirty-tree guard's and
# the tag-republish guard's `exit 1`. The tampered copy is then run with
# _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED=1 forged in the environment. Before the
# fix, a bare `-n` check on that marker would skip the self re-exec entirely
# and run the tampered on-disk bytes as-is, including their own neutralized
# guards -- no --assume-unchanged trickery required, just one env var. After
# the fix, the forged marker (not equal to this process's own PID) is
# rejected, the real re-exec fires, and the genuine (HEAD, untampered)
# dirty-tree guard correctly refuses on the actual (git-status-visible)
# dirty tree.
_ia_script_env_marker_injection_behavioral() {
    local script="$1"
    _ia_require_file "scripts/build-ch-oauth-ldap-image.sh" "$script" || return

    # --- part (a): SELF_COPY must not be honored as a deletion target -------
    local adir="$RUN_TMP_DIR/env-marker-injection-copy"
    command mkdir -p "$adir/emptyrepo"
    local victim="$adir/victim.txt"
    printf 'do not delete me\n' >"$victim"

    REPO="$adir/emptyrepo" \
        TMPDIR="$adir/tmp" \
        _CH_OAUTH_LDAP_IMAGE_SELF_COPY="$victim" \
        bash "$script" \
        >"$adir/run.out" 2>"$adir/run.err"
    local a_status=$?

    if [ "$a_status" -eq 0 ]; then
        fail "env-marker injection proof (deletion): expected the script to fail the Dockerfile precheck against $adir/emptyrepo (which has no Dockerfile.ch-oauth-ldap), got exit 0 -- see $adir/run.out"
    elif [ -e "$victim" ]; then
        pass "env-marker injection proof (deletion): a caller-supplied _CH_OAUTH_LDAP_IMAGE_SELF_COPY pointing at an unrelated file is NOT deleted by the cleanup trap"
    else
        fail "env-marker injection proof (deletion): cleanup trap deleted a caller-supplied _CH_OAUTH_LDAP_IMAGE_SELF_COPY path ($victim) on an early, pre-re-exec exit -- the private marker was trusted straight from the environment instead of being bound to this process's own PID"
    fi

    # --- part (b): SELF_VERIFIED must not skip the self re-exec -------------
    if ! command -v git >/dev/null 2>&1; then
        fail "env-marker injection proof (provenance bypass): git not on PATH"
        return
    fi

    local base="$RUN_TMP_DIR/env-marker-injection-verified"
    local repo="$base/repo"
    command mkdir -p "$repo/scripts" "$repo/cmd/ch-oauth-ldap" "$base/stub" "$base/tmp"

    git -C "$repo" init -q
    git -C "$repo" config user.email gate@example.invalid
    git -C "$repo" config user.name gate
    printf 'FROM scratch\n' >"$repo/Dockerfile.ch-oauth-ldap"
    printf 'module example.com/ia-env-marker\n\ngo 1.22\n' >"$repo/go.mod"
    printf 'package main\n\nfunc main() {}\n' >"$repo/cmd/ch-oauth-ldap/main.go"
    command cp "$script" "$repo/scripts/build-ch-oauth-ldap-image.sh"
    command chmod +x "$repo/scripts/build-ch-oauth-ldap-image.sh"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m init

    # Plain edit -- no --assume-unchanged -- neutralizing both guards'
    # `exit 1`. This intentionally makes the working tree dirty per an
    # ordinary `git status`; the point of this test is that the OLD
    # (vulnerable) code never even reaches that check, because a forged
    # SELF_VERIFIED alone was enough to skip straight to running these
    # tampered bytes.
    local tampered="$repo/scripts/build-ch-oauth-ldap-image.sh"
    local dtg_anchor dtg_exit_line trg_anchor trg_exit_line
    dtg_anchor=$(command grep -nF 'so canonical publication requires a clean tree' "$tampered" | command head -n1 | command cut -d: -f1)
    trg_anchor=$(command grep -nF 'There is no force override.' "$tampered" | command head -n1 | command cut -d: -f1)
    if [ -z "$dtg_anchor" ] || [ -z "$trg_anchor" ]; then
        fail "env-marker injection proof (provenance bypass): could not locate both guards' refusal text in the committed script to tamper"
        return
    fi
    dtg_exit_line=$((dtg_anchor + 2))
    trg_exit_line=$((trg_anchor + 1))
    command awk -v d="$dtg_exit_line" -v t="$trg_exit_line" '
        NR == d { sub(/exit 1/, ": # tampered: dirty-tree guard neutralized") }
        NR == t { sub(/exit 1/, ": # tampered: tag-republish guard neutralized") }
        { print }
    ' "$tampered" >"$tampered.new"
    command mv "$tampered.new" "$tampered"
    command chmod +x "$tampered"
    if ! command grep -qF 'tampered: dirty-tree guard neutralized' "$tampered" || \
        ! command grep -qF 'tampered: tag-republish guard neutralized' "$tampered"; then
        fail "env-marker injection proof (provenance bypass): failed to tamper both guards (dirty-tree line $dtg_exit_line, tag-republish line $trg_exit_line were not the expected 'exit 1')"
        return
    fi

    # This test expects the dirty-tree guard to refuse before the script
    # ever reaches a tag-existence check, so this stub should never
    # actually run -- kept only as defensive scaffolding in case ordering
    # changes; "denied" + nonzero mirrors ghcr.io's real (ambiguous)
    # response rather than signaling "tag exists" (exit 0).
    cat >"$base/stub/docker" <<'DOCKER_STUB'
#!/bin/bash
if [ "$1" = "manifest" ] && [ "$2" = "inspect" ]; then
    echo "denied" >&2
    exit 1
fi
exit 0
DOCKER_STUB
    command chmod +x "$base/stub/docker"

    REPO="$repo" \
        TMPDIR="$base/tmp" \
        PATH="$base/stub:$PATH" \
        _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED=1 \
        bash "$tampered" \
        >"$base/run.out" 2>"$base/run.err"
    local b_status=$?

    if [ "$b_status" -ne 0 ] && command grep -qF "refusing to publish" "$base/run.err"; then
        pass "env-marker injection proof (provenance bypass): a caller-forged _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED=1 does not skip the self re-exec from HEAD -- the genuine (untampered) guard still refused (exit $b_status)"
    else
        fail "env-marker injection proof (provenance bypass): script exited $b_status without the genuine guard's refusal -- a caller-forged _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED=1 skipped the self re-exec, letting the tampered on-disk copy's neutralized guards run: $(command tail -n5 "$base/run.err")"
    fi
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

    # All six path filters (plan section 25).
    assert_match "$workflow" 'cmd/ch-oauth-ldap/**'
    assert_match "$workflow" 'internal/**'
    assert_match "$workflow" 'go.mod'
    assert_match "$workflow" 'go.sum'
    assert_match "$workflow" 'Dockerfile.ch-oauth-ldap'
    assert_match "$workflow" '.github/workflows/build-ch-oauth-ldap.yml'

    # Version stamp, both architectures (plan sections 23, 25).
    assert_match "$workflow" 'main.version='
    assert_match "$workflow" 'amd64'
    assert_match "$workflow" 'arm64'

    # Immutable tag for the BUILD; `:latest` allowed only as a pointer
    # (plan section 21, amended when the `:latest` alias was added).
    #
    # Plan section 21's rule was "no mutable alias at all", enforced as a
    # blanket ban on the `:latest` string anywhere in the workflow. That is
    # now too coarse: `:latest` exists, but only as an alias repointed at an
    # immutable `<prefix>-<sha>` manifest that this same run already
    # published under the full per-arch and republication guards. What
    # section 21 actually protects -- that a tag can never be silently moved
    # to a manifest nobody built under those guards -- is unchanged, because
    # nothing is ever BUILT for `:latest`.
    #
    # So the assertions below check that specific shape instead of banning
    # the string:
    #   * `:main` stays banned outright -- there is no such alias;
    #   * the alias is created with `imagetools create` from the immutable
    #     tag, never from the per-arch sub-tags and never from a build;
    #   * no `docker build`/`buildx build` line may mention `:latest`;
    #   * the alias step is gated to a push with the default prefix.
    assert_not_match "$workflow" ':main'

    # The alias is a pointer built from the immutable tag, not from a build
    # or from raw per-arch sub-tags.
    assert_match "$workflow" 'imagetools create -t "${FULL}:latest" "${FULL}:${TAG}"'

    # No BUILD step may produce `:latest` directly. The build path is
    # docker/build-push-action's `tags:` input (line ~203) plus any literal
    # `docker build` / `docker buildx build` invocation; `imagetools
    # create`/`inspect` are explicitly not builds, which is the whole point
    # of the alias design. Matching on a bare "build" substring would catch
    # `buildx imagetools` and `needs.build.outputs`, so the patterns below
    # are anchored to real build invocations.
    #
    # $workflow is a PATH (assert_match takes a file), so this greps the
    # file rather than a variable.
    if grep -nE '^[[:space:]]*(tags|uses):.*:latest|docker (buildx )?build[[:space:]].*:latest' "$workflow" >/dev/null; then
        fail "workflow: a build/tag input mentions ':latest' -- the alias must only ever be created by 'imagetools create' from an already-published immutable tag, never built"
    else
        pass "workflow: no build/tag input mentions ':latest'"
    fi

    # The per-arch build must still push only an immutable sub-tag.
    assert_match "$workflow" 'tags: ${{ env.REGISTRY }}/${{ env.IMAGE }}:${{ steps.vars.outputs.tag }}-${{ matrix.arch }}'

    # The alias only moves for a default-prefix push, never for an
    # out-of-band workflow_dispatch with a custom tag_prefix.
    assert_match "$workflow" "github.event_name == 'push' && needs.build.outputs.tag_prefix == 'ldap'"

    # Per-arch $RUNNER_TEMP/runner.temp context; Docker context never
    # checkout root; go build -o points into runner temp (plan section 25).
    assert_match "$workflow" 'RUNNER_TEMP'
    assert_match "$workflow" 'runner.temp'
    assert_not_match "$workflow" 'context: .'
    assert_match "$workflow" '-o "$RUNNER_TEMP/'

    # Concurrency (plan amendment A7).
    assert_match "$workflow" 'cancel-in-progress: true'

    _ia_workflow_tag_republish_static "$workflow"
    _ia_workflow_tag_immutability_fail_closed_static "$workflow"
    _ia_workflow_no_errexit_unsafe_capture_static "$workflow"
    _ia_workflow_tag_guard_behavioral "$workflow"
    _ia_workflow_actionlint_check "$workflow"
    _ia_workflow_actionlint_negative_case "$workflow"
    _ia_workflow_actionlint_jwt_verify_informational "$_IA_WORKFLOW_JWT"
}

# _ia_workflow_no_errexit_unsafe_capture_static WORKFLOW
# Static proof that the exact anti-pattern behind the confirmed defect
# never regresses: a `run:` line of the form `UPPER_VAR=$(...)` (an
# assignment via command substitution, unguarded by an `if`/`while`/`!`
# context that would suspend errexit for it) with the very next line
# reading `$?`. Under GitHub-hosted runners' `bash --noprofile --norc -eo
# pipefail`, that shape means a failing command inside the substitution
# kills the step at the assignment, before `$?` is ever read -- exactly
# the bug that blocked every first image publication. This only flags the
# bare, unguarded shape (a line that, once whitespace is stripped, BEGINS
# with the assignment) -- it does not flag `if OUT=$(...); then ... else
# RC=$?; fi`, since there `OUT=$(...)` is the condition of an `if` and
# `$?` never appears on the line immediately below it.
_ia_workflow_no_errexit_unsafe_capture_static() {
    local workflow="$1"
    local bad=0 line_no content next_line

    while IFS=: read -r line_no content; do
        next_line=$(command sed -n "$((line_no + 1))p" "$workflow")
        if printf '%s' "$next_line" | command grep -qE '\$\?'; then
            bad=1
            fail "$workflow:$line_no: errexit-unsafe capture -- '$(printf '%s' "$content" | command sed 's/^[[:space:]]*//')' is immediately followed by a \$? read on line $((line_no + 1)) ('$(printf '%s' "$next_line" | command sed 's/^[[:space:]]*//')'), which dies under this workflow's fail-fast \`bash -e\` before \$? is ever reached for a genuinely failing command"
        fi
    done < <(command grep -nE '^[[:space:]]*[A-Z_]+=\$\(' "$workflow")

    if [ "$bad" -eq 0 ]; then
        pass "$workflow: no run: body contains the errexit-unsafe 'UPPER_VAR=\$(...)' assignment immediately followed by a \$? read on the next line"
    fi
}

# _ia_workflow_write_step_extractor
# Writes a small Go program to $RUN_TMP_DIR/wf-step-extractor/main.go that
# parses a GitHub Actions workflow YAML file with the repository's existing
# gopkg.in/yaml.v3 dependency and prints one step's literal `run:` block
# body to stdout. Run with cwd=$REPO_ROOT (see _ia_workflow_extract_step),
# exactly like embedded-assertions.sh's generated verifier, so the import
# resolves from the repo's own go.mod/go.sum -- never a temporary go.mod,
# never `go build ./...`.
#
# CLI: go run main.go <workflow.yml> <job-id> <step-name>
# Exits nonzero with a message on stderr if the job or the named step is
# not found, or the step has no `run:` body (e.g. it is a `uses:` step).
_ia_workflow_write_step_extractor() {
    command mkdir -p "$RUN_TMP_DIR/wf-step-extractor"
    cat > "$RUN_TMP_DIR/wf-step-extractor/main.go" <<'WF_EXTRACTOR_EOF'
// Generated by helm/ch-oauth-ldap/ci/lib/image-assertions.sh. Not part of
// the Go module's build (it lives under a caller-owned temp directory and
// is invoked directly via `go run <abs-path>`, never `go build ./...`).
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type wfStep struct {
	Name string `yaml:"name"`
	Run  string `yaml:"run"`
}

type wfJob struct {
	Steps []wfStep `yaml:"steps"`
}

type wfFile struct {
	Jobs map[string]wfJob `yaml:"jobs"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: main <workflow.yml> <job-id> <step-name>")
		os.Exit(2)
	}
	workflowPath, jobID, stepName := os.Args[1], os.Args[2], os.Args[3]

	data, err := os.ReadFile(workflowPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var wf wfFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		fmt.Fprintln(os.Stderr, "parsing", workflowPath, ":", err)
		os.Exit(1)
	}
	job, ok := wf.Jobs[jobID]
	if !ok {
		fmt.Fprintf(os.Stderr, "job %q not found in %s\n", jobID, workflowPath)
		os.Exit(1)
	}
	for _, step := range job.Steps {
		if step.Name != stepName {
			continue
		}
		if step.Run == "" {
			fmt.Fprintf(os.Stderr, "step %q in job %q has no run: body\n", stepName, jobID)
			os.Exit(1)
		}
		fmt.Print(step.Run)
		return
	}
	fmt.Fprintf(os.Stderr, "step %q not found in job %q\n", stepName, jobID)
	os.Exit(1)
}
WF_EXTRACTOR_EOF
}

# _ia_workflow_extract_step WORKFLOW JOB STEP_NAME OUT_FILE
# Runs the extractor (writing it first) with cwd=$REPO_ROOT -- so
# `gopkg.in/yaml.v3` resolves from the repository's own go.mod/go.sum, per
# plan A5's convention, reused from embedded-assertions.sh -- and writes
# the named step's `run:` body to OUT_FILE. Fails and returns nonzero if
# extraction did not succeed.
_ia_workflow_extract_step() {
    local workflow="$1" job="$2" step_name="$3" out_file="$4" err_file
    err_file="${out_file}.err"
    if ! ( cd "$REPO_ROOT" && go run "$RUN_TMP_DIR/wf-step-extractor/main.go" "$workflow" "$job" "$step_name" ) >"$out_file" 2>"$err_file"; then
        fail "workflow tag-guard behavioral proof: could not extract job '$job' step '$step_name' from $workflow: $(command tail -n5 "$err_file")"
        return 1
    fi
    return 0
}

# _ia_workflow_tag_guard_scenario LABEL STEP_FILE DOCKER_RC DOCKER_STDERR EXPECT ENV_ASSIGN...
# Executes STEP_FILE -- an extracted `run:` body, already known to be plain
# bash (no leftover `${{ }}` expressions once TAG/ARCH/FULL come in via
# `env:`) -- under the exact invocation shape GitHub-hosted runners use for
# a `run:` step: `bash --noprofile --norc -eo pipefail`. A PATH-stubbed
# `docker` answers a `buildx imagetools inspect ...` call with exit
# DOCKER_RC and DOCKER_STDERR on stderr (these bodies never call any other
# docker subcommand). ENV_ASSIGN... are "VAR=value" pairs exported for the
# run, mirroring the step's real `env:` block (REGISTRY/IMAGE/TAG/ARCH for
# the build job's guard, TAG/FULL for the manifest job's recheck). EXPECT
# is one of:
#   proceed   -- the tag is genuinely absent (the confirmed-defect case):
#                must complete with exit 0, i.e. NOT be blocked.
#   present   -- the tag already exists: must abort nonzero with the
#                "already exists" refusal.
#   ambiguous -- an unrelated transport/auth error: must abort nonzero with
#                the "could not determine" refusal.
_ia_workflow_tag_guard_scenario() {
    local label="$1" step_file="$2" docker_rc="$3" docker_stderr="$4" expect="$5"
    shift 5
    local -a env_assign=("$@")
    local dir status bash_bin slug

    slug=$(printf '%s' "$label" | command tr -c 'A-Za-z0-9' '-')
    dir="$RUN_TMP_DIR/wf-step-extractor/scenario-$slug"
    command mkdir -p "$dir/stub"
    bash_bin=$(command -v bash)

    cat > "$dir/stub/docker" <<DOCKER_STUB
#!/bin/bash
if [ "\$1" = "buildx" ] && [ "\$2" = "imagetools" ] && [ "\$3" = "inspect" ]; then
    printf '%s\n' $(printf '%q' "$docker_stderr") >&2
    exit $docker_rc
fi
exit 0
DOCKER_STUB
    command chmod +x "$dir/stub/docker"

    ( env -i "PATH=$dir/stub:/usr/bin:/bin" "${env_assign[@]}" \
        "$bash_bin" --noprofile --norc -eo pipefail "$step_file" \
        >"$dir/run.out" 2>"$dir/run.err" )
    status=$?

    case "$expect" in
        proceed)
            if [ "$status" -eq 0 ]; then
                pass "workflow tag-guard behavioral ($label): tag-absent scenario completes with exit 0 -- first publication is not blocked"
            else
                fail "workflow tag-guard behavioral ($label): tag-absent scenario must exit 0 (proceed) but exited $status -- stdout/stderr: $(command tail -n5 "$dir/run.out" "$dir/run.err")"
            fi
            ;;
        present)
            if [ "$status" -ne 0 ] && command grep -qF "already exists" "$dir/run.err"; then
                pass "workflow tag-guard behavioral ($label): tag-present scenario aborts (exit $status) with the \"already exists\" refusal"
            else
                fail "workflow tag-guard behavioral ($label): tag-present scenario must abort with the \"already exists\" refusal -- exit=$status, stderr: $(command tail -n5 "$dir/run.err")"
            fi
            ;;
        ambiguous)
            if [ "$status" -ne 0 ] && command grep -qF "could not determine" "$dir/run.err"; then
                pass "workflow tag-guard behavioral ($label): ambiguous-error scenario aborts (exit $status) with the \"could not determine\" refusal"
            else
                fail "workflow tag-guard behavioral ($label): ambiguous-error scenario must abort with the \"could not determine\" refusal -- exit=$status, stderr: $(command tail -n5 "$dir/run.err")"
            fi
            ;;
        *)
            fail "workflow tag-guard behavioral ($label): unknown expect '$expect' (internal test bug)"
            ;;
    esac
}

# _ia_workflow_tag_guard_behavioral WORKFLOW
# The behavioral proof for the confirmed defect: extracts both tag-guard
# steps' literal `run:` bodies from the actual, unmodified workflow YAML
# and runs each through the three scenarios above. See
# _ia_workflow_tag_guard_scenario's contract comment for what each scenario
# proves.
_ia_workflow_tag_guard_behavioral() {
    local workflow="$1"
    _ia_require_file ".github/workflows/build-ch-oauth-ldap.yml" "$workflow" || return

    if ! command -v go >/dev/null 2>&1; then
        fail "workflow tag-guard behavioral proof: go not on PATH"
        return
    fi

    _ia_workflow_write_step_extractor

    local build_step="$RUN_TMP_DIR/wf-step-extractor/build-step.sh"
    local manifest_step="$RUN_TMP_DIR/wf-step-extractor/manifest-step.sh"

    _ia_workflow_extract_step "$workflow" build "Refuse to republish an already-published tag" "$build_step" || return
    _ia_workflow_extract_step "$workflow" manifest "Refuse to republish an already-published tag (final recheck)" "$manifest_step" || return

    local -a build_env=(REGISTRY=ghcr.io IMAGE=altinity/ch-oauth-ldap TAG=ldap-abc1234 ARCH=amd64)
    local -a manifest_env=(TAG=ldap-abc1234 FULL=ghcr.io/altinity/ch-oauth-ldap)

    _ia_workflow_tag_guard_scenario "build-guard-absent" "$build_step" 1 "no such manifest" proceed "${build_env[@]}"
    _ia_workflow_tag_guard_scenario "build-guard-present" "$build_step" 0 "" present "${build_env[@]}"
    _ia_workflow_tag_guard_scenario "build-guard-ambiguous" "$build_step" 2 "docker: error requesting authorization" ambiguous "${build_env[@]}"

    _ia_workflow_tag_guard_scenario "manifest-guard-absent" "$manifest_step" 1 "no such manifest" proceed "${manifest_env[@]}"
    _ia_workflow_tag_guard_scenario "manifest-guard-present" "$manifest_step" 0 "" present "${manifest_env[@]}"
    _ia_workflow_tag_guard_scenario "manifest-guard-ambiguous" "$manifest_step" 2 "docker: error requesting authorization" ambiguous "${manifest_env[@]}"
}

# _ia_workflow_tag_republish_static WORKFLOW
# Static proof of the review's Finding 2 fix in the workflow: the
# `docker buildx imagetools inspect` existence check must run before the
# build-push action, with no force-override input. Also proves the review
# pass 3 fix: ordering alone is not enough -- the guard must inspect BOTH
# the shared final tag (${FULL}:${TAG}) AND this job's own per-arch sub-tag
# (${FULL}:${TAG}-${{ matrix.arch }}), matching scripts/build-ch-oauth-ldap-
# image.sh's per-arch loop, so a retry after a partial run can't silently
# overwrite an already-published sub-tag just because the final manifest
# tag was never assembled.
_ia_workflow_tag_republish_static() {
    local workflow="$1"
    local step_line inspect_line buildpush_line guard_block

    assert_match "$workflow" 'docker buildx imagetools inspect' F

    inspect_line=$(command grep -nF 'docker buildx imagetools inspect' "$workflow" | command head -n1 | command cut -d: -f1)
    buildpush_line=$(command grep -nF 'docker/build-push-action' "$workflow" | command head -n1 | command cut -d: -f1)

    if [ -z "$inspect_line" ] || [ -z "$buildpush_line" ]; then
        fail "$workflow: could not locate both 'docker buildx imagetools inspect' and 'docker/build-push-action' to order them"
        return
    fi
    if [ "$inspect_line" -lt "$buildpush_line" ]; then
        pass "$workflow: docker buildx imagetools inspect existence check (line $inspect_line) precedes docker/build-push-action (line $buildpush_line)"
    else
        fail "$workflow: expected the docker buildx imagetools inspect existence check (line $inspect_line) to precede docker/build-push-action (line $buildpush_line)"
    fi

    # Tag-identity check (not just step ordering): the guard STEP's own body
    # -- from its "- name:" line (not just the inspect line itself, since
    # the candidate tags are built one bash statement EARLIER, in a `for
    # CANDIDATE in ...` line) up to the build-push line -- must reference
    # both the final tag and this job's per-arch sub-tag, so the check
    # cannot pass merely by inspecting the final tag while a different tag
    # is what actually gets pushed.
    step_line=$(command grep -nF 'Refuse to republish an already-published tag' "$workflow" | command head -n1 | command cut -d: -f1)
    if [ -z "$step_line" ]; then
        fail "$workflow: could not locate the 'Refuse to republish an already-published tag' step to scope the tag-identity check"
        return
    fi
    guard_block=$(command sed -n "${step_line},${buildpush_line}p" "$workflow")
    if printf '%s' "$guard_block" | command grep -qF '${FULL}:${TAG}"' && \
        printf '%s' "$guard_block" | command grep -qF '${FULL}:${TAG}-${'; then
        pass "$workflow: the republish guard step (lines $step_line-$buildpush_line) inspects both the final tag and a per-arch sub-tag, not the final tag alone"
    else
        fail "$workflow: the republish guard step (lines $step_line-$buildpush_line) must inspect both \${FULL}:\${TAG} and a per-arch \${FULL}:\${TAG}-<arch> sub-tag before push -- found: $guard_block"
    fi

    assert_not_match "$workflow" 'FORCE' F
}

# _ia_workflow_tag_immutability_fail_closed_static WORKFLOW
# Static proof of review pass 4's two workflow fixes, mirroring the manual
# script's check_tag_absent:
#   (1) fail-closed disambiguation -- both the per-arch guard step (build
#       job) and the manifest job's own recheck must require an unambiguous
#       "not found" signature in the inspect output before treating a tag as
#       absent, never a bare nonzero-exit check (a registry auth/transport
#       error looks identical to a genuine absence on exit code alone).
#   (2) non-atomicity -- the manifest job must recheck the shared final tag
#       immediately before `docker buildx imagetools create` mutates it,
#       rather than relying solely on the per-arch guard that ran earlier,
#       in a different job, against a possibly-stale registry state.
_ia_workflow_tag_immutability_fail_closed_static() {
    local workflow="$1"
    local recheck_step_line create_line manifest_job_line

    # NOT_FOUND_PATTERN appears exactly four times -- a definition and a
    # use in the build job's per-arch guard, and the same pair again in the
    # manifest job's final recheck. Any other count means one of the two
    # guard steps regressed to a bare truthiness check (or the pattern was
    # factored out somewhere this test would no longer see it).
    assert_count "$workflow" 'NOT_FOUND_PATTERN' 4 F

    manifest_job_line=$(command grep -nE '^[[:space:]]*manifest:' "$workflow" | command head -n1 | command cut -d: -f1)
    recheck_step_line=$(command grep -nF 'Refuse to republish an already-published tag (final recheck)' "$workflow" | command head -n1 | command cut -d: -f1)
    create_line=$(command grep -nF 'docker buildx imagetools create' "$workflow" | command head -n1 | command cut -d: -f1)

    if [ -z "$manifest_job_line" ] || [ -z "$recheck_step_line" ] || [ -z "$create_line" ]; then
        fail "$workflow: could not locate the manifest job, its final-recheck step, and 'docker buildx imagetools create' to order them"
        return
    fi
    if [ "$recheck_step_line" -lt "$manifest_job_line" ]; then
        fail "$workflow: the final-recheck step (line $recheck_step_line) must be inside the manifest job (which starts at line $manifest_job_line), not before it"
        return
    fi
    if [ "$recheck_step_line" -lt "$create_line" ]; then
        pass "$workflow: the manifest job's final-recheck step (line $recheck_step_line) precedes 'docker buildx imagetools create' (line $create_line)"
    else
        fail "$workflow: expected the manifest job's final-recheck step (line $recheck_step_line) to precede 'docker buildx imagetools create' (line $create_line)"
    fi

    assert_not_match "$workflow" 'FORCE' F
}

# =============================================================================
# actionlint validity gate -- added after a literal `${{ }}` inside a `run:`
# bash comment made build-ch-oauth-ldap.yml an invalid workflow file on main.
# GitHub Actions evaluates `${{ ... }}` expressions anywhere inside a `run:`
# string -- comments included -- before bash ever runs; an empty expression
# is a parse error, and any actual push-triggered run against the file fails
# instantly with no job logs. actionlint catches this statically, so it is
# gated here rather than relying on a human re-reading every `run:` comment.
# =============================================================================

# _ia_workflow_actionlint_check WORKFLOW
# Runs the pinned actionlint (ensure_actionlint in common.sh must already
# have resolved $ACTIONLINT_BIN -- this fails closed, never silently skips,
# if it has not) with `-no-color` against the real, unmodified WORKFLOW and
# requires exit 0 with empty stdout+stderr.
_ia_workflow_actionlint_check() {
    local workflow="$1"
    local out

    _ia_require_file ".github/workflows/build-ch-oauth-ldap.yml" "$workflow" || return

    if [ -z "${ACTIONLINT_BIN:-}" ]; then
        fail "actionlint: ACTIONLINT_BIN is not set -- ensure_actionlint must run (and succeed) before this check; no silent skip"
        return
    fi

    if out=$("$ACTIONLINT_BIN" -no-color "$workflow" 2>&1); then
        if [ -z "$out" ]; then
            pass "actionlint: $workflow is valid (exit 0, no findings)"
        else
            fail "actionlint: $workflow exited 0 but reported findings (expected empty output): $out"
        fi
    else
        fail "actionlint: $workflow FAILED validation: $out"
    fi
}

# _ia_workflow_actionlint_jwt_verify_informational WORKFLOW_JWT
# Runs the same pinned actionlint against build-ch-jwt-verify.yml, purely
# informationally: that file is out of this fix's scope, so a finding there
# is reported via `note` and never turns into a `fail`.
_ia_workflow_actionlint_jwt_verify_informational() {
    local workflow="$1"
    local out

    if [ ! -f "$workflow" ]; then
        note "actionlint (informational): $workflow not found, skipping"
        return
    fi
    if [ -z "${ACTIONLINT_BIN:-}" ]; then
        note "actionlint (informational): ACTIONLINT_BIN not set, skipping the out-of-scope build-ch-jwt-verify.yml check"
        return
    fi

    if out=$("$ACTIONLINT_BIN" -no-color "$workflow" 2>&1); then
        if [ -z "$out" ]; then
            note "actionlint (informational, out of scope): $workflow is valid (exit 0, no findings)"
        else
            note "actionlint (informational, out of scope): $workflow reported findings (NOT a gate failure -- this file is out of this fix's scope): $out"
        fi
    else
        note "actionlint (informational, out of scope): $workflow FAILED validation (NOT a gate failure -- this file is out of this fix's scope): $out"
    fi
}

# _ia_workflow_actionlint_negative_case WORKFLOW
# Proves the check above actually inspects expressions inside `run:`
# comments, rather than trivially passing every file: copies the real,
# already-valid WORKFLOW, injects a literal `${{ }}` into a bash comment
# immediately following the file's first `run: |` block scalar (at that
# line's own indentation, so the injected line is valid YAML block-scalar
# content and the ONLY defect is the reintroduced expression-parse error),
# and asserts the pinned actionlint FAILS against the tampered copy.
_ia_workflow_actionlint_negative_case() {
    local workflow="$1"
    local tampered="$RUN_TMP_DIR/actionlint-negative-case.yml"
    local run_line content_line_no content_line indent out

    _ia_require_file ".github/workflows/build-ch-oauth-ldap.yml" "$workflow" || return

    if [ -z "${ACTIONLINT_BIN:-}" ]; then
        fail "actionlint negative case: ACTIONLINT_BIN is not set -- ensure_actionlint must run (and succeed) before this check; no silent skip"
        return
    fi

    run_line=$(command grep -nE '^[[:space:]]*run: \|[[:space:]]*$' "$workflow" | command head -n1 | command cut -d: -f1)
    if [ -z "$run_line" ]; then
        fail "actionlint negative case: could not find a 'run: |' block scalar in $workflow to inject into"
        return
    fi
    content_line_no=$((run_line + 1))
    content_line=$(command sed -n "${content_line_no}p" "$workflow")
    indent=$(printf '%s' "$content_line" | command sed -E 's/^([[:space:]]*).*/\1/')

    {
        command sed -n "1,${run_line}p" "$workflow"
        printf '%s# negative-case probe: literal ${{ }} in a run: comment\n' "$indent"
        command sed -n "${content_line_no},\$p" "$workflow"
    } >"$tampered"

    if out=$("$ACTIONLINT_BIN" -no-color "$tampered" 2>&1); then
        fail "actionlint negative case: expected actionlint to FAIL on a copy of $workflow with a literal \${{ }} injected into a run: comment (line $((content_line_no + 1)) of $tampered), but it exited 0 -- the check would not have caught the real defect"
    else
        if printf '%s' "$out" | command grep -qF '[expression]'; then
            pass "actionlint negative case: actionlint correctly FAILS on a run: comment containing a literal \${{ }} (proves the check inspects expressions inside comments): $out"
        else
            fail "actionlint negative case: actionlint failed on the tampered copy, but not with the expected [expression] parse error -- got: $out"
        fi
    fi
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
    _IA_WORKFLOW_JWT="$REPO_ROOT/.github/workflows/build-ch-jwt-verify.yml"

    note "run_image_assertions: Dockerfile=$_IA_DOCKERFILE script=$_IA_SCRIPT workflow=$_IA_WORKFLOW workflow(informational)=$_IA_WORKFLOW_JWT"

    local before="${GATE_FAILURES:-0}"

    _ia_dockerfile_assertions
    _ia_script_static_assertions
    _ia_script_sigint_regression "$_IA_SCRIPT"
    _ia_script_dirty_tree_guard "$_IA_SCRIPT"
    _ia_script_dirty_tree_guard_bypasses "$_IA_SCRIPT"
    _ia_script_self_tamper_behavioral "$_IA_SCRIPT"
    _ia_script_realistic_reexec_behavioral "$_IA_SCRIPT"
    _ia_script_head_export_behavioral "$_IA_SCRIPT"
    _ia_script_tag_immutability_fail_closed_behavioral "$_IA_SCRIPT"
    _ia_script_env_marker_injection_behavioral "$_IA_SCRIPT"
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
