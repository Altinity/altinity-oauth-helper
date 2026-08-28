#!/usr/bin/env bash
# helm/ch-oauth-ldap/ci/lib/common.sh
#
# Shared bash library for the ch-oauth-ldap chart's committed verification
# gate (helm/ch-oauth-ldap/test.sh) and every assertion library it sources
# from helm/ch-oauth-ldap/ci/lib/*.sh.
#
# THIS FILE IS A LIBRARY. It must be `source`d, never executed directly.
#
# Contract this file provides (other libraries and test.sh depend on the
# exact names and signatures below — do not rename or reshape without
# updating every consumer):
#
#   Matcher (section 34 "Gate dependencies"):
#     gate_line_count FILE PATTERN [MODE]
#       Prints the number of matching *lines* in FILE (0 if FILE is absent
#       or nothing matches). MODE is "F" (fixed string, default) or "E"
#       (POSIX extended regex). Prefers `rg` when it is on PATH; otherwise
#       falls back to `grep -F` / `grep -E`. No correctness assertion in
#       this gate may require ripgrep — the grep fallback must be able to
#       express every check the gate makes.
#
#   Assertion primitives (write a one-line PASS/FAIL/NOTE/SKIP message to
#   stderr; only `fail` — directly or via an assert_* helper — increments
#   the shared failure counter $GATE_FAILURES):
#     pass MESSAGE
#     fail MESSAGE
#     note MESSAGE
#     skip MESSAGE
#     assert_eq ACTUAL EXPECTED [MESSAGE]
#     assert_match FILE PATTERN [MODE=F]
#     assert_not_match FILE PATTERN [MODE=F]
#     assert_count FILE PATTERN N [MODE=F]
#
#   Pinned, reproducible kubeconform (sections 35 and A4):
#     KUBECONFORM_VERSION            default v0.8.0, env-overridable
#     KUBECONFORM_SCHEMA_COMMIT      default: a real commit SHA on
#                                    yannh/kubernetes-json-schema's default
#                                    branch, resolved once at authoring time
#                                    via:
#                                      gh api repos/yannh/kubernetes-json-schema/commits/master --jq .sha
#                                    env-overridable.
#     KUBECONFORM_SCHEMA_LOCATION    default: the raw.githubusercontent.com
#                                    template pinned to KUBECONFORM_SCHEMA_COMMIT,
#                                    env-overridable (e.g. to a local mirror
#                                    for offline use).
#     ensure_kubeconform BIN_DIR
#     kubeconform_check MANIFEST
#     print_gate_pins
#
#   Pinned, reproducible actionlint (workflow-validity gate, added for the
#   ${{ }}-in-a-run:-comment incident that made build-ch-oauth-ldap.yml an
#   invalid workflow file on main):
#     ACTIONLINT_VERSION             default v1.7.7, env-overridable
#     ensure_actionlint BIN_DIR
#     print_gate_pins (also prints ACTIONLINT_VERSION)
#
#   Deterministic SIGINT/cleanup regression harness (sections 29, 50):
#     gate_sigint_regression LABEL SCRIPT RUN_DIR_PREFIX STATE_DIR
#       Runs the real, unmodified SCRIPT under an isolated $TMPDIR with a
#       `mkdir` shim that holds it inside its own run-directory mkdir,
#       SIGINTs the whole process group, and asserts (via pass/fail) that
#       it exited non-zero AND removed its run directory. Shared by
#       test.sh (against a copy of itself) and image-assertions.sh
#       (against scripts/build-ch-oauth-ldap-image.sh).
#
# Gate-soundness rule: `fail` increments $GATE_FAILURES in the CURRENT
# shell. Never call fail, or any assert_*/helper that may call fail, inside
# a `$(...)` command substitution or a pipeline -- both fork a subshell and
# the increment is lost, so the gate would report PASS over a real failure.
#
# Explicitly NOT required by this file or anything it installs: yq,
# kubectl, a Docker daemon, registry credentials, or a Kubernetes cluster.

# --- sourced-only guard -----------------------------------------------------
# `${BASH_SOURCE[0]}` is this file's own path; it only equals `$0` (the
# path used to invoke the running script) when this file is executed
# directly rather than sourced.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "common.sh: this file is a library; source it, do not execute it" >&2
    exit 1
fi

# --- failure counter ---------------------------------------------------------
# Consumers may read $GATE_FAILURES after running assertions to decide the
# gate's overall exit code. Do not reset it here if it is already set, so
# that a driver script sourcing multiple assertion libraries in sequence
# keeps one running total.
: "${GATE_FAILURES:=0}"

# --- matcher (section 34) ---------------------------------------------------

# gate_has_rg
# True (exit 0) if `rg` is available on PATH.
gate_has_rg() {
    command -v rg >/dev/null 2>&1
}

# gate_line_count FILE PATTERN [MODE]
# Prints the number of matching lines in FILE for PATTERN. MODE is "F"
# (fixed string; default) or "E" (POSIX extended regex). Prints 0 (and
# returns success) if FILE does not exist or nothing matches. The ONLY
# non-zero return is 2 for an unknown MODE: this function is always run
# inside `$(...)` by the assert_* helpers, so it must not call fail itself
# (the increment would be lost in the subshell) -- the caller turns the
# return code into a fail in the parent shell.
gate_line_count() {
    local file="$1" pattern="$2" mode="${3:-F}" n grep_flag rg_flag

    # grep and rg disagree on flag spelling here: grep needs an explicit
    # -E for POSIX extended regex (its default is BRE), while rg's -E is
    # a *different* flag (--encoding, which requires an argument) and rg
    # already matches as a (Rust-flavored) regex by default -- so E mode
    # passes rg no flag at all, only F mode passes -F to either tool.
    case "$mode" in
        F)
            grep_flag=-F
            rg_flag=-F
            ;;
        E)
            grep_flag=-E
            rg_flag=
            ;;
        *)
            printf '%s\n' 0
            return 2
            ;;
    esac

    if [ ! -f "$file" ]; then
        printf '%s\n' 0
        return 0
    fi

    if gate_has_rg; then
        if [ -n "$rg_flag" ]; then
            n=$(rg -c "$rg_flag" -- "$pattern" "$file" 2>/dev/null) || n=0
        else
            n=$(rg -c -- "$pattern" "$file" 2>/dev/null) || n=0
        fi
    else
        n=$(command grep -c "$grep_flag" -- "$pattern" "$file" 2>/dev/null) || n=0
    fi

    printf '%s\n' "${n:-0}"
}

# --- assertion primitives ----------------------------------------------------

# note MESSAGE
# Informational line. Does not affect the failure counter.
note() {
    printf 'NOTE: %s\n' "$*" >&2
}

# skip MESSAGE
# Records that a check was intentionally skipped (e.g. an optional doc is
# absent). Does not affect the failure counter.
skip() {
    printf 'SKIP: %s\n' "$*" >&2
}

# pass MESSAGE
# Records a successful check. Does not affect the failure counter.
pass() {
    printf 'PASS: %s\n' "$*" >&2
}

# fail MESSAGE
# Records a failed check and increments $GATE_FAILURES.
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    GATE_FAILURES=$((GATE_FAILURES + 1))
}

# assert_eq ACTUAL EXPECTED [MESSAGE]
assert_eq() {
    local actual="$1" expected="$2" msg="${3:-}"
    if [ "$actual" = "$expected" ]; then
        pass "assert_eq${msg:+ ($msg)}: '$actual' == '$expected'"
    else
        fail "assert_eq${msg:+ ($msg)}: expected '$expected', got '$actual'"
    fi
}

# assert_match FILE PATTERN [MODE=F]
# Fails unless PATTERN matches at least one line of FILE.
assert_match() {
    local file="$1" pattern="$2" mode="${3:-F}" n
    if ! n=$(gate_line_count "$file" "$pattern" "$mode"); then
        fail "assert_match: unknown MODE '$mode' (want F or E) for pattern '$pattern'"
        return
    fi
    if [ "$n" -gt 0 ]; then
        pass "assert_match: '$pattern' found in $file ($n line(s))"
    else
        fail "assert_match: '$pattern' NOT found in $file"
    fi
}

# assert_not_match FILE PATTERN [MODE=F]
# Fails if PATTERN matches any line of FILE.
assert_not_match() {
    local file="$1" pattern="$2" mode="${3:-F}" n
    if ! n=$(gate_line_count "$file" "$pattern" "$mode"); then
        fail "assert_not_match: unknown MODE '$mode' (want F or E) for pattern '$pattern'"
        return
    fi
    if [ "$n" -eq 0 ]; then
        pass "assert_not_match: '$pattern' absent from $file"
    else
        fail "assert_not_match: '$pattern' unexpectedly found in $file ($n line(s))"
    fi
}

# assert_count FILE PATTERN N [MODE=F]
# Fails unless PATTERN matches exactly N lines of FILE.
assert_count() {
    local file="$1" pattern="$2" expected="$3" mode="${4:-F}" n
    if ! n=$(gate_line_count "$file" "$pattern" "$mode"); then
        fail "assert_count: unknown MODE '$mode' (want F or E) for pattern '$pattern'"
        return
    fi
    if [ "$n" -eq "$expected" ]; then
        pass "assert_count: '$pattern' occurs $n time(s) in $file (expected $expected)"
    else
        fail "assert_count: '$pattern' occurs $n time(s) in $file, expected $expected"
    fi
}

# --- reproducible kubeconform (sections 35, A4) ------------------------------

# Pinned kubeconform release. `v0.8.0` is the version this gate was
# authored and verified against. Override with the environment for a
# different pinned version -- never install the unpinned "latest" tag.
: "${KUBECONFORM_VERSION:=v0.8.0}"

# Pinned commit on yannh/kubernetes-json-schema's default branch, resolved
# once at authoring time via:
#   gh api repos/yannh/kubernetes-json-schema/commits/master --jq .sha
: "${KUBECONFORM_SCHEMA_COMMIT:=14355cdd490a43d21e05985668815a36a6f97da6}"

# Resolved schema-location template, pinned to the commit above. Override
# with the environment to point at a local mirror (e.g. for offline use);
# the override is a full location string, not just a commit.
#
# NOTE: this default is built with a plain `if`/assignment, not the usual
# `: "${VAR:=default}"` idiom used for the other pins above. The default
# contains literal Go-template braces (`{{...}}`), and this bash's
# parameter-expansion parser (verified on GNU bash 5.3.9) mis-parses `{{`
# / `}}` inside a `${VAR:=word}` default, silently truncating the value.
# A plain conditional assignment does not hit that parser path.
if [ -z "${KUBECONFORM_SCHEMA_LOCATION:-}" ]; then
    KUBECONFORM_SCHEMA_LOCATION="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/${KUBECONFORM_SCHEMA_COMMIT}/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json"
fi

# Resolved path to the kubeconform binary this library will use, set by
# ensure_kubeconform. Empty until ensure_kubeconform runs.
KUBECONFORM_BIN="${KUBECONFORM_BIN:-}"

# ensure_kubeconform BIN_DIR
# Uses an existing `kubeconform` on PATH only if its `-v` output equals the
# pinned $KUBECONFORM_VERSION (an unpinned or older PATH binary would make
# the schema-validation result irreproducible). Otherwise installs the
# pinned $KUBECONFORM_VERSION with `go install` into BIN_DIR (never the
# unpinned "latest" tag). Sets $KUBECONFORM_BIN to the resolved binary
# path. Requires network access to the Go module proxy only in the
# install path.
ensure_kubeconform() {
    local bin_dir="$1" on_path reported

    if on_path=$(command -v kubeconform 2>/dev/null); then
        reported=$("$on_path" -v 2>/dev/null | command head -n1 | tr -d '[:space:]')
        if [ "$reported" = "$KUBECONFORM_VERSION" ]; then
            KUBECONFORM_BIN="$on_path"
            note "using kubeconform already on PATH: $KUBECONFORM_BIN (reports ${reported}, matches pin)"
            return 0
        fi
        note "kubeconform on PATH at $on_path reports '${reported:-<nothing>}', not the pinned ${KUBECONFORM_VERSION}; installing the pinned version instead"
    fi

    if [ -z "$bin_dir" ]; then
        fail "ensure_kubeconform: BIN_DIR argument is required when kubeconform is not on PATH"
        return 1
    fi

    mkdir -p "$bin_dir"
    note "installing kubeconform ${KUBECONFORM_VERSION} into $bin_dir"
    # kubeconform's own `-v` flag prints a `main.version` package var that
    # is normally set by its release tooling's ldflags, not by plain `go
    # install` -- without this, the installed binary reports "development"
    # instead of the pinned version. Set it ourselves so `kubeconform -v`
    # actually confirms the pin.
    if ! GOBIN="$bin_dir" go install -ldflags "-X main.version=${KUBECONFORM_VERSION}" "github.com/yannh/kubeconform/cmd/kubeconform@${KUBECONFORM_VERSION}"; then
        fail "ensure_kubeconform: go install failed for kubeconform@${KUBECONFORM_VERSION}"
        return 1
    fi

    KUBECONFORM_BIN="$bin_dir/kubeconform"
    if [ ! -x "$KUBECONFORM_BIN" ]; then
        fail "ensure_kubeconform: expected binary not found at $KUBECONFORM_BIN after install"
        return 1
    fi
    reported=$("$KUBECONFORM_BIN" -v 2>/dev/null | command head -n1 | tr -d '[:space:]')
    if [ "$reported" != "$KUBECONFORM_VERSION" ]; then
        fail "ensure_kubeconform: installed binary reports '${reported:-<nothing>}', expected ${KUBECONFORM_VERSION}"
        return 1
    fi
    note "installed kubeconform at $KUBECONFORM_BIN (reports ${reported})"
}

# kubeconform_check MANIFEST
# Runs the pinned kubeconform (set up by ensure_kubeconform) against a
# rendered manifest file with the gate's standard flags: -strict -summary
# -kubernetes-version 1.30.0, and the resolved -schema-location. Requires
# network access to fetch schemas unless $KUBECONFORM_SCHEMA_LOCATION has
# been overridden to point at a local mirror.
kubeconform_check() {
    local manifest="$1" bin="${KUBECONFORM_BIN:-kubeconform}"

    "$bin" \
        -strict \
        -summary \
        -kubernetes-version 1.30.0 \
        -schema-location "$KUBECONFORM_SCHEMA_LOCATION" \
        "$manifest"
}

# --- reproducible actionlint (workflow-validity gate) ------------------------

# Pinned actionlint release. `v1.7.7` is the version this check was
# authored and verified against (it is what caught the ${{ }}-in-a-comment
# defect that made build-ch-oauth-ldap.yml an invalid workflow file on
# main). Override with the environment for a different pinned version --
# never install the unpinned "latest" tag.
: "${ACTIONLINT_VERSION:=v1.7.7}"

# Resolved path to the actionlint binary this library will use, set by
# ensure_actionlint. Empty until ensure_actionlint runs.
ACTIONLINT_BIN="${ACTIONLINT_BIN:-}"

# ensure_actionlint BIN_DIR
# Uses an existing `actionlint` on PATH only if its `-version` output's
# first line equals the pinned $ACTIONLINT_VERSION (an unpinned or
# different PATH binary would make workflow-validity results
# irreproducible). Otherwise installs the pinned $ACTIONLINT_VERSION with
# `go install` into BIN_DIR (never the unpinned "latest" tag). Sets
# $ACTIONLINT_BIN to the resolved binary path. Requires network access to
# the Go module proxy only in the install path. Mirrors ensure_kubeconform
# above; fails closed (via `fail`, no silent skip) if the pinned binary
# cannot be resolved on PATH or installed.
ensure_actionlint() {
    local bin_dir="$1" on_path reported

    if on_path=$(command -v actionlint 2>/dev/null); then
        reported=$("$on_path" -version 2>/dev/null | command head -n1 | tr -d '[:space:]')
        if [ "$reported" = "$ACTIONLINT_VERSION" ]; then
            ACTIONLINT_BIN="$on_path"
            note "using actionlint already on PATH: $ACTIONLINT_BIN (reports ${reported}, matches pin)"
            return 0
        fi
        note "actionlint on PATH at $on_path reports '${reported:-<nothing>}', not the pinned ${ACTIONLINT_VERSION}; installing the pinned version instead"
    fi

    if [ -z "$bin_dir" ]; then
        fail "ensure_actionlint: BIN_DIR argument is required when actionlint is not on PATH"
        return 1
    fi

    mkdir -p "$bin_dir"
    note "installing actionlint ${ACTIONLINT_VERSION} into $bin_dir"
    if ! GOBIN="$bin_dir" go install "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}"; then
        fail "ensure_actionlint: go install failed for actionlint@${ACTIONLINT_VERSION}"
        return 1
    fi

    ACTIONLINT_BIN="$bin_dir/actionlint"
    if [ ! -x "$ACTIONLINT_BIN" ]; then
        fail "ensure_actionlint: expected binary not found at $ACTIONLINT_BIN after install"
        return 1
    fi
    reported=$("$ACTIONLINT_BIN" -version 2>/dev/null | command head -n1 | tr -d '[:space:]')
    if [ "$reported" != "$ACTIONLINT_VERSION" ]; then
        fail "ensure_actionlint: installed binary reports '${reported:-<nothing>}', expected ${ACTIONLINT_VERSION}"
        return 1
    fi
    note "installed actionlint at $ACTIONLINT_BIN (reports ${reported})"
}

# print_gate_pins
# Prints the reproducibility pins this gate relies on. test.sh calls this
# in its header output so a run's log records exactly which kubeconform
# version, schema commit, and actionlint version were used.
print_gate_pins() {
    printf 'KUBECONFORM_VERSION=%s\n' "$KUBECONFORM_VERSION"
    printf 'KUBECONFORM_SCHEMA_COMMIT=%s\n' "$KUBECONFORM_SCHEMA_COMMIT"
    printf 'KUBECONFORM_SCHEMA_LOCATION=%s\n' "$KUBECONFORM_SCHEMA_LOCATION"
    printf 'ACTIONLINT_VERSION=%s\n' "$ACTIONLINT_VERSION"
}

# --- deterministic SIGINT/cleanup regression (sections 29, 50) ---------------

# gate_sigint_regression LABEL SCRIPT RUN_DIR_PREFIX STATE_DIR
# Proves that SCRIPT (run real and unmodified via `bash SCRIPT`, never in a
# special test mode) removes its own run directory when the whole process
# group is interrupted while that directory is being created:
#
#   1. STATE_DIR/tmp becomes the child's isolated $TMPDIR; STATE_DIR/shim
#      holds a `mkdir` shim prepended to the child's PATH. The shim
#      intercepts only targets containing RUN_DIR_PREFIX: it runs the real
#      `mkdir` (so the directory genuinely exists on disk for the poll loop
#      to find), then sleeps -- holding the child inside that one foreground
#      `mkdir` call long enough for the SIGINT to land while it is still
#      running. Every other mkdir call passes straight through.
#   2. The child is launched under `set -m` so its PGID equals its PID, and
#      the poll loop looks only inside STATE_DIR/tmp for a
#      RUN_DIR_PREFIX* directory (up to 20s).
#   3. `kill -INT -- -PID` hits the whole group; after `wait`, the child
#      must have exited non-zero/by signal AND the run directory must be
#      gone.
#
# Because the interrupt lands during the run-directory mkdir itself, nothing
# the script would do afterwards (go build, docker, ...) is ever reached.
# Reports via pass/fail (in THIS shell -- never call this inside `$(...)`).
gate_sigint_regression() {
    local label="$1" script="$2" prefix="$3" state_dir="$4"

    if [ ! -f "$script" ]; then
        fail "$label: script not found at $script"
        return
    fi

    local iso_parent="$state_dir/tmp" shim_dir="$state_dir/shim"
    command mkdir -p "$iso_parent" "$shim_dir"

    # The shim is generated so the intercepted prefix is a literal in it.
    {
        printf '%s\n' '#!/bin/bash'
        printf '%s\n' 'for _gate_shim_arg in "$@"; do'
        printf '    case "$_gate_shim_arg" in\n'
        printf '        *%s*)\n' "$prefix"
        printf '%s\n' '            command -p mkdir "$@"'
        printf '%s\n' '            _gate_shim_rc=$?'
        printf '%s\n' '            sleep 5'
        printf '%s\n' '            exit "$_gate_shim_rc"'
        printf '%s\n' '            ;;'
        printf '%s\n' '    esac'
        printf '%s\n' 'done'
        printf '%s\n' 'exec command -p mkdir "$@"'
    } >"$shim_dir/mkdir"
    chmod +x "$shim_dir/mkdir"

    local was_monitor=0
    case "$-" in
        *m*) was_monitor=1 ;;
    esac
    set -m

    TMPDIR="$iso_parent" PATH="$shim_dir:$PATH" bash "$script" \
        >"$state_dir/child.out" 2>"$state_dir/child.err" &
    local child_pid=$!

    local target="" waited=0
    while [ "$waited" -lt 200 ]; do
        target=$(command find "$iso_parent" -maxdepth 1 -type d -name "${prefix}*" 2>/dev/null | command head -n1)
        if [ -n "$target" ]; then
            break
        fi
        sleep 0.1
        waited=$((waited + 1))
    done

    if [ -z "$target" ]; then
        kill -INT -- "-$child_pid" 2>/dev/null
        wait "$child_pid" 2>/dev/null
        [ "$was_monitor" -eq 0 ] && set +m
        fail "$label: no ${prefix}* run directory appeared under $iso_parent within 20s (see $state_dir/child.err)"
        return
    fi

    kill -INT -- "-$child_pid"
    wait "$child_pid"
    local status=$?

    [ "$was_monitor" -eq 0 ] && set +m

    if [ "$status" -ne 0 ]; then
        pass "$label: $script exited non-zero/signal ($status) after whole-process-group SIGINT"
    else
        fail "$label: $script exited 0 after whole-process-group SIGINT (expected non-zero/signal)"
    fi

    if [ -e "$target" ]; then
        fail "$label: run directory $target still present after SIGINT + wait (cleanup did not run or did not know RUN_TMP_DIR)"
    else
        pass "$label: run directory $target removed after SIGINT + wait"
    fi
}
