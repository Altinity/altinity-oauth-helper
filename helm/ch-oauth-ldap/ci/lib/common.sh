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
# returns success) if FILE does not exist or nothing matches -- callers
# never need to guard against a nonzero exit status from this function.
gate_line_count() {
    local file="$1" pattern="$2" mode="${3:-F}" n grep_flag rg_flag

    if [ ! -f "$file" ]; then
        printf '%s\n' 0
        return 0
    fi

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
            fail "gate_line_count: unknown MODE '$mode' (want F or E)"
            printf '%s\n' 0
            return 0
            ;;
    esac

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
    n=$(gate_line_count "$file" "$pattern" "$mode")
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
    n=$(gate_line_count "$file" "$pattern" "$mode")
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
    n=$(gate_line_count "$file" "$pattern" "$mode")
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
# Uses an existing `kubeconform` on PATH if present. Otherwise installs the
# pinned $KUBECONFORM_VERSION with `go install` into BIN_DIR (never the
# unpinned "latest" tag). Sets $KUBECONFORM_BIN to the resolved binary
# path. Requires network access to the Go module proxy only in the
# install path.
ensure_kubeconform() {
    local bin_dir="$1"

    if command -v kubeconform >/dev/null 2>&1; then
        KUBECONFORM_BIN=$(command -v kubeconform)
        note "using kubeconform already on PATH: $KUBECONFORM_BIN"
        return 0
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
    note "installed kubeconform at $KUBECONFORM_BIN"
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

# print_gate_pins
# Prints the reproducibility pins this gate relies on. test.sh calls this
# in its header output so a run's log records exactly which kubeconform
# version and schema commit were used.
print_gate_pins() {
    printf 'KUBECONFORM_VERSION=%s\n' "$KUBECONFORM_VERSION"
    printf 'KUBECONFORM_SCHEMA_COMMIT=%s\n' "$KUBECONFORM_SCHEMA_COMMIT"
    printf 'KUBECONFORM_SCHEMA_LOCATION=%s\n' "$KUBECONFORM_SCHEMA_LOCATION"
}
