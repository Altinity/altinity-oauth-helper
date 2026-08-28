#!/usr/bin/env bash
# build-ch-oauth-ldap-image.sh — build & push the ch-oauth-ldap standalone
# LDAP server image. Cross-compiles a static Go binary per arch into a
# private, owned temporary build context (never the repository checkout),
# runs legacy `docker build`, then assembles a multi-arch `docker manifest`.
# Mirrors scripts/build-image.sh's exact conventions for the sidecar image,
# adapted for ghcr.io/altinity/ch-oauth-ldap.
#
# Usage:
#   scripts/build-ch-oauth-ldap-image.sh [tag-prefix]
#     tag-prefix defaults to "ldap". Final tag: <tag-prefix>-<short-sha>,
#     e.g. ldap-49ecb42. Per-arch tags get -amd64 / -arm64 suffix. Only ever
#     immutable <prefix>-<sha> tags are published — never a mutable "main"
#     or "latest" alias.
#
# Env overrides:
#   REPO     — repo root (auto-detected from this script's location).
#   REGISTRY — defaults to ghcr.io.
#   IMAGE    — defaults to altinity/ch-oauth-ldap.
#   ARCHES   — space-separated arches; default "amd64 arm64".
#
# Shell lifecycle: all private run state (compiled binaries + a copy of
# Dockerfile.ch-oauth-ldap, one per arch) lives under a directory this
# script owns exclusively, $TMPDIR/ch-oauth-ldap-image.<random>, which the
# EXIT/INT/TERM trap below removes on every exit path — including a SIGINT
# landing mid-`mkdir` while that directory is being created. See the
# comments around RUN_TMP_DIR below for why the candidate path is assigned
# BEFORE `mkdir` runs rather than captured from mktemp's own directory-create
# mode after the fact
# (the same fix integration/clickhouse/run.sh applies to RUN_TMP_DIR there —
# see its comments and integration/clickhouse/tests/lib-tests.sh's findings
# 8/9 for the reproduced regression this avoids).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/ch-oauth-ldap}"
ARCHES="${ARCHES:-amd64 arm64}"
TAG_PREFIX="${1:-ldap}"

# The pinned base image the Dockerfile builds FROM (alpine:3.24 — see
# Dockerfile.ch-oauth-ldap). Pulled explicitly, per architecture, before
# each build below: the legacy (non-BuildKit) builder silently reuses
# whatever architecture of this image is already cached locally otherwise,
# which would let a stale wrong-arch base image slip into a "successfully
# built" arm64 (or amd64) image without the docker image inspect check
# below ever catching it as a build-context problem.
ALPINE_BASE="alpine:3.24"

if [[ ! -f "$REPO/Dockerfile.ch-oauth-ldap" ]]; then
    echo "Dockerfile.ch-oauth-ldap not found at $REPO — REPO does not look like an altinity-oauth-helper checkout" >&2
    exit 1
fi

cd "$REPO"

SHA=$(git rev-parse --short=7 HEAD)
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"

# Per-run private state lives under $TMPDIR. Most Linux dev/CI hosts leave
# TMPDIR unset, so default it to $HOME/tmp rather than refusing to run —
# deliberately NOT /tmp: sandboxed Docker hosts (including the one this
# repo's integration fixture was developed on) block /tmp for container
# bind mounts, and the per-arch build contexts below are bind-mounted into
# the Docker build by `docker build`'s own context transfer.
TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR
umask 077

# RUN_TMP_DIR is declared, and the cleanup trap installed, before any other
# per-run state exists — see integration/clickhouse/run.sh's identical
# ordering rationale: this closes the "SIGINT before the trap exists at
# all" window outright, and cleanup() below tolerates running with
# RUN_TMP_DIR still unset (the guard immediately below).
RUN_TMP_DIR=""

cleanup() {
    local rc=$?
    set +e
    if [ -n "${RUN_TMP_DIR:-}" ]; then
        rm -rf "$RUN_TMP_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# RUN_TMP_DIR is deliberately NOT assigned from a directory-creating
# mktemp invocation run via command substitution: mktemp runs as a
# separate process, so there is an unavoidable gap between the moment its
# mkdir(2) syscall creates the directory and the moment this shell finishes
# the command substitution and assigns the path into RUN_TMP_DIR — a
# SIGINT landing in exactly that gap would leave RUN_TMP_DIR unset in
# cleanup() even though the trap is already live, leaking the just-created
# directory. Instead, pre-compute a collision-resistant candidate path
# (via printf -v + several $RANDOM values — a pure bash builtin operation,
# no filesystem state, no forked process) and assign it into RUN_TMP_DIR
# BEFORE calling `mkdir` on it. That assignment is a single in-process bash
# statement — bash only acts on a pending signal between simple commands,
# never mid-statement — so by the time the external `mkdir` runs,
# cleanup() already knows the path regardless of whether mkdir has created
# the directory yet, is interrupted mid-syscall, or never gets to run at
# all. Because the name is no longer handed out atomically by that
# mktemp idiom, plain `mkdir` can fail with EEXIST on a genuine collision;
# clear RUN_TMP_DIR and retry with a fresh candidate rather than assuming
# the first name is free, so cleanup() never targets a path this run did
# not itself create.
for _rt_attempt in {1..10}; do
    printf -v _rt_suffix '%04x%04x%04x%04x' "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM"
    _rt_candidate="$TMPDIR/ch-oauth-ldap-image.$_rt_suffix"
    RUN_TMP_DIR="$_rt_candidate"
    if mkdir -m 700 "$RUN_TMP_DIR" 2>/dev/null; then
        unset _rt_suffix _rt_candidate _rt_attempt
        break
    fi
    RUN_TMP_DIR=""
done
if [ -z "$RUN_TMP_DIR" ]; then
    echo "failed to create a unique run directory under $TMPDIR (ch-oauth-ldap-image.*) after 10 attempts" >&2
    exit 1
fi

# All other run state (per-arch build contexts) is created only now,
# strictly after RUN_TMP_DIR exists and the trap already owns it.
build_one() {
    local arch=$1
    local ctx="$RUN_TMP_DIR/$arch"
    echo
    echo "==> $arch"

    mkdir -p "$ctx"

    # Compile directly into the owned temporary context — never `-o
    # ch-oauth-ldap` in the checkout, so no build artifact is ever left in
    # the repository root.
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
        -ldflags="-s -w -X main.version=${TAG}" \
        -o "$ctx/ch-oauth-ldap" ./cmd/ch-oauth-ldap

    cp "$REPO/Dockerfile.ch-oauth-ldap" "$ctx/Dockerfile"

    docker pull --platform "linux/$arch" "$ALPINE_BASE" >/dev/null

    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f "$ctx/Dockerfile" "$ctx" >/dev/null

    local got
    got=$(docker image inspect "${FULL}:${TAG}-${arch}" --format '{{.Architecture}}')
    if [[ "$got" != "$arch" ]]; then
        echo "ARCH MISMATCH for ${TAG}-${arch}: image says ${got}" >&2
        exit 1
    fi

    docker push "${FULL}:${TAG}-${arch}"
}

set -- $ARCHES
for arch in "$@"; do
    build_one "$arch"
done

if [[ "$#" -gt 1 ]]; then
    echo
    echo "==> manifest ${TAG}"
    docker manifest rm "${FULL}:${TAG}" 2>/dev/null || true
    manifest_args=()
    for arch in "$@"; do
        manifest_args+=("${FULL}:${TAG}-${arch}")
    done
    docker manifest create "${FULL}:${TAG}" "${manifest_args[@]}"
    docker manifest push "${FULL}:${TAG}"
fi

echo
echo "✓ pushed:"
for arch in "$@"; do
    echo "    ${FULL}:${TAG}-${arch}"
done
if [[ "$#" -gt 1 ]]; then
    echo "    ${FULL}:${TAG}     (multi-arch manifest)"
fi
