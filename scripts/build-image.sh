#!/usr/bin/env bash
# build-image.sh — build & push the ch-jwt-verify sidecar image.
#
# Publication is deliberately append-only: a sidecar-<sha> manifest and all
# of its per-architecture tags are refused if they already exist. The image
# is built from a git archive of HEAD in a private temporary directory, never
# from the checkout. The status check below is only a convenient early error;
# the archive prevents ignored or assume-unchanged local files from being
# compiled into a published image.

set -euo pipefail

# Do not let a caller forge the marker that skips the committed-script re-exec
# or nominate an arbitrary file for cleanup. exec keeps a process's PID, so a
# child started by this script can prove its marker while a fresh invocation
# cannot supply the right value in advance.
if [[ "${_CH_JWT_VERIFY_IMAGE_SELF_VERIFIED:-}" != "$$" ]]; then
    unset _CH_JWT_VERIFY_IMAGE_SELF_COPY _CH_JWT_VERIFY_IMAGE_SELF_VERIFIED
fi

RUN_TMP_DIR=""
_CH_JWT_VERIFY_IMAGE_SELF_COPY="${_CH_JWT_VERIFY_IMAGE_SELF_COPY:-}"
cleanup() {
    local rc=$?
    set +e
    [[ -z "${_CH_JWT_VERIFY_IMAGE_SELF_COPY:-}" ]] || rm -f "$_CH_JWT_VERIFY_IMAGE_SELF_COPY"
    [[ -z "${RUN_TMP_DIR:-}" ]] || rm -rf "$RUN_TMP_DIR"
    exit "$rc"
}
trap cleanup EXIT INT TERM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
export REPO
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/ch-jwt-verify}"
ARCHES="${ARCHES:-amd64 arm64}"
TAG_PREFIX="${1:-sidecar}"
ALPINE_BASE="alpine:3.24"

if [[ -n "${_CH_JWT_VERIFY_IMAGE_SELF_VERIFIED:-}" ]]; then
    repo_toplevel="$(git -C "$REPO" rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -z "$repo_toplevel" || "$repo_toplevel" != "$REPO" ]]; then
        echo "REPO ($REPO) does not match its git toplevel after self re-exec" >&2
        exit 1
    fi
fi

cd "$REPO"
# Keep Docker's build context outside /tmp by default. Some sandboxed Docker
# hosts reject /tmp bind-mount contexts; callers may still provide TMPDIR.
DEFAULT_TMP_ROOT="${HOME:-/tmp}"
TMPDIR="${TMPDIR:-$DEFAULT_TMP_ROOT/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR
umask 077

# Run the committed recipe, not a possibly assume-unchanged edit of this
# script. This matches the archive-based provenance of the source it builds.
if [[ -z "${_CH_JWT_VERIFY_IMAGE_SELF_VERIFIED:-}" ]] && git cat-file -e HEAD:scripts/build-image.sh 2>/dev/null; then
    _CH_JWT_VERIFY_IMAGE_SELF_COPY="$(mktemp "$TMPDIR/ch-jwt-verify-image-self.XXXXXXXX")"
    git show HEAD:scripts/build-image.sh >"$_CH_JWT_VERIFY_IMAGE_SELF_COPY"
    chmod 0700 "$_CH_JWT_VERIFY_IMAGE_SELF_COPY"
    export _CH_JWT_VERIFY_IMAGE_SELF_COPY
    export _CH_JWT_VERIFY_IMAGE_SELF_VERIFIED="$$"
    exec bash "$_CH_JWT_VERIFY_IMAGE_SELF_COPY" "$@"
fi

if ! git cat-file -e HEAD:Dockerfile 2>/dev/null; then
    echo "HEAD has no Dockerfile — refusing to publish" >&2
    exit 1
fi

# Fast-fail convenience only. The git archive below, not this status result,
# establishes the exact source tree used for the published image. Deliberately
# do not add --ignored=matching: ignored files cannot enter git archive HEAD,
# while rejecting every local editor cache/.env/node_modules directory creates
# false positives without strengthening that provenance guarantee.
DIRTY_STATUS="$(git status --porcelain --untracked-files=all)"
if [[ -n "$DIRTY_STATUS" ]]; then
    echo "refusing to publish from a dirty working tree (fast-fail convenience check); the build itself always uses git archive HEAD:" >&2
    printf '%s\n' "$DIRTY_STATUS" >&2
    exit 1
fi

SHA="$(git rev-parse --short=7 HEAD)"
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"
set -- $ARCHES

_TAG_NOT_FOUND_PATTERN='no such manifest|manifest unknown|name unknown|not found|404'

# Return 0 only when the registry explicitly says a ref is absent. An inspect
# error with any other response can be auth, network, or a registry failure;
# treating it as absence would allow an immutable tag to be overwritten.
check_tag_absent() {
    local ref="$1" out rc
    if out=$(docker manifest inspect "$ref" 2>&1); then
        return 1
    else
        rc=$?
    fi
    if printf '%s' "$out" | grep -qiE "$_TAG_NOT_FOUND_PATTERN"; then
        return 0
    fi
    echo "refusing to publish: cannot prove ${ref} is absent (docker manifest inspect exited ${rc}; ambiguous errors fail closed). Raw output:" >&2
    printf '%s\n' "$out" >&2
    exit 1
}

# Refuse a complete prior publication and partial prior publications alike.
EXISTING_TAGS=()
if ! check_tag_absent "${FULL}:${TAG}"; then
    EXISTING_TAGS+=("${FULL}:${TAG}")
fi
for arch in "$@"; do
    if ! check_tag_absent "${FULL}:${TAG}-${arch}"; then
        EXISTING_TAGS+=("${FULL}:${TAG}-${arch}")
    fi
done
if [[ ${#EXISTING_TAGS[@]} -gt 0 ]]; then
    echo "refusing to publish: immutable tag(s) already exist:" >&2
    printf '    %s\n' "${EXISTING_TAGS[@]}" >&2
    echo "publish from a new commit or use a different tag prefix; there is no force override" >&2
    exit 1
fi

# Assign the path before mkdir so the trap owns it even if interrupted during
# directory creation. A private directory contains both the exported source
# and the minimal per-arch Docker contexts.
for attempt in {1..10}; do
    printf -v suffix '%04x%04x%04x%04x' "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM"
    RUN_TMP_DIR="$TMPDIR/ch-jwt-verify-image.$suffix"
    if mkdir -m 700 "$RUN_TMP_DIR" 2>/dev/null; then
        break
    fi
    RUN_TMP_DIR=""
done
if [[ -z "$RUN_TMP_DIR" ]]; then
    echo "failed to create a private build directory under $TMPDIR" >&2
    exit 1
fi

SRC_DIR="$RUN_TMP_DIR/src"
mkdir -p "$SRC_DIR"
git archive --format=tar HEAD | tar -x -C "$SRC_DIR"
if [[ ! -f "$SRC_DIR/Dockerfile" ]]; then
    echo "Dockerfile missing from exported HEAD tree — refusing to publish" >&2
    exit 1
fi

build_one() {
    local arch="$1" ctx="$RUN_TMP_DIR/$1" got
    echo "==> $arch"
    mkdir -p "$ctx"
    (
        cd "$SRC_DIR"
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
            -ldflags="-s -w -X main.version=${TAG}" \
            -o "$ctx/ch-jwt-verify" ./cmd/ch-jwt-verify
    )
    chmod 0755 "$ctx/ch-jwt-verify"
    cp "$SRC_DIR/Dockerfile" "$ctx/Dockerfile"
    chmod 0644 "$ctx/Dockerfile"

    docker pull --platform "linux/$arch" "$ALPINE_BASE" >/dev/null
    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f "$ctx/Dockerfile" "$ctx" >/dev/null
    got=$(docker image inspect "${FULL}:${TAG}-${arch}" --format '{{.Architecture}}')
    if [[ "$got" != "$arch" ]]; then
        echo "ARCH MISMATCH for ${TAG}-${arch}: image says ${got}" >&2
        exit 1
    fi

    # Narrow the unavoidable registry TOCTOU window to immediately before
    # the mutating push; this also fails closed on an ambiguous re-inspect.
    if ! check_tag_absent "${FULL}:${TAG}-${arch}"; then
        echo "refusing to publish: ${FULL}:${TAG}-${arch} appeared while this build ran" >&2
        exit 1
    fi
    docker push "${FULL}:${TAG}-${arch}"
}

for arch in "$@"; do
    build_one "$arch"
done

if [[ $# -gt 1 ]]; then
    echo "==> manifest ${TAG}"
    docker manifest rm "${FULL}:${TAG}" 2>/dev/null || true
    manifest_args=()
    for arch in "$@"; do
        manifest_args+=("${FULL}:${TAG}-${arch}")
    done
    docker manifest create "${FULL}:${TAG}" "${manifest_args[@]}"
    # docker manifest create only prepares local state; this recheck is
    # immediately before the registry mutation that publishes the final tag.
    if ! check_tag_absent "${FULL}:${TAG}"; then
        echo "refusing to publish: ${FULL}:${TAG} appeared while this build ran" >&2
        exit 1
    fi
    docker manifest push "${FULL}:${TAG}"
fi

echo "✓ pushed:"
for arch in "$@"; do
    echo "    ${FULL}:${TAG}-${arch}"
done
if [[ $# -gt 1 ]]; then
    echo "    ${FULL}:${TAG}     (multi-arch manifest)"
fi
