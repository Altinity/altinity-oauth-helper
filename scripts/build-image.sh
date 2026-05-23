#!/usr/bin/env bash
# build-image.sh — build & push the ch-jwt-verify sidecar image.
# Cross-compiles a static Go binary per arch, runs legacy `docker build`,
# then assembles a multi-arch `docker manifest`.
#
# Usage:
#   scripts/build-image.sh [tag-prefix]
#     tag-prefix defaults to "sidecar". Final tag: <tag-prefix>-<short-sha>,
#     e.g. sidecar-49ecb42. Per-arch tags get -amd64 / -arm64 suffix.
#
# Env overrides:
#   REPO     — repo root (auto-detected from this script's location).
#   REGISTRY — defaults to ghcr.io.
#   IMAGE    — defaults to altinity/ch-jwt-verify (kept stable with the
#              prior altinity-mcp-shipped image so existing Helm values
#              continue to work).
#   ARCHES   — space-separated arches; default "amd64 arm64".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/ch-jwt-verify}"
ARCHES="${ARCHES:-amd64 arm64}"
TAG_PREFIX="${1:-sidecar}"

if [[ ! -f "$REPO/Dockerfile" ]]; then
    echo "Dockerfile not found at $REPO — REPO does not look like an altinity-oauth-helper checkout" >&2
    exit 1
fi

cd "$REPO"

SHA=$(git rev-parse --short=7 HEAD)
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"

cleanup() { rm -f "$REPO/ch-jwt-verify"; }
trap cleanup EXIT

build_one() {
    local arch=$1
    echo
    echo "==> $arch"

    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
        -ldflags="-s -w -X main.version=${TAG}" \
        -o ch-jwt-verify ./cmd/ch-jwt-verify

    docker pull --platform "linux/$arch" alpine:latest >/dev/null

    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f Dockerfile . >/dev/null

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
