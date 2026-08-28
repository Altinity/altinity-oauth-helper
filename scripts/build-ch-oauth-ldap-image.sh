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
#     The tag is derived from `git rev-parse HEAD`, and the build compiles
#     an EXPORTED copy of exactly that HEAD commit (via `git archive HEAD`
#     into this script's own owned temp dir) — never $REPO's working tree.
#     That export is the actual correctness mechanism for "one tag, one
#     manifest": a bare `git status --porcelain` check (even strengthened
#     with --untracked-files=all) can still be fooled by `git config
#     status.showUntrackedFiles no`, or by a tracked file marked
#     --assume-unchanged/--skip-worktree — both of which `go build` against
#     the live tree would happily compile in anyway. A .gitignore'd file
#     sitting in a package directory is NOT a bypass of anything, precisely
#     because of this export: `git archive HEAD` reads only the committed
#     tree, so a gitignored file can never reach the build regardless of
#     what `git status` reports about it — this is also why the check below
#     deliberately does NOT pass --ignored=matching (dropped in review pass
#     3): flagging every gitignored path in the tree (editor state,
#     `.env` files, `node_modules/`, ...) as a fatal "dirty tree" had real
#     false-positive cost on an ordinary long-lived dev checkout and zero
#     correctness payoff once this export is what the build actually reads
#     from. The `git status` check below is kept only as a fast-fail UX
#     convenience (a clearer message than a mid-build failure) for the two
#     things that DO matter to a human even though they can't reach the
#     build either (an uncommitted change looks like it should be in the
#     tag but silently isn't) — not as the guarantee.
#
#     The same tamper class applies to this script's OWN on-disk bytes, not
#     just the source tree: every check below (dirty-tree guard, tag-
#     republish guard, the archive export itself) would otherwise run from
#     whatever bytes bash happened to load at invocation, never re-read from
#     HEAD, so an --assume-unchanged tamper on this very file would be just
#     as invisible to `git status` as one on a .go file. Immediately below,
#     before any of those checks run, the script re-execs itself from `git
#     show HEAD:scripts/build-ch-oauth-ldap-image.sh` for exactly the same
#     reason the source tree is exported rather than trusted from disk.
#
#     Two things the re-exec'd child must not get wrong, both fixed here:
#     (1) REPO is computed from this script's OWN location (SCRIPT_DIR via
#     BASH_SOURCE[0]) -- in the re-exec'd child, BASH_SOURCE[0] is the temp
#     copy under $TMPDIR, so a naive re-derivation would resolve REPO to
#     $TMPDIR/.. instead of the real checkout. REPO is exported by the
#     parent (a location, not logic, so exporting it does not reopen the
#     tamper gap the re-exec closes) and the child re-validates it against
#     `git -C "$REPO" rev-parse --show-toplevel` before trusting it, so an
#     accidentally wrong/stale REPO value crossing the exec boundary is
#     caught rather than silently building the wrong tree. This is a
#     correctness/accident check, not a security boundary: a parent whose
#     own on-disk bytes are already compromised can skip the re-exec, the
#     export, or both -- there is no defense against that here. (2) the
#     parent's EXIT trap does not survive `exec` (the parent process is
#     overlaid, never runs its own trap), so the temp copy's path is
#     exported too and a single cleanup() (installed once, at the very top
#     of this script, before anything that can fail) removes it in whichever
#     process actually exits.
#
#     Before doing any build work, the script also refuses to publish a
#     `<prefix>-<sha>` tag (or any of its per-arch sub-tags) that already
#     exists in the registry — there is no force override. Republishing the
#     same commit is not guaranteed to reproduce the same manifest byte for
#     byte (the base image and toolchain can drift), so silently moving an
#     already-published tag is refused outright rather than risking two
#     different manifests behind one tag.
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

# --- neutralize caller-supplied private markers -----------------------------
# _CH_OAUTH_LDAP_IMAGE_SELF_COPY and _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED are
# BOTH meant to be private, internal-only state: the self re-exec section
# further down sets and exports them immediately before `exec`, so the
# re-exec'd child inherits them from the very same process (`exec` overlays
# the running program but never changes the process's own PID). Before this
# fix, a caller could set either directly -- `_CH_OAUTH_LDAP_IMAGE_SELF_COPY`
# to an arbitrary path, which the cleanup trap below unconditionally `rm
# -f`s on every exit, or `_CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED` to any
# non-empty value, which made the self re-exec section (guarded by a bare
# `-z` check) skip re-running from `git show HEAD:...` entirely -- the exact
# provenance step that neutralizes an on-disk tamper of this script's own
# bytes (see the header comment above). Bind the marker to something an
# external caller cannot supply in advance: this process's own PID ($$),
# which a legitimate re-exec'd child always inherits unchanged (exec
# preserves PID) but which a caller starting a *new* process cannot predict
# before that process exists. Any inherited value that does not match is
# untrusted -- reject both markers together, before the cleanup trap
# (installed immediately below) can act on a forged SELF_COPY, and before
# the Dockerfile precheck / self re-exec sections further down can honor a
# forged SELF_VERIFIED.
if [[ "${_CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED:-}" != "$$" ]]; then
    unset _CH_OAUTH_LDAP_IMAGE_SELF_COPY _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED
fi

# --- cleanup, installed FIRST, before anything else can fail ---------------
# A single EXIT/INT/TERM trap for every piece of private run state this
# script (or its self-re-exec'd child below) creates: RUN_TMP_DIR (the
# per-run build-context directory, assigned much later) and
# _CH_OAUTH_LDAP_IMAGE_SELF_COPY (the temp copy of this script's own HEAD
# bytes the self re-exec section creates, inherited by the child via the
# environment -- now that the block above neutralizes any value that did not
# survive a genuine self re-exec, this can only ever be empty or a path this
# same run itself created). Both are empty here; cleanup() tolerates that.
# Installed before the Dockerfile precheck, the self re-exec's own git/mkdir
# calls, or any other early exit, so a failure at any of those points still
# removes whatever this run has already created. Bash has exactly one EXIT
# trap -- combine both cleanup responsibilities into this one function
# rather than a second `trap` call later that would silently replace this
# one.
RUN_TMP_DIR=""
_CH_OAUTH_LDAP_IMAGE_SELF_COPY="${_CH_OAUTH_LDAP_IMAGE_SELF_COPY:-}"

cleanup() {
    local rc=$?
    set +e
    if [ -n "${_CH_OAUTH_LDAP_IMAGE_SELF_COPY:-}" ]; then
        rm -f "$_CH_OAUTH_LDAP_IMAGE_SELF_COPY"
    fi
    if [ -n "${RUN_TMP_DIR:-}" ]; then
        rm -rf "$RUN_TMP_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
# Exported so the self re-exec's child (below) inherits the REPO the PARENT
# computed from its own, real, on-disk location -- never re-derived from
# the child's own BASH_SOURCE[0], which points at a throwaway temp copy
# under $TMPDIR and would resolve REPO to $TMPDIR/.. instead of the real
# checkout.
export REPO
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/ch-oauth-ldap}"
ARCHES="${ARCHES:-amd64 arm64}"
TAG_PREFIX="${1:-ldap}"

# When $_CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED is already set, THIS process is
# the self-re-exec'd child (see the section below) -- re-validate the
# inherited REPO against its own git toplevel before trusting it, so an
# accidentally wrong or stale REPO value crossing the exec boundary (a
# tampered/confused parent, a stray exported REPO from an unrelated shell)
# is caught here rather than silently building the wrong tree. This is a
# correctness/accident check, not a security boundary: a parent whose own
# on-disk bytes are already compromised can skip the re-exec, the REPO
# export, or both -- there is no defense against that case, here or
# anywhere else in this script.
if [[ -n "${_CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED:-}" ]]; then
    _REPO_TOPLEVEL="$(cd "$REPO" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -z "$_REPO_TOPLEVEL" || "$_REPO_TOPLEVEL" != "$REPO" ]]; then
        echo "REPO ($REPO) does not match its own git toplevel (${_REPO_TOPLEVEL:-<none>}) after the self re-exec -- refusing to continue" >&2
        exit 1
    fi
    unset _REPO_TOPLEVEL
fi

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

# Per-run private state lives under $TMPDIR. Most Linux dev/CI hosts leave
# TMPDIR unset, so default it to $HOME/tmp rather than refusing to run —
# deliberately NOT /tmp: sandboxed Docker hosts (including the one this
# repo's integration fixture was developed on) block /tmp for container
# bind mounts, and the per-arch build contexts below are bind-mounted into
# the Docker build by `docker build`'s own context transfer. Defaulted here,
# ahead of every check below (including the self re-exec immediately
# following), so the self re-exec's own temp file has somewhere to live.
TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
export TMPDIR
umask 077

# Self re-exec from the committed HEAD bytes (review pass 3 finding): every
# check from here on — the dirty-tree guard, the tag-republish guard, the
# `git archive HEAD` export itself — must run from the committed recipe,
# not from whatever bytes happen to be sitting on disk for THIS script. An
# operator (or attacker) marking this very file `--assume-unchanged` and
# then editing it — e.g. deleting the tag-republish guard a few lines below
# — would otherwise be invisible to every `git status` flag combination
# while every check below silently ran the tampered logic, exactly the gap
# Finding 1 (git archive HEAD) closed for the source tree and
# Dockerfile.ch-oauth-ldap. Close it the same way: re-exec this script from
# `git show HEAD:<path>` before any of those checks run.
#
# Guarded by an env marker against the obvious infinite loop once relaunched
# (that env var is exported, so it survives across `exec`), and skipped
# entirely when $REPO's HEAD does not track this script at the expected
# path — this repo's own test gate deliberately runs this real script
# against throwaway repos that never commit a copy of it (they're testing
# unrelated properties), and there is no self-tamper channel to close when
# there is nothing at HEAD to compare against.
if [[ -z "${_CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED:-}" ]]; then
    _SELF_REL_PATH="scripts/build-ch-oauth-ldap-image.sh"
    if git cat-file -e "HEAD:$_SELF_REL_PATH" 2>/dev/null; then
        _SELF_HEAD_COPY=""
        for _sv_attempt in {1..10}; do
            printf -v _sv_suffix '%04x%04x' "$RANDOM" "$RANDOM"
            _sv_candidate="$TMPDIR/ch-oauth-ldap-image-self.$_sv_suffix"
            if (set -o noclobber; : >"$_sv_candidate") 2>/dev/null; then
                _SELF_HEAD_COPY="$_sv_candidate"
                unset _sv_suffix _sv_candidate _sv_attempt
                break
            fi
        done
        if [[ -z "$_SELF_HEAD_COPY" ]]; then
            echo "failed to create a unique self-verification file under $TMPDIR after 10 attempts" >&2
            exit 1
        fi
        # Assign into the already-trapped _CH_OAUTH_LDAP_IMAGE_SELF_COPY
        # (rather than installing a second, competing trap here) so the
        # single cleanup() installed at the very top of this script also
        # covers this file if anything between here and `exec` fails.
        # Exporting it is what lets the re-exec'd child -- a brand-new bash
        # process that reruns this whole script from the top -- learn the
        # path and remove it itself once the parent's own EXIT trap is
        # destroyed by `exec` (exec overlays the process; the parent never
        # runs its trap).
        _CH_OAUTH_LDAP_IMAGE_SELF_COPY="$_SELF_HEAD_COPY"
        export _CH_OAUTH_LDAP_IMAGE_SELF_COPY
        git show "HEAD:$_SELF_REL_PATH" >"$_SELF_HEAD_COPY"
        chmod 0700 "$_SELF_HEAD_COPY"
        # Bound to this process's own PID (see the marker-neutralization
        # block at the top of this script) rather than a fixed sentinel:
        # `exec` below preserves the PID, so the child's own top-of-script
        # check sees this same value for its own "$$" and trusts it, while
        # an external caller cannot know this PID before this process
        # exists.
        export _CH_OAUTH_LDAP_IMAGE_SELF_VERIFIED="$$"
        exec bash "$_SELF_HEAD_COPY" "$@"
    fi
    unset _SELF_REL_PATH
fi

# Fast-fail UX convenience only — NOT the correctness mechanism. This is a
# cheap, early, clear-message check for the common case of an obviously
# dirty tree. `--untracked-files=all` reports every untracked file
# individually (not collapsed to its containing directory), which is as
# strong as a `git status` invocation can usefully be made here — but it
# can still be bypassed: `git config status.showUntrackedFiles no` hides
# untracked files from `git status` entirely (overridden by the flag
# above), and a tracked file marked `--assume-unchanged` or
# `--skip-worktree` is hidden from `git status` regardless of any flag
# combination, even though `go build` still happily compiles whatever bytes
# are actually sitting on disk. The real guarantee — that the compiled
# image reflects exactly `HEAD`, nothing else — comes from the `git archive
# HEAD` export below (and, for this script's own bytes, the self re-exec
# above), which reads committed object-database content and is immune to
# both of those bypasses regardless of what `git status` reports. See the
# header comment for the full rationale.
DIRTY_STATUS="$(git status --porcelain --untracked-files=all)"
if [[ -n "$DIRTY_STATUS" ]]; then
    echo "refusing to publish: working tree at $REPO is not clean (fast-fail convenience check — see script header) — a ldap-<sha> tag must always identify exactly one manifest (see helm/ch-oauth-ldap/README.md), so canonical publication requires a clean tree. Commit or stash tracked changes; remove (or .gitignore) untracked files. Dirty paths:" >&2
    echo "$DIRTY_STATUS" >&2
    exit 1
fi

SHA=$(git rev-parse --short=7 HEAD)
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"

# ARCHES is fixed into positional parameters once, here, and reused by both
# the tag-existence guard immediately below and the per-arch build loop
# further down — one source of truth for "the arches this run publishes."
set -- $ARCHES

# Finding 2 — immutability enforcement, checked before any build/push work
# runs: refuse outright if this tag, or any of its per-arch sub-tags, has
# already been published. Re-running against the same commit is NOT
# guaranteed to reproduce the same manifest byte for byte
# (Dockerfile.ch-oauth-ldap's `alpine:3.24` base floats within its minor
# version, `apk add ca-certificates` is unpinned, and the Go toolchain can
# drift), so silently overwriting an already-published tag risks moving it
# to a different manifest. There is no force override: publish from a new
# commit, or pass a different tag-prefix argument.
#
# Review pass 4: a bare truthiness check on `docker manifest inspect`'s exit
# code cannot tell "manifest genuinely absent" apart from any OTHER failure
# (expired auth, a network/transport error, a registry 5xx) -- both come
# back nonzero, and treating every nonzero result as "tag absent" lets an
# operational failure silently wave publication through. Some registries
# make this worse: an unauthenticated (or under-scoped) `docker manifest
# inspect` against ghcr.io returns exit 1 with "denied" for a tag that is
# genuinely absent too, so exit code alone can never disambiguate the two on
# every registry. `check_tag_absent` instead requires an UNAMBIGUOUS
# "not found" signature in the inspect output before treating a tag as
# absent; any other nonzero result aborts the whole run rather than
# proceeding -- fail closed on doubt, per the tag-immutability guarantee
# documented in helm/ch-oauth-ldap/README.md.
_TAG_NOT_FOUND_PATTERN='no such manifest|manifest unknown|name unknown|not found|404'

# check_tag_absent REF
# Returns 0 (bash "true") if REF is confirmed absent from the registry, 1 if
# confirmed present (docker manifest inspect exited 0). Aborts the entire
# script — not just this check — if the inspect call fails in a way that is
# not a recognized "not found" response, since that failure could just as
# easily be an auth/transport/registry error masking a tag that actually
# exists.
#
# Note on `-euo pipefail` (set at the top of this script): the
# `out=$(...); rc=$?` capture inside this function looks like the same
# shape that had to be made errexit-safe (`if OUT=$(...); then RC=0; else
# RC=$?; fi`) in .github/workflows/build-ch-oauth-ldap.yml's two guard
# steps, but it is NOT broken here. Every call site below invokes this
# function as `if ! check_tag_absent ...`, and bash suspends `-e` for the
# entire duration of a command (including a function call) that appears as
# the condition of an `if`/`while`/`until`, or is negated with `!` — so a
# nonzero exit from `docker manifest inspect` inside the function body
# never triggers errexit here. Do not call this function outside such a
# context, or the same failure mode the workflow had would reappear.
check_tag_absent() {
    local ref="$1" out rc
    out=$(docker manifest inspect "$ref" 2>&1)
    rc=$?
    if [[ "$rc" -eq 0 ]]; then
        return 1
    fi
    if printf '%s' "$out" | grep -qiE "$_TAG_NOT_FOUND_PATTERN"; then
        return 0
    fi
    echo "refusing to publish: could not determine whether ${ref} already exists in the registry — 'docker manifest inspect' exited ${rc} with a response that is not a recognized \"not found\" signature, so this is being treated as an operational/transport/auth failure rather than proof the tag is absent (see helm/ch-oauth-ldap/README.md's tag-immutability guarantee). Fix the underlying registry-inspection error and re-run. Raw output:" >&2
    printf '%s\n' "$out" >&2
    exit 1
}

EXISTING_TAGS=()
if ! check_tag_absent "${FULL}:${TAG}"; then
    EXISTING_TAGS+=("${FULL}:${TAG}")
fi
for arch in "$@"; do
    if ! check_tag_absent "${FULL}:${TAG}-${arch}"; then
        EXISTING_TAGS+=("${FULL}:${TAG}-${arch}")
    fi
done
if [[ "${#EXISTING_TAGS[@]}" -gt 0 ]]; then
    echo "refusing to publish: the following tag(s) already exist in the registry and would be silently moved to a possibly different manifest:" >&2
    printf '    %s\n' "${EXISTING_TAGS[@]}" >&2
    echo "publish from a new commit, or pass a different tag-prefix argument. There is no force override." >&2
    exit 1
fi

# RUN_TMP_DIR and the single cleanup() EXIT/INT/TERM trap covering it (and
# the self re-exec's temp copy, if this run went through one) are already
# installed at the very top of this script — see the comment there. Nothing
# to (re-)install here; this comment block only covers RUN_TMP_DIR's own
# candidate-assignment ordering below.
#
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

# Finding 1 — the actual correctness mechanism. Export exactly the HEAD
# commit's tree into this run's owned temp dir via `git archive`, strictly
# before any docker preflight (the per-arch `docker pull`/`docker build`
# below): `git archive` reads content straight from the git object
# database keyed by the HEAD commit, so it is immune to
# status.showUntrackedFiles, .gitignore, and --assume-unchanged/
# --skip-worktree bits on $REPO's working tree — none of which the `git
# status` convenience check above can fully see. Every subsequent build
# step reads from $SRC_DIR, never from $REPO.
SRC_DIR="$RUN_TMP_DIR/src"
mkdir -p "$SRC_DIR"
git archive --format=tar HEAD | tar -x -C "$SRC_DIR"

if [[ ! -f "$SRC_DIR/Dockerfile.ch-oauth-ldap" ]]; then
    echo "Dockerfile.ch-oauth-ldap is missing from the exported HEAD tree at $SRC_DIR — HEAD does not look like a valid ch-oauth-ldap checkout" >&2
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

    # Compile from the exported HEAD tree ($SRC_DIR), never from $REPO's
    # working tree, directly into the owned temporary context — never `-o
    # ch-oauth-ldap` in the checkout, so no build artifact is ever left in
    # the repository root.
    (
        cd "$SRC_DIR" &&
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
            -ldflags="-s -w -X main.version=${TAG}" \
            -o "$ctx/ch-oauth-ldap" ./cmd/ch-oauth-ldap
    )

    # `umask 077` above keeps the run directory private, but it also makes
    # `go build` write the binary 0700. `COPY` preserves the source mode, the
    # image runs as UID 65532 (not the root owner), so a 0700 binary would
    # build fine and then fail to exec at container start. Normalize both
    # context files explicitly; Dockerfile.ch-oauth-ldap re-checks the mode
    # at build time.
    chmod 0755 "$ctx/ch-oauth-ldap"

    cp "$SRC_DIR/Dockerfile.ch-oauth-ldap" "$ctx/Dockerfile"
    chmod 0644 "$ctx/Dockerfile"

    docker pull --platform "linux/$arch" "$ALPINE_BASE" >/dev/null

    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f "$ctx/Dockerfile" "$ctx" >/dev/null

    local got
    got=$(docker image inspect "${FULL}:${TAG}-${arch}" --format '{{.Architecture}}')
    if [[ "$got" != "$arch" ]]; then
        echo "ARCH MISMATCH for ${TAG}-${arch}: image says ${got}" >&2
        exit 1
    fi

    # Narrow (not close — see the header rationale) the TOCTOU window
    # between the batch existence check above and this push: a concurrent
    # publisher (this script run manually, alongside an Actions run, on the
    # same commit) could have published this exact sub-tag in the time this
    # arch spent building. check_tag_absent aborts the whole run — fail
    # closed — the same way on an ambiguous inspect result here as it does
    # in the batch check.
    if ! check_tag_absent "${FULL}:${TAG}-${arch}"; then
        echo "refusing to publish: ${FULL}:${TAG}-${arch} was published by another run while this build was in progress — the tag-immutability guarantee means this run must not overwrite it. Publish from a new commit, or pass a different tag-prefix argument." >&2
        exit 1
    fi

    docker push "${FULL}:${TAG}-${arch}"
}

# Positional parameters ($@) were already set to $ARCHES above, before the
# tag-existence guard, so no second `set --` is needed here.
for arch in "$@"; do
    build_one "$arch"
done

if [[ "$#" -gt 1 ]]; then
    echo
    echo "==> manifest ${TAG}"
    # Recheck the shared final tag immediately before assembling it — not
    # just once, in the batch check at the top of this script, before any
    # of the (potentially long-running, per-arch) build/push work ran. A
    # concurrent publisher on the same commit could have published this
    # exact tag while this run's builds were in flight; check_tag_absent
    # aborts (fail closed) on both "it now exists" and any ambiguous
    # inspect failure, rather than silently moving it to a different
    # manifest.
    if ! check_tag_absent "${FULL}:${TAG}"; then
        echo "refusing to publish: ${FULL}:${TAG} was published by another run while this build was in progress — the tag-immutability guarantee means this run must not overwrite it. Publish from a new commit, or pass a different tag-prefix argument." >&2
        exit 1
    fi
    # This only clears any stale LOCAL manifest-list cache for this tag
    # (harmless if none exists, hence `|| true`) — it has no effect on the
    # registry, and is not part of the tag-existence enforcement above.
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
