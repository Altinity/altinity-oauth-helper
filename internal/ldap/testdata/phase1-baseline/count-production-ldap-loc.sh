#!/usr/bin/env bash
# Phase-1 immutable baseline: production-reachable LDAP LOC counter.
#
# Derives the production-reachable package set from
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps ./cmd/ch-oauth-ldap
# and counts physical lines (including comments, blanks, and a final
# unterminated line) of repository-owned, non-test, compiled .go files in
# whichever reachable packages fall under internal/ldap, third_party/goldap,
# or third_party/ldapserver. Command glue, module-cache code, and any
# package under those roots that is NOT production-reachable are excluded,
# along with every *_test.go file.
#
# This script and its committed output (production-ldap-loc.tsv) are a
# historical Phase-1 snapshot: never rewritten merely because a later phase
# changes production. Run it only to confirm the tsv still reproduces; do
# not regenerate the tsv from a modified tree.
#
# Must be run from the module root.
set -euo pipefail

if [ ! -f go.mod ]; then
  echo "count-production-ldap-loc.sh: must be run from the module root (no go.mod here)" >&2
  exit 1
fi

roots=(internal/ldap third_party/goldap third_party/ldapserver)

module_root="$(pwd -P)"

# Reachable package directories, from the same go list invocation the plan
# pins for the production dependency baseline (§4.2/§4.3).
deps_dirs="$(GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f '{{.Dir}}' ./cmd/ch-oauth-ldap)"

printf 'root\tfile\tlines\n'

grand_total=0
any_root_matched=0
for root in "${roots[@]}"; do
  root_abs="$module_root/$root"

  # Reachable package directories at or under this root (prefix match, not
  # just an exact hit on the root itself) — third_party/goldap's reachable
  # package is third_party/goldap/message, not third_party/goldap.
  pkg_dirs="$(printf '%s\n' "$deps_dirs" | LC_ALL=C sort -u | while IFS= read -r d; do
    if [ "$d" = "$root_abs" ] || case "$d" in "$root_abs"/*) true ;; *) false ;; esac; then
      printf '%s\n' "$d"
    fi
  done)"

  [ -n "$pkg_dirs" ] || continue
  any_root_matched=1

  root_total=0
  while IFS= read -r pkg_dir; do
    [ -n "$pkg_dir" ] || continue
    while IFS= read -r f; do
      lines="$(awk 'END{print NR}' "$f")"
      rel="${f#"$module_root"/}"
      printf '%s\t%s\t%s\n' "$root" "$rel" "$lines"
      root_total=$((root_total + lines))
    done < <(command find "$pkg_dir" -maxdepth 1 -name '*.go' ! -name '*_test.go' | LC_ALL=C sort)
  done <<<"$pkg_dirs"

  printf '%s\tTOTAL\t%s\n' "$root" "$root_total"
  grand_total=$((grand_total + root_total))
done

if [ "$any_root_matched" -eq 0 ]; then
  echo "count-production-ldap-loc.sh: no production-reachable packages found under: ${roots[*]}" >&2
  exit 1
fi

printf 'ALL\tGRAND_TOTAL\t%s\n' "$grand_total"
