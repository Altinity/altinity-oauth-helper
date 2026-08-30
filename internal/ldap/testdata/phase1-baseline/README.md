# Phase-1 immutable baselines (Issue #33)

These files are **historical snapshots** of the pre-Phase-1 source tree —
recorded on the unmodified `origin/main` commit `e9c7c3c` before any Issue
#33 work (this directory's own introduction included). They are never
rewritten merely because a later phase intentionally changes production
behavior, dependencies, or LOC.

They exist so Phase 3/4 of Issue #33 (and any later review) can compare an
approved change against the actual pre-rewrite state, rather than against
whatever the tree happened to look like at some other point in time.

Do not edit or regenerate any file in this directory after this baseline
sub-task lands, even when the numbers it recorded become "stale" relative
to current `main` — that staleness is the point. If a later phase needs a
*live*, intentionally-updated expectation (e.g. the production dependency
closure after an approved dependency deletion), that lives in
`internal/securitytest/testdata/production-nonstdlib-deps.txt`, a
deliberately separate, mutable file — see plan-33p1.md §5.

## Files

| File | What |
|---|---|
| `source-head.txt` | HEAD sha this baseline was recorded from, plus confirmation it equals `origin/main`. |
| `toolchain.txt` | `go version` and the pinned `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go env GOVERSION GOOS GOARCH CGO_ENABLED` output. |
| `production-deps.txt` | Full `go list -deps ./cmd/ch-oauth-ldap` output (stdlib included). |
| `production-nonstdlib-deps.txt` | Non-standard-library production dependency closure, normalized/sorted exactly as plan §4.2 specifies. These exact bytes were copied verbatim into the live `internal/securitytest/testdata/production-nonstdlib-deps.txt` expectation at initialization. |
| `count-production-ldap-loc.sh` | Deterministic script deriving the production-reachable package set from `go list -deps ./cmd/ch-oauth-ldap` and counting physical lines (including comments/blanks/a final unterminated line) of repository-owned, non-test `.go` files under `internal/ldap`, `third_party/goldap`, `third_party/ldapserver`. |
| `production-ldap-loc.tsv` | Committed output of the script above: per-file rows, per-root `TOTAL` rows, and a grand `ALL GRAND_TOTAL` row. |
| `security-inventory-baseline.txt` | Snapshot of the `redaction-sites.tsv` rows for scopes `cmd/ch-oauth-ldap`, `internal/ldap`, `third_party/ldapserver`; sha256 of the redaction inventory implementation + manifest; the current fixed six-entry `scopeDirs` list; an explicit record that `third_party/goldap` is not an AST-enumerated scope; an explicit record that `integration/clickhouse/ha/session-probe` is credential-bearing integration tooling outside `scopeDirs` (a pre-existing gap, not claimed covered); and the pass result of the existing redaction inventory tests on this tree. |
| `clickhouse-matrix.tsv` | The historical ClickHouse build-matrix baseline (plan §4.5): compact per-image rows (exact image, result, Docker image ID, RepoDigest where present) from a `run-all-builds.sh` run predating any Issue #33 change. Committed verbatim, not regenerated, for the same immutability reason as every other file above; only the verbose transcript is deliberately not committed. |
