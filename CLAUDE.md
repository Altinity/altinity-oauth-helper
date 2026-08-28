# Contributor guide — altinity-oauth-helper

Go module providing OAuth/JWT helpers for ClickHouse-fronted deployments.
Two binaries ship today:

- `ch-jwt-verify`: a sidecar HTTP server that ClickHouse's
  `<http_authentication_servers>` calls to validate a JWT that upstream
  consumers have repacked as an HTTP Basic password (`base64(email:jwt)`).
- `ch-oauth-ldap`: a standalone LDAPv3 server where the simple-Bind password
  is the JWT; it authenticates via the same shared verifier and exposes the
  caller's mapped ClickHouse roles as synthetic LDAP groups over a
  same-connection restricted Search. Verified end to end against real
  ClickHouse (`altinity/clickhouse-server` 24.8 baseline and 25.8) by the
  manual suite in `integration/clickhouse/`; the working ClickHouse LDAP
  config and the per-version distributed-role caveats are documented in
  `README.md`.

See `README.md` for the full wire diagram and rationale (OSS ClickHouse has
no native Bearer/JWT auth path; Antalya does).

## Repo map

| Path | What |
|---|---|
| `cmd/ch-jwt-verify/` | the sidecar binary — `main.go` (CLI/server wiring), `config.go` (YAML config), `settings.go`, `verify.go` (the `/verify` handler: JWT validation, cache-key binding, identity policy), `verify_test.go` |
| `cmd/ch-oauth-ldap/` | the standalone LDAPv3 server binary — `main.go` (CLI/signal-context/lifecycle wiring: verifier + role pipeline + `internal/ldap.Server`), `config.go` (YAML config, defaults, fail-startup validation, conversion into `verification.Config`/`identity.Config`/`roles.Config`/`internal/ldap.Config`), `config_test.go` (incl. `testdata/operator-guide.yaml` loaded through production `LoadConfig` and strict-decoded with `KnownFields(true)` — the proof backing `docs/ch-oauth-ldap-operator-guide.md`'s YAML fences), `main_test.go` |
| `internal/ldap/` | LDAP protocol package consumed by `cmd/ch-oauth-ldap` — `server.go` (lifecycle/handler-source wiring, dependency-logger suppression, connection cap, timeouts), `controls.go` (unsupported-critical-control guard), `session.go` (per-connection authenticated state), `dn.go` (RFC 4514 Bind-DN parsing/validation), `filter.go` (structural Search-filter authorization), `bind.go`/`search.go`/`unsupported.go` (the LDAP operation handlers, incl. Search sizeLimit/timeLimit/typesOnly enforcement and safe numeric-only Search telemetry), `entry.go` (synthetic `groupOfNames` rendering), plus `*_test.go` including a real-TCP `protocol_test.go` and `adversarial_test.go` |
| `internal/securitytest/` | phase-5 automated security verification, not itself security-relevant production code (see its `doc.go`) — `redaction_inventory_test.go` (AST-enumerates every log/error/response-construction sink across the command/internal packages plus the vendored `third_party/ldapserver` fork and cross-checks `testdata/redaction-sites.tsv`), `sdk_contract_test.go` (pinned `go-mcp-oauth-sdk` version + no-replace + strict-entrypoint AST checks), `release_gate_test.go` (`-tags phase5release` only: fails while any manifest row is `blocked_external`, per amendment A1 — see "Build & test" below), `docs_contract_test.go` (every `config-source`-marked YAML/XML fence in `README.md`/`docs/*.md` is an exact contiguous excerpt of its real source file; required/forbidden HA-and-trust-boundary wording; the stale-1-MiB-comment guard) |
| `docs/` | `ch-oauth-ldap-operator-guide.md` — consolidates (does not restate) the working ClickHouse config, OIDC/Auth0/JWKS field reference, identity/role-pipeline behavior, the cache invariant, measured ClickHouse Search-limit behavior (scenario G'), the plaintext-bearer trust boundary, and HA/capacity incl. the Kubernetes runbook. Every fence in it is enforced against its real source by `internal/securitytest/docs_contract_test.go` |
| `integration/clickhouse/` | real-ClickHouse acceptance suite for `ch-oauth-ldap` — `run.sh` (4-service Docker fixture: synthetic IdP + helper + two ClickHouse nodes, preflight, sources `scenarios/*.sh` A–I plus phase-5 scenario G' Search-limit compatibility), `run-all-builds.sh` (every build in `lib/expectations.sh`), `lib/expectations.sh` (per-ClickHouse-version expected outcomes for the two tracked upstream bugs, #78791/#79099 and #116840, plus scenario G's per-build Search-limit-overflow outcome), `scenarios/65-ldap-search-limits.sh` (scenario G'), `clickhouse/common/config.d/ldap.xml` (the working LDAP config `README.md` copies, incl. `<search_limit>256</search_limit>`), `compose-ha.yml`/`run-ha.sh`/`ha/` (phase-5 Docker HA harness: HAProxy frontend + two independent replicas + a persistent same-socket session probe — see `docs/ch-oauth-ldap-operator-guide.md` §8 for its exact claim boundary versus the Kubernetes runbook). Manual/local gate, not CI; see `integration/clickhouse/README.md` |
| `cmd/synthetic-idp/` | a controllable in-process test IdP (imported from altinity-mcp) used by examples/local dev and the integration suite (`/sign` mints RS256 JWTs, repeatable `role=` → `roles` claim) — not part of the shipped image |
| `helm/ch-jwt-verify/` | Helm chart — ConfigMaps (sidecar config, CH `http_authentication_servers` XML) + a reusable container fragment (`_helpers.tpl`) for sidecar mode, plus a standalone Deployment+Service mode; see `helm/ch-jwt-verify/README.md` |
| `helm/ch-oauth-ldap/` | standalone Helm chart for the environment-level LDAP deployment — two-replica Deployment, internal-only `ClusterIP` Service on 389, default-on source-restricting NetworkPolicy, PDB, and the two ConfigMaps (helper config, CH LDAP XML); committed local gate is `helm/ch-oauth-ldap/test.sh` (render/negative-matrix/embedded-content/packaging/actionlint checks, plus its own `ci/` fixtures) — see `helm/ch-oauth-ldap/README.md` |
| `examples/` | consumer × deploy-style recipes (`_platform` is the shared Dex+Postgres+ClickHouse+sidecar base every consumer overlay layers on); `examples/README.md` tracks the working/planned/broken matrix |
| `scripts/build-image.sh` | multi-arch (`amd64`+`arm64`) build & push for `ghcr.io/altinity/ch-jwt-verify`, legacy `DOCKER_BUILDKIT=0` |
| `scripts/build-ch-oauth-ldap-image.sh` | multi-arch (`amd64`+`arm64`) build & push for `ghcr.io/altinity/ch-oauth-ldap`, mirrors `build-image.sh`'s legacy `DOCKER_BUILDKIT=0` convention; never compiles into the checkout, and builds only from an exported `git archive HEAD` tree (never the live working tree); refuses to republish an already-existing tag (no force override) |
| `scripts/build-synthetic-idp-image.sh` | image build for the synthetic IdP used in examples |
| `Dockerfile` / `Dockerfile.synthetic-idp` / `Dockerfile.ch-oauth-ldap` | consumed by the three build scripts above (`Dockerfile.ch-oauth-ldap` by `scripts/build-ch-oauth-ldap-image.sh`) |
| `.github/workflows/build-ch-oauth-ldap.yml` | push-to-main image publication for `ghcr.io/altinity/ch-oauth-ldap` (tag `ldap-<short-sha>`), mirroring `build-ch-jwt-verify.yml`'s structure |

JWKS fetching, JWT validation, and identity-policy helpers (verified-email,
allowed domains, `iss`/`aud` checks) live upstream in
[`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk).
This repo consumes that module via `go.mod` and should not re-implement or
fork that logic — extend the SDK instead when the need is generic (not
`ch-jwt-verify`-specific).

## Build & test

- `go build ./...` — compiles all binaries (`ch-jwt-verify`, `ch-oauth-ldap`, `synthetic-idp`).
- `go test ./...` — the test suite; `cmd/ch-jwt-verify/verify_test.go` spins
  up an in-process test IdP (RSA-signed JWTs against an httptest JWKS
  server) rather than depending on any shared fixture, since the sidecar is
  independent of any e2e test elsewhere. There is no coverage gate. There
  are **two** push-to-main image-publication workflows —
  `.github/workflows/build-ch-jwt-verify.yml` (path-filtered to
  `cmd/ch-jwt-verify/**`, `go.mod`/`go.sum`, `Dockerfile`) and
  `.github/workflows/build-ch-oauth-ldap.yml` (path-filtered to
  `cmd/ch-oauth-ldap/**`, `internal/**`, `third_party/**`, `go.mod`/`go.sum`,
  `Dockerfile.ch-oauth-ldap`) — and **neither is a PR-time test/lint gate**;
  both only build+push an image on push to `main`. Run the gate yourself
  before calling a change done; write tests for new behavior, especially
  around cache-key isolation and identity-policy edge cases, since those are
  the security-relevant surface.
- `go vet ./...` before sending a change, plus
  `go vet -tags phase5release ./internal/securitytest` (amendment A5) so the
  release-gate build tag itself never bit-rots even though `go vet ./...`
  alone does not compile it.
- `go test ./internal/securitytest -count=1` — the redaction/SDK/docs
  consistency gate (see `internal/securitytest/doc.go`); this must stay
  green in normal development. `go test -tags phase5release
  ./internal/securitytest -count=1` is the separate, stricter final release
  gate — it is currently **expected to fail** on the known, externally-owned
  `go-mcp-oauth-sdk@v0.2.0` `kid`-rotation row while
  `SDK_REDACTION_AUTHORIZATION_GATE` remains open (coordinator amendment A1);
  do not treat that specific failure as a regression, and never silence it
  by relaxing the gate.
- `go test -race ./internal/ldap` — the LDAP package's race gate; run it
  whenever touching connection-local session state or the critical-control
  guard.
- `./integration/clickhouse/run.sh` (or `run-all-builds.sh`) — the real-ClickHouse
  integration suite; manual and Docker-based, not run by any workflow. Run it
  when touching `cmd/ch-oauth-ldap`, `internal/ldap`, or ClickHouse-facing config.
  `./integration/clickhouse/run-ha.sh` is the separate, also-manual Docker HA
  harness (`compose-ha.yml`/`ha/`) — run it when touching
  `internal/ldap`'s connection-local-state invariants or `cmd/ch-oauth-ldap`'s
  HA-relevant wiring; see `docs/ch-oauth-ldap-operator-guide.md` §8 for
  exactly what it does and does not prove versus the Kubernetes runbook.
- `helm/ch-oauth-ldap/test.sh` — the `ch-oauth-ldap` chart's committed local
  gate (render matrix, negative-render matrix, embedded-YAML/XML structural
  checks, kubeconform, packaging hygiene, and a pinned-actionlint validity
  check on `.github/workflows/build-ch-oauth-ldap.yml`, informational-only
  against `build-ch-jwt-verify.yml`). Like the Go gate, it is not run by any
  workflow — run it yourself when touching `helm/ch-oauth-ldap/**`.
- No Makefile, no linter config committed yet — if you add `golangci-lint`
  or similar, wire it into a real CI workflow in the same change, not just
  locally.

## Conventions

- **Commit messages**: Conventional-Commits style, `type(scope): summary`
  (e.g. `fix(ch-jwt-verify): bind verification cache key to username`,
  `feat(helm): standalone Deployment+Service mode for ch-jwt-verify`,
  `test(ch-jwt-verify): cover symmetric direction of cache-key isolation`).
  Scope is usually the binary/chart/dir touched (`ch-jwt-verify`, `helm`,
  `examples`, etc.).
- **No secrets in git.** `examples/*/superset-secrets.yaml` is gitignored
  (see `.gitignore`); the platform's Dex/ClickHouse configs checked in under
  `examples/_platform/` and `examples/curl/config.yaml` are demo
  configuration for the synthetic IdP, not real credentials — don't treat
  that as precedent for committing anything issued by a real IdP.
- **Sidecar trust model is load-bearing.** `ch-jwt-verify` is the *only*
  cryptographic gate on the auth path; the Helm chart's default mode
  deliberately renders no Deployment/StatefulSet because the sidecar must
  share a pod with ClickHouse (loopback-only exposure). Don't add a
  network-exposed deployment mode without preserving that trust boundary —
  the standalone Deployment+Service mode added in `feat(helm)` is for
  scenarios where the caller explicitly accepts a different trust model
  (document why, in the chart README, when you touch it).
- **`ch-oauth-ldap`'s environment-level trust model is a distinct, separately
  accepted exception — it does not weaken the sidecar guidance above.**
  Unlike `ch-jwt-verify`'s loopback-only sidecar, `ch-oauth-ldap` runs as its
  own environment-level Deployment behind a `ClusterIP` Service, so the OAuth
  bearer necessarily crosses a real network hop (ClickHouse → helper) as the
  LDAP simple-bind password, in clear text (`ADR #16` deviation; named risk
  owner Boris Tyshkevich / `@BorisTyshkevich`; see `README.md`). The
  compensating controls are: the Service stays `ClusterIP`-only with no
  public-exposure knobs, and the chart renders a default-on
  source-restricting NetworkPolicy that fails closed on every allow-all
  ClickHouse selector shape (empty, nested-empty, and `DoesNotExist`/`NotIn`-
  only expressions, which match everything lacking the key) — but a
  NetworkPolicy is reachability control, not
  transport confidentiality, so don't describe it as one in docs or review.
  Removing the exception means TLS on the LDAP listener or moving to a
  loopback sidecar, not relaxing the NetworkPolicy default.
- **Cache-key correctness is a security property, not a perf detail.** The
  `/verify` response cache key must stay bound to the identity the JWT
  authenticates as (see `e2be32a fix(ch-jwt-verify): bind verification cache
  key to username` and its test in `a43aa3b`) — a change to caching here
  needs a test proving isolation in both directions, not just a happy path.

## Working discipline

- Keep `README.md`, `examples/README.md`'s capability matrix,
  `docs/ch-oauth-ldap-operator-guide.md`, and both Helm charts' own READMEs
  in sync with behavior changes in the same commit — this is the complete
  set of docs in this repo, and `internal/securitytest/docs_contract_test.go`
  only enforces that marked config fences don't drift from their source, not
  that prose elsewhere stays current — a stale unmarked paragraph is still a
  docs bug a test won't catch.
- There is no PR-time CI gate. Before calling a change done, actually run
  `go build ./...`, `go vet ./...`, and `go test ./...` yourself rather than
  assuming a gate will catch it.
