# Contributor guide — altinity-oauth-helper

Go module providing OAuth/JWT helpers for ClickHouse-fronted deployments.
The only shipped binary today is `ch-jwt-verify`: a sidecar HTTP server that
ClickHouse's `<http_authentication_servers>` calls to validate a JWT that
upstream consumers have repacked as an HTTP Basic password
(`base64(email:jwt)`). See `README.md` for the full wire diagram and
rationale (OSS ClickHouse has no native Bearer/JWT auth path; Antalya does).

## Repo map

| Path | What |
|---|---|
| `cmd/ch-jwt-verify/` | the sidecar binary — `main.go` (CLI/server wiring), `config.go` (YAML config), `settings.go`, `verify.go` (the `/verify` handler: JWT validation, cache-key binding, identity policy), `verify_test.go` |
| `cmd/synthetic-idp/` | a controllable in-process test IdP (imported from altinity-mcp) used by examples/local dev — not part of the shipped image |
| `helm/ch-jwt-verify/` | Helm chart — ConfigMaps (sidecar config, CH `http_authentication_servers` XML) + a reusable container fragment (`_helpers.tpl`) for sidecar mode, plus a standalone Deployment+Service mode; see `helm/ch-jwt-verify/README.md` |
| `examples/` | consumer × deploy-style recipes (`_platform` is the shared Dex+Postgres+ClickHouse+sidecar base every consumer overlay layers on); `examples/README.md` tracks the working/planned/broken matrix |
| `scripts/build-image.sh` | multi-arch (`amd64`+`arm64`) build & push for `ghcr.io/altinity/ch-jwt-verify`, legacy `DOCKER_BUILDKIT=0` |
| `scripts/build-synthetic-idp-image.sh` | image build for the synthetic IdP used in examples |
| `Dockerfile` / `Dockerfile.synthetic-idp` | consumed by the two build scripts above |

JWKS fetching, JWT validation, and identity-policy helpers (verified-email,
allowed domains, `iss`/`aud` checks) live upstream in
[`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk).
This repo consumes that module via `go.mod` and should not re-implement or
fork that logic — extend the SDK instead when the need is generic (not
`ch-jwt-verify`-specific).

## Build & test

- `go build ./...` — compiles both binaries.
- `go test ./...` — the test suite; `cmd/ch-jwt-verify/verify_test.go` spins
  up an in-process test IdP (RSA-signed JWTs against an httptest JWKS
  server) rather than depending on any shared fixture, since the sidecar is
  independent of any e2e test elsewhere. There is no coverage gate, and
  `.github/workflows/build-ch-jwt-verify.yml` only builds+pushes the image on
  push to `main` (path-filtered to `cmd/ch-jwt-verify/**`, `go.mod`/`go.sum`,
  `Dockerfile`) — it is not a PR-time test/lint gate. Run the gate yourself
  before calling a change done; write tests for new behavior, especially
  around cache-key isolation and identity-policy edge cases, since those are
  the security-relevant surface.
- `go vet ./...` before sending a change.
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
- **Cache-key correctness is a security property, not a perf detail.** The
  `/verify` response cache key must stay bound to the identity the JWT
  authenticates as (see `e2be32a fix(ch-jwt-verify): bind verification cache
  key to username` and its test in `a43aa3b`) — a change to caching here
  needs a test proving isolation in both directions, not just a happy path.

## Working discipline

- Keep `README.md`, `examples/README.md`'s capability matrix, and the Helm
  chart's own README in sync with behavior changes in the same commit —
  they're the only docs in this repo, so a stale one is the only docs bug
  there is.
- There is no PR-time CI gate. Before calling a change done, actually run
  `go build ./...`, `go vet ./...`, and `go test ./...` yourself rather than
  assuming a gate will catch it.
