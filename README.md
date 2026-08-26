# altinity-oauth-helper

OAuth helpers for ClickHouse-fronted deployments. The first (and currently
only) helper is `ch-jwt-verify`: a tiny HTTP server that ClickHouse calls from
its `<http_authentication>` handler to validate JWT bearers.

## Why this exists

Native OAuth / JWT authentication isn't in stock OSS ClickHouse. Today you
get it in two places only:

- **ClickHouse Cloud** (commercial), where SSO + JWT login is wired into the
  managed control plane.
- **[Altinity Antalya][antalya]**, Altinity's ClickHouse fork, which accepts
  `Authorization: Bearer <jwt>` directly on the HTTP interface and validates
  it against a JWKS the server is configured to trust.

If you're running OSS ClickHouse outside Cloud, neither is available. The
workaround this repo implements is to lean on ClickHouse's built-in
[`<http_authentication_servers>`][ch-http-auth] mechanism: define an external
HTTP authenticator, point ClickHouse at it, and let *that* service do the JWT
validation. ClickHouse forwards the `Authorization` header to the helper on
every authenticated request and trusts a `200 OK` response.

`ch-jwt-verify` is that helper. The catch is that ClickHouse's HTTP auth
backend only understands HTTP **Basic** — there's no Bearer path on OSS — so
upstream consumers (Superset, Grafana, MCP servers, your own scripts) have to
repack the user's JWT as the Basic-auth password (`base64(email:jwt)`) before
calling ClickHouse. The helper then pulls the JWT back out of the password
field, verifies it (signature, `iss`/`aud`/`exp`, identity policy), and
either returns 200 or rejects. See the wire diagram below for the full path.

If you can run Antalya, do — the entire repacking trick + this sidecar go
away. This repo is the bridge for everyone still on OSS.

[antalya]: https://github.com/Altinity/ClickHouse
[ch-http-auth]: https://clickhouse.com/docs/operations/external-authenticators/http

## ch-jwt-verify

A single-binary sidecar designed to run colocated with a ClickHouse pod
(StatefulSet or Deployment). Wire contract:

```
client ── Authorization: Bearer <JWT> ──> upstream (MCP / Superset / Grafana / …)
                                          rewrites to
client ── Authorization: Basic base64(email:JWT) ──> ClickHouse :8123
                                          <http_authentication_servers>
                                                │
                                                ▼
                                   ch-jwt-verify GET/POST /verify
                                                │  validates signature, iss, aud,
                                                │  exp/nbf/iat, required scopes,
                                                │  identity policy (verified-email,
                                                │  allowed domains), user↔email match
                                                ▼
                                   200 + optional CH session settings  →  CH accepts query
                                   non-200                              →  CH returns 516 WRONG_PASSWORD
```

The sidecar is the only cryptographic gate on the path: the upstream is a
pure forwarder. Per-user provisioning on the CH side:

```sql
CREATE USER "alice@example.com"
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
```

(The grammar token is `http`, not `http_authenticator` — the latter is
rejected with `SYNTAX_ERROR`.)

## Quick start

### Run locally against an existing IdP

```bash
git clone https://github.com/altinity/altinity-oauth-helper
cd altinity-oauth-helper

$EDITOR examples/curl/config.yaml      # fill in issuer + audience
go run ./cmd/ch-jwt-verify -c examples/curl/config.yaml &

examples/curl/verify.sh alice@example.com "$JWT"
# → HTTP/1.1 200 OK
#   {"settings":null,"email":"alice@example.com"}
```

See [`examples/curl/README.md`](examples/curl/README.md)
for the failure-mode cheatsheet.

### Deploy alongside ClickHouse

The Helm chart in [`helm/ch-jwt-verify/`](helm/ch-jwt-verify/) renders two
ConfigMaps (sidecar YAML, CH `<http_authentication_servers>` XML) and a
reusable container fragment you splice into your CH pod spec. It does **not**
render a Deployment/StatefulSet — the sidecar must share a pod with
ClickHouse so the loopback trust model holds.

See [`helm/ch-jwt-verify/README.md`](helm/ch-jwt-verify/README.md) for the
wiring (including the clickhouse-operator `default` emptyDir quirk).

For worked end-to-end examples (Superset, Grafana, …), see
[`examples/`](examples/) — the [`examples/README.md`](examples/README.md)
matrix tracks which consumer × deploy-style combinations are working.

## Building images

**CI (default):** [`.github/workflows/build-ch-jwt-verify.yml`](.github/workflows/build-ch-jwt-verify.yml)
builds and pushes automatically on every push to `main` that touches
`cmd/ch-jwt-verify/**`, `go.mod`/`go.sum`, or the `Dockerfile` — tag
`sidecar-<short-sha>`, multi-arch (amd64+arm64), pushed to
`ghcr.io/altinity/ch-jwt-verify` using the repo's own `GITHUB_TOKEN` (no PAT
needed). Trigger a one-off build with a custom prefix via **Actions → Build &
push ch-jwt-verify image → Run workflow**.

**Manual / local:**

```bash
scripts/build-image.sh feature-strict-iss
# → ghcr.io/altinity/ch-jwt-verify:feature-strict-iss-<short-sha>
#   (multi-arch manifest + per-arch -amd64 / -arm64 tags)
```

The script cross-compiles statically-linked binaries for amd64+arm64, builds
with legacy `DOCKER_BUILDKIT=0`, pushes per-arch, and assembles the multi-arch
manifest. Image name stays at `ghcr.io/altinity/ch-jwt-verify` so existing
Helm values continue to work. The CI workflow does the same thing (buildx +
QEMU instead of Docker Desktop's built-in emulation) — use this locally when
you need a build from an unmerged branch or a sandbox without registry push
access.

## Layout

```
cmd/ch-jwt-verify/     # the sidecar binary (main, config, settings, verify)
helm/ch-jwt-verify/    # Helm chart (ConfigMaps + container fragment, no Deployment)
scripts/build-image.sh # multi-arch image build & push
examples/              # _platform shared compose base, plus curl / superset /
                       # grafana consumer overlays (see examples/README.md)
Dockerfile             # consumed by scripts/build-image.sh
```

JWKS fetching, JWT validation, and the shared identity-policy helpers live
in [`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk);
this repo consumes that module via `go.mod`.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
