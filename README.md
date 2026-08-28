# altinity-oauth-helper

OAuth helpers for ClickHouse-fronted deployments. Two binaries ship today:

- **`ch-jwt-verify`** — a tiny HTTP server that ClickHouse calls from its
  `<http_authentication_servers>` handler to validate JWT bearers repacked as
  a Basic-auth password.
- **`ch-oauth-ldap`** — a standalone LDAPv3 server that authenticates a
  simple Bind's password as a JWT and exposes the caller's mapped ClickHouse
  roles as synthetic LDAP groups, for consumers that speak LDAP rather than
  HTTP Basic.

Both share the same underlying JWT verification and identity-policy logic
from [`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk).

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

## ch-oauth-ldap

A standalone LDAPv3 server for consumers that authenticate over LDAP rather
than HTTP Basic. It speaks only simple Bind and a narrowly restricted Search
— there is no generic directory behind it:

- **LDAP-only.** No HTTP endpoint, no TLS/LDAPS/StartTLS, no SASL, no
  Add/Modify/Delete/Compare — those fail closed.
- **The simple-Bind password is the JWT.** The Bind DN's leading RDN
  (`uid=<username>,<user_base_dn>` by default) carries the requested
  username; the password field carries the raw JWT, exactly as
  `ch-jwt-verify` expects it packed into a Basic-auth password.
- **The shared verifier owns authentication and identity policy.** Signature,
  `iss`/`aud`/`exp`, and identity-policy checks (verified-email, allowed
  domains, deny-list) are the same `internal/verification` + `internal/roles`
  pipeline `ch-jwt-verify` uses — the LDAP layer does not reimplement any of
  it, and every failure class collapses into one generic `invalidCredentials`
  response so no failure reason is disclosed over the wire.
- **Roles are derived once at Bind and snapshotted** on that connection. A
  subsequent Search never re-verifies the JWT or recomputes roles — it reads
  only the stored snapshot.
- **Search is restricted to the caller's own membership.** A same-connection
  Search against the configured group base, with the documented
  `(&(objectClass=groupOfNames)(member=<bound DN>))` filter shape, returns one
  synthetic `groupOfNames` entry per mapped role (`cn` gets a configurable
  transport prefix, e.g. `clickhouse_ch_engineer`); anything else — another
  member's DN, a different base/scope/filter — is rejected without exposing
  data.

This is the **standalone phase-2 LDAP server** described above. It has not
yet been wired up against a real ClickHouse instance — real ClickHouse 24.8
LDAP configuration and end-to-end interoperability testing is deferred to
phase 3. Treat it today as a protocol-correct LDAP server you can Bind and
Search against directly, not yet as a drop-in ClickHouse LDAP backend.

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
cmd/ch-oauth-ldap/     # the standalone LDAPv3 server (main, config)
internal/ldap/         # LDAP session/DN/filter/entry primitives + Bind/Search handlers
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
