# altinity-oauth-helper

OAuth helpers for ClickHouse-fronted deployments. The first (and currently
only) helper is `ch-jwt-verify`: a tiny HTTP server that ClickHouse calls from
its `<http_authentication>` handler to validate JWT bearers. Future helpers
(JWE generators, token introspectors, …) will live alongside.

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

For a worked end-to-end example with Apache Superset as the upstream, see
[`examples/superset-otel/`](examples/superset-otel/).

## Building images

```bash
scripts/build-image.sh feature-strict-iss
# → ghcr.io/altinity/ch-jwt-verify:feature-strict-iss-<short-sha>
#   (multi-arch manifest + per-arch -amd64 / -arm64 tags)
```

The script cross-compiles statically-linked binaries for amd64+arm64, builds
with legacy `DOCKER_BUILDKIT=0`, pushes per-arch, and assembles the multi-arch
manifest. Image name stays at `ghcr.io/altinity/ch-jwt-verify` so existing
Helm values continue to work.

## Layout

```
cmd/ch-jwt-verify/     # the sidecar binary (main, config, settings, verify)
pkg/oauth/             # JWKS-based JWT verifier + identity-policy helpers
helm/ch-jwt-verify/    # Helm chart (ConfigMaps + container fragment, no Deployment)
scripts/build-image.sh # multi-arch image build & push
examples/              # curl smoke test, Superset deploy
Dockerfile             # consumed by scripts/build-image.sh
```

`pkg/oauth` is intentionally leaf-level (no `internal/` ties to the
sidecar): other helpers in this repo and downstream consumers can import it
directly.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
