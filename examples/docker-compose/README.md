# docker-compose example — full end-to-end on a laptop

Bring up the entire ch-jwt-verify wire — IdP, ClickHouse, sidecar,
Superset, shared Postgres — with one command. Verifies the sidecar
pattern works against a real OIDC IdP (Dex) and a real consumer
(Superset → ClickHouse).

```
browser ──► Superset ──► (FAB OAuth) Dex
                │
                └─► clickhouse-connect ──► ClickHouse
                       Authorization: Basic base64(email:JWT)
                                              │
                                              └─► ch-jwt-verify /verify
                                                  (loopback, JWKS validation)
```

Two ways to drive it:
- **Automated** — `./run-tests.sh` mints a token via ROPC and curls the
  whole chain. Useful for CI, debugging, and demoing the wire format
  without a browser.
- **Manual** — open `http://localhost:8088`, sign in as
  `alice@example.com` / `alice`, and run `SELECT 1` in SQL Lab against
  the pre-wired ClickHouse connection.

## Prerequisites

- Docker Engine + Compose v2.6+ (the script uses `compose up --wait`).
- Free TCP ports `5556` (Dex), `8088` (Superset), `8123` (ClickHouse
  HTTP), `9999` (sidecar). Postgres stays internal.
- About 2 GB of RAM headroom; Superset is the heaviest service.

## Quick start

```bash
./up.sh             # build sidecar image, pull others, wait for healthy
./run-tests.sh      # ✓ all tests passed
./down.sh           # stop + delete volumes
```

`up.sh` is idempotent: re-running it picks up where it left off, so
iteration on `superset_config.py` or `dex/config.yaml` only needs
`docker compose restart <service>` followed by `./up.sh` again to
re-await health.

## Manual browser walkthrough

1. `./up.sh` and wait for `✓ stack up.`
2. Open <http://localhost:8088>.
3. Click **Sign In with dex**. Dex's login form appears.
4. Sign in as `alice@example.com` / `alice`. Dex auto-approves consent
   (`skipApprovalScreen: true` in `dex/config.yaml`); the browser is
   redirected back to Superset, which now has alice in `g.user` plus
   the OAuth access_token captured into the Flask session.
5. **Settings → Database Connections → + Database**:
   - Supported Databases: **ClickHouse Connect (Superset)**
   - SQLAlchemy URI: `clickhousedb://default@clickhouse:8123/default`
     (Superset's `DB_CONNECTION_MUTATOR` rewrites `default@` to
     `alice@example.com:<JWT>` at engine-creation time — see
     `superset/superset_config.py`.)
   - Click **Test Connection**, then **Connect**.
6. **SQL Lab** → pick the ClickHouse database → run `SELECT 1` → returns
   `1`.
7. Tail the sidecar to see verification entries:
   ```bash
   docker compose logs -f ch-jwt-verify | grep verify
   ```

## What's in the box

| Service          | Image                                       | Role                                                       |
|------------------|---------------------------------------------|------------------------------------------------------------|
| `postgres`       | `postgres:16-alpine`                        | Shared metadata DB for Dex AND Superset.                   |
| `dex`            | `ghcr.io/dexidp/dex:v2.41.1`                | OIDC IdP. Static client + static password.                 |
| `clickhouse`     | `clickhouse/clickhouse-server:25.3`         | Data plane. Wires `<http_authentication>` to the sidecar.  |
| `ch-jwt-verify`  | built from `../../Dockerfile` source        | Validates JWT, answers CH's auth callback.                 |
| `superset-init`  | `ghcr.io/altinity/superset-jwt-overlay:otel-d62f314` | One-shot: `superset db upgrade` + `fab create-admin`. |
| `superset`       | `ghcr.io/altinity/superset-jwt-overlay:otel-d62f314` | Browser-facing app, wired to Dex via FAB OAuth. |

The `superset-jwt-overlay` image is `apache/superset:5.0.0` +
`clickhouse-connect`; everything else is stock.

## Gotchas worth knowing

- **Dex issuer URL is browser-facing, not container-facing.** Tokens
  carry `iss = http://localhost:5556/dex` — the host's port mapping —
  because the browser does the OAuth code dance and validates `iss`
  against the URL it was redirected through. Inside containers, Dex is
  reachable via the docker-DNS name `dex:5556`, which is what
  `ch-jwt-verify` hits for `jwks_url` and what Superset uses for the
  token exchange / userinfo backend calls. Both `superset_config.py`
  and `ch-jwt-verify/config.yaml` split these.
- **Audience claim.** Dex sets `aud = client_id` for first-party
  clients. The sidecar pins `audience: superset` to match the
  Superset client_id defined in `dex/config.yaml`.
- **`email_verified` is genuinely tested.** Dex sets `email_verified:
  true` for `staticPasswords` users by default, so the sidecar's
  `require_email_verified: true` is exercised, not silently bypassed.
- **No CIMD here.** Dex doesn't speak MCP-style client metadata
  documents. This example demonstrates the sidecar wire — a different
  example (`examples/curl-smoke-test/`) is the minimal sidecar-only
  walkthrough.
- **Regenerating staticPasswords.** Hash format is bcrypt cost 10:
  ```bash
  htpasswd -bnBC 10 "" <password> | tr -d ':\n'
  ```
  Paste the result into `dex/config.yaml` and `docker compose restart
  dex`.
- **TLS is intentionally absent.** Everything is plain HTTP because the
  browser is on the same host as the containers and we want to keep
  the example one-command. Don't deploy this layout as-is.

## Where to look when something breaks

| Symptom                                       | First place to check                                            |
|-----------------------------------------------|-----------------------------------------------------------------|
| `docker compose up --wait` times out          | `docker compose ps` — which service is `unhealthy`?             |
| Dex login page 404s                           | `dex/config.yaml` issuer must match `http://localhost:5556/dex` |
| Sidecar returns 403, log says `aud mismatch`  | `audience` in `ch-jwt-verify/config.yaml` ≠ Dex client_id       |
| Sidecar returns 403, log says `email_verified false` | Dex isn't emitting `email_verified=true` (re-check staticPasswords) |
| ClickHouse returns 516 `WRONG_PASSWORD`       | `docker compose logs ch-jwt-verify` — sidecar saw the request?  |
| SQL Lab "Connection failed"                   | `docker compose logs superset` — look for `MUTATOR rewrote`     |
