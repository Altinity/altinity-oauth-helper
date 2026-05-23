# Superset → ClickHouse via `ch-jwt-verify`

Bring up an end-to-end Superset stack where the user's OAuth access
token (JWT, minted by Dex) is forwarded to ClickHouse as the password,
and ClickHouse's `<http_authentication>` backend calls the
`ch-jwt-verify` sidecar to validate it. Per-user identity ends up
visible in ClickHouse — `currentUser()` returns the OAuth email.

```
browser ──► Superset ──► (FAB OAuth) Dex
                │
                └─► clickhouse-connect ──► ClickHouse
                       Authorization: Basic base64(email:JWT)
                                              │
                                              └─► ch-jwt-verify /verify
                                                  (loopback, JWKS validation)
```

This overlay reuses the shared platform (postgres + dex + clickhouse +
ch-jwt-verify) defined in `../../_platform/docker/`. It only adds the
two Superset services on top.

## Prereqs

- Docker Engine + Compose v2.6+ (`compose up --wait`).
- Free TCP ports `5556` (Dex), `8088` (Superset), `8123` (ClickHouse),
  `9999` (sidecar). Postgres stays internal.
- ~2 GB RAM headroom (Superset is the heaviest service).

## Run

```bash
./up.sh             # build + pull, wait for healthy
./run-tests.sh      # ROPC + sidecar /verify + CH query + 4 negative cases
./down.sh           # stop + drop volumes
```

`up.sh` is idempotent — re-running picks up where it left off. To
iterate on `superset/superset_config.py` or `../../_platform/docker/dex/config.yaml`,
restart the affected service and re-run `./up.sh`.

## Manual browser walkthrough

1. `./up.sh` and wait for `✓ stack up.`
2. Open <http://localhost:8088>.
3. Click **Sign In with dex**. Dex's login form appears.
4. Sign in as `alice@example.com` / `alice`. Consent is auto-approved
   (`skipApprovalScreen: true` in the platform's `dex/config.yaml`).
5. **SQL Lab** → database picker → **ClickHouse (oauth)** (pre-seeded
   by `superset/init.sh`) → run:
   ```sql
   SELECT 1 AS one, currentUser() AS who
   ```
   Returns `1, alice@example.com`. `currentUser()` confirms ClickHouse
   sees alice's identity, not a service account.
6. Tail the sidecar to watch verifications:
   ```bash
   docker compose -f ../../_platform/docker/compose.yml -f compose.yml \
       logs -f ch-jwt-verify
   ```
   The sidecar logs at INFO are quiet on success — set the command in
   the platform compose to `--log-level debug` if you want one line
   per `/verify`.

## What this overlay adds

| Service          | Image (built locally)                              | Role                                                   |
|------------------|----------------------------------------------------|--------------------------------------------------------|
| `superset-init`  | `apache/superset:5.0.0` + clickhouse-connect + psql| One-shot: psql-provisions the superset DB+user, runs `superset db upgrade`, creates the admin user, seeds the `ClickHouse (oauth)` connection. |
| `superset`       | (same image)                                       | Browser-facing app, FAB OAuth wired to Dex.            |

Everything else (postgres, dex, clickhouse, ch-jwt-verify) is shared
with future consumer overlays via `../../_platform/docker/compose.yml`.

## Gotchas worth knowing

- **Dex issuer URL is browser-facing, not container-facing.** Tokens
  carry `iss = http://localhost:5556/dex` — the host's port mapping —
  because the browser does the OAuth code dance and validates `iss`
  against the URL it was redirected through. Inside containers Dex is
  `dex:5556`. `superset_config.py` pins `jwks_uri` to the
  container-resolvable name explicitly so authlib doesn't read the
  browser-facing URL out of Dex's discovery document and fail.
- **Audience claim.** Dex sets `aud = client_id` for first-party
  clients. The sidecar pins `audience: superset` to match the
  `superset` Dex client defined in `../../_platform/docker/dex/config.yaml`.
- **`email_verified` is genuinely exercised.** Dex sets
  `email_verified: true` for `staticPasswords` users by default, so
  `require_email_verified: true` in the sidecar config isn't a no-op.
- **TLS is intentionally absent.** Plain HTTP throughout so the example
  is one-command on a laptop. Don't deploy this layout as-is.

## Where to look when something breaks

| Symptom                                              | First place to check                                                                       |
|------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `up --wait` times out                                | `docker compose ps` — which service is `unhealthy`?                                        |
| Dex login: "the request to sign in was denied"       | `docker compose logs superset` — usually authlib failing to fetch JWKS at `localhost:5556` |
| Sidecar 403 `aud mismatch`                           | Platform's `ch-jwt-verify/config.yaml` `audience` ≠ Dex client_id                          |
| Sidecar 403 `email_verified false`                   | Dex isn't emitting `email_verified=true` (re-check `staticPasswords`)                      |
| CH 194 `default: Authentication failed`              | Mutator skipped (no JWT in session/store) — see `MUTATOR skip` in `superset` logs          |
| CH 516 `… not allowed`                               | Missing or revoked CH user — `../../_platform/docker/clickhouse/.../00-users.sql`          |
| SQL Lab "Connection failed"                          | `docker compose logs superset` for `MUTATOR rewrote` lines (jwt_len should be ~700–900)    |
