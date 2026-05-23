# Grafana → ClickHouse via `ch-jwt-verify`

> **Status: partially working — backend patch lands, browser flow does
> not yet.** The vertamedia plugin's TypeScript frontend posts queries
> directly to `/api/datasources/proxy/uid/<UID>/?…` (Grafana's
> data-source proxy), bypassing the Go plugin's `QueryData` handler.
> With `oauthPassThru: true`, the proxy forwards the user's raw
> `Authorization: Bearer …` to ClickHouse, which rejects it
> (`Code: 516 — 'Bearer' HTTP Authorization scheme is not supported`).
>
> The backend patch in `grafana/plugin/0001-jwt-as-password.patch` IS
> functional — a direct `POST /api/ds/query` from a logged-in session
> returns `currentUser() = alice@example.com`. But Explore's **Run
> Query** does not hit that path, so the UI demo fails.
>
> The clean way out is to drop the Bearer→Basic repacking entirely and
> run [**Altinity Antalya**][antalya] (Altinity's ClickHouse fork) on
> the data plane — Antalya accepts `Authorization: Bearer <jwt>`
> natively, so the plugin's frontend can forward the user's token
> as-is via `oauthPassThru` and the whole "stuff the JWT into Basic
> auth" trick (plus this patch, plus the sidecar) goes away. Until the
> example is rewired onto Antalya, a complete fix here needs a
> parallel frontend patch (route through `QueryData`, or transform
> `_request` to avoid the proxy) — tracked as follow-up work.
>
> [antalya]: https://github.com/Altinity/ClickHouse
>
> What still works in this directory:
> - `./up.sh` and `./down.sh` for the platform + Grafana stack.
> - `./run-tests.sh` (headless sidecar + ClickHouse wire checks).
> - The provisioned `ClickHouse (oauth)` datasource and Dex login.
> - A scripted `POST /api/ds/query` against the patched plugin.

Bring up an end-to-end Grafana stack where the logged-in user's OAuth
access token (JWT, minted by Dex) is forwarded to ClickHouse as the
Basic-auth password, and ClickHouse's `<http_authentication>` backend
calls the `ch-jwt-verify` sidecar to validate it. Per-user identity
ends up visible in ClickHouse — `currentUser()` returns the OAuth
email.

```
browser ──► Grafana ──► (generic OAuth) Dex
              │
              └─► vertamedia-clickhouse-datasource (patched) ──► ClickHouse
                     Authorization: Basic base64(email:JWT)
                                            │
                                            └─► ch-jwt-verify /verify
                                                (loopback, JWKS validation)
```

This overlay reuses the shared platform (postgres + dex + clickhouse +
ch-jwt-verify) defined in `../../_platform/docker/`. It adds one
service — `grafana` — built from an image that bakes in a locally
patched build of the Altinity ClickHouse plugin.

## Why patch the plugin

This example is built for **OSS ClickHouse**, which doesn't read
`Authorization: Bearer …` — it only speaks HTTP Basic. Production
deployments that want real per-user JWT identity should instead run
[**Altinity Antalya**][antalya], Altinity's ClickHouse fork that
accepts Bearer tokens natively (validating them against a JWKS the
server is configured to trust). With Antalya the entire
`ch-jwt-verify` sidecar + Bearer-as-Basic repacking trick used in
these examples becomes unnecessary: the OAuth token flows straight
through to ClickHouse and is verified there. The OSS-flavoured demo
in this directory exists because most users will encounter OSS first.

[antalya]: https://github.com/Altinity/ClickHouse

Back to OSS: Grafana's `oauthPassThru` forwards the user's bearer
token to the plugin, but the upstream plugin doesn't repack it as
Basic-auth. A ~30 LoC patch (`grafana/plugin/0001-jwt-as-password.patch`)
teaches it to do exactly that:

```go
if Bearer in Authz && UserEmail != "":
    req.SetBasicAuth(UserEmail, jwt)
```

Tracked upstream at
[`Altinity/clickhouse-grafana#622`](https://github.com/Altinity/clickhouse-grafana/issues/622).
Once merged + released, this example drops the patch and pins a tag.

The official `grafana-clickhouse-datasource` plugin builds credentials
inside `clickhouse-go`'s connection pool, which has no per-request
hook — patching it would be 100+ LoC of architectural rework. The
Altinity plugin's plain `net/http` outbound path is the right place
to land this.

## Prereqs

- Docker Engine + Compose v2.6+ (`compose up --wait`).
- Free TCP ports `3000` (Grafana), `5556` (Dex), `8123` (ClickHouse),
  `9999` (sidecar). Postgres stays internal.
- ~2 GB RAM headroom and ~3-5 minutes for the first build (the
  plugin's Go backend + JS frontend are compiled from source).
  Subsequent runs reuse the image and come up in seconds.

## Run

```bash
./up.sh             # build + pull, wait for healthy (slow on first run)
./run-tests.sh      # ROPC + sidecar /verify + CH query + 4 negative cases
./down.sh           # stop + drop volumes
```

`up.sh` is idempotent — re-running picks up where it left off. To
iterate on the plugin patch, edit `grafana/plugin/0001-jwt-as-password.patch`
then `docker compose build grafana && docker compose up -d grafana`.

`run-tests.sh` exercises the sidecar + ClickHouse wire directly (ROPC
to Dex, sidecar `/verify`, CH `SELECT 1`, 4 negative cases). It does
**not** drive Grafana headlessly — the Grafana flow needs a real
browser session, which the manual walkthrough below covers.

## Manual browser walkthrough

1. `./up.sh` and wait for `✓ stack up.`
2. Open <http://localhost:3000>.
3. Click **Sign in with Dex**. Dex's login form appears.
4. Sign in as `alice@example.com` / `alice`. Consent is auto-approved.
5. **Explore** (compass icon) → datasource picker → **ClickHouse (oauth)**
   (pre-provisioned). Click **SQL Editor** if Grafana defaults to the
   visual query builder, then run:
   ```sql
   SELECT 1 AS one, currentUser() AS who
   ```
   Expect `1, alice@example.com`. `currentUser()` is the proof that
   ClickHouse saw alice's identity — not a service account.
6. Tail the sidecar to watch verifications:
   ```bash
   docker compose -f ../../_platform/docker/compose.yml -f compose.yml \
       logs -f ch-jwt-verify
   ```

## What this overlay adds

| Service   | Image (built locally)                                            | Role                                                                                  |
|-----------|------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| `grafana` | `grafana/grafana:11.4.0` + patched `vertamedia-clickhouse-datasource` | Browser-facing app, generic-OAuth wired to Dex, ClickHouse datasource pre-provisioned. |

Everything else (postgres, dex, clickhouse, ch-jwt-verify) is shared
with the Superset overlay via `../../_platform/docker/compose.yml`.
The Dex `superset` static client is reused — its redirect-URI list
already includes Grafana's callback, and the sidecar's
`audience: superset` check works for both consumers.

## Gotchas worth knowing

1. **OSS ClickHouse doesn't speak Bearer.** The plugin patch packs
   the JWT into the Basic-auth password — that's the whole point.
2. **First build is slow** (~3-5 minutes) because the patched plugin
   is compiled from source. Cached after.
3. **`GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS`** is required because
   the patch invalidates the plugin's upstream signature.
4. **`oauthPassThru` must stay on.** Without it, Grafana doesn't
   forward the bearer header to the plugin, so the patch's "Bearer
   present" branch is never taken and the plugin falls back to empty
   static creds — ClickHouse rejects as the `default` user. The
   provisioned datasource has it on; don't disable it.
5. **Refresh tokens.** `GF_AUTH_GENERIC_OAUTH_USE_REFRESH_TOKEN=true`
   keeps the access token fresh past Dex's 1-hour default. Without
   it, queries start 401'ing an hour after login.
6. **Auto-assigned Admin role.** `GF_USERS_AUTO_ASSIGN_ORG_ROLE=Admin`
   is a demo shortcut so new OAuth users can hit Explore without
   role-mapping ceremony. Don't ship this default.

## Where to look when something breaks

| Symptom                                              | First place to check                                                                                  |
|------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `up --wait` times out on first run                   | The plugin build is slow — `docker compose logs grafana` to see if it's still going.                  |
| Dex login: redirect_uri error                        | `../../_platform/docker/dex/config.yaml` — Grafana's URI listed under the `superset` client?         |
| Explore: "datasource health check failed"            | `docker compose logs grafana` for plugin load errors; check `GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS`. |
| CH 194 `default: Authentication failed`              | `oauthPassThru: false` on the datasource, OR the user logged in via local Grafana admin, not Dex.     |
| CH 516 `… not allowed`                               | Missing or revoked CH user — `../../_platform/docker/clickhouse/.../00-users.sql`.                    |
| Sidecar 403 `aud mismatch`                           | Platform's `ch-jwt-verify/config.yaml` `audience` ≠ Dex `client_id` (= `superset`).                   |
| Queries start 401'ing after ~1h                      | Refresh tokens disabled — see gotcha #5.                                                              |
