# `_platform/docker/` — shared data plane

Reusable Docker Compose base every consumer example layers on top of.
**Not runnable standalone in any useful sense.** The user-facing entry
points are in `../<consumer>/docker/` (e.g. `../superset/docker/`).

## What's inside

| Service          | Image                                       | Role                                                     |
|------------------|---------------------------------------------|----------------------------------------------------------|
| `postgres`       | `postgres:16-alpine`                        | Dex storage. Consumer overlays add their own DBs here.   |
| `dex`            | `ghcr.io/dexidp/dex:v2.41.1`                | OIDC IdP. Static client + static password users.         |
| `clickhouse`     | `clickhouse/clickhouse-server:25.3`         | Data plane. `<http_authentication>` wired to the sidecar.|
| `ch-jwt-verify`  | built from `../../..` (the repo root)       | Validates JWTs for ClickHouse's auth callback.           |

Ports published to the host:
- `5556` — Dex (browser-facing login + JWKS).
- `8123` — ClickHouse HTTP.
- `9999` — sidecar `/verify` and `/healthz`.

Postgres stays internal.

## How a consumer overlay layers on top

```bash
docker compose \
    -f ../../_platform/docker/compose.yml \
    -f ./compose.yml \
    up -d --wait
```

The consumer overlay only declares its own services + any extra
provisioning (creating a Postgres user/DB via psql in its init step,
mounting OAuth secrets, etc.). It does **not** redeclare postgres /
dex / clickhouse / ch-jwt-verify.

See `../superset/docker/compose.yml` for a worked example.

## Identities provisioned out of the box

- Dex `staticClients`: `superset` (secret: `supersetsecret`). Reuse this
  for any consumer that's happy with a single OAuth client, or add
  more in `dex/config.yaml`.
- Dex `staticPasswords`: `alice@example.com` / `alice`,
  `bob@example.com` / `bob` (alice for happy-path, bob for negative
  tests). Regenerate hashes with
  `htpasswd -bnBC 10 "" <password> | tr -d ':\n'`.
- ClickHouse: `alice@example.com IDENTIFIED WITH http SERVER 'ch_jwt_verify'`.
  Add more users in `clickhouse/docker-entrypoint-initdb.d/`.

## Why not a single all-in-one compose?

Two reasons:
1. **Multi-consumer demos.** Once you have `superset/`, `grafana/`,
   `python/`, and a couple of MCP variants, an all-in-one stack is
   confusing — every consumer's container is always running even when
   you're only exercising one. Per-consumer overlays let you bring up
   exactly what you need.
2. **Keeps the platform consumer-agnostic.** New consumer = new
   `consumer-name/docker/compose.yml`, plus a paragraph in
   `examples/README.md`. No changes here.
