# Examples

End-to-end recipes for putting `ch-jwt-verify` between a ClickHouse
deployment and various consumers. The layout is **consumer × deploy
style** — pick the consumer you care about, then the deploy style you
have at hand.

```
examples/
├── _platform/                shared data plane (postgres + dex + CH + sidecar)
│   ├── docker/               ← compose base every consumer's docker overlay layers on
│   └── k8s/                  ← manifests/helm-values base every consumer's k8s overlay layers on
├── curl/                     "bring your own JWT" against a manually-run sidecar
├── python/                   clickhouse-connect script against the platform CH
├── clickhouse-client/        CLI client with `--password $JWT`
├── altinity-mcp/             MCP server fronting CH; downstream uses JWT-as-password
├── superset/                 Apache Superset (FAB OAuth → CH via JWT)
├── superset-mcp/             MCP wrapper exposing Superset to AI assistants
├── grafana/                  Grafana OAuth → CH datasource via JWT
└── grafana-mcp/              MCP wrapper exposing Grafana to AI assistants
```

## Capability matrix

| Consumer            | Docker                                  | K8s / Helm                                |
|---------------------|-----------------------------------------|-------------------------------------------|
| `curl/`             | ✅ [README](curl/README.md) (no compose, BYO sidecar) | — (not applicable) |
| `python/`           | 🟡 planned                              | 🟡 planned                                |
| `clickhouse-client/`| 🟡 planned                              | 🟡 planned                                |
| `altinity-mcp/`     | 🟡 planned                              | 🟡 planned (uses `../helm/ch-jwt-verify`) |
| `superset/`         | ✅ [README](superset/docker/README.md)  | 🟡 planned                                |
| `superset-mcp/`     | 🟡 planned                              | 🟡 planned                                |
| `grafana/`          | 🟡 [README](grafana/docker/README.md) (backend patch lands; frontend rework still needed — see README) | 🟡 planned |
| `grafana-mcp/`      | 🟡 planned                              | 🟡 planned                                |

✅ working, 🟡 planned, 🔴 known broken on this version.

## The shared platform

`_platform/` is **not run standalone** — it's the base every consumer
overlay layers on top of. See `_platform/docker/README.md` for what's
in the box (postgres, dex, clickhouse with `<http_authentication>`
wired up, ch-jwt-verify built from this repo) and how a consumer
overlay invokes it.

A consumer's `docker/up.sh` typically reduces to:

```bash
docker compose \
    -f ../../_platform/docker/compose.yml \
    -f ./compose.yml \
    up -d --wait
```

Same idea on k8s: `helm install` (or `kubectl apply`) the platform
once, then the consumer overlay points at `clickhouse:8123` in-cluster.

## Adding a new consumer

1. `mkdir -p examples/<consumer>/{docker,k8s}` and an `examples/<consumer>/README.md`.
2. `docker/compose.yml` only declares the consumer's own services. It
   reads bind mounts, env vars, and Dex client IDs from
   `../../_platform/docker/` — *don't* re-declare postgres / dex /
   clickhouse / ch-jwt-verify.
3. `docker/up.sh` invokes `compose -f ../../_platform/docker/compose.yml -f ./compose.yml`.
4. If your consumer needs its own Postgres metadata schema, create it
   from your own init step (psql or app-specific migration). The
   platform's `_platform/docker/postgres/docker-entrypoint-initdb.d/`
   creates only the Dex DB and is consumer-agnostic.
5. Append your consumer to the matrix above.

Per-example README template:

```
1. Wire diagram (ASCII)
2. Prereqs (host ports, RAM, image names)
3. Quick start (./up.sh / ./run-tests.sh / ./down.sh)
4. Manual walkthrough (if there's a UI)
5. What this overlay adds (table of services)
6. Gotchas
7. Where to look when something breaks (symptom → first place to check)
```

## TLS, secrets, multi-replica, prod

These examples are intentionally laptop-sized: plain HTTP, demo-grade
secrets in YAML, single replicas, in-memory caches. The `helm/ch-jwt-verify/`
chart in the repo root is the production-shaped artifact; consult
`helm/ch-jwt-verify/values.yaml` and the comments in `pkg/oauth/config.go`
for the real knobs.
