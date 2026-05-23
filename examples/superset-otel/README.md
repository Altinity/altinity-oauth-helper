# superset-otel — Superset reusing the otel ch-jwt-verify sidecar

> **Note.** This directory is a snapshot of the live `superset-otel` deployment
> kept here as a worked example of consuming `ch-jwt-verify` from a non-MCP
> client. The canonical, deploy-tracked copy of these files lives under
> `$MCP_DEPLOY_DIR/superset-otel/` for Altinity-internal use; any drift between
> the two is intentional — treat this copy as illustrative, not the source of
> truth for the live `superset.demo.altinity.cloud` cluster.

End-to-end OAuth identity from Superset → ClickHouse via the same
`ch-jwt-verify` sidecar that gates `otel-mcp` (altinity-mcp PR #128). No
shared service-account on the CH side: every Superset user's queries
carry their own per-request JWT, validated cryptographically by the
sidecar against Auth0's JWKS.

Pairs with [`../otel/README.md`](../otel/README.md) — same audience, same
sidecar, same per-user `CREATE USER … IDENTIFIED WITH http` provisioning.
Adding Superset on top of the sidecar required **no source patch** to
either altinity-mcp or Superset; everything sits on the public
`CUSTOM_SECURITY_MANAGER` + `DB_CONNECTION_MUTATOR` extension points.

## Files

| File | Purpose |
|---|---|
| `superset-values.yaml`            | Helm values for the bundled `apache/superset` chart (chart at `superset/helm/superset` in the apache/superset Git checkout). Contains the `configOverrides` snippets that render into `/app/pythonpath/superset_config.py` (OAuth provider, custom SecurityManager, `DB_CONNECTION_MUTATOR`). |
| `superset-secrets.yaml.example`   | Template for the secrets-only values file. Copy to `superset-secrets.yaml` (gitignored) and fill in `SUPERSET_SECRET_KEY` + Auth0 client id/secret. |
| `README.md`                       | This file. |

The Docker image is built from a separate repo at
`/Users/Workspaces/altinity/superset-jwt-overlay/` — see that repo's
README for the Dockerfile + build script.

## How the pieces fit together

```
browser ─https─> superset-otel pod
                       │  Flask-AppBuilder OAuth (AUTH_TYPE=AUTH_OAUTH)
                       │  → Auth0 /authorize?audience=https://otel-mcp.demo.altinity.cloud/
                       │  Auth0 issues JWT bound to the otel audience.
                       │  JWTSecurityManager.oauth_user_info() stashes
                       │  access_token in flask.session["clickhouse_jwt"].
                       │
                       │  user opens chart / SQL Lab
                       ▼
                Database._get_sqla_engine("clickhousedb://…")
                       │  DB_CONNECTION_MUTATOR rewrites:
                       │      username = g.user.email
                       │      password = session["clickhouse_jwt"]
                       ▼
                clickhouse-connect HTTP request to CH
                  Authorization: Basic base64(email:JWT)
                       │
                       ▼              (same path as otel-mcp queries)
                chi-otel-otel-0-0-0 pod
                  clickhouse-pod (8123)
                    ↓ http_authentication
                  ch-jwt-verify (127.0.0.1:9999) — validates JWT vs Auth0 JWKS
```

The only thing Superset adds beyond the existing otel-mcp deploy is the
browser-facing OAuth dance. Once the user is logged in, each ClickHouse
query is byte-identical (at the wire level) to what otel-mcp sends today.

## Prerequisites

### Auth0 application

In the `altinity.auth0.com` tenant, create one *Regular Web Application*:

- Name: `Superset (otel demo)`
- Allowed Callback URLs: `https://superset.demo.altinity.cloud/oauth-authorized/auth0`
- Allowed Logout URLs:   `https://superset.demo.altinity.cloud/`
- Allowed Web Origins:   `https://superset.demo.altinity.cloud`

No API-side authorisation toggle is needed. Regular Web Apps using the
Authorization Code flow are first-party clients in Auth0; they can
request the existing API audience `https://otel-mcp.demo.altinity.cloud/`
directly. The `ch-jwt-verify` sidecar requires no custom scopes
(`required_scopes: []` in `../otel/ch-jwt-verify-configmap.yaml`).

### ghcr.io image-pull secret

The overlay image is private. Reuse the `ghcr-pull-secret` already
present in the `demo` namespace (same one `otel-mcp` uses).

### Per-user CH provisioning

Each Auth0 user must exist as a CH user before they can query. Same
recipe as `../otel/README.md`:

```sql
CREATE USER OR REPLACE "alice@example.com"
  ON CLUSTER 'otel'
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE <whatever_role>;
```

Mirror an existing peer's grants with `SHOW CREATE USER`/`SHOW GRANTS`
when in doubt — see `[memory]: gating-mode CH 'read: EOF' = missing CH user`.

## Deploy / upgrade

```bash
cp superset-secrets.yaml.example superset-secrets.yaml
# Edit superset-secrets.yaml with real values:
#   SUPERSET_SECRET_KEY  $(openssl rand -base64 42)
#   AUTH0_CLIENT_ID      from Auth0 console
#   AUTH0_CLIENT_SECRET  from Auth0 console

helm upgrade --install superset-otel \
  /Users/Workspaces/altinity/superset/helm/superset \
  -n demo \
  -f superset-values.yaml \
  -f superset-secrets.yaml \
  --timeout 8m

kubectl rollout status deploy/superset-otel -n demo
```

## Register the ClickHouse database in Superset

After Auth0 sign-in, in the admin UI: Settings → Database Connections → +:

- Engine: `ClickHouse Connect (Superset)`
- Host: `clickhouse-otel.demo.svc.cluster.local`
- Port: `8123`
- Database: `claude_otel`
- Username / Password: any non-empty placeholder (e.g. `default` / `placeholder`).
  The values are replaced per request by `DB_CONNECTION_MUTATOR`; we
  don't leave them empty because Superset's connection-test ping uses the
  registered creds *before* the mutator kicks in.

## Verify

```bash
# Pod healthy
kubectl get pods -n demo -l app.kubernetes.io/instance=superset-otel

# Logs
kubectl logs -n demo deploy/superset-otel --tail=50

# Sidecar saw the verify request (after running a query in SQL Lab)
kubectl logs -n demo chi-otel-otel-0-0-0 -c ch-jwt-verify --tail=50
```

Pass criteria: `SELECT currentUser(), now()` in SQL Lab returns
`currentUser()` = your verified Auth0 email (not `default`), and the
sidecar log shows a corresponding `verify: ok user=<your-email>` entry.

## Known pitfalls

- **`/app/pythonpath/` is overlay-mounted by the chart.** The chart's
  Secret-backed `superset_config.py` mount at `/app/pythonpath/` hides
  anything baked into the image at that path. The custom SecurityManager
  is therefore defined *inline* inside `configOverrides.20_security_manager`
  rather than shipped as a separate `.py` file in the image.

- **The `apache/superset:5.0.0` base is the "lean" image.** It lacks
  Postgres + ClickHouse drivers. The overlay Dockerfile installs both
  (`psycopg2-binary` for Superset's metadata DB, `clickhouse-connect`
  for the target DB).

- **`supersetWorker` ignores `enabled: false`.** The chart always renders
  the worker Deployment. To suppress it, set
  `supersetWorker.replicas: {enabled: true, replicaCount: 0}` and clear
  `supersetWorker.initContainers: []` so the (now-empty) Deployment
  doesn't wait-for-redis forever. Celery isn't needed for the JWT demo.

- **JWT expiry.** Auth0 default access-token lifetime is 24h. After
  expiry the next query 403s at the sidecar; user re-authenticates by
  logging out and back in. No refresh-token plumbing is wired up on
  purpose — it would couple Superset to Auth0-specific token-rotation
  semantics we don't need for the demo.

## Image

Built from `/Users/Workspaces/altinity/superset-jwt-overlay/`. Multi-arch
manifest at `ghcr.io/altinity/superset-jwt-overlay:<tag>`. Bump
`image.tag` in `superset-values.yaml` after each rebuild.
