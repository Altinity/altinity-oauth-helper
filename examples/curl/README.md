# `curl` — minimal "bring your own JWT" sidecar smoke test

Smallest possible end-to-end exercise: run `ch-jwt-verify` locally with
your real IdP's config, hit `/verify` with `curl` carrying a JWT *you*
have already minted. Same wire contract ClickHouse uses
(`Authorization: Basic base64(user:JWT)`), so any rejection you see is
the exact rejection ClickHouse would report.

Different shape from the other consumer examples: this one is
**sidecar-only, BYO JWT**. The other examples (`../superset/docker/`,
`../python/docker/`, …) bring up a full stack with Dex as the IdP, so
you can drive the wire end-to-end without an external IdP at all. Use
those when iterating on the consumer side; use this one when bringing
the sidecar up against a brand-new external IdP for the first time.

## Run

```bash
# 1. Fill in oauth.issuer + oauth.audience in config.yaml.
$EDITOR examples/curl/config.yaml

# 2. Start the sidecar locally (from the repo root):
go run ./cmd/ch-jwt-verify -c examples/curl/config.yaml &

# 3. Mint a JWT from your IdP (Auth0, Google, etc.) for the configured audience,
#    then hit /verify with it:
examples/curl/verify.sh alice@example.com "eyJhbGciOi…"
# or via env:
CH_JWT_USER=alice@example.com CH_JWT_TOKEN="eyJhbGciOi…" \
  examples/curl/verify.sh
```

Expected on success:

```
HTTP/1.1 200 OK
Content-Type: application/json
{"settings":null,"email":"alice@example.com"}
```

On rejection the sidecar returns `HTTP/1.1 403 Forbidden` plus a one-line
reason (`token validation failed: …`, `does not match`, etc.). Run the sidecar
with `--log-level debug` to see the underlying claim — the body never echoes
the token.

## Common failures

| Symptom | Likely cause |
|---|---|
| `403 token validation failed: failed to verify JWT signature` | JWT signed by a key not in the IdP's published JWKS (wrong tenant, or the token came from a different IdP). |
| `403 token validation failed: invalid OAuth token` (aud mismatch) | `oauth.audience` in `config.yaml` does not byte-equal the JWT's `aud` claim. |
| `403 does not match` | The Basic-auth user differs from the JWT's `email` (or `sub`, depending on `identity.username_claim`). |
| `403 OAuth email is not verified` | `identity.require_email_verified: true` and the token's `email_verified` is false. Either fix the IdP enrolment or relax the flag. |
| `503` on `/readyz` | JWKS fetch failing — see sidecar logs; usually a misconfigured `issuer` or a network policy blocking egress. |
