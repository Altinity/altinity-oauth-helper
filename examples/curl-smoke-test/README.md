# curl-smoke-test

A local end-to-end smoke test of the `ch-jwt-verify` sidecar with a real JWT.
Exercises the same wire contract ClickHouse uses (`Authorization: Basic
base64(user:JWT)` against `/verify`), so any rejection you see here is the
exact rejection CH would report.

## Run

```bash
# 1. Fill in oauth.issuer + oauth.audience in config.yaml.
$EDITOR examples/curl-smoke-test/config.yaml

# 2. Start the sidecar locally (from the repo root):
go run ./cmd/ch-jwt-verify -c examples/curl-smoke-test/config.yaml &

# 3. Mint a JWT from your IdP (Auth0, Google, etc.) for the configured audience,
#    then hit /verify with it:
examples/curl-smoke-test/verify.sh alice@example.com "eyJhbGciOi…"
# or via env:
CH_JWT_USER=alice@example.com CH_JWT_TOKEN="eyJhbGciOi…" \
  examples/curl-smoke-test/verify.sh
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
