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

On rejection the sidecar returns `HTTP/1.1 403 Forbidden` with a single fixed
body, `authentication failed` — deliberately the same text regardless of
*why* the request was rejected (bad signature, wrong issuer/audience,
expired token, username mismatch, reserved username, or email/domain
policy). A caller can never distinguish which check failed from the
response alone; that's a security property (see `cmd/ch-jwt-verify/verify.go`),
not a missing detail. Run the sidecar with `--log-level debug` to see the
real reason in the server-side log line — the body never echoes the token,
and the debug log never echoes it either.

## Common failures

| Symptom | Likely cause |
|---|---|
| `403 authentication failed` | Any rejection — bad signature, wrong issuer, wrong audience, expired/missing `exp`, Basic-auth user not matching the configured `identity.username_claim`, a reserved (`denied_usernames`) user, or `identity.require_email_verified`/domain-allowlist policy. Check the sidecar's debug log for the specific cause. |
| `503` on `/readyz` | JWKS fetch failing — see sidecar logs; usually a misconfigured `issuer` or a network policy blocking egress. |
