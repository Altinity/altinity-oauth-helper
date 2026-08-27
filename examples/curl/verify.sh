#!/usr/bin/env bash
# Smoke-test the ch-jwt-verify sidecar against a real JWT.
#
# Usage:
#   examples/curl/verify.sh [user] [jwt]
#
#   user — the email (or sub, depending on identity.username_claim in
#          config.yaml) you expect to match against the token's claims.
#          Defaults to $CH_JWT_USER if set.
#   jwt  — the bearer JWT. Defaults to $CH_JWT_TOKEN if set.
#
# Prerequisites:
#   1. ch-jwt-verify running locally with this directory's config.yaml:
#        go run ./cmd/ch-jwt-verify -c examples/curl/config.yaml
#      (from the repo root).
#   2. config.yaml's oauth.issuer / oauth.audience filled in.
#   3. A valid JWT minted by your IdP for that audience, with verified email.
#
# Expected output on success:
#   HTTP/1.1 200 OK
#   {"settings":null,"email":"…@…"}    # or non-empty settings, per your config
#
# On rejection the sidecar returns a 403 with a single fixed body,
# "authentication failed" — deliberately the same regardless of which check
# failed (signature/issuer/audience/expiry/username/domain policy). Run the
# sidecar with --log-level debug to see the real reason server-side.

set -euo pipefail

URL="${URL:-http://127.0.0.1:9999/verify}"
USER_VAL="${1:-${CH_JWT_USER:-}}"
TOKEN="${2:-${CH_JWT_TOKEN:-}}"

if [[ -z "$USER_VAL" || -z "$TOKEN" ]]; then
    echo "usage: verify.sh <user> <jwt>" >&2
    echo "       or set CH_JWT_USER + CH_JWT_TOKEN in the environment" >&2
    exit 2
fi

# `-u user:token` is the same shape ClickHouse forwards under
# <http_authentication_servers>: Authorization: Basic base64(user:token).
exec curl -sS -i -u "${USER_VAL}:${TOKEN}" "${URL}"
