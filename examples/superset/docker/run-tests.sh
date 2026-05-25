#!/usr/bin/env bash
# Headless end-to-end smoke for the docker-compose stack.
#
# Mints an access_token from Dex via ROPC (the only grant that's
# tractable without a browser), then verifies it lands in CH through
# the sidecar:
#
#   1. Dex /token (ROPC)        → JWT
#   2. sidecar /verify direct   → 200
#   3. CH HTTP 8123 SELECT 1    → "1"
#   4. mismatched user          → 403 from sidecar
#   5. empty bearer             → 401 from sidecar
#   6. tampered bearer          → 403 from sidecar
#
# Pre-req: `./up.sh` ran to completion (all services healthy).
set -euo pipefail

cd "$(dirname "$0")"

DEX_URL="${DEX_URL:-http://localhost:5556/dex}"
SIDECAR_URL="${SIDECAR_URL:-http://localhost:9999}"
CH_URL="${CH_URL:-http://localhost:8123}"
CLIENT_SECRET="${DEX_CLIENT_SECRET:-supersetsecret}"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "✓ $*"; }

# ---- 1. ROPC: ask Dex for a JWT on behalf of alice ----
echo "→ Dex /token (ROPC password grant)"
TOKEN_JSON=$(curl -fsS -u "superset:${CLIENT_SECRET}" \
    -X POST "${DEX_URL}/token" \
    -d grant_type=password \
    -d username=alice@example.com \
    -d password=alice \
    -d scope="openid profile email")
TOKEN=$(echo "$TOKEN_JSON" | jq -r .access_token)
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] \
    || fail "Dex returned no access_token: $TOKEN_JSON"
pass "got access_token (len=${#TOKEN})"

# Decode the JWT payload and confirm the sidecar can find an email claim.
# If this step fails, the sidecar's `username_claim: email` will not
# match anything and every /verify call will 403. Switch the sidecar
# claim to `sub` (and CH user name to the userID UUID) if needed.
payload_b64=$(echo "$TOKEN" | cut -d. -f2)
pad=$(( (4 - ${#payload_b64} % 4) % 4 ))
payload=$(echo "${payload_b64}$(printf '=%.0s' $(seq 1 $pad))" | tr '_-' '/+' | base64 -d 2>/dev/null || true)
echo "  JWT payload claims:"
echo "  $payload" | jq -c '{iss, aud, sub, email, email_verified, exp}'
[[ "$(echo "$payload" | jq -r .email)" == "alice@example.com" ]] \
    || fail "access_token has no email=alice@example.com claim — see plan gotcha #1"

# ---- 2. Direct sidecar verify ----
echo "→ sidecar /verify (alice)"
code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -u "alice@example.com:$TOKEN" "${SIDECAR_URL}/verify")
[[ "$code" == "200" ]] || fail "sidecar /verify expected 200, got $code"
pass "sidecar /verify returned 200"

# ---- 3. End-to-end through ClickHouse ----
echo "→ ClickHouse SELECT 1 as alice"
result=$(curl -fsS -u "alice@example.com:$TOKEN" \
    "${CH_URL}/?query=SELECT+1" || true)
[[ "$result" == "1" ]] || fail "CH SELECT 1 expected '1', got '$result'"
pass "ClickHouse accepted query"

# Mint two more fresh tokens for the negative cases. The sidecar's
# verify cache keys on sha256(token) only, so reusing $TOKEN here would
# hit the cached "ok for alice" entry and bypass matchUser/signature
# checks. Each negative case gets its own previously-unseen token.
mint_token() {
    curl -fsS -u "superset:${CLIENT_SECRET}" \
        -X POST "${DEX_URL}/token" \
        -d grant_type=password \
        -d username=alice@example.com \
        -d password=alice \
        -d scope="openid profile email" | jq -r .access_token
}

# ---- 4. user / email mismatch → sidecar rejects ----
echo "→ sidecar /verify (basic-auth user mismatched with email claim)"
TOKEN_MISMATCH=$(mint_token)
code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -u "bob@example.com:$TOKEN_MISMATCH" "${SIDECAR_URL}/verify")
[[ "$code" == "403" ]] || fail "sidecar mismatch expected 403, got $code"
pass "sidecar rejected user/email mismatch with 403"

# ---- 5a. no Authorization header at all ----
echo "→ sidecar /verify (no Authorization header)"
code=$(curl -sS -o /dev/null -w '%{http_code}' "${SIDECAR_URL}/verify")
[[ "$code" == "401" ]] || fail "sidecar no-auth expected 401, got $code"
pass "sidecar rejected missing Authorization with 401"

# ---- 5b. empty bearer (Basic alice:) — header present but no JWT to verify ----
echo "→ sidecar /verify (empty bearer)"
code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -u "alice@example.com:" "${SIDECAR_URL}/verify")
[[ "$code" == "403" ]] || fail "sidecar empty-token expected 403, got $code"
pass "sidecar rejected empty bearer with 403"

# ---- 6. tampered token (signature bytes mutated → bad signature) ----
# Replace the last 5 chars of the JWT signature with "AAAAA". The very last
# base64url char of an RSA-256 signature only carries 2 significant bits
# (the rest are don't-care padding), so a single-char swap can decode to the
# same bytes; mutating 5 chars guarantees a real signature change.
echo "→ sidecar /verify (tampered token)"
TOKEN_FRESH=$(mint_token)
TAMPERED="${TOKEN_FRESH::-5}AAAAA"
code=$(curl -sS -o /dev/null -w '%{http_code}' \
    -u "alice@example.com:$TAMPERED" "${SIDECAR_URL}/verify")
[[ "$code" == "403" ]] || fail "sidecar tampered-token expected 403, got $code"
pass "sidecar rejected tampered token with 403"

echo
echo "✓ all tests passed"
