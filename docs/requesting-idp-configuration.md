# Requesting IdP configuration for `ch-jwt-verify` / `ch-oauth-ldap`

Audience: the operator deploying one of the two helpers, who now has to ask
the team that runs the identity provider (IdP) for the right setup. This page
explains what to ask for and why, then gives a message you can paste into a
ticket. The field-by-field YAML reference lives in
[`ch-oauth-ldap-operator-guide.md`](ch-oauth-ldap-operator-guide.md) §2–§4;
this page does not repeat it.

## 1. What the helpers do and do not need from the IdP

Both helpers are **token verifiers**, not OAuth clients. They receive a JWT
from a consumer (Superset, Grafana, an MCP server, a script), check its
signature against the IdP's published keys, check issuer/audience/expiry and
identity policy, and map group claims to ClickHouse roles.

Consequences for your request:

- **The helpers need no client secret, no API key and no IdP account.** They
  fetch only public data: the JWKS (and optionally OIDC discovery metadata).
  Do not ask for, and do not accept, a secret "for the helper".
- **Client IDs and secrets are for the consumers**, e.g. Superset's or
  Grafana's OAuth login. Those belong in the consumer's own secret store, not
  in the helper's config or in this repo (see "No secrets in git" in
  `CLAUDE.md`).
- **The token must be a signed JWT.** An opaque access token cannot be
  verified offline; a JWE (encrypted) token cannot be read by the helper.
  This is the most common reason a first rollout fails.

## 2. What to ask for

| # | Item | Why the helper needs it | Maps to |
|---|---|---|---|
| 1 | **Issuer URL**, exactly as it appears in the `iss` claim (mind trailing slashes) | `iss` must match exactly | `oauth.expected_issuer` (`ch-oauth-ldap`), `oauth.issuer` (`ch-jwt-verify`) |
| 2 | **JWKS URL** (usually `…/.well-known/jwks.json` or the `jwks_uri` in OIDC discovery) | Source of signature-verification keys | `oauth.jwks_url` |
| 3 | **Audience value(s)**: the identifier the IdP will put in `aud` for tokens meant for ClickHouse | Rejects tokens minted for some other API | `oauth.expected_audiences` (list) |
| 4 | Confirmation that **access tokens are signed JWTs** with asymmetric keys published at the JWKS URL | Offline verification | n/a (precondition) |
| 5 | **Username claim**: which claim carries the ClickHouse login (default `email`), and that it is unique and stable per person | Bound to the requested username; also part of the cache key | `oauth.username_claim` |
| 6 | **`email_verified`** present and truthful, if you use `require_email_verified` | Identity policy | `identity.require_email_verified` |
| 7 | **Groups claim**: claim name, and that it is a **string array** (or a plain string) in the access token | Source for ClickHouse roles. A malformed claim fails authentication; a missing one yields zero roles | `oauth.groups_claim` |
| 8 | **The actual group names** that should become ClickHouse roles, and the owner who approves membership | Input to `roles_mapping` / `roles_filter` | `roles.*` |
| 9 | Optional: **scopes** the token must carry | Extra gate | `oauth.required_scopes` |
| 10 | Optional: allowed **email domains** / hosted domains for your tenant | Extra gate | `identity.allowed_email_domains`, `identity.allowed_hosted_domains` |
| 11 | **Consumer app registrations**: client ID and secret, redirect URIs, scopes, one per consumer and environment | So the consumer can log users in and obtain tokens carrying the audience and claims above | consumer config, not the helper |
| 12 | **Access-token lifetime** and how **signing-key rotation** is announced | Token and JWKS cache TTLs; rotation must not surprise you | `jwks_cache_lifetime`, `token_cache_lifetime` |

Network, not IdP-team, but ask your platform team in the same breath: the
helper pod must be able to reach the JWKS host over HTTPS (outbound
allow-list), and the consumer must be able to reach the IdP's authorize and
token endpoints.

## 3. IdP-specific traps

These are general hints about common setups. They are **not** tested by this
repo (the operator guide deliberately has no IdP-specific YAML shape); check
each against your IdP's current documentation.

- **Auth0**: audience is the *API identifier* of an Auth0 API you create for
  ClickHouse; without one, Auth0 may issue an opaque token. The issuer has a
  trailing slash (`https://tenant.auth0.com/`). Custom claims (roles/groups)
  must be namespaced and added via an Action/rule.
- **Okta**: use a **custom authorization server**; its issuer looks like
  `https://<org>.okta.com/oauth2/<server-id>`. Add a *groups* claim to the
  access token explicitly; it is not there by default.
- **Microsoft Entra ID**: ask for **v2.0 tokens** (the app's
  `accessTokenAcceptedVersion` must be 2), whose issuer is
  `https://login.microsoftonline.com/<tenant-id>/v2.0`. The `aud` is the
  application's client ID or Application ID URI depending on setup; confirm
  which. Group claims are **object-ID GUIDs**, not names, and users in many
  groups get an overage reference instead of a list. Prefer app roles or a
  filtered "groups assigned to the application" claim.
- **Keycloak**: issuer is `https://<host>/realms/<realm>`. Add an *Audience*
  mapper (client scope) so `aud` contains your ClickHouse audience, and a
  *Group Membership* mapper for groups; decide whether group names carry
  their full path (`/team/readers` vs `readers`).
- **Dex**: Dex issues ID tokens; confirm the token your consumer forwards is
  the one carrying the audience and groups, and note that `groups` depends on
  the upstream connector.

## 4. Message to paste into the ticket

Replace everything in `<…>`. Delete the optional lines you do not need.

```text
Subject: OIDC setup for ClickHouse access via JWT (<environment>)

Hi <IdP team>,

We are putting a token verifier in front of ClickHouse so users can log in
with their <IdP name> identity. The verifier only validates JWTs against your
published keys. It needs no client secret and no IdP account. Could you
please set up and send us the following?

1. Issuer URL exactly as it appears in the `iss` claim.
2. JWKS URL (and confirm it is reachable from <network/cluster>, outbound
   HTTPS, no auth).
3. An API/resource audience for ClickHouse, and its exact `aud` value.
   Suggested name: <clickhouse-<env>>.
4. Confirmation that access tokens for that audience are signed JWTs
   (not opaque, not encrypted) using asymmetric keys from the JWKS above.
5. Claims in the access token:
   - `email` (our username claim) and `email_verified`
   - a groups claim named `<groups>` containing an array of group names
   - optionally <scope names> in `scp`/`scope`
6. The group names to use: <idp-readers, idp-engineers>, plus who approves
   membership of each.
7. An OAuth client registration for <consumer, e.g. Superset> in <env>:
   redirect URI(s) <https://…/oauth-authorized/<provider>>, allowed scopes
   <openid email profile …>. Please deliver the client secret through
   <your secret-sharing channel>, not in the ticket.
8. Access-token lifetime, and how you announce signing-key rotation.

Please also send us a sample decoded access token (header and claims only,
NOT the signed token itself) for a test user so we can check the claims
before go-live.

Needed by: <date>. Contact: <name/team>.
```

## 5. Checking what you got

Before wiring anything, verify the answers against reality. Do this with a
test user, and never paste a real token into a ticket, chat or log; a token
is a credential until it expires.

```sh
# 1. Discovery document: issuer and jwks_uri must match what you were given.
curl -s <issuer>/.well-known/openid-configuration | jq '{issuer, jwks_uri}'

# 2. The JWKS is reachable from where the helper will run, and has keys.
curl -s <jwks_url> | jq '.keys | length'

# 3. Decode a test user's access token locally (header and claims only).
#    Check: iss, aud, exp, the username claim, email_verified, the groups claim.
printf '%s' "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq 'keys'
```

Step 3 prints only claim *names*; to inspect a specific value, query just that
claim (`jq '.aud'`, `jq '.iss'`) rather than dumping the whole payload.

Expected: `iss` equals your `expected_issuer` byte for byte; `aud` contains one
of `expected_audiences`; the groups claim is an array of strings; `exp` is in
the future. The token must be three dot-separated segments; if it is not, you
have an opaque token and go back to item 4 of the request.

## 6. From answers to config

Once you have the answers, fill the `oauth:`, `identity:` and `roles:` blocks
as shown in the operator guide (`ch-oauth-ldap`) or the root `README.md`
(`ch-jwt-verify`). Role names produced by `roles.*` must already exist in
ClickHouse; the helpers never create roles or grants.
