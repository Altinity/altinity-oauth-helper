# altinity-oauth-helper

OAuth helpers for ClickHouse-fronted deployments. Two binaries ship today:

- **`ch-jwt-verify`** — a tiny HTTP server that ClickHouse calls from its
  `<http_authentication_servers>` handler to validate JWT bearers repacked as
  a Basic-auth password.
- **`ch-oauth-ldap`** — a standalone LDAPv3 server that authenticates a
  simple Bind's password as a JWT and exposes the caller's mapped ClickHouse
  roles as synthetic LDAP groups, for consumers that speak LDAP rather than
  HTTP Basic.

Both share the same underlying JWT verification and identity-policy logic
from [`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk).

## Why this exists

Native OAuth / JWT authentication isn't in stock OSS ClickHouse. Today you
get it in two places only:

- **ClickHouse Cloud** (commercial), where SSO + JWT login is wired into the
  managed control plane.
- **[Altinity Antalya][antalya]**, Altinity's ClickHouse fork, which accepts
  `Authorization: Bearer <jwt>` directly on the HTTP interface and validates
  it against a JWKS the server is configured to trust.

If you're running OSS ClickHouse outside Cloud, neither is available. The
workaround this repo implements is to lean on ClickHouse's built-in
[`<http_authentication_servers>`][ch-http-auth] mechanism: define an external
HTTP authenticator, point ClickHouse at it, and let *that* service do the JWT
validation. ClickHouse forwards the `Authorization` header to the helper on
every authenticated request and trusts a `200 OK` response.

`ch-jwt-verify` is that helper. The catch is that ClickHouse's HTTP auth
backend only understands HTTP **Basic** — there's no Bearer path on OSS — so
upstream consumers (Superset, Grafana, MCP servers, your own scripts) have to
repack the user's JWT as the Basic-auth password (`base64(email:jwt)`) before
calling ClickHouse. The helper then pulls the JWT back out of the password
field, verifies it (signature, `iss`/`aud`/`exp`, identity policy), and
either returns 200 or rejects. See the wire diagram below for the full path.

If you can run Antalya, do — the entire repacking trick + this sidecar go
away. This repo is the bridge for everyone still on OSS.

[antalya]: https://github.com/Altinity/ClickHouse
[ch-http-auth]: https://clickhouse.com/docs/operations/external-authenticators/http

## ch-jwt-verify

A single-binary sidecar designed to run colocated with a ClickHouse pod
(StatefulSet or Deployment). Wire contract:

```
client ── Authorization: Bearer <JWT> ──> upstream (MCP / Superset / Grafana / …)
                                          rewrites to
client ── Authorization: Basic base64(email:JWT) ──> ClickHouse :8123
                                          <http_authentication_servers>
                                                │
                                                ▼
                                   ch-jwt-verify GET/POST /verify
                                                │  validates signature, iss, aud,
                                                │  exp/nbf/iat, required scopes,
                                                │  identity policy (verified-email,
                                                │  allowed domains), user↔email match
                                                ▼
                                   200 + optional CH session settings  →  CH accepts query
                                   non-200                              →  CH returns 516 WRONG_PASSWORD
```

The sidecar is the only cryptographic gate on the path: the upstream is a
pure forwarder. Per-user provisioning on the CH side:

```sql
CREATE USER "alice@example.com"
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
```

(The grammar token is `http`, not `http_authenticator` — the latter is
rejected with `SYNTAX_ERROR`.)

## ch-oauth-ldap

A standalone LDAPv3 server for consumers that authenticate over LDAP rather
than HTTP Basic. It speaks only simple Bind and a narrowly restricted Search
— there is no generic directory behind it:

- **LDAP-only.** No HTTP endpoint, no TLS/LDAPS/StartTLS, no SASL, no
  Add/Modify/Delete/Compare — those fail closed.
- **The simple-Bind password is the JWT.** The Bind DN's leading RDN
  (`uid=<username>,<user_base_dn>` by default) carries the requested
  username; the password field carries the raw JWT, exactly as
  `ch-jwt-verify` expects it packed into a Basic-auth password.
- **The shared verifier owns authentication and identity policy.** Signature,
  `iss`/`aud`/`exp`, and identity-policy checks (verified-email, allowed
  domains, deny-list) are the same `internal/verification` + `internal/roles`
  pipeline `ch-jwt-verify` uses — the LDAP layer does not reimplement any of
  it, and every failure class collapses into one generic `invalidCredentials`
  response so no failure reason is disclosed over the wire.
- **Roles are derived once at Bind and snapshotted** on that connection. A
  subsequent Search never re-verifies the JWT or recomputes roles — it reads
  only the stored snapshot.
- **Search is restricted to the caller's own membership.** A same-connection
  Search against the configured group base, with the documented
  `(&(objectClass=groupOfNames)(member=<bound DN>))` filter shape, returns one
  synthetic `groupOfNames` entry per mapped role (`cn` gets a configurable
  transport prefix, e.g. `clickhouse_ch_engineer`); anything else — another
  member's DN, a different base/scope/filter — is rejected without exposing
  data.

### Wiring ClickHouse to `ch-oauth-ldap`

ClickHouse's built-in [LDAP external user directory][ch-ldap] does the rest:
users that do not exist locally are materialized in memory on a successful
Bind, and the roles ClickHouse assigns them come from an LDAP `role_mapping`
Search — which `ch-oauth-ldap` answers from the JWT's mapped groups. The
ClickHouse username travels as the Bind DN's `uid`, and **the JWT travels as
the simple-Bind password**.

This path is verified end to end by the real-ClickHouse integration suite in
[`integration/clickhouse/`](integration/clickhouse/) against
`altinity/clickhouse-server:24.8.11.51285.altinitystable` (the baseline
target) and `altinity/clickhouse-server:25.8.28.10001.altinitystable`. The
configuration below is copied verbatim from that working fixture
(`integration/clickhouse/clickhouse/common/config.d/ldap.xml`) — note that
`role_mapping` sits **directly under `<ldap>`**, not nested inside a `<roles>`
element:

<!-- config-source: integration/clickhouse/clickhouse/common/config.d/ldap.xml -->
```xml
<clickhouse>
    <ldap_servers>
        <oauth_helper>
            <host>ch-oauth-ldap</host>
            <port>389</port>
            <bind_dn>uid={user_name},ou=users,dc=altinity,dc=internal</bind_dn>
            <verification_cooldown>0</verification_cooldown>
            <enable_tls>no</enable_tls>
            <search_limit>256</search_limit>
        </oauth_helper>
    </ldap_servers>

    <user_directories>
        <ldap>
            <server>oauth_helper</server>
            <role_mapping>
                <base_dn>ou=groups,dc=altinity,dc=internal</base_dn>
                <scope>subtree</scope>
                <search_filter>(&amp;(objectClass=groupOfNames)(member={bind_dn}))</search_filter>
                <attribute>cn</attribute>
                <prefix>clickhouse_</prefix>
            </role_mapping>
        </ldap>
    </user_directories>
</clickhouse>
```

What the fixture proves, and what you should expect in production:

- **`verification_cooldown` must be `0`.** ClickHouse otherwise caches a
  successful Bind and skips re-authentication for the cooldown window, so a
  reconnect with a new token (new groups) would keep the stale role set.
  With `0`, every authentication reaches the helper and sees the current
  token-derived roles (scenario F).
- **Mapped roles must pre-exist locally.** `role_mapping` strips the
  `clickhouse_` transport prefix and activates a role of that name *only if
  it exists*; an unknown name confers nothing. ClickHouse remains the sole
  authority for roles, grants, row policies and quotas — the helper never
  creates users or roles (scenario C).
- **Local users take precedence.** A user defined in ClickHouse itself is
  authenticated by ClickHouse; the LDAP directory is consulted only for
  names that do not exist locally (scenario G).
- **`search_limit` must cover a user's maximum mapped-role count.**
  `<search_limit>256</search_limit>` makes ClickHouse's own built-in default
  explicit. Acceptance scenario G' measured, live, that a Search returning
  `sizeLimitExceeded` fails the whole authentication attempt outright on
  both tested ClickHouse builds (24.8 and 25.8) — see
  [`docs/ch-oauth-ldap-operator-guide.md`](docs/ch-oauth-ldap-operator-guide.md#6-clickhouse-search-limits--measured-not-assumed)
  for the exact measured wire tuple and consequence.
- **Distributed queries carry the external roles to remote nodes** via
  `push_external_roles_in_interserver_queries` over secret-authenticated
  interserver connections — **with an important compatibility caveat.** The
  fixture found two upstream ClickHouse defects:
  - it requires ClickHouse **≥ 25.8** (containing [#79099][ch-79099]); on
    24.8 and 25.3 — including every Altinity Stable 24.8 build — the remote
    node logs that the role was received but it never authorizes anything
    ([#78791][ch-78791]);
  - on **every** current version (through 26.3) the pushed role is lost when
    the remote table is a normal `VIEW` ([#116840][ch-116840]) — point
    `Distributed` tables at base tables.

  `integration/clickhouse/lib/expectations.sh` records these per-version
  outcomes and the suite fails loudly if ClickHouse's behavior changes.
- **The exact byte-level LDAP request wire format is documented and
  evidenced separately.** [`docs/clickhouse-ldap-wire-profile.md`](docs/clickhouse-ldap-wire-profile.md)
  is the issue #33 phase-1 engineering evidence: source-cited ClickHouse
  (`Altinity/ClickHouse`) and OpenLDAP behavior for both tracked lines, a
  committed non-secret corpus of sanitized captured request PDUs under
  [`internal/ldap/testdata/clickhouse-wire/`](internal/ldap/testdata/clickhouse-wire/),
  and the resulting `cryptobyte`-vs-bounded-first-party-cursor primitive
  decision behind the production parser. It does not restate this
  fixture's configuration and is not a second operator-facing guide — read
  it only if you're implementing or reviewing that parser.
- **⚠️ This validates plain LDAP only — the OAuth bearer travels in clear
  text.** TLS, LDAPS and StartTLS are out of MVP scope, so the JWT (the
  OAuth bearer) crosses the ClickHouse→helper hop as the *LDAP simple-bind password*,
  in clear text, on the wire between ClickHouse and `ch-oauth-ldap`. This is a
  **deliberate MVP deviation from `ADR #16`**
  (which calls for a confidential transport), not an oversight or an
  unresolved planning question. Boris Tyshkevich (`@BorisTyshkevich`) is the
  **named risk owner** who accepted this exception for the environment-level
  deployment described below.
  - The `ch-oauth-ldap` Service is **internal-only**: it is hard-coded to
    `type: ClusterIP`, there is no Ingress/LoadBalancer/NodePort knob, and the
    chart renders a source-restricting `NetworkPolicy` by default.
  - **`NetworkPolicy is not transport confidentiality`** — it is a
    reachability control (who may open a TCP connection to the pod), not
    encryption. A NetworkPolicy does nothing to stop anyone already on the
    permitted path from reading the bearer off the wire.
  - The paths to remove this exception are **TLS** on the LDAP listener (not
    yet implemented; see `ADR #16`) or running the helper **co-located on
    loopback** as a sidecar instead of as an environment-level service (the
    same trust model `ch-jwt-verify` already uses, below). Until one of those
    lands, keep `ch-oauth-ldap` on a trusted internal network and never
    expose it publicly.

### Compatibility profile

`internal/ldap/profile/` is `cmd/ch-oauth-ldap`'s only LDAP backend — a
first-party, bounded ClickHouse compatibility profile that issue #33 phase 4
cut over into ordinary, untagged production code, deleting the vendored
`third_party/goldap`/`third_party/ldapserver` LDAP stack and the first-party
legacy `internal/ldap` package that drove it. There is no build tag, runtime
selector, or fallback path: every ordinary build and the published
`Dockerfile.ch-oauth-ldap` image construct the same `internal/ldap/profile.Server`.
The package was certified ahead of that cutover, in Phase 3, through a
temporary compile-time `phase3profile` Go build tag applied only to
`integration/clickhouse/Dockerfile`'s helper build — under that selector it
was proven against the real command composition, both tracked ClickHouse
images, HA (`run-ha.sh`), the committed wire-fixture corpus (verify-only, no
regeneration), and all five native fuzz targets. See
[`docs/clickhouse-ldap-wire-profile.md`](docs/clickhouse-ldap-wire-profile.md)
§11.5 for that historical Phase 3 evidence record (tested commit,
certified-surface digest, and every result) and §11.6 for Phase 4's own
cutover evidence.

Two ClickHouse-configured values stayed genuinely variable, not hard-coded,
across cutover:

- **`search_limit`** stays a client/operator-controlled `N` (the fixture default
  above is `256`);
- **client `timeLimit`** is honored as sent (the currently tracked ClickHouse
  value is `20` seconds).

Cutover also brought several **deliberate narrowings** — behavior the
deleted legacy server tolerated that this implementation does not. Phase 3
reviewed and explicitly `ACCEPT`ed all eleven of them (see the disposition
table below); none was a merely-incidental parser gap, and all eleven are
now the repository's permanent, current behavior:

- **Search-shape narrowing.** Only subtree scope, `derefAliases=0`,
  `typesOnly=false`, and exactly one requested attribute (case-insensitive
  `cn`) are accepted; an empty attribute list, `*`, `1.1`, or any other/
  multiple attribute selection is rejected (result 50) instead of the
  deleted legacy server's generic projection.
- **LDAPv3-only narrowing.** Only LDAPv3 simple Bind is accepted; the
  deleted legacy server's incidental Bind-version-2 acceptance is not
  retained (result 2 instead). A version-boundary refinement was reviewed
  separately: version 0, negative, or non-minimally-encoded values close the
  connection as malformed, while minimally encoded values `>=128` can decode
  and receive result 2, even though the deleted legacy `goldap` fork closed
  above 127 — tracked ClickHouse only ever emits version 3, so the parser is
  neither widened nor narrowed to copy that incidental legacy behavior.
- **DN-grammar narrowing.** Multi-valued RDNs, `;` RDN separators, `#`
  BER-hexstring values, dotted-decimal/OID attribute types, and arbitrary
  escaped attribute-type names are rejected; supported whitespace handling
  and `\XX` value escapes remain.
- **Control-plane narrowing.** Ordinary Abandon remains a no-response
  compatibility no-op but no longer cancels an in-flight operation; ordinary
  RFC 3909 Cancel is an unsupported Extended request (result 53) instead of
  the deleted legacy server's vendored Cancel scheduler; a peer disconnect no
  longer asynchronously cancels an already-running verification call.
- **New response-PDU cap.** Every outbound LDAPMessage is capped at 64 KiB;
  an oversized `SearchResultEntry` is dropped in favor of `SearchResultDone`
  result 11 (`adminLimitExceeded`), with the already-emitted entry count
  preserved. This was a genuinely new client-visible behavior at cutover, not
  parity — the deleted legacy server's write path had no outbound size bound
  at all.
- **New `UserRDNAttribute` startup validation.** This implementation requires
  the configured attribute descriptor to match `[A-Za-z][A-Za-z0-9-]*`; the
  deleted legacy server only rejected an empty/whitespace value.

See [`docs/clickhouse-ldap-wire-profile.md`](docs/clickhouse-ldap-wire-profile.md)
§11 for the full engineering-evidence writeup of all eleven narrowings (rows
`1`, `1a`, `2`–`10`) and their Phase 3 `ACCEPT` dispositions, and
[`docs/ch-oauth-ldap-operator-guide.md`](docs/ch-oauth-ldap-operator-guide.md#10-the-compatibility-profile-and-its-deliberate-narrowings-versus-the-historical-legacy-server)
§10 for the equivalent operator-facing note.

[ch-ldap]: https://clickhouse.com/docs/operations/external-authenticators/ldap
[ch-79099]: https://github.com/ClickHouse/ClickHouse/pull/79099
[ch-78791]: https://github.com/ClickHouse/ClickHouse/issues/78791
[ch-116840]: https://github.com/ClickHouse/ClickHouse/issues/116840

## Quick start

### Run locally against an existing IdP

```bash
git clone https://github.com/altinity/altinity-oauth-helper
cd altinity-oauth-helper

$EDITOR examples/curl/config.yaml      # fill in issuer + audience
go run ./cmd/ch-jwt-verify -c examples/curl/config.yaml &

examples/curl/verify.sh alice@example.com "$JWT"
# → HTTP/1.1 200 OK
#   {"settings":null,"email":"alice@example.com"}
```

See [`examples/curl/README.md`](examples/curl/README.md)
for the failure-mode cheatsheet.

### Deploy alongside ClickHouse

The two binaries deploy in two different trust models — pick the one that
matches which binary you're running:

- **`ch-jwt-verify` — colocated sidecar.** The chart in
  [`helm/ch-jwt-verify/`](helm/ch-jwt-verify/) renders two ConfigMaps
  (sidecar YAML, CH `<http_authentication_servers>` XML) and a reusable
  container fragment you splice into your CH pod spec. It does **not**
  render a Deployment/StatefulSet — the sidecar must share a pod with
  ClickHouse so the loopback trust model holds (see
  [`helm/ch-jwt-verify/README.md`](helm/ch-jwt-verify/README.md) for the
  wiring, including the clickhouse-operator `default` emptyDir quirk).
- **`ch-oauth-ldap` — environment-level Deployment+ClusterIP.** The
  standalone chart in [`helm/ch-oauth-ldap/`](helm/ch-oauth-ldap/) renders a
  two-replica Deployment and an internal-only `ClusterIP` Service on LDAP
  port 389, plus a default-on source-restricting `NetworkPolicy`, a PDB, and
  the two ConfigMaps (helper config, CH LDAP XML) — see
  [`helm/ch-oauth-ldap/README.md`](helm/ch-oauth-ldap/README.md) for values,
  the validation contract, and the clear-text-bearer risk acceptance
  recapped above.

For worked end-to-end examples (Superset, Grafana, …), see
[`examples/`](examples/) — the [`examples/README.md`](examples/README.md)
matrix tracks which consumer × deploy-style combinations are working.

Operating `ch-oauth-ldap` in production — OIDC/Auth0/JWKS field reference,
identity and role-pipeline behavior, the cache invariant, measured
ClickHouse Search-limit behavior, the trust boundary, and HA/capacity
(including the Kubernetes runbook) — is consolidated in
[`docs/ch-oauth-ldap-operator-guide.md`](docs/ch-oauth-ldap-operator-guide.md).

## Building images

There are two independent image publication pipelines, one per binary. Both
push to `ghcr.io`, are multi-arch (amd64+arm64), and only ever push
immutable, SHA-suffixed tags — neither pipeline is a PR-time gate; both
trigger only on push to `main` (plus manual `workflow_dispatch`).

PR-time verification is a separate, third workflow:
[`.github/workflows/pr-gate.yml`](.github/workflows/pr-gate.yml) (workflow
`PR gate`, single job `Required PR gate`). It runs on every pull request and
every push to `main`, with no path filters, and executes `go build ./...`,
`go vet ./...`, `go test -race ./...`, `go test -tags phase5release
./internal/securitytest -count=1`, and `bash
integration/clickhouse/tests/lib-tests.sh`. It publishes nothing, consumes no
secrets, and holds only `contents: read`; the two image pipelines below
publish but verify nothing. The real Docker ClickHouse compatibility matrix
(`integration/clickhouse/run-all-builds.sh`) stays outside that gate and
remains a manual, local suite.

### `ch-jwt-verify`

**CI (default):** [`.github/workflows/build-ch-jwt-verify.yml`](.github/workflows/build-ch-jwt-verify.yml)
builds and pushes automatically on every push to `main` that touches
`cmd/ch-jwt-verify/**`, `go.mod`/`go.sum`, or the `Dockerfile` — tag
`sidecar-<short-sha>`, multi-arch (amd64+arm64), pushed to
`ghcr.io/altinity/ch-jwt-verify` using the repo's own `GITHUB_TOKEN` (no PAT
needed). Trigger a one-off build with a custom prefix via **Actions → Build &
push ch-jwt-verify image → Run workflow**.

**Manual / local:**

```bash
scripts/build-image.sh feature-strict-iss
# → ghcr.io/altinity/ch-jwt-verify:feature-strict-iss-<short-sha>
#   (multi-arch manifest + per-arch -amd64 / -arm64 tags)
```

The script cross-compiles statically-linked binaries for amd64+arm64, builds
with legacy `DOCKER_BUILDKIT=0`, pushes per-arch, and assembles the multi-arch
manifest. Image name stays at `ghcr.io/altinity/ch-jwt-verify` so existing
Helm values continue to work. The CI workflow does the same thing (buildx +
QEMU instead of Docker Desktop's built-in emulation) — use this locally when
you need a build from an unmerged branch or a sandbox without registry push
access.

### `ch-oauth-ldap`

**CI (default):** [`.github/workflows/build-ch-oauth-ldap.yml`](.github/workflows/build-ch-oauth-ldap.yml)
builds and pushes automatically on every push to `main` that touches
`cmd/ch-oauth-ldap/**`, `internal/**`, `third_party/**`, `go.mod`/`go.sum`,
or `Dockerfile.ch-oauth-ldap` — tag `ldap-<short-sha>`, multi-arch
(amd64+arm64), pushed to `ghcr.io/altinity/ch-oauth-ldap` using the repo's
own `GITHUB_TOKEN`. Trigger a one-off build with a custom tag prefix (default
`ldap`, still emitted as `<prefix>-<short-sha>`) via **Actions → Run
workflow**'s `tag_prefix` input.

**Manual / local:**

```bash
scripts/build-ch-oauth-ldap-image.sh
# → ghcr.io/altinity/ch-oauth-ldap:ldap-<short-sha>
#   (multi-arch manifest + per-arch -amd64 / -arm64 tags)
```

Mirrors `scripts/build-image.sh`'s exact conventions — legacy
`DOCKER_BUILDKIT=0`, a per-arch base-image pull before each build, static
binaries stamped with `-X main.version=<final-tag>`, per-arch push, and
multi-arch manifest assembly — but never compiles into the checkout: each
architecture is built from a throwaway `$TMPDIR` context containing only that
arch's binary and `Dockerfile.ch-oauth-ldap` (copied in as `Dockerfile`).
Nor does it ever compile the live working tree: the binary and Dockerfile
both come from an export of exactly `HEAD` (`git archive HEAD` into that
same throwaway context), so an untracked, `.gitignore`d, or
`--assume-unchanged`-hidden local modification can never end up baked into
a published tag — a `git status` check alone cannot see all three. The
script also refuses outright to publish any `ldap-<sha>` tag (or per-arch
sub-tag) that already exists in the registry; there is no force override.

## Layout

```
cmd/ch-jwt-verify/     # the sidecar binary (main, config, settings, verify)
cmd/ch-oauth-ldap/     # the standalone LDAPv3 server (main, config, ldap_backend: the one production LDAP adapter)
internal/ldap/profile/ # the production LDAP implementation (session/DN/filter/entry primitives, Bind/Search
                       # handlers, bounded cryptobyte framing) — cmd/ch-oauth-ldap's only backend since issue #33
                       # phase 4's cutover; no build tag, runtime selector, or fallback path
internal/ldap/testdata/phase1-baseline/ # immutable pre-replacement snapshot (issue #33 phase 1; never rewritten)
internal/ldap/testdata/clickhouse-wire/ # committed sanitized ClickHouse LDAP request corpus (issue #33 phase 1)
internal/wirefixture/  # shared Profile/Session/PDU schema + constructed-fixture generator (issue #33 phase 1;
                       # test/tooling support only, mechanically absent from the production closure)
internal/securitytest/ # phase-5 AST redaction inventory, SDK contract, docs contract (see its doc.go)
docs/                  # ch-oauth-ldap-operator-guide.md: config/roles/cache/Search-limit/trust/HA consolidated
                       # clickhouse-ldap-wire-profile.md: byte-level wire evidence + primitive decision (issue #33 phase 1)
integration/clickhouse/ # real-ClickHouse acceptance suite for ch-oauth-ldap (manual; see its README)
                       # scenarios/65-ldap-search-limits.sh (G'), compose-ha.yml/run-ha.sh/ha/ (Docker HA harness)
                       # wirecapture/ (ldap-wire-recorder: capture/sanitize/construct/compare tool),
                       # compose-wirecapture.yml + capture-ldap-wire.sh (issue #33 phase-1 wire-capture fixture),
                       # tests/cases/wirecapture-*.sh (compose/fallback/collision parity, daemon-free)
helm/ch-jwt-verify/    # Helm chart (ConfigMaps + container fragment, no Deployment)
helm/ch-oauth-ldap/    # Helm chart (Deployment + ClusterIP Service + NetworkPolicy + PDB + ConfigMaps)
scripts/build-image.sh # multi-arch image build & push (ch-jwt-verify)
scripts/build-ch-oauth-ldap-image.sh # multi-arch image build & push (ch-oauth-ldap)
examples/              # _platform shared compose base, plus curl / superset /
                       # grafana consumer overlays (see examples/README.md)
Dockerfile             # consumed by scripts/build-image.sh
Dockerfile.ch-oauth-ldap # consumed by scripts/build-ch-oauth-ldap-image.sh
.github/workflows/build-ch-jwt-verify.yml  # push-to-main image publication (ch-jwt-verify)
.github/workflows/build-ch-oauth-ldap.yml  # push-to-main image publication (ch-oauth-ldap)
```

JWKS fetching, JWT validation, and the shared identity-policy helpers live
in [`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk);
this repo consumes that module via `go.mod`.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
