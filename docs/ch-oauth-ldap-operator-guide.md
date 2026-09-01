# `ch-oauth-ldap` operator guide

This consolidates the operational knowledge an operator needs to configure,
size, and reason about the trust boundary of `ch-oauth-ldap` — it does not
restate the wire diagram or protocol design already covered by the root
[`README.md`](../README.md#ch-oauth-ldap) and
[`helm/ch-oauth-ldap/README.md`](../helm/ch-oauth-ldap/README.md); read those
first for "what this binary is." This guide is "how to configure and run it
correctly," gathered in one place (issue #19 phase 5).

Every YAML fence below is copied verbatim, byte-for-byte, from
[`cmd/ch-oauth-ldap/testdata/operator-guide.yaml`](../cmd/ch-oauth-ldap/testdata/operator-guide.yaml)
— the exact file
`TestOperatorGuideYAML_LoadsThroughProductionLoadConfig` loads through the
real production `LoadConfig`, and `TestOperatorGuideYAML_StrictKnownFields`
(both in `cmd/ch-oauth-ldap/config_test.go`) additionally strict-decodes with
`yaml.NewDecoder(...).KnownFields(true)` against the production `Config`
struct. That strict test — not eyeballing this document — is the proof that
every field shown here is real and current; `internal/securitytest/docs_contract_test.go`
enforces that each fence is an exact contiguous excerpt of that file (or, for
the ClickHouse XML below, of the real fixture) so this guide cannot drift
from either source silently.

## 1. The working ClickHouse configuration

Copied verbatim from the `<clickhouse>...</clickhouse>` element of
[`integration/clickhouse/clickhouse/common/config.d/ldap.xml`](../integration/clickhouse/clickhouse/common/config.d/ldap.xml),
the fixture the real-ClickHouse acceptance suite in
`integration/clickhouse/` runs against all four tracked builds —
`altinity/clickhouse-server:24.8.11.51285.altinitystable`,
`altinity/clickhouse-server:25.8.28.10001.altinitystable`,
`altinity/clickhouse-server:26.3.16.10001.altinitystable` and
`clickhouse/clickhouse-server:26.8.1.2041`:

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

`role_mapping` sits **directly under `<ldap>`**, not nested inside an
illustrative `<roles>` element — the real LDAP-directory parser reads it
there on every tracked line (24.8 through 26.8). `verification_cooldown` must be `0` so every authentication
reaches the helper and sees the current token-derived roles (a nonzero value
lets ClickHouse skip re-authentication for the cooldown window on reconnect,
serving a stale role snapshot). `enable_tls=no` reflects the trust boundary
in §7 below — TLS is not implemented.

`<search_limit>256</search_limit>` makes ClickHouse's own built-in default
explicit and actionable — see §6 for exactly what happens when a caller's
mapped-role count exceeds it, measured live rather than assumed. The chart's
embedded copy of this XML (`helm/ch-oauth-ldap/templates/_helpers.tpl`) is
templated — `host`, `bind_dn`, `role_mapping/base_dn`, and
`role_mapping/prefix` are rendered from `.Values.ldap.*` and so vary with
each release's configuration, unlike this fixture's fixed literal values.
What `helm/ch-oauth-ldap/test.sh`'s embedded-XML assertion actually
cross-checks between the chart and this fixture is narrower: the overall
element structure (same elements, same nesting) and the `<search_limit>`
value specifically, which the assertion requires to equal `256` in both
places. The templated fields are instead cross-checked against the
*rendering's own* `config.yaml` values (e.g. the XML's `bind_dn` must equal
that render's `ldap.user_rdn_attribute` + `ldap.user_base_dn`), not against
this fixture's literal text — see `helm/ch-oauth-ldap/ci/lib/embedded-assertions.sh`.
This guide's own fence above, by contrast, is a byte-for-byte copy of the
fixture (enforced by `docs_contract_test.go`), so it does stay identical to
the fixture — it just isn't identical to the chart's templated output.

**Distributed-role propagation to a remote node requires ClickHouse ≥ 25.8**
(fixed upstream by [ClickHouse #79099](https://github.com/ClickHouse/ClickHouse/pull/79099));
on 24.8 and 25.3 the pushed role never authorizes anything even though the
remote node's own log claims it was applied, and on every version through
26.8 the role is additionally lost across a normal `VIEW`
([#116840](https://github.com/ClickHouse/ClickHouse/issues/116840), still
open upstream). This is
a recorded ClickHouse limitation, not a `ch-oauth-ldap` defect — see the
root README's [ClickHouse compatibility caveats][root-caveats] for the full
two-bug write-up and `integration/clickhouse/lib/expectations.sh` for the
per-version expectation matrix; this guide does not duplicate it.

[root-caveats]: ../README.md#wiring-clickhouse-to-ch-oauth-ldap

For the byte-level evidence behind this configuration — exact ClickHouse/
OpenLDAP source citations, the committed sanitized request corpus, and the
`cryptobyte`-vs-bounded-parser primitive decision behind the production
parser — see [`docs/clickhouse-ldap-wire-profile.md`](clickhouse-ldap-wire-profile.md)
(issue #33 phase 1); it is engineering evidence for that implementation, not a
second copy of the configuration above.

## 2. OIDC / Auth0 / JWKS configuration

<!-- config-source: cmd/ch-oauth-ldap/testdata/operator-guide.yaml -->
```yaml
oauth:
  expected_issuer: https://tenant.example.auth0.com/
  jwks_url: https://tenant.example.auth0.com/.well-known/jwks.json
  expected_audiences:
    - clickhouse
    - mcp
  username_claim: email
  groups_claim: roles
  verifier_leeway: 60s
  required_scopes: []
  jwks_cache_lifetime: 5m
  token_cache_lifetime: 30s
```

- **`expected_issuer`** and **`jwks_url`** — at least one of the two must be
  set (`cmd/ch-oauth-ldap/config.go`'s `validateConfig` fails startup
  otherwise). Set both, as above, to pin an explicit JWKS endpoint instead of
  relying on OIDC discovery from the issuer alone; set only `expected_issuer`
  to let the shared verifier discover the JWKS endpoint from the issuer's
  `.well-known` metadata instead.
- **`expected_audiences` is a plural list, and it is the *only* audience
  vocabulary this binary accepts.** There is no LDAP-side singular
  `audience` compatibility alias. This is a deliberate asymmetry, not an
  oversight: `ch-jwt-verify` is the older binary and keeps its legacy
  singular `audience` surface for its own existing deployments, but
  `ch-oauth-ldap` is a new binary with no backward-compatibility surface to
  preserve, so it only ever exposes the plural form. Singular-versus-plural
  is therefore a `ch-jwt-verify`-specific compatibility rule, not a second
  supported LDAP YAML shape.
- **`verifier_leeway`** (default `60s`) is the clock-skew tolerance the
  shared verifier applies to `exp`/`nbf`/`iat` checks.
- **`jwks_cache_lifetime`** (default `5m`) and **`token_cache_lifetime`**
  (default `30s`) are TTLs for the JWKS key set and per-token verification
  outcome caches, respectively — see §5 for the token cache's actual
  expiration invariant, which is stricter than a flat TTL.
- **`username_claim`** and **`groups_claim`** are covered in §3 and §4.

Auth0 maps onto these generic fields with no LDAP-specific configuration
surface: `expected_issuer` is your Auth0 tenant's issuer URL (as above),
`jwks_url` is that tenant's `/.well-known/jwks.json`, and Auth0's default
`email`/custom-namespaced-claim conventions plug into `username_claim`/
`groups_claim` the same way any other OIDC-compliant IdP's claims would.
There is no separate, untested Auth0-specific YAML shape — the fields above
are the entire contract regardless of which IdP issues the token.

## 3. Identity behavior

<!-- config-source: cmd/ch-oauth-ldap/testdata/operator-guide.yaml -->
```yaml
identity:
  username_match: lowercase_equal
  require_email_verified: true
  allowed_email_domains:
    - example.com
  allowed_hosted_domains: []
  denied_usernames:
    - default
    - admin
```

- **`username_claim`** (in the `oauth:` block, §2) defaults to `email` when
  left empty — not `sub`, and not a hard failure. Set it to `sub` or any
  other string-valued top-level/extra claim name to bind against something
  else instead.
- **`username_match`** defaults to `lowercase_equal` when left empty. Valid
  values are exactly `exact` and `lowercase_equal`; any other value fails
  config validation at startup. `lowercase_equal` trims outer whitespace and
  compares case-insensitively; `exact` requires a byte-for-byte match between
  the Bind DN's requested username and the resolved claim value.
- **Denied-user normalization is independent of `username_match`.**
  `denied_usernames` is always compared using trimmed, case-insensitive
  matching, regardless of the configured match mode — so `Default`, `
  default `, and `DEFAULT` are all denied when `default` is listed, even
  under `username_match: exact`.
- **Credential-shaped requested usernames are redacted before ever reaching
  a log line or error message.** Basic auth's `user:token` split places no
  format constraint on the "user" half, so an attacker (or a confused
  client) can put an entire JWT there. Anything longer than 128 bytes, or
  shaped like a compact JWT (three non-empty, dot-separated segments), is
  replaced with a fixed `[redacted requested-username, N bytes]` marker
  everywhere the requested username is echoed ahead of successful identity
  binding — never a prefix or suffix of the original value, since a
  truncated JWT is still a credential fragment.

## 4. Roles: the pipeline order

<!-- config-source: cmd/ch-oauth-ldap/testdata/operator-guide.yaml -->
```yaml
roles:
  roles_mapping:
    idp-readers: ch_readonly
    idp-engineers: ch_engineer
  roles_filter: '^ch_[A-Za-z0-9_]+$'
  roles_transform: 's/^ch_//'
```

The role pipeline (`internal/roles.Pipeline.Roles`) runs in exactly this
order, and the order is normative, not an implementation detail:

```text
groups extraction → input dedupe → roles_mapping → full-match roles_filter → roles_transform → final dedupe
```

- **Groups extraction** reads `oauth.groups_claim` (default `groups` —
  Antalya's vocabulary — when left empty) from the token's claims.
  - A **missing** claim yields **zero roles**, not an error — an
    unauthenticated-for-roles-but-otherwise-valid token still authenticates,
    it just maps to no ClickHouse roles.
  - A **malformed** configured claim — present, but not a string array (nor
    a plain string) — is a **hard authentication failure**
    (`roles.ErrMalformedGroupsClaim`), never silently coerced to zero roles.
- **Input dedupe** removes duplicate raw group names before mapping,
  preserving first-occurrence order.
- **`roles_mapping`** translates an IdP group name to a role candidate.
  **A group with no mapping entry passes through unchanged** — mapping is
  not the fail-closed control; `roles_filter` is.
- **`roles_filter`**, when configured, is a regex every candidate must
  **match in its entirety** to survive (not merely contain as a substring) —
  this is the actual deployment fail-closed control: an unmapped or
  unexpectedly-named group cannot become a ClickHouse role unless it
  matches this pattern.
- **`roles_transform`**, when configured, is an Antalya-style
  `s/pattern/replacement/flags` rewrite applied to surviving candidates
  *after* filtering (filtering sees the pre-transform name). Worked example
  with the fence above: `idp-readers` maps to `ch_readonly`, which matches
  `roles_filter` and survives, and `roles_transform`'s `s/^ch_//` then
  strips the `ch_` prefix, yielding the final ClickHouse role name
  `readonly` (`idp-engineers` → `ch_engineer` → `engineer` the same way).
- **Final dedupe** removes duplicates again, since distinct groups may
  map/transform onto the same final role name.
- **Role names must already exist in ClickHouse.** Exactly as documented for
  the root README's ClickHouse wiring: `role_mapping` strips the transport
  prefix and activates a role of that name only if it already exists
  locally. `ch-oauth-ldap` and the LDAP directory mechanism never create
  ClickHouse roles, grants, row policies, or quotas — ClickHouse remains the
  sole authority.

## 5. Cache invariant

The shared verification cache (`internal/verification`) enforces:

```text
cache_expiration = min(now + PositiveTTL, JWT.exp)
```

A cached positive verification outcome can never outlive the JWT it was
computed from, however large `token_cache_lifetime` (§2) is configured. The
cache key is a hash of `requestedUsername + NUL + token`, so a cached
outcome is bound to *both* the identity a caller claimed and the exact token
presented — a stale or cross-user cache hit is not possible by construction.
This is existing phase-1 behavior (see `internal/verification/verifier.go`);
this guide only cross-references it rather than restating the
implementation.

## 6. ClickHouse Search limits — measured, not assumed

The fixture in §1 sets `<search_limit>256</search_limit>` — ClickHouse's own
long-standing built-in default for this LDAP-directory setting, now made
explicit. Acceptance scenario **G'**
(`integration/clickhouse/scenarios/65-ldap-search-limits.sh`) mints a token
carrying 257 mapped role names — one more than this limit — and measures,
live against every tracked ClickHouse image, what actually happens.

**The measured wire tuple, decoded from ClickHouse's real Search request
against the helper, is identical on all four tracked builds:**

```text
size_limit=256 time_limit=20 types_only=false
```

`time_limit=20` is ClickHouse's compiled-in handle-wide Search time limit,
installed by `LDAPClient::openConnection()` via
`ldap_set_option(LDAP_OPT_TIMELIMIT, ...)` and sent on every Search because
this configuration path requests no per-call deadline of its own. There is
no `<search_timeout>` XML key for this path — do not add one; it is not
read — but that absence yields the handle default on the wire, not zero.

> **Correction.** This tuple was recorded here and in
> `lib/expectations.sh` as `time_limit=0` until the 26.3/26.8 lines were
> added, reasoning from the missing XML key. That was wrong on every line —
> and it contradicted this repository's own wire-profile document, whose
> §8.2 has always recorded `timeLimit` 20 for the same Search. Two further
> independent sources confirm 20: decoding `SearchRequest.timeLimit`
> out of the committed capture corpus
> (`internal/ldap/testdata/clickhouse-wire/<line>/success/002-search-request.ber`
> — BER `02 01 14`, identical on all four lines), and the helper's own live
> telemetry during a real scenario G' run, which logs `time_limit=20`. No
> behavior changed; the field was recorded and logged but never asserted
> against the telemetry, which is how the two records contradicted each
> other unnoticed.

**The measured consequence of the resulting `sizeLimitExceeded` (LDAP result
4) Search response is also identical on all four tracked builds:**
`ch-oauth-ldap` correctly emits exactly 256 entries and returns result 4 (its
own `ldap search size limit exceeded` log line records
`size_limit=256 entries=256 result=4`), and **ClickHouse's LDAP-directory
login path treats that non-success Search result as fatal — the whole
authentication attempt fails** (a non-200 response at the ClickHouse HTTP
interface — measured as HTTP 403 on all four tracked builds, though
`assert_search_limit_overflow_outcome` in `lib/expectations.sh` only asserts
`CH_LAST_STATUS != 200`, not that specific code, matching this suite's
elsewhere-documented discipline of never asserting a specific error
string/status for a rejection whose exact shape isn't part of the
contract; the query behind the request never runs) rather than
authenticating with a truncated 256-of-257 role set. This was an open
question the phase-5 plan explicitly required measuring rather than
assuming for 25.8 — it turned out to share 24.8's behavior rather than
differ from it, and 26.3/26.8 later matched both.

**Operational consequence: `search_limit` must be sized to cover the maximum
legitimate mapped-role count for any one user**, or that user's
authentication fails outright once their role count crosses the configured
limit. Raise `<search_limit>` in the ClickHouse LDAP-directory configuration
(§1) if a real deployment has users with legitimately large mapped-role
counts.

## 7. Trust boundary: plaintext bearer over LDAP

**The OAuth bearer (the JWT) travels in clear text as the LDAP simple-bind
password** between ClickHouse and `ch-oauth-ldap`. This is a **deliberate
MVP deviation from ADR #16** (which calls for a confidential transport), not
an oversight or an unresolved planning question — Boris Tyshkevich
(`@BorisTyshkevich`) is the named risk owner who accepted this exception for
the environment-level deployment.

The compensating controls actually implemented are network-layer, not
transport-layer:

- the `ch-oauth-ldap` Service is hard-coded `type: ClusterIP` — no
  Ingress/LoadBalancer/NodePort knob exists anywhere in the chart;
- the chart renders a default-on, source-restricting `NetworkPolicy` that
  fails closed on every allow-all ClickHouse selector shape (empty,
  nested-empty, and `DoesNotExist`/`NotIn`-only expressions).

**`NetworkPolicy is not transport confidentiality.`** It restricts *who can
reach the Service*; it does nothing to the bytes on the wire. Anyone already
on the permitted network path can read the bearer in the clear.

There is **no LDAPS, no StartTLS**, anywhere in this MVP — `enable_tls=no`
in §1's fixture is intentional. The two paths that remove this exception
entirely: implement TLS on the LDAP listener (not done in this phase), or
move to a loopback/co-located sidecar deployment model instead of an
environment-level `Deployment` + `ClusterIP` (the same trust model
`ch-jwt-verify` already uses). Removing the exception means one of those two
changes, never relaxing the `NetworkPolicy` default.

## 8. HA and capacity

### 8.1 Docker HA — what it proves, and its explicit boundary

`./integration/clickhouse/run-ha.sh` (not executed by this guide — see
`integration/clickhouse/README.md`'s HA section and
`integration/clickhouse/compose-ha.yml`/`integration/clickhouse/ha/`) brings
up two independent `ch-oauth-ldap` replicas behind an HAProxy TCP frontend
and proves, live, via a persistent same-socket session probe and mechanical
HAProxy stats-socket observation (never a fixed sleep):

- two independent helpers both authenticate;
- no shared session store, verifier cache, or role cache is required for
  correctness;
- session state stays on the original TCP connection;
- killing replica A destroys an A-owned session — the phrase to remember is
  **existing connection to a killed replica may fail**, and this is
  expected, not a bug: there is no session migration to the surviving
  replica B;
- fresh authentication succeeds on B immediately after A is killed;
- a recreated A is rediscovered and re-admitted once its DNS name resolves
  again;
- backend health is observed mechanically (HAProxy stats), never inferred
  from a sleep.

Docker does **not** prove ClusterIP dataplane behavior, EndpointSlice
convergence, kube-proxy/eBPF/CNI behavior, `kubectl delete pod` semantics,
Kubernetes readiness/termination timing, scheduler replacement timing, PDB
behavior under actual eviction, real-CNI NetworkPolicy/probe interaction, or
any Kubernetes failover SLA. Every one of those claims is summarized in one
phrase: **not verified in this environment** — execute the Kubernetes
runbook below on a real cluster before relying on them.

**Issue #33 phase history.** This same Docker HA harness was first run, in
Phase 3, against the first-party compatibility profile (`internal/ldap/profile`)
for both tracked ClickHouse images (`24.8.11.51285`, `25.8.28.10001`), with
the profile selected only by a temporary compile-time `phase3profile` Go
build tag applied solely to `integration/clickhouse/Dockerfile`'s helper
build — see [`docs/clickhouse-ldap-wire-profile.md`](clickhouse-ldap-wire-profile.md)
§11.5 for that historical result record. Both runs passed with the
**identical claim boundary above, verbatim**: they proved the same
Docker/HAProxy socket-local-session behavior described above and nothing
about Kubernetes routing, EndpointSlice/CNI convergence, pod-eviction
semantics, or a failover SLA. Issue #33 phase 4's cutover then deleted the
`phase3profile` tag and the legacy server it stood in for: `internal/ldap/profile`
is now the only LDAP backend `cmd/ch-oauth-ldap` builds, ordinarily and
untagged — the exact same server code the Phase 3 HA runs above already
exercised, now running in every ordinary build and the published
`ghcr.io/altinity/ch-oauth-ldap` image with no selector of any kind.

### 8.2 Kubernetes runbook (not executed in this environment)

No live Kubernetes cluster was available to this phase's implementation.
The following is a documented runbook — **not verified in this
environment** — to execute against a real cluster before trusting
Kubernetes ClusterIP/EndpointSlice failover behavior in production:

1. Deploy the existing chart with two replicas; require both `Ready`.
2. Inspect the `ClusterIP` `Service`.
3. Record both `Ready` EndpointSlice endpoints.
4. Inspect the `PodDisruptionBudget` and `NetworkPolicy`.
5. Perform fresh authentications until both pods have each served a
   successful Bind.
6. Delete a known-serving pod normally (not `--force`).
7. Watch `EndpointSlice` removal for that pod.
8. Require another `Ready` endpoint still remains.
9. Boundedly retry **new** ClickHouse authentications.
10. Require survivor success.
11. Do **not** require existing-connection survival — an in-flight
    connection to the deleted pod failing is an expected outcome, exactly
    like the Docker HA harness's own "existing connection to a killed
    replica may fail" observation above.
12. Wait for the replacement pod to become `Ready`.
13. Require two `Ready` endpoints again.
14. Fresh-authenticate until the replacement pod has served a Bind.

Retain only redacted metadata from this exercise, never raw bearers. Do not
claim any specific failover SLA unless the target cluster itself defines
one — this runbook proves correctness of convergence, not a time bound.

### 8.3 Capacity numbers

The server (`internal/ldap/profile`) enforces three fixed, hard constraints:

- a **64 KiB** maximum declared LDAP message body per connection
  (`internal/ldap/profile/frame.go`'s bounded-before-allocation framing);
- **256** concurrent connections per process (`internal/ldap/profile/server.go`'s
  admission cap);
- **30 seconds** read/write timeouts per connection (`internal/ldap/profile/protocol.go`'s
  `defaultDeadline`).

`256 × 64 KiB` (16 MiB) describes only the **admitted per-message body
buffer** worst case for one process — not total process memory, and not a
capacity guarantee once ordinary Go runtime overhead, goroutine stacks, and
everything else the process holds is accounted for. Two replicas therefore
imply roughly ~512 connection slots in aggregate, as an arithmetic
consequence of the per-process limit, not a load-balancing guarantee —
Kubernetes Services do not promise even distribution across replicas.

## 9. Filter-nesting hardening (fixed, nonrecursive decoder)

`internal/ldap/profile/search.go`'s `decodeMembershipFilter` does not
implement general Search-filter grammar at all — it recognizes exactly one
fixed two-predicate shape,
`(&(objectClass=groupOfNames)(member={bind_dn}))` in either child order, and
rejects everything else (result 50) as an unauthorized filter. The decoder
is deliberately nonrecursive: it never calls itself, and it calls its
equality-child decoder exactly twice
(`internal/securitytest/profile_architecture_contract_test.go` mechanically
enforces both facts). There is no AND/OR/NOT nesting depth to bound because
there is no nesting to decode in the first place — this replaces the
formerly vendored `third_party/goldap` fork's configurable 32-deep nesting
cap (a general-filter-grammar hardening bound, deleted along with the fork
at issue #33 phase 4's cutover) with an authorization boundary that admits
only the one filter shape ClickHouse ever sends. This is not an
operator-configurable knob in either design.

## 10. The compatibility profile, and its deliberate narrowings versus the historical legacy server

`internal/ldap/profile/` is `cmd/ch-oauth-ldap`'s only LDAP backend today —
issue #33 phase 4 deleted the vendored `third_party/goldap`/`third_party/ldapserver`
LDAP stack this section used to describe as "current production" and the
first-party legacy `internal/ldap` package that drove it, and made this
compatibility profile's composition ordinary, untagged production code with
no build tag, runtime selector, or fallback path. The package was certified
ahead of that cutover, in Phase 3, through a temporary compile-time
`phase3profile` Go build tag applied only to
`integration/clickhouse/Dockerfile`'s helper build — under that selector it
was proven against the real command composition (config, verifier, role
pipeline, listener, lifecycle), both tracked ClickHouse images, HA (§8.1
above), the committed wire-fixture corpus (verify-only), and all five native
fuzz targets. It carries its own real-TCP black-box tests, native fuzzing,
real-TCP replay of every committed wire fixture, and
dependency/architecture/redaction contracts; see `CLAUDE.md`'s
`internal/ldap/profile/` repo-map row and
[`docs/clickhouse-ldap-wire-profile.md`](clickhouse-ldap-wire-profile.md) §11
for the complete engineering-evidence writeup (§11.5 records that Phase 3
certification as frozen history; §11.6 records Phase 4's own cutover
evidence).

Cutover also brought several **deliberate narrowings** versus the deleted
legacy server's behavior — behavior that server tolerated which this
implementation does not. Phase 3 reviewed and explicitly `ACCEPT`ed all
eleven of them ahead of cutover (see
[`docs/clickhouse-ldap-wire-profile.md`](clickhouse-ldap-wire-profile.md)
§11.3's disposition table); none was a merely-incidental parser gap, and all
eleven are now the repository's permanent, current behavior. They are
recorded here for an operator who remembers the old server's more permissive
edges and needs to know they are gone, not as a pending change.

### Search values that stayed variable

Two operator/client-controlled Search values stayed genuinely variable
across cutover:

- `search_limit` remains a client/operator-controlled `N` — §1's fixture
  default is `256`;
- client `timeLimit` is honored as sent — the currently tracked ClickHouse
  value is `20` seconds (§6).

### Deliberate Search-shape narrowing

The compatibility profile accepts only: subtree scope, `derefAliases=0`,
`typesOnly=false`, exactly one requested attribute (case-insensitive `cn`),
and the exact two-predicate membership filter — no empty attribute list, no
`*`, no `1.1`, no arbitrary/multiple attributes. The deleted legacy server
was broader for `derefAliases`, `typesOnly`, and attribute projection, but
those forms were outside documented ClickHouse traffic.

### Deliberate LDAPv3 narrowing

Only LDAPv3 simple Bind is accepted; the deleted legacy server's incidental
Bind-version-2 acceptance is not retained (this implementation returns
result 2 `protocolError` instead). A separately reviewed decoder-boundary
note: version 0, negative, or non-minimally-encoded values close the
connection as malformed, while minimally encoded values `>=128` can decode
and receive result 2, even though the deleted legacy `goldap` fork closed
above 127 — tracked ClickHouse emits version 3, so the parser is neither
widened nor narrowed merely to copy that incidental legacy behavior.

### Deliberate DN narrowing

The restricted DN grammar (`internal/ldap/profile/dn.go`, used for
configured bases, Bind DNs, Search bases, and the membership filter's member
assertion) drops: multi-valued RDNs, `;` RDN separators,
`#` BER-hexstring values, dotted-decimal/OID attribute types, and arbitrary
escaped attribute-type names. Supported whitespace handling and `\XX` value
escapes remain.

### Deliberate control-plane narrowing

Ordinary Abandon remains a no-response compatibility operation but no longer
cancels an in-flight target; ordinary RFC 3909 Cancel is an unsupported
Extended request (result 53) rather than the deleted legacy server's
vendored Cancel implementation; critical Cancel/Abandon retain their
result-12/no-target-action behavior where applicable; a peer disconnect no
longer asynchronously cancels an already-running verification call. These
are real legacy-behavior removals, permitted by this implementation's
bounded synchronous architecture. Phase 3 reviewed and explicitly `ACCEPT`ed
each one (see
[`docs/clickhouse-ldap-wire-profile.md`](clickhouse-ldap-wire-profile.md)
§11.3/§11.5 rows 6, 7, and 8) ahead of the Phase 4 cutover.

### New response-PDU cap and `UserRDNAttribute` validation

Two further narrowings were new client-visible behavior at cutover, not
parity, and are called out separately because neither was a removal of
existing tolerance:

- every outbound LDAPMessage is capped at 64 KiB; an oversized
  `SearchResultEntry` is dropped in favor of `SearchResultDone` result 11
  (`adminLimitExceeded`), already-emitted count preserved — the deleted
  legacy server's write path had no outbound size bound at all;
- this implementation requires the configured `UserRDNAttribute` to match
  `[A-Za-z][A-Za-z0-9-]*` at startup; the deleted legacy server only
  rejected an empty/whitespace value.
