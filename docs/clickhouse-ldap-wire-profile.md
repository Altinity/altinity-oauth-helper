# ClickHouse LDAP Wire Profile

This is the engineering evidence document for issue #33 Phase 1. It exists to
answer one question precisely enough that Phase 2/3 can build a replacement
LDAP request parser without re-deriving anything: **what does ClickHouse's
own LDAP user-directory client actually put on the wire when it talks to
`ch-oauth-ldap`, and is `golang.org/x/crypto/cryptobyte` a safe primitive
layer for parsing it?**

It is not operator-facing configuration narrative — that role stays with
`README.md` and `docs/ch-oauth-ldap-operator-guide.md`. This document does
not restate how to deploy `ch-oauth-ldap`; it records where the wire shapes
Phase 2/3 must parse come from, why, and the resulting primitive-layer
decision.

Every provenance claim below (commit hashes, blob SHAs, OpenLDAP pins, cited
source lines) was re-verified against the live `Altinity/ClickHouse`,
`ClickHouse/openldap`, and `openldap/openldap` repositories by fetching the
exact blobs at the pinned commits and re-checking every cited line number
and function name against them, in addition to the plan's own pre-verified
"Confirmation" record. That pass found and corrected ten line-number/
function-name citations this document had wrong — one in §4, the rest in
§7 and §8.3 — including one bullet that named the wrong OpenLDAP function
entirely (§7's Unbind citation); see those sections for the corrected
values. Commit hashes, blob SHAs, and OpenLDAP pins were all already
correct and needed no change. No committed fixture and no source citation,
corrected or otherwise, contradicted the architecture this phase assumes
(plan §1's stop condition was checked and did not fire), so the evidence
and the decision below are recorded as final for Phase 1.

## 1. Tracked-line authority

"Tracked" means exactly the images listed in
`integration/clickhouse/run-all-builds.sh`'s `BUILDS` array — nothing
broader, and nothing added ad hoc by this document. That file is the single
source of truth for which ClickHouse builds Phase 1 owes fixtures for;
everything else in this document exists to explain and cite evidence *for*
those two lines, not to extend the set.

| Line   | Tracked image (verbatim from `BUILDS`)                     |
| ------ | ------------------------------------------------------------ |
| `24.8` | `altinity/clickhouse-server:24.8.11.51285.altinitystable`   |
| `25.8` | `altinity/clickhouse-server:25.8.28.10001.altinitystable`   |

`internal/securitytest`'s wire-profile contract (`wire_profile_contract_test.go`)
derives its own expected set from that same runner file and cross-checks it
against this table, the fixture directories under
`internal/ldap/testdata/clickhouse-wire/`, and every committed `profile.json`
— so the four are held equal mechanically, not by review.

## 2. Exact source provenance

### 2.1 Repository, tag, commit, OpenLDAP pin

The tracked ClickHouse source repository is explicitly **`Altinity/ClickHouse`**,
not upstream `ClickHouse/ClickHouse` — the two tags below were confirmed to
resolve to these exact commits in that fork.

| Line   | ClickHouse repository | Tag                              | Commit                                     | OpenLDAP repository   | Pin                                        | Version |
| ------ | ---------------------- | --------------------------------- | ------------------------------------------- | ---------------------- | -------------------------------------------- | ------- |
| `24.8` | `Altinity/ClickHouse`  | `v24.8.11.51285.altinitystable`  | `351edb1a2ec26940aee4c2d1d332fd280c232964` | `ClickHouse/openldap`  | `5671b80e369df2caf5f34e02924316205a43c895`  | 2.5.16  |
| `25.8` | `Altinity/ClickHouse`  | `v25.8.28.10001.altinitystable`  | `568824f4327b379e86bce93f12b9cebe0cfd9ff5` | `openldap/openldap`    | `22fe35c6b4098e3ad166469f9574c79832c42952`  | 2.6.10  |

Both `build/version.var` files at those exact pins were fetched and read
directly: the 24.8 line's submodule reports `ol_major=2 ol_minor=5
ol_patch=16`, and the 25.8 line's reports `ol_major=2 ol_minor=6
ol_patch=10` — matching the table with no interpretation required.

### 2.2 Exact ClickHouse source blob SHAs

Full 40-hex git blob SHAs, not truncated prefixes, for every ClickHouse
source file this document cites. These were independently recomputed with
`git hash-object` against each file fetched live from
`Altinity/ClickHouse` at the two commits above, and matched on the first
attempt — the plan's pre-recorded values are exact.

| File                                    | 24.8 blob                                   | 25.8 blob                                   |
| ---------------------------------------- | -------------------------------------------- | -------------------------------------------- |
| `src/Access/LDAPClient.cpp`              | `3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0`  | `3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0`  |
| `src/Access/LDAPClient.h`                | `0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6`  | `0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6`  |
| `src/Access/LDAPAccessStorage.cpp`       | `917ad7cbb922083ab82f85ab25c120a17fd009c7`  | `fc55c6b081b38ecccbf4894a9a5fa223d3cd2bd8`  |
| `src/Access/ExternalAuthenticators.cpp`  | `77812ac5eb5d0027f081ac43dccc6b89110aeb73`  | `ca61b55dc5dc200353971ff53580b2ee04439334`  |

`LDAPClient.cpp` and `LDAPClient.h` are byte-identical across the two
tracked commits — every citation into those two files below therefore uses
one line number that is valid for both lines. `LDAPAccessStorage.cpp` and
`ExternalAuthenticators.cpp` differ between the two commits (the config
parsing and role-mapping call path was reshaped between 24.8 and 25.8), so
citations into those two files are given per-commit where the line numbers
actually moved.

`profile.json` under each tracked-line fixture directory carries this exact
same repository/tag/commit/blob map, and `wire_profile_contract_test.go`
requires it to match this table field-for-field.

## 3. Configuration authority

The executable configuration authority for the fixture's ClickHouse LDAP
user directory is:

`integration/clickhouse/clickhouse/common/config.d/ldap.xml`

That file — not this document — is the single source of truth for the
shipped configuration values, and it is not duplicated here (nor should it
be edited to match anything in this document; the relationship runs the
other way). For orientation only, the request-relevant values it sets are:
LDAP host `ch-oauth-ldap`, port 389, Bind DN
`uid={user_name},ou=users,dc=altinity,dc=internal`, verification cooldown
`0`, Search size limit `256`, role-search base
`ou=groups,dc=altinity,dc=internal`, subtree scope, filter
`(&(objectClass=groupOfNames)(member={bind_dn}))`, and requested attribute
`cn`. See that file directly for the authoritative, literal values, and
`README.md` for how it is wired into the fixture's ClickHouse nodes.

`profile.json`'s `clickhouse_config_element_sha256` field is the SHA-256 of
`strings.TrimSpace` applied to exactly the file's `<clickhouse>...</clickhouse>`
element (computed by `internal/wirefixture.ClickHouseConfigElementSHA256`,
so a comment-only edit outside that element never perturbs it, while any
edit inside it — e.g. changing the Search limit — does) — that hash, not a
pasted copy of the element, is this document's drift detector for the
config file.

## 4. The ClickHouse → libldap call chain

Every wire byte ClickHouse's LDAP user-directory storage sends starts from
one authentication attempt and flows through exactly four layers before it
becomes a socket write. Each hop below is cited as
`repository@commit:file::function[:lines]`.

1. **`LDAPAccessStorage::authenticateImpl`**
   (`Altinity/ClickHouse@568824f4:src/Access/LDAPAccessStorage.cpp:453`,
   `@351edb1a:...:456`) calls into
2. **`LDAPAccessStorage::areLDAPCredentialsValidNoLock`**
   (`@568824f4:...:347`, `@351edb1a:...:350`), which — for a
   `BasicCredentials` (the caller's email+JWT repacked as HTTP Basic,
   exactly the shape `cmd/ch-jwt-verify` produces) — calls
3. **`ExternalAuthenticators::checkLDAPCredentials`**
   (`@568824f4:src/Access/ExternalAuthenticators.cpp:399`,
   `@351edb1a:...:389`), which constructs an `LDAPSimpleAuthClient` from the
   parsed `LDAPClient::Params` (built by `parseLDAPServer`, same file,
   reading the `<ldap_servers><oauth_helper>` block) and calls
4. **`LDAPSimpleAuthClient::authenticate`**
   (`Altinity/ClickHouse@351edb1a2ec26940aee4c2d1d332fd280c232964:src/Access/LDAPClient.cpp::LDAPSimpleAuthClient::authenticate`,
   line 587 — identical in both commits), which drives the actual libldap
   calls:
   * `LDAPClient::openConnection` (`LDAPClient.cpp:213`) — connection setup
     and every `ldap_set_option` (§5 below);
   * the simple Bind itself, via `ldap_sasl_bind_s(...,
     LDAP_SASL_SIMPLE, ...)` (`LDAPClient.cpp:360`);
   * for each configured role-mapping entry, `LDAPClient::search`
     (`LDAPClient.cpp:405`, issuing `ldap_search_ext_s` at `LDAPClient.cpp:445`);
   * `LDAPClient::closeConnection` (`LDAPClient.cpp:391`, issuing
     `ldap_unbind_ext_s` at `LDAPClient.cpp:398`) once the `~LDAPClient`
     destructor runs or the connection is otherwise torn down.

Role-search parameters themselves are parsed by
`parseLDAPRoleSearchParams` (`ExternalAuthenticators.cpp:259` in the 24.8
commit, `:269` in the 25.8 commit — the two commits' `checkLDAPCredentials`/
`parseLDAPServer` bodies differ in length above this function, shifting its
line number, even though the function itself is otherwise equivalent) and
threaded through `LDAPAccessStorage`'s own
`role_search_params` member (`LDAPAccessStorage.cpp`, constructed around
line 71–84 in both commits), which is what turns the fixture's single
`<role_mapping>` block into the one `LDAPClient::RoleSearchParams` instance
`LDAPSimpleAuthClient::authenticate` iterates and searches with.

Mapped-role results flow back up through `checkLDAPCredentials`'s
`role_search_results` out-parameter into
`LDAPAccessStorage::assignRolesNoLock` (`LDAPAccessStorage.cpp:199`/`206`),
which is where the wire evidence's job ends and ClickHouse's own local-role
bookkeeping begins — out of this document's scope.

## 5. Complete `ldap_set_option` classification

`LDAPClient::openConnection` (`LDAPClient.cpp:213`, identical in both
commits) sets exactly these options, in this order, every one of them
before the Bind is issued (`LDAPClient.cpp:246`–`340`):

| Option                        | Set at (`LDAPClient.cpp`) | Category                  | Treatment                                                                                       |
| ------------------------------ | -------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------- |
| `LDAP_OPT_PROTOCOL_VERSION`   | line 246                  | Protocol selection        | Server-visible semantic input; fixes the connection to LDAPv3 (both tracked lines run version 3).|
| `LDAP_OPT_RESTART`            | line 249                  | Client/socket behavior    | Source fact (auto-retry interrupted syscalls); not a BER request field.                          |
| `LDAP_OPT_KEEPCONN`           | line 252 (`#ifdef LDAP_OPT_KEEPCONN`) | Client/socket behavior | Source fact; not a BER request field. Guarded by an `#ifdef`, present on both tracked OpenLDAP pins. |
| `LDAP_OPT_TIMEOUT`            | line 260 (`#ifdef LDAP_OPT_TIMEOUT`) | Operation/network timeout | The overall per-operation timeout (40 s default) — distinct from `SearchRequest.timeLimit`. Guarded by its own `#ifdef`, exactly like `LDAP_OPT_KEEPCONN`; present on both tracked OpenLDAP pins. |
| `LDAP_OPT_NETWORK_TIMEOUT`    | line 269 (`#ifdef LDAP_OPT_NETWORK_TIMEOUT`) | Operation/network timeout | Connect/network-level timeout (30 s default) — distinct from both the above and `timeLimit`. Likewise its own `#ifdef`-guarded block, present on both tracked OpenLDAP pins. |
| `LDAP_OPT_TIMELIMIT`          | line 275                  | Search defaults           | Handle-wide default Search time limit (20 s); superseded per-call (§6). Not `#ifdef`-guarded — set unconditionally. |
| `LDAP_OPT_SIZELIMIT`          | line 280                  | Search defaults           | Handle-wide default Search size limit (256); superseded per-call (§6). Not `#ifdef`-guarded — set unconditionally. |
| `LDAP_OPT_X_TLS_PROTOCOL_MIN` (line 294), `LDAP_OPT_X_TLS_REQUIRE_CERT` (line 308), `LDAP_OPT_X_TLS_NEWCTX` (line 340) | lines 283–296, 298–309, 337–341 | TLS configuration | Each guarded **only** by its own compile-time `#ifdef` (does the macro exist on this OpenLDAP build) — there is no `params.enable_tls` check and no field-present check on any of these three. They run unconditionally whenever compiled with TLS support, `<enable_tls>no</enable_tls>` notwithstanding. |
| `LDAP_OPT_X_TLS_CERTFILE`, `LDAP_OPT_X_TLS_KEYFILE`, `LDAP_OPT_X_TLS_CACERTFILE`, `LDAP_OPT_X_TLS_CACERTDIR`, `LDAP_OPT_X_TLS_CIPHER_SUITE` | lines 312–335 | TLS configuration | Each guarded by its own `#ifdef` **and** a field-emptiness check (`if (!params.tls_*.empty())`) — not by `params.enable_tls`. In this fixture's config all five fields are empty, so these five specifically do not fire; the three above still do. |

Recorded for completeness of the source read. **None of these eight options
gate on `params.enable_tls`** — the fixture's `<enable_tls>no</enable_tls>`
only controls the later, separately guarded `ldap_start_tls_s` call (line
344: `if (params.enable_tls == ...::YES_STARTTLS) ldap_start_tls_s(...)`),
which is what actually starts TLS on the wire. So while three of these
eight `ldap_set_option` calls (`PROTOCOL_MIN`, `REQUIRE_CERT`, `NEWCTX`) do
execute for the captured sessions, none of them causes any TLS wire traffic
by itself — they only configure OpenLDAP's TLS context object for a
`ldap_start_tls_s`/`ldaps://` call that this fixture's `enable_tls=no`
config never makes, so still no `LDAP_OPT_X_TLS_*` value or TLS byte
reaches the wire this document characterizes.

The non-TLS options above — the seven this document treats as the complete
non-TLS inventory — are exactly:
`LDAP_OPT_PROTOCOL_VERSION`, `LDAP_OPT_RESTART`, `LDAP_OPT_KEEPCONN`,
`LDAP_OPT_TIMEOUT`, `LDAP_OPT_NETWORK_TIMEOUT`, `LDAP_OPT_TIMELIMIT`, and
`LDAP_OPT_SIZELIMIT`. Nothing else appears in `openConnection`'s option
inventory before the Bind; this is the sentinel list a later mechanical
check (plan §30.1/§30.2) compares against, so the source read this table
reflects is meant to be exhaustive, not illustrative.

## 6. Source-of-value table

For every documented request property, its authority is one of: (1)
repository XML, (2) a ClickHouse compiled-in default, (3) a ClickHouse
handle option set once at connection-open time, (4) an explicit libldap
call argument passed at the point of the actual request, (5) a libldap
fallback/default, or (6) only observable on the wire itself.

| Property                       | Value in this fixture | Authority                                                                                                    |
| -------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Bind DN template                | `uid={user_name},ou=users,dc=altinity,dc=internal` | (1) repository XML (`ldap.xml`'s `<bind_dn>`)                                       |
| Protocol version                | 3                      | (2) ClickHouse default (`LDAPClient.h:96`, `ProtocolVersion::V3`) applied via (3) `LDAP_OPT_PROTOCOL_VERSION`   |
| Operation timeout               | 40 s                   | (2) ClickHouse compiled-in default (`LDAPClient.h:120`) applied via (3) `LDAP_OPT_TIMEOUT` — handle-wide only, no explicit per-call libldap operation-timeout argument exists for this call shape. |
| Network timeout                 | 30 s                   | (2) ClickHouse compiled-in default (`LDAPClient.h:121`) applied via (3) `LDAP_OPT_NETWORK_TIMEOUT` — handle-wide only, same reasoning as above. |
| Search time limit                | 20 s                   | (2) ClickHouse compiled-in default (`LDAPClient.h:122`), applied **both** via (3) `LDAP_OPT_TIMELIMIT` at connection-open time **and** (4) as the explicit `&timeout` argument `LDAPClient::search` builds and passes to `ldap_search_ext_s` (`LDAPClient.cpp:434`,`445`) — the handle-wide default is redundant with, not overridden by, the per-call value here, since both derive from the same `params.search_timeout`. |
| Search size limit ("Search limit")| 256                    | (1) repository XML (`ldap.xml`'s `<search_limit>`, which overwrites (2) ClickHouse's own compiled-in default of 256 — `LDAPClient.h:123` — with the same numeric value, making this line behavior-neutral versus leaving it unset), applied **both** via (3) `LDAP_OPT_SIZELIMIT` and (4) the explicit `params.search_limit` argument to `ldap_search_ext_s` (`LDAPClient.cpp:445`), for the same belt-and-suspenders reason as the Search time limit. |
| Search base DN                  | `ou=groups,dc=altinity,dc=internal` | (1) repository XML (`ldap.xml`'s `role_mapping/base_dn`)                                    |
| Search scope                    | subtree                | (1) repository XML (`ldap.xml`'s `role_mapping/scope`), mapped to `LDAP_SCOPE_SUBTREE` (`LDAPClient.cpp:405`ff.) |
| `derefAliases`                   | `neverDerefAliases` (0) | (5) libldap fallback/default — `LDAPClient::search` calls `ldap_search_ext_s` (`LDAPClient.cpp:445`), whose signature has no `deref` parameter at all; `ldap_search_ext_s` hardcodes `deref = -1` internally when it delegates to `ldap_pvt_search_s` (`search.c:151`, both pins), and `ldap_build_search_req`'s non-UDP branch resolves any negative `deref` to the handle's own `ld_deref` (`search.c:326`, both pins: `(deref < 0) ? ld->ld_deref : deref`). `ld_deref` is a per-handle copy of the process-wide global default options made at handle-creation time (`open.c:150`, inside the `ldap_create` already cited in §7), and that global default is set once by `ldap_int_initialize_global_options` (`init.c:563`, both pins: `gopts->ldo_deref = LDAP_DEREF_NEVER;`, i.e. `0x00` — `ldap.h:795`). ClickHouse never calls `ldap_set_option(..., LDAP_OPT_DEREF, ...)` anywhere in `LDAPClient.cpp`, so nothing overrides this chain. Confirmed on the wire: byte `00` in the `derefAliases` ENUMERATED immediately following the `scope` ENUMERATED in every committed `002-search-request.ber` fixture (24.8 and 25.8, `success` and `timeout-abandon`). |
| Search filter                   | `(&(objectClass=groupOfNames)(member={bind_dn}))` | (1) repository XML (`ldap.xml`'s `role_mapping/search_filter`), placeholders substituted per §6.3 below |
| Requested attribute             | `cn`                   | (1) repository XML (`ldap.xml`'s `role_mapping/attribute`)                                                  |
| MessageID sequence              | 1, 2, 3, …             | (6) observed wire / (5) libldap fallback — see §6.4; no ClickHouse or repository input chooses these values at all. |

## 7. OpenLDAP wire construction (both pins)

Both tracked OpenLDAP pins were fetched and read directly for this section
(`ClickHouse/openldap@5671b80e369df2caf5f34e02924316205a43c895` for 2.5.16,
`openldap/openldap@22fe35c6b4098e3ad166469f9574c79832c42952` for 2.6.10).
Every citation below is, after the line-number and function-name
corrections noted at the top of this document, the stated function present
at the stated line in the 2.6.10 pin, and — where the bullet says so
explicitly — the same construction present in the 2.5.16 pin as well (the
two pins' `libldap` directories implement the same architecture across this
version gap, and no divergence was found that would matter to this
document's request shapes); no bullet below claims an unverified line
number for the 2.5.16 pin specifically.

* **`build/version.var`** — the pin's own version stamp; `ol_minor=5
  ol_patch=16` (2.5.16 pin) and `ol_minor=6 ol_patch=10` (2.6.10 pin),
  matching §2.1 exactly.
* **`libraries/libldap/open.c::ldap_create`** (line 119 in both pins) —
  allocates the `LDAP` handle with `LDAP_CALLOC` (line 139), which
  zero-initializes the whole struct, including `ld_msgid`; then sets
  `ld->ld_lberoptions = LBER_USE_DER` at **line 221 in both pins**. This is
  the single line that establishes DER (not just BER) encoding discipline
  — canonical, minimal-length, definite-form — for every request this
  handle ever sends, and it is identical between the 2.5.16 and 2.6.10
  pins.
* **`libraries/libldap/ldap-int.h::LDAP_NEXT_MSGID`** (line 561 in the
  2.6.10 pin) — `(id) = ++(ld)->ld_msgid`, mutex-guarded. Every request
  builder below calls this macro exactly once, immediately before
  constructing its PDU, and uses the returned value as that PDU's
  MessageID. Combined with the zero-initialization above: **the first
  request issued on a freshly created handle is always MessageID 1**, and
  it increments by exactly one per request issued on that same handle,
  irrespective of request type.
* **Simple-Bind construction** —
  `libraries/libldap/sasl.c::ldap_build_bind_req` (line 48, 2.6.10 pin):
  calls `LDAP_NEXT_MSGID` (line 80), then for `LDAP_SASL_SIMPLE`
  (ClickHouse's only configured mechanism) builds the PDU with
  `ber_printf(ber, "{it{istON}", *msgidp, LDAP_REQ_BIND, ld->ld_version,
  dn, LDAP_AUTH_SIMPLE, cred)` (lines 83–86) — i.e. `LDAPMessage ::=
  SEQUENCE { messageID, [APPLICATION 0] SEQUENCE { version INTEGER, name
  OCTET STRING, [0] simple OCTET STRING } }`, exactly RFC 4511's
  `BindRequest`/`AuthenticationChoice::simple` shape.
* **Search-request construction** —
  `libraries/libldap/search.c::ldap_build_search_req` (line 249, 2.6.10
  pin; same construction present at 2.5.16): calls `LDAP_NEXT_MSGID`
  (line 305), then builds the PDU with `ber_printf(ber, "{it{seeiib",
  *idp, LDAP_REQ_SEARCH, base, scope, deref, sizelimit, timelimit,
  attrsonly)` (lines 324–329, the non-UDP branch — a separate
  `LDAP_CONNECTIONLESS`-only branch immediately above it builds the same
  fields with an extra `dn` argument and is inapplicable to this fixture's
  plain-TCP LDAP) followed by the filter and attribute-list encoding later
  in the same function — i.e. `SEQUENCE { messageID,
  [APPLICATION 3] SEQUENCE { baseObject OCTET STRING, scope ENUMERATED,
  derefAliases ENUMERATED, sizeLimit INTEGER, timeLimit INTEGER, typesOnly
  BOOLEAN, filter Filter, attributes SEQUENCE OF AttributeDescription } }`.
* **Synchronous Search wait and timeout → Abandon** —
  `libraries/libldap/search.c` (both pins; 2.5.16 pin lines 181–188,
  2.6.10 pin the equivalent `ldap_search_ext_s`/`ldap_result` pairing):
  the synchronous wrapper calls `ldap_result(ld, msgid, LDAP_MSG_ALL,
  timeout, res)`; when that call itself returns `LDAP_TIMEOUT`, the wrapper
  immediately calls `ldap_abandon(ld, msgid)` on the very same MessageID
  it was waiting on, before propagating `LDAP_TIMEOUT` back to
  `LDAPClient::search`. This is the exact mechanism behind this document's
  `timeout-abandon` fixture: a stalled Search response times out client-side
  and libldap reacts by abandoning that same Search, never by tearing down
  the connection outright.
* **Abandon-request construction** —
  `libraries/libldap/abandon.c` (2.6.10 pin: `ldap_abandon` at line 99,
  the internal `do_abandon` from line 121): calls `LDAP_NEXT_MSGID` (line
  207) to mint the AbandonRequest **its own new MessageID**, then builds
  `ber_printf(ber, "{iti", id, LDAP_REQ_ABANDON, msgid)` (lines 229–231,
  the non-UDP branch — a separate `LDAP_CONNECTIONLESS`-only branch
  immediately above it, format string `"{isti"`, is inapplicable here) —
  i.e. `SEQUENCE { messageID [own, freshly allocated], [APPLICATION 16]
  INTEGER [the target request's MessageID, implicit-tagged, not
  re-wrapped] }`. The AbandonRequest's own MessageID and the MessageID it
  targets are therefore always two different values by construction — this
  document's fixtures reflect this directly (see §9).
* **Unbind construction** —
  `libraries/libldap/unbind.c::ldap_send_unbind` (2.6.10 pin, declared at
  line 270; same shape at 2.5.16) is where the UnbindRequest PDU is
  actually built — not `ldap_unbind_ext` (line 38 in both pins), which only
  runs client-control checks and calls `ldap_ld_free` (line 74), which in
  turn calls `ldap_free_connection` (`libraries/libldap/request.c:733`,
  2.6.10 pin) with its `unbind` argument set, and that is what actually
  invokes `ldap_send_unbind` (`request.c:792`). `ldap_send_unbind` calls
  `LDAP_NEXT_MSGID` (line 290), then `ber_printf(ber, "{itn", id,
  LDAP_REQ_UNBIND)` (lines 293–294) — i.e. `SEQUENCE {
  messageID, [APPLICATION 2] NULL }`, RFC 4511's empty `UnbindRequest`.
  Like Abandon, Unbind gets its own freshly allocated MessageID; it is not
  sent with a reused or zero MessageID.
* **DER INTEGER encoding** —
  `libraries/liblber/encode.c::ber_put_int_or_enum` (2.6.10 pin, line
  170): encodes the two's-complement content bytes one at a time from the
  low end, stopping as soon as the accumulated value's top bit is clear
  (`unum < 0x80`) — i.e. the shortest content-byte sequence that keeps the
  value's sign correct, which is exactly DER's minimal-length INTEGER
  requirement. This one routine is what produces both the single content
  byte `0x7f` for MessageID 127 and the two-byte `0x00 0x80` for MessageID
  128 (a leading zero forced in precisely because a bare `0x80` would flip
  the sign): every MessageID and every Search INTEGER/ENUMERATED field
  this document discusses passes through this same function, on both pins.

## 8. Request semantics as implemented

### 8.1 Bind and protocol version

Every tracked connection issues exactly one `BindRequest` before any
`SearchRequest`, using LDAP protocol version 3
(`LDAPClient::Params::protocol_version` defaults to `ProtocolVersion::V3`,
`LDAPClient.h:96`, and every tracked deployment leaves that default in
place) and `AuthenticationChoice::simple` — never SASL, never anonymous —
via `ldap_sasl_bind_s(handle, final_bind_dn.c_str(), LDAP_SASL_SIMPLE,
&cred, ...)` (`LDAPClient.cpp:360`). The credential (`cred.bv_val`) is the
caller's password field verbatim — in this fixture's deployment, the
caller-side JWT — with no client-side transformation.

### 8.2 Search fields

Exactly one `SearchRequest` per role-mapping entry follows a successful
Bind (this fixture's config has exactly one `<role_mapping>`, so exactly
one Search per session). Its fields, resolved per §6 above: base DN
`ou=groups,dc=altinity,dc=internal`, scope `wholeSubtree`, `derefAliases`
`neverDerefAliases` (0 — ClickHouse passes no explicit deref value at all,
so this is libldap's own handle default, never a ClickHouse or repository
choice; see §6), filter
`(&(objectClass=groupOfNames)(member={bind_dn}))` with `{bind_dn}`
substituted, `sizeLimit` 256, `timeLimit` 20, `typesOnly` false (ClickHouse
never sets it), and the single requested attribute `cn`. Every request PDU this fixture captures — Bind, Search, Abandon, Unbind
alike — carries no LDAP Controls: `ldap_sasl_bind_s` and `ldap_search_ext_s`
are both called from `LDAPClient.cpp` with `nullptr` for both the server-
and client-controls arguments (`LDAPClient.cpp:360`,`445`); `Unbind` goes
through `ldap_unbind_ext_s(handle, nullptr, nullptr)` (`LDAPClient.cpp:398`);
and the client-side-timeout `Abandon` (§8.6) is libldap's own internal
`ldap_abandon(ld, msgid)` call inside `ldap_result` (§7), which itself
always passes `NULL, NULL` for controls (`abandon.c:102`, both pins). So
`controls` is absent (not merely empty) on the wire throughout — no
`Controls` sequence follows any `LDAPMessage`'s protocolOp.

### 8.3 Placeholder substitution and escaping pipeline

`LDAPClient.cpp`'s anonymous-namespace helpers (identical in both tracked
commits) do the substitution in two distinct escaping modes, and
`LDAPClient::search` (`LDAPClient.cpp:420`ff.) is careful to apply the
filter-safe one specifically to filter placeholders:

* **`escapeForDN`** (`LDAPClient.cpp:89`): backslash-escapes the RFC 4514
  DN special characters (`, \ # + < > ; "` and `=`) one at a time. Used
  once, on the raw HTTP username, to produce `final_user_name`
  (`LDAPClient.cpp:347`), which then feeds the Bind DN template's
  `{user_name}` placeholder (`LDAPClient.cpp:348`) via a plain
  string-replace helper (`replacePlaceholders`, `LDAPClient.cpp:149`).
* **`escapeForFilter`** (`LDAPClient.cpp:116`): RFC 4515 filter-escapes
  `*`, `(`, `)`, `\`, and NUL as `\2A`, `\28`, `\29`, `\5C`, `\00`
  respectively. Used when building the Search filter's own placeholders
  (`{user_name}`, `{bind_dn}`, `{user_dn}`, `{base_dn}` —
  `LDAPClient.cpp:427`–`430`), never for the DN fields themselves — the
  same underlying string is escaped differently depending on which BER
  field it is about to land in.

Neither escaping routine is a general-purpose LDAP-string escaper; each
handles exactly the character set relevant to the BER field it feeds
(DN vs. filter), matching RFC 4514/4515's distinct escaping rules for
those two contexts.

### 8.4 MessageID behavior and this document's determinism basis

MessageIDs are never chosen by ClickHouse or by this fixture's
configuration — they come entirely from libldap's own per-handle counter
(§7). The concrete consequence, and the basis every byte-for-byte fixture
comparison in this repository relies on: **on a fresh connection, the
first request sent is MessageID 1, and each subsequent request on that
same connection is one higher, in the order actually issued** — so a
`success` session sees Bind=1, Search=2, Unbind=3, and a `timeout-abandon`
session sees Bind=1, Search=2, Abandon=3 (targeting MessageID 2, its own
freshly allocated ID, per §7's Abandon citation), Unbind=4. Both committed
`session.json` fixtures record exactly this sequence.

This determinism is not automatic in general — it depends on three things
holding for every capture:

1. **One connection per session** (`connection_count: 1` in every committed
   `session.json`) — libldap's counter is per-handle, so a second Bind on
   the same handle would not restart at 1, and this document's equality
   claims would not hold if ClickHouse ever reused a handle across
   authentication attempts (it does not, per §4/§7: `~LDAPClient` closes
   the connection, and each authentication attempt constructs a fresh
   `LDAPSimpleAuthClient`).
2. **The Bind DN and Search filter derive only from the fixed HTTP user**
   the capture script authenticates as — no other request-shaping input
   varies between runs.
3. **Placeholder-length constancy** — the sanitizer (§9.2) replaces the
   Bind credential bytes with same-length filler, so a byte-identical
   fixture comparison also requires the *replaced* credential to be the
   same length on every regeneration. That, in turn, depends on the
   synthetic IdP's `/sign` endpoint (`cmd/synthetic-idp/main.go:138-173`)
   emitting a fixed claim set with fixed-digit `iat`/`exp` values and no
   random `jti` — a JWT with a randomized claim would produce a
   varying-length token and break this invariant on every recapture, not
   just occasionally.

Separately, the constructed MessageID-127/128 boundary fixture (§9.1)
deliberately does **not** flow through the synthetic IdP at all: its fixed
Bind password literal is `wirefixture_constructed_boundary_not_a_token_000`
(`internal/wirefixture/constructed.go`), chosen specifically so it is not
JWT-shaped — it does not have the three-base64url-segment, JSON-header-decoding
shape this repository's own JWT-shape scanner (plan §30.6) looks for. A
JWT-shaped literal in a *constructed* fixture would have caused that
scanner's own committed fixture to trip its own positive-match logic.

### 8.5 Unbind

Every session ends with exactly one `UnbindRequest` — `SEQUENCE {
messageID, [APPLICATION 2] NULL }` — issued from `~LDAPClient`'s call to
`closeConnection` (`LDAPClient.cpp:391`, `ldap_unbind_ext_s` at line 398)
with its own freshly allocated MessageID (§7). It carries no credential
content of any kind.

### 8.6 Timeout-triggered Abandon

When the recorder's `stall-after-bind` mode (`integration/clickhouse/wirecapture`)
never answers the Search, ClickHouse's client-side Search timeout (20 s,
§6) expires inside `ldap_result`, which — per §7's citation — reacts by
calling `ldap_abandon` on that same Search's MessageID before returning
`LDAP_TIMEOUT` to `LDAPClient::search`. The result on the wire is a fourth
observed PDU class this document's fixtures capture: `AbandonRequest`,
`SEQUENCE { messageID [new], [APPLICATION 16] INTEGER [target] }`, with
`abandon_target` in the committed `session.json` recording the Search's
MessageID it names. `LDAPClient::search` then propagates the timeout as an
error up through `authenticate`, and `~LDAPClient` still runs its normal
Unbind on the way out — hence four PDUs (Bind, Search, Abandon, Unbind),
not three, in every committed `timeout-abandon` session.

## 9. Captured evidence

### 9.1 Provenance classes

Every committed PDU carries a `provenance_class` of either
`captured-redacted` or `constructed`, and the two are never conflated:

* **`captured-redacted`** — a real libldap request byte stream, captured by
  proxying the real `ch-oauth-ldap` binary through
  `integration/clickhouse/wirecapture`'s recorder against a real,
  containerized ClickHouse instance running one of the two tracked images,
  then sanitized (§9.2) before being written to disk. `24.8/success/`,
  `24.8/timeout-abandon/`, `25.8/success/`, and `25.8/timeout-abandon/` are
  all of this class.
* **`constructed`** — hand-built by `internal/wirefixture`'s
  `BuildConstructedSimpleBind`, exercising exactly one BER encoding
  boundary (the MessageID 127/128 DER-minimal-length transition) that
  real, sequential capture traffic cannot conveniently be made to land on
  deterministically. `constructed/message-id-boundary/` is the only
  fixture of this class, and it is `applicability`-tagged for both tracked
  lines rather than duplicated per line, since the encoding rule it proves
  (§7's `ber_put_int_or_enum`) is shared, not ClickHouse-version-specific.

Independently confirmed while writing this document: the three
`captured-redacted` `.ber` files that exist in both tracked lines'
`success/` sessions (`001-bind-request.ber`, `002-search-request.ber`,
`003-unbind-request.ber`) are byte-for-byte identical between `24.8` and
`25.8`, despite the two lines' `LDAPAccessStorage.cpp`/
`ExternalAuthenticators.cpp` source blobs differing (§2.2). This is
recorded here strictly as an **observed server-visible result** — the two
lines' compiled `LDAPClient.cpp`/`.h` are the byte-identical files that
actually build the wire request (§2.2), so identical output from differing
higher-level source is fully expected, not evidence that the two lines'
source provenance can be collapsed into one. Each fixture's `profile.json`
keeps its own line's full commit/blob provenance regardless of whether the
resulting bytes matched another line's.

### 9.2 Capture and sanitization mechanism

`integration/clickhouse/capture-ldap-wire.sh` drives a five-service Docker
Compose fixture (`integration/clickhouse/compose-wirecapture.yml`) in which
`integration/clickhouse/wirecapture`'s recorder sits as a transparent proxy
between the real ClickHouse node and the real `ch-oauth-ldap` helper,
framing and recording every LDAP PDU it forwards to a container-private
tmpfs. The one real credential involved — a JWT minted by the synthetic
IdP for a fixed, non-secret test user — is transferred into the sanitizer
by stdin only (no flag, no environment variable); `readCredentialFromStdin`
implements that single path, and a dedicated test
(`TestSanitize_CredentialTransferIsStdinOnly`, a source-level string grep,
not an AST-level check) is what actually enforces no other path exists.
The sanitizer finds that exact byte string within the raw Bind PDU and
replaces it in place with same-length ASCII `x` filler before anything
leaves the container. `placeholder_length` in each committed `session.json`
records that filler's length so a fresh capture can be checked for
length-parity with the committed one without either capture ever
containing a live credential. Alongside the sanitized PDUs, every committed
`session.json` also carries `token_claim_recipe` — the fixed, non-secret
description of how that credential was minted
(`internal/wirefixture.FixedTokenClaimRecipe`, passed to `sanitize
--token-claim-recipe` since it is a description, never the credential
itself) — and each PDU's
`expected_semantics`, populated from one fixed per-operation table
(`internal/wirefixture.ExpectedSemanticsForOperation`) rather than left
blank; both are part of the same stable-comparison projection as the raw
PDU bytes (plan §28's stable session/PDU metadata). Every export path
(generate-mode promotion and verify-mode comparison alike) additionally
runs this repository's existing exact-token leak scanner
(`integration/clickhouse/lib/leakscan.sh`) over the run's transcript,
diagnostics, and exported staging before anything is trusted, and the
whole corpus — including this document — is scanned by a structural
JWT-shape detector (plan §30.6) as a second, independent backstop.

## 10. Cryptobyte characterization and primitive-layer decision

`internal/ldap/clickhouse_wire_cryptobyte_test.go`'s
`TestClickHouseWireCryptobyteDecision` loads every fixture this document
describes — all four captured sessions and the constructed
MessageID-boundary bundle — through `internal/wirefixture`, and for each
valid PDU proves, using `golang.org/x/crypto/cryptobyte` plus a small set
of fixed first-party checks: the outer `LDAPMessage` SEQUENCE is consumed
completely with no trailing bytes at any nesting level; every length is
definite-form and canonical; MessageID is a canonical non-negative INTEGER
including at the 127/128 boundary; the application tags match Bind
(`0x60`)/Unbind (`0x42`)/Search (`0x63`)/Abandon (`0x50`); Bind's version
and `[0]` simple-auth context tag are correct; Search's ENUMERATED,
INTEGER, and BOOLEAN fields decode within their expected ranges; the
Search filter's supported context tags parse recursively; and Abandon's
`[APPLICATION 16]`-implicit-tagged target integer — which cryptobyte's own
tag-fixed high-level readers cannot address directly — is validated by a
small hand-written first-party helper rather than by inventing a second
general parser. The same test then runs twelve bounded negative mutations
(indefinite length, non-minimal long-form length, truncation,
negative/non-minimal INTEGER, malformed ENUMERATED/BOOLEAN, wrong tags,
trailing data) and confirms every one is rejected rather than silently
misparsed. Eleven of the twelve mutate a single byte within a real,
committed fixture used as a template; the twelfth
("redundant-integer-padding") is a fully hand-built byte sequence, not
derived from any committed fixture, because no committed template happens
to exercise that exact non-minimal-INTEGER encoding shape.

Per the plan's decision rule: the choice is `cryptobyte` if and only if
every valid, supported fixture is safely consumable this way, and rejected
malformed input never counts against that — a parser correctly refusing
garbage is not evidence it needs a hand-rolled cursor. No fixture in this
corpus required anything cryptobyte plus the fixed profile checks above
could not safely consume, so:

<!-- ldap-primitive-decision: cryptobyte -->

That marker is this document's only occurrence of the decision text, and
its value is not an independent editorial judgment — it is required to
equal, byte-for-byte, whatever
`TestClickHouseWireCryptobyteDecision` computes at test time; a future
fixture that broke that agreement would fail
`go test -race ./internal/ldap -run '^TestClickHouseWireCryptobyteDecision$'`
rather than silently drift from this document.

## 11. Phase 2/3 handoff

This document, together with the committed fixtures under
`internal/ldap/testdata/clickhouse-wire/` and the `internal/wirefixture`
schema that owns their format, is the complete baseline Phase 2/3 needs to
build the replacement parser:

* the exact request shapes to support (§8) and the two BER edge cases that
  matter (the 127/128 MessageID boundary from §7/§9.1, and Abandon's
  implicit-tagged target integer from §10);
* the exact, machine-checkable source provenance behind every shape (§2,
  §4–§7), so a future ClickHouse version bump can be evaluated by diffing
  against this document's citations rather than re-deriving them from
  scratch;
* the primitive-layer decision (§10) and the reasoning that produced it —
  `cryptobyte` plus a small number of named, fixed first-party checks
  (canonical MessageID, application-tag dispatch, and the Abandon implicit
  integer), not a general hand-rolled BER cursor;
* what Phase 1 deliberately did **not** decide: production TLS handling
  (§5's TLS row is inspected but inapplicable to this plain-LDAP fixture),
  the general-LDAP dependency denylist (`internal/securitytest/dependency_contract_test.go`'s
  Phase 3 extension), and any change to `cmd/ch-oauth-ldap`'s current
  production behavior, which this phase leaves untouched by design.

A later phase that finds a captured shape this document does not account
for should extend the fixture corpus and this document together, in the
same change — not silently widen the replacement parser past what the
evidence here actually supports.

### 11.1 Phase 2 implementation status

Phase 2 built the replacement at `internal/ldap/profile/` (package
`profile`), following the primitive decision above: `cryptobyte` for every
ASN.1 primitive, plus the same small set of fixed first-party checks named
in §10 — including the Abandon `[APPLICATION 16]`-implicit-tagged target
integer, whose content bytes are read directly under the application tag
and then validated with the identical minimal-positive-INTEGER rule the
LDAPMessage envelope's MessageID uses (the same shared rule the 127/128
boundary and the differential oracle below both exercise for Abandon).

This is implementation and test evidence only. `cmd/ch-oauth-ldap` still
runs the legacy `internal/ldap` server in production; nothing
production-reachable imports `internal/ldap/profile` yet — that import
happens in Phase 4. Proof of the replacement's correctness comes from,
entirely outside the Docker ClickHouse suite:

* real-TCP black-box tests driving the profile server directly (ported from
  the legacy `protocol_test.go`, plus adversarial/mid-Search/hostile-DN/
  redaction-boundary/limits suites);
* real-TCP replay of every committed session under
  `internal/ldap/testdata/clickhouse-wire/**` through the profile server
  (`internal/ldap/profile/replay_test.go`);
* a profile-valid differential oracle against the vendored goldap decoder
  (`internal/ldap/profile/differential_test.go`, `package profile`,
  importing goldap only from `_test.go`);
* five native fuzz targets (`FuzzLDAPFrame`, `FuzzBindRequest`,
  `FuzzSearchRequest`, `FuzzRestrictedDN`, `FuzzMemberAssertionDN`) seeded
  from this document's own fixture corpus plus hand-built boundary/malformed
  vectors — every committed seed runs under ordinary `go test`; a short fuzz
  smoke beyond seeds is
  `go test ./internal/ldap/profile -run '^$' -fuzz=Fuzz<Name> -fuzztime=20s`,
  one target at a time, never a real 20/30-second production deadline in an
  ordinary unit test;
* dependency contracts (`internal/securitytest/profile_dependency_contract_test.go`)
  proving the profile is absent from `./cmd/ch-oauth-ldap`'s live closure and
  that the profile's own closure requires `golang.org/x/crypto/cryptobyte`
  while excluding the vendored/general LDAP stack;
* an architecture contract (`internal/securitytest/profile_architecture_contract_test.go`)
  mechanically enforcing exactly one production goroutine spawn, no
  request-indexed state, a nonrecursive two-child membership-filter decoder,
  and diagnostic/reason bytes reachable only through their closed enums;
* redaction-inventory coverage (`internal/securitytest`'s `scopeDirs`, sink
  kind `ldap-profile-diagnostic`) with marker-bearing proofs at default and
  trace log levels.

Measured physical LOC for the nine production files this replaces
(`server.go`, `frame.go`, `protocol.go`, `session.go`, `bind.go`,
`search.go`, `dn.go`, `encode.go`, `logging.go`) plus `config.go` (the public
`Config`/`ValidateConfig` surface) and `doc.go` (package-status doc) — using
Phase 1's physical-line definition, comments and blanks counted, i.e.
`wc -l` summed over exactly those eleven files (equivalently: `wc -l
$(ls internal/ldap/profile/*.go | grep -v _test.go)`) — is **2,659** as of
the phase-2 compat-profile sub-task that hardened the write-stall/Search-
deadline classification, the DN parse-error redaction, and the wire-facing
descriptor comparisons (each of those touched `dn.go`, `config.go`, and/or
`search.go`). It was previously measured at 2,608 (nine-file total 2,426 +
`config.go` 148 + `doc.go` 34) before that sub-task. The plan's
consolidation-review trigger is 2,500 physical LOC for this package; the
coordinator's recorded disposition on the earlier 2,608 figure — accepted,
since the overshoot is exactly the `config.go`/`doc.go` public-surface and
package-status files the plan's own file table omitted, not undocumented
growth — stands unchanged at 2,659: both figures are well below ADR #32's
separate ~3,500-line architecture-review trigger, and consolidation review
against that trigger still folds into Phase 4's legacy deletion, not this
sub-task. That disposition is recorded in the issue #33 ship log; see it
for the full accounting, not a restatement here.

### 11.2 Restricted-profile acceptance: what the replacement accepts

The replacement is a bounded ClickHouse compatibility profile, not a general
LDAP server. It accepts exactly: LDAPv3 simple Bind; a same-connection Search
against subtree scope, `derefAliases=0`, `typesOnly=false`, exactly one
requested attribute (case-insensitive `cn`), and the fixed two-predicate
`(&(objectClass=groupOfNames)(member=<bind DN>))` filter shape; client-
declared `sizeLimit`/`timeLimit` honored as sent (not hard-coded to the
captured `256`/`20`); Abandon recognized and dropped with no response;
Unbind/close. Every mapped unsupported operation and every out-of-profile
Search form returns a fixed result code — never a decode error that would
suggest the input was malformed.

### 11.3 The ten Phase-3 narrowings

Cutover replaces several places where current production is more permissive
than the documented ClickHouse traffic actually requires, or adds a bound
current production does not have at all. Phase 3 must explicitly accept or
reject each one before Phase 4 is authorized:

1. Bind version `!= 3` changes from current incidental acceptance to result
   2 `protocolError` (LDAPv3-only). This narrowing's own result-2 path is
   reached only for a version value that decodes successfully (minimally
   encoded, in range `1..MaxInt32`) and simply isn't 3: the version field is
   decoded through the same shared minimal-positive-INTEGER rule
   (`minimalPositiveInt32`) the LDAPMessage envelope's MessageID uses, so a
   version of 0, a negative version, or a non-minimally-encoded value is
   malformed at decode time and closes the connection before the version
   check ever runs — it never reaches result 2. This matches legacy
   goldap's own decode window for this field (a 1..127 range at the
   single-octet BER-integer level).
2. Search `derefAliases != 0` changes from current tolerance to result 50.
3. Search `typesOnly=true` changes from current supported generic rendering
   to result 50.
4. Search empty, `*`, `1.1`, non-`cn`, and multi-attribute selections change
   from current generic projection to result 50.
5. The restricted DN grammar drops legacy-`go-ldap` forms: multi-valued
   RDNs with unescaped `+`, `;` RDN separators, `#` BER-hexstring values,
   dotted-decimal/OID attribute types, arbitrary escaped attribute-type
   names, schema-based normalization, and arbitrary RFC 4514 equivalence.
6. A peer disconnect no longer asynchronously cancels an in-flight
   verification call (the synchronous replacement does not concurrently
   read EOF while blocked in `Verify`).
7. Ordinary Abandon no longer cancels an in-flight operation (decoded and
   dropped; no target lookup, no cancellation).
8. Ordinary RFC 3909 Cancel no longer has the vendored RouteMux's
   target/result semantics (protocolError/noSuchOperation/cannotCancel/
   canceled); it returns result 53 `operation not supported` like any other
   unsupported Extended request.
9. **(new client-visible behavior, not parity)** The response-PDU 64 KiB
   cap: a `SearchResultEntry` that would exceed it is dropped in favor of
   `SearchResultDone` result 11 `adminLimitExceeded`, already-emitted count
   preserved. Current production's write path
   (`third_party/ldapserver/client.go`'s `writeMessage`) serializes whatever
   the handler wrote with no outbound size bound at all.
10. **(new client-visible behavior, not parity)** `UserRDNAttribute` gains a
    startup-time descriptor-shape check (`[A-Za-z][A-Za-z0-9-]*`); current
    production (`internal/ldap/dn.go`, `cmd/ch-oauth-ldap/config.go`) only
    rejects an empty/whitespace value.

### 11.4 Phase 4's bounded test-only cursor supersedes this document's oracle

§10's `TestClickHouseWireCryptobyteDecision` currently uses `cryptobyte`
itself as the independent decoder proving fixture well-formedness. Phase 2's
plan deliberately selects, for Phase 4, a **bounded test-only cursor** as
that independent oracle's replacement — not the Phase 2 `profile` decoder —
because using the eventual production decoder to prove fixture
well-formedness for itself would be self-referential. Phase 4 must
therefore: delete `internal/ldap/profile/differential_test.go`; replace this
document's/`internal/ldap`'s independent goldap fixture decoder with a small,
bounded, test-only definite-length structural cursor; preserve the
well-formedness/filter-structure anti-drift assertions the current oracle
provides; and never use the production `profile` package as that
independent oracle. This explicitly supersedes the alternative the Phase 1
ship log left open (replacing the oracle with the production decoder
itself).
