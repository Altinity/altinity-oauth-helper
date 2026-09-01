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
values. Within the scope of that Phase 1 audit — the `24.8` and `25.8`
lines, the only ones tracked at the time — commit hashes, blob SHAs and
OpenLDAP pins were all already correct and needed no change. That scoping
is load-bearing rather than pedantic: the later `26.3`/`26.8` expansion did
have to correct a commit hash, because `v26.8.1.2041-lts` is an annotated
tag and its tag-object SHA was recorded where the peeled commit belonged
(§2.1, §11.7). No committed fixture and no source citation,
corrected or otherwise, contradicted the architecture this phase assumes
(plan §1's stop condition was checked and did not fire), so the evidence
and the decision below are recorded as final for Phase 1.

## 1. Tracked-line authority

"Tracked" means exactly the images listed in
`integration/clickhouse/run-all-builds.sh`'s `BUILDS` array — nothing
broader, and nothing added ad hoc by this document. That file is the single
source of truth for which ClickHouse builds this document owes fixtures for;
everything else in this document exists to explain and cite evidence *for*
those four lines, not to extend the set.

| Line   | Tracked image (verbatim from `BUILDS`)                     |
| ------ | ------------------------------------------------------------ |
| `24.8` | `altinity/clickhouse-server:24.8.11.51285.altinitystable`   |
| `25.8` | `altinity/clickhouse-server:25.8.28.10001.altinitystable`   |
| `26.3` | `altinity/clickhouse-server:26.3.16.10001.altinitystable`   |
| `26.8` | `clickhouse/clickhouse-server:26.8.1.2041`                  |

`internal/securitytest`'s wire-profile contract (`wire_profile_contract_test.go`)
derives its own expected set from that same runner file and cross-checks it
against this table, the fixture directories under
`internal/ldap/testdata/clickhouse-wire/`, and every committed `profile.json`
— so the four are held equal mechanically, not by review.

## 2. Exact source provenance

### 2.1 Repository, tag, commit, OpenLDAP pin

Three of the four tracked lines are built from the Altinity fork,
**`Altinity/ClickHouse`**. The `26.8` line is the deliberate exception: it
is built from upstream **`ClickHouse/ClickHouse`**, because no Altinity
Stable 26.8 build exists — at the time this line was added the newest
Altinity tags were `26.3.16.10001.altinitystable` and
`26.6.2.20001.altinityantalya`, and upstream 26.8 had shipped. Tracking it
upstream is what makes the 26.8 line trackable at all; the alternative was
to leave the current LTS line uncovered. What `run-all-builds.sh` requires
of any image is a *tag equal to the server's `version()` string*, which
both registries satisfy, so this deviation costs the suite nothing. Every
tag below was confirmed to resolve to the exact commit shown, in the
repository shown.

The **Commit** column holds commit-object SHAs, never tag-object SHAs. That
distinction is load-bearing for `26.8` specifically: `v26.8.1.2041-lts` is
an **annotated** tag, so its ref reports object type `tag` and SHA
`be4175ff9ba169fe2421dc8c7d06b0e94cfb4594` — the tag object. Peeling it
(`gh api repos/ClickHouse/ClickHouse/git/tags/be4175ff… --jq .object.sha`)
gives the commit recorded below. The other three tags are lightweight and
resolve directly. A tag SHA substituted here would still fetch the right
file contents — the GitHub contents API peels refs — so §2.2's blob SHAs
are unaffected by the distinction; what breaks is anyone trying to resolve
the recorded value as a commit, which is exactly what this table promises.

| Line   | ClickHouse repository | Tag                              | Commit                                     | OpenLDAP repository   | Pin                                        | Version |
| ------ | ---------------------- | --------------------------------- | ------------------------------------------- | ---------------------- | -------------------------------------------- | ------- |
| `24.8` | `Altinity/ClickHouse`  | `v24.8.11.51285.altinitystable`  | `351edb1a2ec26940aee4c2d1d332fd280c232964` | `ClickHouse/openldap`  | `5671b80e369df2caf5f34e02924316205a43c895`  | 2.5.16  |
| `25.8` | `Altinity/ClickHouse`  | `v25.8.28.10001.altinitystable`  | `568824f4327b379e86bce93f12b9cebe0cfd9ff5` | `openldap/openldap`    | `22fe35c6b4098e3ad166469f9574c79832c42952`  | 2.6.10  |
| `26.3` | `Altinity/ClickHouse`  | `v26.3.16.10001.altinitystable`  | `8de06fed91fa7a6545a72f37c98e81d4cc024bb1` | `openldap/openldap`    | `22fe35c6b4098e3ad166469f9574c79832c42952`  | 2.6.10  |
| `26.8` | `ClickHouse/ClickHouse` | `v26.8.1.2041-lts`              | `537693a9b20b947a3cf0c4ac90c7c966eee963c9` | `openldap/openldap`    | `22fe35c6b4098e3ad166469f9574c79832c42952`  | 2.6.10  |

Every `build/version.var` at those exact pins was fetched and read
directly: the 24.8 line's submodule reports `ol_major=2 ol_minor=5
ol_patch=16`, and the 25.8, 26.3 and 26.8 lines all report `ol_major=2
ol_minor=6 ol_patch=10` — matching the table with no interpretation
required. The last three share one OpenLDAP pin
(`22fe35c6b4098e3ad166469f9574c79832c42952`). For the two lines added
later, `26.3` and `26.8`, that pin was read from the `contrib/openldap`
submodule entry at each line's own ClickHouse commit rather than assumed
to carry forward from `25.8`; the shared pin is a finding, not an
inheritance.

### 2.2 Exact ClickHouse source blob SHAs

Full 40-hex git blob SHAs, not truncated prefixes, for every ClickHouse
source file this document cites. These were read from each tracked line's
own repository at the commit recorded in §2.1 — `Altinity/ClickHouse` for
`24.8`/`25.8`/`26.3`, upstream `ClickHouse/ClickHouse` for `26.8`.

| File                                    | 24.8 blob                                   | 25.8 blob                                   | 26.3 blob                                   | 26.8 blob                                   |
| ---------------------------------------- | -------------------------------------------- | -------------------------------------------- | -------------------------------------------- | -------------------------------------------- |
| `src/Access/LDAPClient.cpp`              | `3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0`  | `3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0`  | `e76d084f35745778667115865883c910fbdf82a5`  | `7465096b834f789bd8856cc74cc5dbefe6397ded`  |
| `src/Access/LDAPClient.h`                | `0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6`  | `0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6`  | `558017704e75731fd1b2bb0eb88367c00d40aa69`  | `558017704e75731fd1b2bb0eb88367c00d40aa69`  |
| `src/Access/LDAPAccessStorage.cpp`       | `917ad7cbb922083ab82f85ab25c120a17fd009c7`  | `fc55c6b081b38ecccbf4894a9a5fa223d3cd2bd8`  | `939b99396c300abd67abbdfa55d97411ec258261`  | `e464d5818b552b4e7623cb34f3e43f6e5302e176`  |
| `src/Access/ExternalAuthenticators.cpp`  | `77812ac5eb5d0027f081ac43dccc6b89110aeb73`  | `ca61b55dc5dc200353971ff53580b2ee04439334`  | `6fa7c28bc980ce5f639a88b0094e63ca65dd383e`  | `40fc3b719d195fc600961e10059a827c0cd7545e`  |

`LDAPClient.cpp`/`LDAPClient.h` are byte-identical **within** each pair —
`24.8` = `25.8`, and `26.3` = `26.8` for the header, with the two `.cpp`
blobs differing only as described below — but **not across** the pairs. So
a citation into those two files is valid for a pair, not for all four
lines. Every `LDAPClient.cpp` citation in this document is therefore given
in the form `24.8/25.8 → 26.3/26.8` (§4, §5, §6, §8). `LDAPClient.h` is the
exception that needs no such treatment: its blob differs between the pairs
and the file grew from 161 to 163 lines, but every line this document cites
from it (`:96`, `:120`–`:123` — the protocol-version and timeout/limit
defaults) sits at an unchanged line number in both pairs, verified rather
than assumed.

Two source deltas separate the pairs, both established by direct diff
rather than inferred from the differing SHAs:

- **`24.8`/`25.8` → `26.3`: one behavioral change.** 26.3 introduced a
  `<follow_referrals>` LDAP-server config key. `openConnection()` gained a
  corresponding `ldap_set_option(handle, LDAP_OPT_REFERRALS,
  params.follow_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF)` call
  (`LDAPClient.cpp:250`–`255`, `#ifdef`-guarded), `follow_referrals` joined
  the connection-params hash, and the search-reference log line became a
  two-branch `LOG_TRACE` instead of a single `LOG_WARNING`. §5 classifies
  the new option; it has no wire consequence for this profile.
- **`26.3` → `26.8`: no behavioral change.** The only `LDAPClient.cpp`
  delta is value-initialization hygiene — `::timeval operation_timeout{}`,
  `::timeval network_timeout{}`, `::berval cred{}`, `::berval bv{}` — and
  `LDAPClient.h` is byte-identical between them. The two lines are treated
  as one source pair throughout this document for that reason.

`LDAPAccessStorage.cpp` and `ExternalAuthenticators.cpp` differ on all four
commits (the config parsing and role-mapping call path has been reshaped
repeatedly), so citations into those two files are given per-commit where
the line numbers actually moved.

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
   `@351edb1a:...:456`, `@8de06fed:...:438`,
   `ClickHouse/ClickHouse@537693a9:...:439`) calls into
2. **`LDAPAccessStorage::areLDAPCredentialsValidNoLock`**
   (`@568824f4:...:347`, `@351edb1a:...:350`, `@8de06fed:...:332`,
   `@537693a9:...:333`), which — for a
   `BasicCredentials` (the caller's email+JWT repacked as HTTP Basic,
   exactly the shape `cmd/ch-jwt-verify` produces) — calls
3. **`ExternalAuthenticators::checkLDAPCredentials`**
   (`@568824f4:src/Access/ExternalAuthenticators.cpp:399`,
   `@351edb1a:...:389`, and `:403` in both `@8de06fed` and `@537693a9`),
   which constructs an `LDAPSimpleAuthClient` from the
   parsed `LDAPClient::Params` (built by `parseLDAPServer`, same file —
   `:61` in both 26.x commits — reading the `<ldap_servers><oauth_helper>`
   block) and calls
4. **`LDAPSimpleAuthClient::authenticate`**
   (`Altinity/ClickHouse@351edb1a2ec26940aee4c2d1d332fd280c232964:src/Access/LDAPClient.cpp::LDAPSimpleAuthClient::authenticate`,
   line 587 → 600 — identical within each source pair), which drives the
   actual libldap
   calls:
   * `LDAPClient::openConnection` (`LDAPClient.cpp:213` → `:214`) — connection setup
     and every `ldap_set_option` (§5 below);
   * the simple Bind itself, via `ldap_sasl_bind_s(...,
     LDAP_SASL_SIMPLE, ...)` (`LDAPClient.cpp:360` → `:368`);
   * for each configured role-mapping entry, `LDAPClient::search`
     (`LDAPClient.cpp:405` → `:413`, issuing `ldap_search_ext_s` at
     `LDAPClient.cpp:445` → `:453`);
   * `LDAPClient::closeConnection` (`LDAPClient.cpp:391` → `:399`, issuing
     `ldap_unbind_ext_s` at `LDAPClient.cpp:398` → `:406`) once the `~LDAPClient`
     destructor runs or the connection is otherwise torn down.

Role-search parameters themselves are parsed by
`parseLDAPRoleSearchParams` (`ExternalAuthenticators.cpp:259` in the 24.8
commit, `:269` in the 25.8 commit, `:273` in both the 26.3 and 26.8 commits
— the commits' `checkLDAPCredentials`/`parseLDAPServer` bodies differ in
length above this function, shifting its line number, even though the
function itself is otherwise equivalent) and
threaded through `LDAPAccessStorage`'s own
`role_search_params` member (`LDAPAccessStorage.cpp`, constructed around
line 71–84 in the 24.8/25.8 commits and 66–79 in the 26.3/26.8 commits),
which is what turns the fixture's single
`<role_mapping>` block into the one `LDAPClient::RoleSearchParams` instance
`LDAPSimpleAuthClient::authenticate` iterates and searches with.

Mapped-role results flow back up through `checkLDAPCredentials`'s
`role_search_results` out-parameter into
`LDAPAccessStorage::assignRolesNoLock` (`LDAPAccessStorage.cpp:199`/`206`),
which is where the wire evidence's job ends and ClickHouse's own local-role
bookkeeping begins — out of this document's scope.

## 5. Complete `ldap_set_option` classification

`LDAPClient::openConnection` sets exactly these options, in this order,
every one of them before the Bind is issued. The function is byte-identical
within each source pair but not across them (§2.2), so line numbers are
given per pair: `LDAPClient.cpp:213` (`246`–`340`) on the 24.8/25.8 lines,
`LDAPClient.cpp:214` (`247`–`348`) on the 26.3/26.8 lines. The "Set at"
column below gives both, as `24.8/25.8 → 26.3/26.8`.

| Option                        | Set at (`LDAPClient.cpp`) | Category                  | Treatment                                                                                       |
| ------------------------------ | -------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------- |
| `LDAP_OPT_PROTOCOL_VERSION`   | line 246 → 247            | Protocol selection        | Server-visible semantic input; fixes the connection to LDAPv3 (both tracked lines run version 3).|
| `LDAP_OPT_REFERRALS`          | — → line 250 (`#ifdef LDAP_OPT_REFERRALS`) | Client-side referral chasing | **26.3/26.8 only.** Set from the `<follow_referrals>` server-config key, which `ExternalAuthenticators.cpp` reads only when `config.has(...)` reports it present; absent from this fixture's config, so the option is set to `LDAP_OPT_OFF`. No wire consequence for this profile either way — `ch-oauth-ldap` never emits a `SearchResultReference` for a client to chase. Recorded because the audit is of what the source SETS. |
| `LDAP_OPT_RESTART`            | line 249 → 257            | Client/socket behavior    | Source fact (auto-retry interrupted syscalls); not a BER request field.                          |
| `LDAP_OPT_KEEPCONN`           | line 252 → 260 (`#ifdef LDAP_OPT_KEEPCONN`) | Client/socket behavior | Source fact; not a BER request field. Guarded by an `#ifdef`, present on both tracked OpenLDAP pins. |
| `LDAP_OPT_TIMEOUT`            | line 260 → 268 (`#ifdef LDAP_OPT_TIMEOUT`) | Operation/network timeout | The overall per-operation timeout (40 s default) — distinct from `SearchRequest.timeLimit`. Guarded by its own `#ifdef`, exactly like `LDAP_OPT_KEEPCONN`; present on both tracked OpenLDAP pins. |
| `LDAP_OPT_NETWORK_TIMEOUT`    | line 269 → 277 (`#ifdef LDAP_OPT_NETWORK_TIMEOUT`) | Operation/network timeout | Connect/network-level timeout (30 s default) — distinct from both the above and `timeLimit`. Likewise its own `#ifdef`-guarded block, present on both tracked OpenLDAP pins. |
| `LDAP_OPT_TIMELIMIT`          | line 275 → 283            | Search defaults           | Handle-wide default Search time limit (20 s). This configuration path requests no per-call deadline, so this value is what reaches the wire: every captured `SearchRequest.timeLimit` in the corpus is 20 (BER `02 01 14`), on all four lines. Not `#ifdef`-guarded — set unconditionally. |
| `LDAP_OPT_SIZELIMIT`          | line 280 → 288            | Search defaults           | Handle-wide default Search size limit, set from this fixture's explicit `<search_limit>256</search_limit>`; reaches the wire as `SearchRequest.sizeLimit` = 256 on all four lines. Not `#ifdef`-guarded — set unconditionally. |
| `LDAP_OPT_X_TLS_PROTOCOL_MIN` (line 294 → 302), `LDAP_OPT_X_TLS_REQUIRE_CERT` (line 308 → 316), `LDAP_OPT_X_TLS_NEWCTX` (line 340 → 348) | lines 283–296, 298–309, 337–341 → 291–304, 306–317, 345–349 | TLS configuration | Each guarded **only** by its own compile-time `#ifdef` (does the macro exist on this OpenLDAP build) — there is no `params.enable_tls` check and no field-present check on any of these three. They run unconditionally whenever compiled with TLS support, `<enable_tls>no</enable_tls>` notwithstanding. |
| `LDAP_OPT_X_TLS_CERTFILE`, `LDAP_OPT_X_TLS_KEYFILE`, `LDAP_OPT_X_TLS_CACERTFILE`, `LDAP_OPT_X_TLS_CACERTDIR`, `LDAP_OPT_X_TLS_CIPHER_SUITE` | lines 312–335 → 320–343 | TLS configuration | Each guarded by its own `#ifdef` **and** a field-emptiness check (`if (!params.tls_*.empty())`) — not by `params.enable_tls`. In this fixture's config all five fields are empty, so these five specifically do not fire; the three above still do. |

Recorded for completeness of the source read. **None of these eight options
gate on `params.enable_tls`** — the fixture's `<enable_tls>no</enable_tls>`
only controls the later, separately guarded `ldap_start_tls_s` call (line
344 → 352: `if (params.enable_tls == ...::YES_STARTTLS)
ldap_start_tls_s(...)`),
which is what actually starts TLS on the wire. So while three of these
eight `ldap_set_option` calls (`PROTOCOL_MIN`, `REQUIRE_CERT`, `NEWCTX`) do
execute for the captured sessions, none of them causes any TLS wire traffic
by itself — they only configure OpenLDAP's TLS context object for a
`ldap_start_tls_s`/`ldaps://` call that this fixture's `enable_tls=no`
config never makes, so still no `LDAP_OPT_X_TLS_*` value or TLS byte
reaches the wire this document characterizes.

The non-TLS options above — the complete non-TLS inventory across every
tracked line, seven of them on 24.8/25.8 and eight on 26.3/26.8 —
are exactly:
`LDAP_OPT_PROTOCOL_VERSION`, `LDAP_OPT_REFERRALS` (26.3/26.8 only),
`LDAP_OPT_RESTART`, `LDAP_OPT_KEEPCONN`,
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
| Search time limit                | 20 s                   | (2) ClickHouse compiled-in default (`LDAPClient.h:122`), applied **both** via (3) `LDAP_OPT_TIMELIMIT` at connection-open time **and** (4) as the explicit `&timeout` argument `LDAPClient::search` builds and passes to `ldap_search_ext_s` (`LDAPClient.cpp:434`,`445` → `:442`,`:453`) — the handle-wide default is redundant with, not overridden by, the per-call value here, since both derive from the same `params.search_timeout`. |
| Search size limit ("Search limit")| 256                    | (1) repository XML (`ldap.xml`'s `<search_limit>`, which overwrites (2) ClickHouse's own compiled-in default of 256 — `LDAPClient.h:123` — with the same numeric value, making this line behavior-neutral versus leaving it unset), applied **both** via (3) `LDAP_OPT_SIZELIMIT` and (4) the explicit `params.search_limit` argument to `ldap_search_ext_s` (`LDAPClient.cpp:445` → `:453`), for the same belt-and-suspenders reason as the Search time limit. |
| Search base DN                  | `ou=groups,dc=altinity,dc=internal` | (1) repository XML (`ldap.xml`'s `role_mapping/base_dn`)                                    |
| Search scope                    | subtree                | (1) repository XML (`ldap.xml`'s `role_mapping/scope`), mapped to `LDAP_SCOPE_SUBTREE` (`LDAPClient.cpp:405`ff. → `:413`ff.) |
| `derefAliases`                   | `neverDerefAliases` (0) | (5) libldap fallback/default — `LDAPClient::search` calls `ldap_search_ext_s` (`LDAPClient.cpp:445` → `:453`), whose signature has no `deref` parameter at all; `ldap_search_ext_s` hardcodes `deref = -1` internally when it delegates to `ldap_pvt_search_s` (`search.c:151`, both pins), and `ldap_build_search_req`'s non-UDP branch resolves any negative `deref` to the handle's own `ld_deref` (`search.c:326`, both pins: `(deref < 0) ? ld->ld_deref : deref`). `ld_deref` is a per-handle copy of the process-wide global default options made at handle-creation time (`open.c:150`, inside the `ldap_create` already cited in §7), and that global default is set once by `ldap_int_initialize_global_options` (`init.c:563`, both pins: `gopts->ldo_deref = LDAP_DEREF_NEVER;`, i.e. `0x00` — `ldap.h:795`). ClickHouse never calls `ldap_set_option(..., LDAP_OPT_DEREF, ...)` anywhere in `LDAPClient.cpp`, so nothing overrides this chain. Confirmed on the wire: byte `00` in the `derefAliases` ENUMERATED immediately following the `scope` ENUMERATED in every committed `002-search-request.ber` fixture (all four tracked lines, `success` and `timeout-abandon`). |
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
&cred, ...)` (`LDAPClient.cpp:360` → `:368`). The credential (`cred.bv_val`) is the
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
and client-controls arguments (`LDAPClient.cpp:360`,`445` → `:368`,`:453`);
`Unbind` goes through `ldap_unbind_ext_s(handle, nullptr, nullptr)`
(`LDAPClient.cpp:398` → `:406`);
and the client-side-timeout `Abandon` (§8.6) is libldap's own internal
`ldap_abandon(ld, msgid)` call inside `ldap_result` (§7), which itself
always passes `NULL, NULL` for controls (`abandon.c:102`, both pins). So
`controls` is absent (not merely empty) on the wire throughout — no
`Controls` sequence follows any `LDAPMessage`'s protocolOp.

### 8.3 Placeholder substitution and escaping pipeline

`LDAPClient.cpp`'s anonymous-namespace helpers (identical in both tracked
commits) do the substitution in two distinct escaping modes, and
`LDAPClient::search` (`LDAPClient.cpp:420`ff. → `:428`ff.) is careful to apply the
filter-safe one specifically to filter placeholders:

* **`escapeForDN`** (`LDAPClient.cpp:89` → `:90`): backslash-escapes the RFC 4514
  DN special characters (`, \ # + < > ; "` and `=`) one at a time. Used
  once, on the raw HTTP username, to produce `final_user_name`
  (`LDAPClient.cpp:347` → `:355`), which then feeds the Bind DN template's
  `{user_name}` placeholder (`LDAPClient.cpp:348` → `:356`) via a plain
  string-replace helper (`replacePlaceholders`, `LDAPClient.cpp:149` → `:150`).
* **`escapeForFilter`** (`LDAPClient.cpp:116` → `:117`): RFC 4515 filter-escapes
  `*`, `(`, `)`, `\`, and NUL as `\2A`, `\28`, `\29`, `\5C`, `\00`
  respectively. Used when building the Search filter's own placeholders
  (`{user_name}`, `{bind_dn}`, `{user_dn}`, `{base_dn}` —
  `LDAPClient.cpp:427`–`430` → `:435`–`:438`), never for the DN fields themselves — the
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
`closeConnection` (`LDAPClient.cpp:391` → `:399`, `ldap_unbind_ext_s` at
line 398 → 406)
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

### 11.1 Phase 2 implementation status and the corrected LOC baseline

Phase 2 built the replacement at `internal/ldap/profile/` (package
`profile`), following the primitive decision above: `cryptobyte` for every
ASN.1 primitive, plus the same small set of fixed first-party checks named
in §10 — including the Abandon `[APPLICATION 16]`-implicit-tagged target
integer, whose content bytes are read directly under the application tag
and then validated with the identical minimal-positive-INTEGER rule the
LDAPMessage envelope's MessageID uses (the same shared rule the 127/128
boundary and the differential oracle below both exercise for Abandon).

This is implementation and test evidence only. `cmd/ch-oauth-ldap` built
the ordinary, untagged way — which is what `Dockerfile.ch-oauth-ldap`,
`scripts/build-ch-oauth-ldap-image.sh`, and
`.github/workflows/build-ch-oauth-ldap.yml` all still do — still runs the
legacy `internal/ldap` server in production, and nothing reachable from
that ordinary build imports `internal/ldap/profile`. Phase 3 adds a
second, temporary `cmd/ch-oauth-ldap` composition, selected only by the
`phase3profile` build tag (`ldap_backend_phase3profile.go`, alongside the
default `ldap_backend_legacy.go`), that *does* import
`internal/ldap/profile` — but that tagged composition is exercised only by
`internal/securitytest`'s Docker-free tagged-build/closure contracts and
by `integration/clickhouse/Dockerfile`'s helper build (§11.4a), never by
the published production image. Full production cutover — making the
profile adapter the only one, deleting the legacy adapter and the tag —
remains Phase 4's, per §11.4's handoff list. Proof of the replacement's
correctness comes from, entirely outside the Docker ClickHouse suite:

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
* an architecture contract in two files: the syntactic invariants
  (`internal/securitytest/profile_architecture_contract_test.go` — exactly
  one production goroutine spawn, a nonrecursive two-child
  membership-filter decoder, diagnostic/reason bytes reachable only through
  their closed enums, and the import bans) plus the type-semantic
  invariants (`internal/securitytest/profile_types_contract_test.go` — no
  request-indexed map/channel state beyond the allowlisted `Server` fields,
  and `Verifier.Verify`/`RoleResolver.Roles` each referenced exactly once,
  in `bind.go`), the latter enforced over the fully type-checked package
  with go/types on gc export data, not AST shape enumeration;
* redaction-inventory coverage (`internal/securitytest`'s `scopeDirs`, sink
  kind `ldap-profile-diagnostic`) with marker-bearing proofs at default and
  trace log levels.

**Corrected LOC baseline.** This section previously recorded **2,659** as
if it were the figure standing unchanged into Phase 3. It is not: 2,659
was an intermediate Phase 2 measurement, and repository history shows
further Phase 2 review work landed after it, before merge. This
correction replaces the earlier text rather than merely appending a
caveat to it.

Measured physical LOC for the nine production files this replaces
(`server.go`, `frame.go`, `protocol.go`, `session.go`, `bind.go`,
`search.go`, `dn.go`, `encode.go`, `logging.go`) plus `config.go` (the public
`Config`/`ValidateConfig` surface) and `doc.go` (package-status doc) — using
Phase 1's physical-line definition, comments and blanks counted, i.e.
`wc -l` summed over exactly those eleven files (equivalently: `wc -l
$(ls internal/ldap/profile/*.go | grep -v _test.go)`):

* commit `d273414` recorded **2,659** as of the phase-2 compat-profile
  sub-task that hardened the write-stall/Search-deadline classification,
  the DN parse-error redaction, and the wire-facing descriptor comparisons
  (each of those touched `dn.go`, `config.go`, and/or `search.go`). It was
  previously measured at 2,608 (nine-file total 2,426 + `config.go` 148 +
  `doc.go` 34) before that sub-task — the coordinator's recorded
  disposition on that earlier 2,608 figure (accepted, since the overshoot
  is exactly the `config.go`/`doc.go` public-surface and package-status
  files the plan's own file table omitted, not undocumented growth) is
  recorded in the issue #33 ship log and is not restated here.
* between the `d273414` measurement and merged `main`, further Phase 2
  **review** work — not Phase 3 growth — changed two more files:
  `search.go` changed `+39/-17` (net `+22`), and between the later
  `f3bf13b` review state and merged `main`, `bind.go` changed `+3/-2` (net
  `+1`). Together, a net `+23` lines landed on top of the `d273414`
  measurement before Phase 2 merged.
* the **merged Phase 2 baseline — the number Phase 3 actually starts
  from — is therefore `2,682`, pinned to this repository's Phase 2 merge
  commit `e26e30f`, not `2,659`.** `2,682` is a historical fact about that
  one commit. It is never recomputed against today's tree, and no future
  edit is expected to keep it accurate — Phase 3's own final measurement
  is a separate, freshly recomputed number, recorded in §11.5, not here.

The plan's consolidation-review trigger is 2,500 physical LOC for this
package; both `2,659` and `2,682` are above that trigger and both remain
well below ADR #32's separate ~3,500-line architecture-review trigger —
the prior `>2,500` acceptance covers both figures, and consolidation
review against the ~3,500 trigger still folds into Phase 4's legacy
deletion, not this sub-task or Phase 3 generally.

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

### 11.3 The Phase-3 narrowings and their cutover dispositions

Cutover replaces several places where current production is more permissive
than the documented ClickHouse traffic actually requires, or adds a bound
current production does not have at all. Phase 3 must explicitly accept or
reject each one before Phase 4 is authorized:

1. Bind version `!= 3` on the recognizable **simple**-Bind path changes
   from current incidental acceptance to result 2 `protocolError`
   (LDAPv3-only). This narrowing's own result-2 path is reached only for a
   version value that decodes successfully (minimally encoded, in range
   `1..MaxInt32`), simply isn't 3, *and* the authentication CHOICE is
   `simple` — the version field is decoded before the authentication
   CHOICE is inspected, but the CHOICE switch itself checks SASL first and
   returns result 7 `authMethodNotSupported` unconditionally, before the
   version check further down the same function is ever reached. So a
   version of 0, a negative version, or a non-minimally-encoded value is
   malformed at decode time and closes the connection before the version
   check ever runs — it never reaches result 2 — and, independently, a
   *decodable* SASL Bind at any version (including one that isn't 3) never
   reaches result 2 either: it always returns result 7 first, regardless of
   version. Only a decodable **simple** Bind at a non-3 version reaches
   result 2. **(new client-visible
   behavior, not parity)** This does *not* match legacy: legacy goldap's own
   Bind version decoder (`BindRequestVersionMin`/`BindRequestVersionMax` in
   `third_party/goldap/message/struct.go`) only accepts `1..127` and returns
   a decode error — closing the connection, no response written — for
   anything outside that window. This profile's `1..MaxInt32` decode range
   is wider than legacy's, not equivalent to it: a version `>=128` decodes
   successfully here and receives a graceful result-2 `protocolError`
   response, a case legacy never reaches because it never gets past decode.
   Phase 3 must explicitly accept this widening or narrow the version decode
   to legacy's `1..127`, the same way items 9-10 below are called out rather
   than left implicit.
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

#### 11.3 dispositions

The Phase 3 coordinator/maintainer, not a test, owns the cutover
adjudication below — tests establish behavior and applicability, they do
not decide product acceptance. Item 1 above covers two independently
adjudicated rows: `1` itself, and `1a`, the decoder-boundary note about
versions `0`/negative/non-minimal and `>=128` embedded in item 1's own
prose. The only permitted disposition values are the exact strings
`ACCEPT` or `REJECT` — no prefix grammar, no variants such as `ACCEPT AS
DOCUMENTED`. If any row below is ever changed to `REJECT`, the bounded
correction must be implemented and tested before certification, and — if
the correction materially widens the compatibility profile — the unit
returns to ADR #32 for reconsideration.

| ID | Disposition | Evidence / hardening label | Rationale |
| -- | ------------ | --------------------------- | --------- |
| 1  | `ACCEPT` | wire-evidence: item 1 above; `bind.go`/`bind_test.go`/`protocol_test.go`; replayed against every tracked-line session | Decodable simple Bind version `!=3` returns result 2. Tracked ClickHouse traffic is LDAPv3 simple Bind; generic older/newer LDAP versions are outside the supported profile. |
| 1a | `ACCEPT` | wire-evidence: item 1's decoder-boundary paragraph above; `bind_test.go`/fuzz seed corpus covering the shared minimal-positive-INTEGER rule | Version 0, negative, or non-minimal values close as malformed; minimally encoded values `>=128` can decode and receive result 2 although legacy goldap closed above 127. Tracked ClickHouse emits version 3, so the parser is not widened or narrowed merely to copy incidental legacy behavior. |
| 2  | `ACCEPT` | wire-evidence: item 2 above; `search.go`/`search_test.go`; every tracked session's recorded `derefAliases=0` | `derefAliases != 0` returns result 50. Supported ClickHouse sends 0. |
| 3  | `ACCEPT` | wire-evidence: item 3 above; `search.go`/`search_test.go`; scenario G' recorded `types_only=false` | `typesOnly=true` returns result 50. Supported ClickHouse sends false. |
| 4  | `ACCEPT` | wire-evidence: item 4 above; `search.go`/`search_test.go`/`search_fuzz_test.go`; every tracked session's single recorded `cn` attribute request | Empty, `*`, `1.1`, non-`cn`, or multi-attribute projections return result 50. Supported role mapping asks for exactly `cn`. |
| 5  | `ACCEPT` | wire-evidence: item 5 above; `dn.go`/`dn_test.go`/`hostile_dn_test.go`/`dn_fuzz_test.go`; every tracked capture's plain single-RDN Bind/Search DNs | Restricted DN grammar intentionally drops generic RFC4514/go-ldap forms not emitted by the tracked configuration. |
| 6  | `ACCEPT` | hardening: lifecycle (synchronous-connection tradeoff, not a wire-parity claim) | Peer EOF does not asynchronously cancel a blocked `Verify`. |
| 7  | `ACCEPT` | wire-evidence: item 7 above; `protocol.go`/`server.go`/`protocol_test.go`/`replay_test.go`; the tracked timeout-abandon session's Abandon PDU | Abandon is recognized/dropped without target cancellation, matching ADR #32's bounded compatibility decision. |
| 8  | `ACCEPT` | wire-evidence: item 8 above; `protocol.go`/`protocol_test.go`; absence of any Cancel/Extended PDU in every tracked capture | RFC 3909 Cancel loses the generic RouteMux semantics and returns the fixed unsupported-Extended result. Tracked ClickHouse does not emit Cancel. |
| 9  | `ACCEPT` | hardening: resource (deliberate 64 KiB outbound bound; not a legacy-parity claim — legacy has none) | New 64 KiB outbound PDU cap fails closed using `adminLimitExceeded`. |
| 10 | `ACCEPT` | hardening: config (deliberate operator-config check; not a legacy-parity claim — legacy only rejects empty/whitespace) | Startup `UserRDNAttribute` descriptor check is consistent with the restricted structural DN model. |

### 11.4 The two permanent bounded test-only cursors that own independent-decoder evidence

§10's `TestClickHouseWireCryptobyteDecision` characterizes each fixture with
`cryptobyte` itself, but a cryptobyte characterization failure only counts
as evidence (the local-ber-cursor justification) once it is corroborated by
a *second, structurally independent* decoder proving fixture
well-formedness. Through Phase 3 that second decoder was
`independentlyWellFormedBER`, the vendored, patched goldap decoder. Phase 4
deleted the vendored `third_party/goldap`/`third_party/ldapserver` forks
along with every production and test dependency on them, and replaced that
single goldap-backed oracle with two separately hand-written, bounded,
test-only BER cursors that share no decoding helpers with each other, with
cryptobyte, or with the production `internal/ldap/profile` decoder — using
the eventual production decoder to prove fixture well-formedness for itself
would be self-referential, which is exactly what both cursors exist to
avoid.

**Oracle A** — fixture well-formedness / primitive-selection evidence —
lives permanently at
`internal/ldap/profile/clickhouse_wire_cryptobyte_test.go` (moved there,
package `profile`, from this document's Phase 1 location under
`internal/ldap`). Its `oracleAWellFormed` cursor independently checks
exactly the supported fixture shapes named in §10's own scope (outer
LDAPMessage sequence, bounded definite lengths, the minimal non-negative
MessageID encoding including the 127/128 boundary, the four supported
operations, Bind, the fixed Search fields/filter/attributes, empty Unbind,
a valid positive Abandon target, no trailing bytes) and preserves the same
three-way cryptobyte/local-ber-cursor/malformed verdict `§10` always used,
including the mutation proving the cursor rejects malformed input rather
than rubber-stamping it.

**Oracle B** — wire-profile semantic decoder evidence — lives permanently
at `internal/securitytest/wire_oracle_b_test.go`. It decodes only what
`wire_profile_contract_test.go`'s own assertions need — Bind DN,
`derefAliases`, the Controls presence/criticality sentinel, and the outer
Search filter's operator and its two `equalityMatch` children — and
requires the fixed `AND(objectClass==groupOfNames, member==<Bind DN>)`
shape (either child order), retaining the AND→OR, `derefAliases`, and
Controls sabotage cases that used to run against goldap.

`internal/ldap/profile/differential_test.go`, the old/new differential
oracle against the vendored goldap decoder, is deleted along with the
vendored forks it depended on; its permanent successors are Oracle A,
Oracle B, the committed frozen ClickHouse corpus, profile replay, the
profile unit/adversarial/fuzz suites, real ClickHouse integration, HA, and
wire verify — not a second general BER dependency and not the production
`profile` package standing in as its own oracle.

### 11.4a Wire-capture verification policy (Phase 3)

`compose-wirecapture.yml` runs `/bin/ch-oauth-ldap` from the same
integration image as `ldap-helper-upstream`; once that image's helper
build carries `-tags=phase3profile` (§11.4/`integration/clickhouse/Dockerfile`),
that service's traffic is served by the replacement.

The committed `captured-redacted` corpus under
`internal/ldap/testdata/clickhouse-wire/**` remains Phase 1 evidence of
real libldap request traffic and keeps its historical provenance
unchanged. Phase 3's policy toward it is deliberately narrow:

* **`--mode generate` is frozen.** No committed fixture is regenerated or
  promoted by Phase 3, regardless of which server answers the capture.
* **only `--mode verify` runs**, against the existing corpus:

  ```text
  bash integration/clickhouse/capture-ldap-wire.sh \
    --mode verify \
    --fixtures internal/ldap/testdata/clickhouse-wire
  ```

  (invoked via `bash <path>` rather than `./<path>` — the script is
  tracked non-executable; see §11.5's evidence for the observed
  workaround).
* a passing verify run is **replacement-backed verification of Phase 1's
  existing provenance** — proof the replacement reproduces the
  already-audited bytes — never new fixture provenance and never a
  license to broaden the parser.
* had verify exposed a new request shape from a tracked ClickHouse client,
  Phase 3 would stop rather than silently broaden the parser or regenerate
  the baseline to match. It did not (§11.5).

This distinction is also recorded in
`integration/clickhouse/README.md`'s own "Wire capture" section.

### §11.5 is historical; §11.6 is the current production certification

§11.5 immediately below is preserved exactly as Phase 3's Stage B manual
certification recorded it, byte-for-byte, between its own marker pair. It
is not, and after Phase 4 must never again be read as, a live assertion
about the current tree: the certified surface it describes (the
`phase3profile`-tagged, dual-adapter composition) no longer exists.
`internal/securitytest/wire_profile_contract_test.go`'s `Phase3Evidence*`
tests check only that §11.5's recorded facts remain unchanged from what
Phase 3 attested — never that today's tree still matches them.

§11.6, added below after Phase 4's own manual certification completes, is
the current production certification of record: it describes the ordinary,
untagged `internal/ldap/profile`-backed production composition this
document's earlier sections now describe as shipped, and its own live
digest contract binds that section's recorded facts to the exact source
tree certified — the same role §11.5 played for Phase 3, for the tree
Phase 3 actually certified.

<!-- phase3-release-gate-evidence:start -->
### 11.5 Phase 3 replacement release-gate evidence

This section is the populated Stage C evidence record for Phase 3's
manual certification (Stage B), machine-checked for completeness,
absence of placeholders, and internal consistency by
`internal/securitytest/wire_profile_contract_test.go` — those checks
prove this section's *shape and self-consistency*, never that the
Docker/fuzz commands below were actually run. Only the coordinator can
attest that; see the human-attested list this document's plan carries.

**Certification identity**

- **tested_behavior_head:** `e4deecdae41d5c192aa9578934d41a32c65acf6c`
- **Selector:** `phase3profile`
- **Integration Dockerfile:** `integration/clickhouse/Dockerfile` (sole
  `-tags=phase3profile` build line, the `ch-oauth-ldap` helper)
- **Normal production path:** ordinary `go build ./...`, the published
  `Dockerfile.ch-oauth-ldap` image, `scripts/build-ch-oauth-ldap-image.sh`,
  and `.github/workflows/build-ch-oauth-ldap.yml` all remain untagged and
  select the legacy `internal/ldap` server — this evidence changes none of
  that; production cutover stays Phase 4's.
- **Certified-surface digest (SHA-256):** `90619015fcb4965888a0e090474f8ed11d7991a7bc24b67e71b7251147b52c48`
  — computed at `tested_behavior_head` over the "Certified-surface
  anti-drift digest" file set (this plan's own definition), reproduced 3×
  identically over 173 tracked files.

**Supported ClickHouse matrix** (`integration/clickhouse/run-all-builds.sh`, expectations table unedited)

| Image | Result |
| ----- | ------ |
| `altinity/clickhouse-server:24.8.11.51285.altinitystable` | `PASS` |
| `altinity/clickhouse-server:25.8.28.10001.altinitystable` | `PASS` |

Both runs completed scenarios A–I including phase-5 scenario G' (Search-limit
overflow); the two recorded ClickHouse upstream-bug expected failures
(#78791/not-backported-to-24.8, and #116840's VIEW `external_roles` drop)
reproduced exactly as expected — no expectation-table edit was needed or
made.

**HA** (`integration/clickhouse/run-ha.sh`, existing HAProxy + two-replica
harness, existing persistent same-socket session probe — no new probe
created)

| Image | Result |
| ----- | ------ |
| `altinity/clickhouse-server:24.8.11.51285.altinitystable` | `PASS` |
| `altinity/clickhouse-server:25.8.28.10001.altinitystable` | `PASS` |

- **Session-probe result:** `PASS` on both images — both replicas
  authenticate; no shared LDAP session store is required; authenticated
  state is socket/connection-local; killing the replica owning a
  connection kills that session rather than migrating it; fresh
  authentication proceeds through the survivor; the recreated replica
  rejoins. As documented at §"HA applicability", this proves none of
  Kubernetes routing, EndpointSlice/CNI convergence, pod-eviction
  semantics, or a failover SLA.

**Wire-capture verification**

- **Command:** `bash integration/clickhouse/capture-ldap-wire.sh --mode verify --fixtures internal/ldap/testdata/clickhouse-wire`
- **generation: frozen**
- **Result:** `PASS` for both tracked lines (`24.8`, `25.8`); every
  committed session compared byte-for-byte equal; zero fixture drift; no
  new request shape observed.

**Fuzz smoke** (`go test ./internal/ldap/profile -run '^$' -fuzz=<Target> -fuzztime=20s`, one target at a time)

| Fuzz target | Duration | Result |
| ------------------------ | -------- | ------ |
| `FuzzLDAPFrame` | `20s` | `PASS` |
| `FuzzBindRequest` | `20s` | `PASS` |
| `FuzzSearchRequest` | `20s` | `PASS` |
| `FuzzRestrictedDN` | `20s` | `PASS` |
| `FuzzMemberAssertionDN` | `20s` | `PASS` |

No crasher was found for any of the five targets. (`FuzzRestrictedDN`'s
first attempt hit an infrastructure timeout while racing a concurrent
Docker rebuild on the same host — no failing input was ever written to a
fuzz corpus — and was re-run in isolation to the clean `PASS` recorded
above; this is a sandbox-contention artifact, not a discovered bug.)

**LOC guardrail**

- **Merged Phase 2 baseline:** `2682` (pinned to `e26e30f`; see §11.1 — not
  recomputed against today's tree)
- **Final Phase 3 LOC:** `2702`
- **Phase 3 delta:** `+20`
- 2,702 remains 798 lines below ADR #32's ~3,500 architecture-review
  trigger; no architecture-review stop condition was reached.

**§11.3 narrowing dispositions** (see §11.3 for full rationale/evidence
per row; reproduced here as the compact recorded field)

| ID | Disposition |
| -- | ------------ |
| 1  | `ACCEPT` |
| 1a | `ACCEPT` |
| 2  | `ACCEPT` |
| 3  | `ACCEPT` |
| 4  | `ACCEPT` |
| 5  | `ACCEPT` |
| 6  | `ACCEPT` |
| 7  | `ACCEPT` |
| 8  | `ACCEPT` |
| 9  | `ACCEPT` |
| 10 | `ACCEPT` |

**Redaction / release gate**

- **`phase5release` vet:** `PASS`
- **`phase5release` test:** `PASS`
- `internal/ldap/profile` remains in `scopeDirs`; `redaction-sites.tsv` is
  reconciled for the `cmd-seam` sub-task's sink moves/additions.

**TLS applicability:** N/A — issue #31 is a separate open unit and is out of scope for #33 Phase 3

**Phase 4 handoff recap** (full list at §"Phase 4 mandatory handoff";
restated here as this evidence section's own pointer, not a second
authority):

- delete the `phase3profile` selector everywhere it appears today
  (`cmd/ch-oauth-ldap/ldap_backend_phase3profile.go`'s tag,
  `ldap_backend_legacy.go`, `integration/clickhouse/Dockerfile`,
  `internal/securitytest/phase3_selector_contract_test.go`'s own
  selector-specific assertions);
- invert `productionLDAPClosureStage` to `replacement` and
  `ProfileImplementationIsNotProduction`'s polarity, and flip the
  cryptobyte-presence contract from absence to presence in the ordinary
  closure;
- delete `TestDependencyContract_Phase3ReplacementCommandBuilds` once
  ordinary `go build ./...` itself compiles the replacement, and delete
  `TestDependencyContract_Phase3ReplacementCommandTests` once ordinary
  `go test ./...` itself runs the replacement's tests;
- delete the differential oracle (`internal/ldap/profile/differential_test.go`)
  and replace remaining independent goldap fixture decoding with the
  bounded test-only cursor (§11.4);
- delete legacy non-test `internal/ldap`, the vendored `ldapserver`/`goldap`
  forks, and their `replace` directives/dependencies;
- reconcile now-stale redaction rows and rerun the full matrix/HA/security/
  release gates on the untagged production path.

<!-- phase3-release-gate-evidence:end -->

<!-- phase4-release-gate-evidence:start -->
### 11.6 Phase 4 production-cutover release-gate evidence

This section is the populated evidence record for Phase 4's production
cutover — replacing the legacy `internal/ldap` server with the ordinary,
untagged `internal/ldap/profile`-backed production composition — manually
certified against `tested_behavior_head` below and machine-checked for
completeness, absence of placeholders, internal consistency, (unlike
§11.5) live equality with the current certified-surface source tree, and
that the recorded digest is actually bound to `tested_behavior_head`
itself — not merely to whatever tree happens to be checked out when the
suite runs — by `internal/securitytest/phase4_evidence_contract_test.go`.
Those checks prove this section's shape, self-consistency, that the
recorded certified-surface digest matches both the tree they run against
and the git objects recorded at `tested_behavior_head`, and that
`tested_behavior_head` names a real commit reachable from this branch's
history — never that the Docker/fuzz commands below were actually run.
Only the coordinator can attest that; see the human-attested list this
document's plan carries.

**Certification identity**

- **tested_behavior_head:** `fbb83ac21ef4553e429bf8d710e0382f82147db2`
- **manual_verification_head:** `e3304522586d6c17cf3ae6cd0c4e32a526a8f34c` — the
  commit the Docker/fuzz/wire-capture suites below (Supported ClickHouse
  matrix, HA, Wire-capture verification, Fuzz smoke) were actually executed
  against, tracing back to the original manual certification at `76e8bcc`.
  Kept as its own field, distinct from `tested_behavior_head` above, because
  the two are not always the same commit: `tested_behavior_head` is free to
  advance past `manual_verification_head` for a comment-only or otherwise
  behavior-preserving certified-surface edit (as it did here — see below),
  without that re-triggering a fresh manual run, but the coordinator
  attestation must keep citing the commit manual verification was actually
  run against, never whichever commit `tested_behavior_head` happens to name
  at the time.
- **Selector/composition:** ordinary, untagged production — `cmd/ch-oauth-ldap`
  builds without any build tag and its `newLDAPServer` constructs
  `internal/ldap/profile.Server` unconditionally; there is no
  `phase3profile` tag, no legacy `internal/ldap` server, no YAML/CLI/
  environment parser selector, and no fallback adapter anywhere in the
  production, test, or integration build paths.
- **Integration Dockerfile:** `integration/clickhouse/Dockerfile` builds
  `./cmd/ch-oauth-ldap` untagged (no `-tags=phase3profile`), copies no
  `third_party` tree, and installs the resulting binary at
  `/out/ch-oauth-ldap` / `/bin/ch-oauth-ldap`, exactly as
  `internal/securitytest/ch_oauth_ldap_build_contract_test.go` requires.
- **Phase 3 selector absence:** confirmed absent from
  `integration/clickhouse/Dockerfile`, `Dockerfile.ch-oauth-ldap`,
  `scripts/build-ch-oauth-ldap-image.sh`,
  `.github/workflows/build-ch-oauth-ldap.yml`, and every Go build
  constraint under `cmd/ch-oauth-ldap` and `internal/ldap/profile`.
- **Certified-surface digest (SHA-256):** `82d78be760a84047414701d92b0c10660de650795b4ab9554cf216a11f0163da`
  — computed over the same "Certified-surface anti-drift digest" file set
  §11.5 used (`certifiedSurfacePatterns`, unchanged, `third_party/**` kept
  even though the directory is now empty), reproduced 3× identically over
  109 tracked files. This is not merely computed at `tested_behavior_head`
  by assertion: `TestPhase4Evidence_DigestBoundToTestedBehaviorHead` reads
  every certified-surface file straight out of the git object database at
  the exact commit `tested_behavior_head` names (never the working tree)
  and requires the two hash equal, so the field above and the head above
  it are mechanically bound to each other, not merely both individually
  self-consistent.
  Both head fields, the digest, and the tracked-file count above were
  advanced together when ClickHouse 26.3 and 26.8 became tracked lines
  (see §11.7). That change edited certified-surface files — `BUILDS`,
  `lib/expectations.sh`, `scenarios/65-ldap-search-limits.sh`,
  `tests/lib-tests.sh`, `capture-ldap-wire.sh` — and added 20 new fixture
  files under `internal/ldap/testdata/clickhouse-wire/`, taking the tracked
  count from 89 to 109. Per the plan's stop condition 9, a certified-surface
  change after the attested head voids the attestation and is never resolved
  by prose: it is resolved by re-running the manual suites against the new
  head and advancing both fields to the commit that actually contains the
  change, so the digest genuinely is the digest at the recorded head. That
  re-run happened — every image in the tables below was re-certified against
  `manual_verification_head`, not carried forward from the head before it.

  `tested_behavior_head` has since advanced twice past
  `manual_verification_head` — each time for a behavior-preserving
  certified-surface edit — and now names
  `fbb83ac21ef4553e429bf8d710e0382f82147db2`. This is the case these
  two fields exist to distinguish: the head advances so the digest is
  genuinely the digest at the recorded head, while the coordinator
  attestation keeps citing the commit the Docker/fuzz suites were actually
  executed against.

  The first advance, `16d16142e39c2282594d2134625c86e46bfa7909`, corrects
  `26.8`'s recorded `clickhouse_commit` from the annotated tag object
  `v26.8.1.2041-lts` resolves to, to the commit it peels to (§2.1), touching
  two certified-surface files: the provenance table in
  `capture-ldap-wire.sh` and the `clickhouse_commit` metadata field in
  `26.8`'s `profile.json`. No captured byte, no code, and no suite outcome
  changes — the tracked-file count stays 109, and the corrected value
  denotes the same tree the tag always peeled to. `--mode verify` was
  nonetheless re-run after the correction and passed on all four lines.

  The second advance, `fbb83ac21ef4553e429bf8d710e0382f82147db2`, is the
  Dependabot module bump `golang.org/x/crypto v0.54.0 → v0.55.0` and
  `github.com/urfave/cli/v3 v3.10.1 → v3.11.0` (Dependabot PRs #52 and #53,
  landed as one change). It touches `go.mod` and `go.sum` only, so the
  tracked-file count stays 109. It is behavior-preserving on evidence, not
  on assertion:

  - `golang.org/x/crypto` reaches the production closure only as
    `cryptobyte` and `cryptobyte/asn1` — the profile decoder's BER
    primitive — and those packages' sources are **byte-identical** between
    v0.54.0 and v0.55.0 (`diff -r` over the two module-cache trees reports
    no difference anywhere under `cryptobyte/`; the release's actual changes
    are in `ssh`, `acme`, `ocsp`, and `internal/poly1305`, none of which
    this repository imports). The parser's inputs did not change at all.
  - `github.com/urfave/cli/v3` v3.11.0's non-test source changes are
    confined to help/completion rendering, `MutuallyExclusiveFlags`,
    `BoolWithInverseFlag.GetDefaultText`, a nil-`reflect.Type` guard for
    interface-typed flag values, and an empty-`os.Args` guard. Both commands
    use only `cli.Command`, `cli.StringFlag`, and `cli.EnvVars`; a
    `StringFlag`'s `f.Value` is a `string`, so `reflect.TypeOf` is never nil
    and the guarded branch is the one taken before and after.

  The manual matrix was **not** re-run in full for this bump, which is why
  `manual_verification_head` and the coordinator attestation below still
  cite the earlier commit. What was re-run against it, and passed: the
  ClickHouse `25.8` acceptance suite (`run.sh`, scenarios A–I including G',
  with both recorded upstream-bug expectations reproducing unchanged), the
  Docker HA harness on `25.8`, `capture-ldap-wire.sh --mode verify` across
  all four tracked lines (zero fixture drift, `Search precedes Abandon`
  confirmed on every `timeout-abandon` session), and all five fuzz targets
  at `-fuzztime=20s`. `git status --porcelain` showed only `go.mod`/`go.sum`
  after every one of those runs, and `docker ps -a` showed no leftovers.

**Supported ClickHouse matrix** (`integration/clickhouse/run-all-builds.sh`, expectations table unedited)

| Image | Result |
| ----- | ------ |
| `altinity/clickhouse-server:24.8.11.51285.altinitystable` | `PASS` |
| `altinity/clickhouse-server:25.8.28.10001.altinitystable` | `PASS` |

Both runs completed scenarios A–I including phase-5 scenario G' (Search-limit
overflow); the two recorded ClickHouse upstream-bug expected failures
(#78791/not-backported-to-24.8, and #116840's VIEW `external_roles` drop)
reproduced exactly as expected against the untagged production build — no
expectation-table edit was needed or made.

**HA** (`integration/clickhouse/run-ha.sh`, run once per tracked image via
`PHASE3_CH_IMAGE`, existing HAProxy + two-replica harness, existing
persistent same-socket session probe — no new probe created)

| Image | Result |
| ----- | ------ |
| `altinity/clickhouse-server:24.8.11.51285.altinitystable` | `PASS` |
| `altinity/clickhouse-server:25.8.28.10001.altinitystable` | `PASS` |

- **Session-probe result:** `PASS` on both images — both replicas
  authenticate; no shared LDAP session store is required; authenticated
  state is socket/connection-local; killing the replica owning a
  connection kills that session rather than migrating it (confirmed on
  both runs: the A-bound probe failed within the bound and helper B's Bind
  count was unchanged by killing A); fresh authentication proceeds through
  the survivor; the recreated replica rejoins and independently serves a
  fresh Bind. As §"HA applicability" documents, this proves none of
  Kubernetes routing, EndpointSlice/CNI convergence, pod-eviction
  semantics, or a failover SLA.

**Wire-capture verification**

- **Command:** `bash integration/clickhouse/capture-ldap-wire.sh --mode verify --fixtures internal/ldap/testdata/clickhouse-wire`
- **generation: frozen** — zero fixtures were regenerated or promoted;
  `--mode verify` only.
- **Result:** `PASS` for both tracked lines this section certifies
  (`24.8`, `25.8`); every committed session compared byte-for-byte equal
  against the untagged production build; zero fixture drift; no new request
  shape observed. The verify run at this head covered all four tracked
  lines and passed on every one — see §11.7 for the `26.3`/`26.8` half.
- **Search-before-Abandon:** confirmed for both tracked lines' recorded
  timeout-abandon session (`wirecapture: diagnostic — Search precedes
  Abandon as expected`).

**Fuzz smoke** (`go test ./internal/ldap/profile -run '^$' -fuzz=<Target> -fuzztime=20s`, one target at a time)

| Fuzz target | Duration | Result |
| ------------------------ | -------- | ------ |
| `FuzzLDAPFrame` | `20s` | `PASS` |
| `FuzzBindRequest` | `20s` | `PASS` |
| `FuzzSearchRequest` | `20s` | `PASS` |
| `FuzzRestrictedDN` | `20s` | `PASS` |
| `FuzzMemberAssertionDN` | `20s` | `PASS` |

No crasher was found for any of the five targets.

**LOC guardrail**

- **Phase 3 profile-only historical LOC:** `2702` (pinned to §11.5's
  `tested_behavior_head`; not recomputed against today's tree)
- **Phase 4 profile-only LOC:** `2693` — `internal/ldap/profile/*.go`
  non-test files at `tested_behavior_head`, using the identical
  profile-only counting rule (`phase3FreshProfileLOC`, reused unmodified
  for this component per the plan's "Final LOC accounting")
- **Profile-only delta:** `-9`
- **cmd/ch-oauth-ldap/ldap_backend.go LDAP-wiring LOC:** `64`
- **Final Phase 4 production LDAP LOC:** `2757` (`2693 + 64`) — 743 lines
  below ADR #32's ~3,500 architecture-review trigger; no architecture-review
  stop condition was reached.

**§11.3 narrowing dispositions** (unchanged from §11.5; Phase 4 revisited
none of them)

| ID | Disposition |
| -- | ------------ |
| 1  | `ACCEPT` |
| 1a | `ACCEPT` |
| 2  | `ACCEPT` |
| 3  | `ACCEPT` |
| 4  | `ACCEPT` |
| 5  | `ACCEPT` |
| 6  | `ACCEPT` |
| 7  | `ACCEPT` |
| 8  | `ACCEPT` |
| 9  | `ACCEPT` |
| 10 | `ACCEPT` |

**Dependency closure and module graph**

- **Production dependency closure:** `PASS` — `TestDependencyContract_ProductionClosureHasNoGeneralLDAP`
  (unconditional; the `legacyUntilPhase4`/`replacement` staging mechanism no
  longer exists), `TestDependencyContract_ProfileIsProductionImplementation`,
  and `TestDependencyContract_NoNonStandardCryptobyte` (now requiring
  cryptobyte's presence) all pass against the ordinary `./cmd/ch-oauth-ldap`
  closure.
- **Root test/module graph:** `PASS` — `TestModuleDenylistContract_RootTestGraphHasNoGeneralLDAP`
  (deterministic `go list -deps -test` over `./...`) and
  `TestModuleDenylistContract_RootModuleMetadataHasNoGeneralLDAP`
  (`go mod edit -json`) both confirm none of the five denylisted module
  paths appears anywhere in the root test-inclusive dependency graph or in
  `go.mod`'s `Require`/`Replace`.

**Redaction / release gate**

- **`phase5release` vet:** `PASS`
- **`phase5release` test:** `PASS`

**TLS applicability:** N/A — issue #31 is a separate open unit and is out of scope for #33 Phase 4

**Rollback:** no dual parser is retained. Rollback is a source-level revert
of the complete Phase 4 migration, or redeploying the immediately previous
known-good `ghcr.io/altinity/ch-oauth-ldap:ldap-<short-sha>` image; a source
revert must restore the command adapter pair, the legacy `internal/ldap`
package, the module requirements, and the vendored forks coherently, never
partially.

**Coordinator attestation:** Boris Tyshkevich (`@BorisTyshkevich`) certifies
that every Docker/fuzz/wire-capture command and script named in this section
(Supported ClickHouse matrix, HA, Wire-capture verification, Fuzz smoke) was
run to completion against `e3304522586d6c17cf3ae6cd0c4e32a526a8f34c`
(`manual_verification_head` above — **not** `tested_behavior_head`, which
has since advanced to `fbb83ac21ef4553e429bf8d710e0382f82147db2` for the two
behavior-preserving certified-surface edits described above; manual
verification remains at the earlier commit and this attestation
deliberately cites that one), that `git status
--porcelain` was unchanged by verification, and that `docker ps -a` showed
no suite leftovers after verification.

The two tables immediately above remain this section's own Phase 4
cutover record and name the two lines tracked at that time. The 26.3 and
26.8 lines, and the four-image re-certification performed at this head,
are recorded separately in §11.7.

<!-- phase4-release-gate-evidence:end -->

### 11.7 Tracked-line expansion: ClickHouse 26.3 and 26.8

This section records the evidence for extending the tracked set from two
lines to four. Unlike §11.5 and §11.6 it carries **no contract of its own**:
the machinery that would otherwise guard it already does so from elsewhere —
`wire_profile_contract_test.go` holds the four-way tracked-line set equal
(BUILDS ↔ this document's §1/§2.1/§2.2 ↔ fixture directories ↔ every
`profile.json`), and §11.6's live digest and head fields were advanced to
the commit this work landed in. What is recorded here is the manual,
Docker-and-fuzz evidence no test can produce.

**Certification identity**

- **Tested at:** `e3304522586d6c17cf3ae6cd0c4e32a526a8f34c` — the commit
  §11.6 records as `manual_verification_head`. §11.6's
  `tested_behavior_head` has since advanced to
  `fbb83ac21ef4553e429bf8d710e0382f82147db2`, through the behavior-preserving
  provenance correction recorded as finding 3 below and then the
  behavior-preserving Dependabot module bump §11.6 describes; the manual
  suites in this section were run against the earlier commit and were not
  re-run in full for either edit — see §11.6 for exactly what was re-run
  after each.
- **Composition:** unchanged. Ordinary, untagged production
  (`cmd/ch-oauth-ldap` → `internal/ldap/profile`); no build tag, no
  selector, no second backend. Adding tracked lines changes what the suite
  is *run against*, never what is built.

**Why 26.8 is an upstream image**

No Altinity Stable 26.8 build exists. At the time this line was added the
newest Altinity tags were `26.3.16.10001.altinitystable` (2026-07-01) and
`26.6.2.20001.altinityantalya` (2026-08-26), while upstream 26.8 had
shipped. `run-all-builds.sh` requires only a tag equal to the server's
`version()` string; both registries satisfy that, confirmed live for both
new images before any suite ran. §2.1 records the same deviation.

**Supported ClickHouse matrix** (`integration/clickhouse/run-all-builds.sh`, all four builds)

| Image | Result |
| ----- | ------ |
| `altinity/clickhouse-server:24.8.11.51285.altinitystable` | `PASS` |
| `altinity/clickhouse-server:25.8.28.10001.altinitystable` | `PASS` |
| `altinity/clickhouse-server:26.3.16.10001.altinitystable` | `PASS` |
| `clickhouse/clickhouse-server:26.8.1.2041` | `PASS` |

All four completed scenarios A–I including G'. The recorded upstream-bug
expected failures reproduced exactly as recorded: #78791 on 24.8 only, and
#116840's VIEW `external_roles` drop on every one of the four — that bug is
still open upstream, so the H' canary stays an expected-fail on 26.8 too.

**HA** (`integration/clickhouse/run-ha.sh`, once per image via `PHASE3_CH_IMAGE`)

| Image | Result |
| ----- | ------ |
| `altinity/clickhouse-server:24.8.11.51285.altinitystable` | `PASS` |
| `altinity/clickhouse-server:25.8.28.10001.altinitystable` | `PASS` |
| `altinity/clickhouse-server:26.3.16.10001.altinitystable` | `PASS` |
| `clickhouse/clickhouse-server:26.8.1.2041` | `PASS` |

**Session-probe result:** `PASS` on all four images — the A-bound probe
confirmed live (heartbeat n=2, freshness bound satisfied), then correctly
failed within the bound after helper A was killed, on every image. Same
claim boundary as §11.6: this proves nothing about Kubernetes routing,
EndpointSlice/CNI convergence, pod-eviction semantics, or a failover SLA.

**Wire capture**

- **Generation:** run once, into a fresh output directory, for the two new
  lines only. The phase-3 freeze was narrowed, not lifted — see §11.4a.
- **Committed fixtures were not rewritten.** The generate run re-derived
  all four lines; `24.8` and `25.8` reproduced every committed `.ber` byte
  exactly, and only `26.3/` and `26.8/` were promoted. `git status` after
  promotion showed additions only.
- **Verify command:** `bash integration/clickhouse/capture-ldap-wire.sh --mode verify --fixtures internal/ldap/testdata/clickhouse-wire`
- **Verify result:** `PASS` for all four tracked lines, both sessions each;
  `Search precedes Abandon` confirmed on every `timeout-abandon` session;
  zero fixture drift.
- **No new request shape.** Every `26.3` and `26.8` request PDU is
  byte-identical to the corresponding `25.8` PDU. The bounded compatibility
  profile therefore covers 26.x with no parser change, and none was made.

**Fuzz smoke** (`-run '^$' -fuzz=<target> -fuzztime=20s`, one target at a time)

| Fuzz target | Duration | Result |
| ----- | ----- | ----- |
| `FuzzLDAPFrame` | 20s | `PASS` |
| `FuzzBindRequest` | 20s | `PASS` |
| `FuzzSearchRequest` | 20s | `PASS` |
| `FuzzRestrictedDN` | 20s | `PASS` |
| `FuzzMemberAssertionDN` | 20s | `PASS` |

One honest note on that table: an earlier `FuzzMemberAssertionDN` run
failed with `context deadline exceeded` while the machine was still loaded
from the Docker suites. It was investigated rather than re-run until green.
No crasher was written, no reproducer exists, the repository stayed clean of
fuzz artifacts, and the target passed 3/3 at reduced parallelism and again
on an idle machine — Go's fuzzing coordinator failing to retire workers
inside its shutdown grace period, not a defect in `decodeMembershipFilter`.
Recorded because a green table that quietly replaced a red one would be the
more misleading artifact.

**Source-audit findings**

- **26.3 added one non-TLS `ldap_set_option`.** A new `<follow_referrals>`
  server-config key introduced
  `ldap_set_option(handle, LDAP_OPT_REFERRALS, ...)` into
  `openConnection()` (§5 classifies it). `ExternalAuthenticators.cpp` sets
  it only when `config.has(...)` finds the key; this fixture does not set
  it, so the option is `LDAP_OPT_OFF`, and the captured bytes confirm no
  wire effect.
- **26.3 → 26.8 is LDAP-behaviorally identical** — value-initialization
  hygiene only (§2.2).

**Two defects review found in this expansion's own first cut**

3. **`26.8`'s `clickhouse_commit` recorded an annotated tag object, not a
   commit.** `v26.8.1.2041-lts` is the only annotated tag among the four
   tracked lines; its ref reports object type `tag` and SHA `be4175ff…`,
   which was recorded as the commit in all four places provenance lives.
   The peeled commit is `537693a9…`. Nothing else moved — the GitHub
   contents API peels refs, so §2.2's blob SHAs and the OpenLDAP pin were
   already correct and were re-verified directly against the peeled commit.
   The cause was method drift: three lines were resolved with
   `git/ref/tags/<tag>` printing `.object.type` (all `commit`), while `26.8`
   used `git/matching-refs` printing only `.object.sha`, so the `tag` type
   was never seen. §2.1 and both provenance tables now state the peeling
   requirement.

   Worth recording precisely because of what could NOT have caught it:
   `--mode verify` compares the committed `profile.json` against a fresh one
   derived from `capture-ldap-wire.sh`'s own table, so it agrees whenever
   those two agree. It validates consistency, not correctness, and passed
   with the wrong SHA on both sides. No offline contract can check a commit
   SHA against a remote repository either, so this remains a documented
   manual step, not a new mechanical guard — an honest gap rather than a
   check that would only appear to close it.

4. **The §5 TLS-block citations were left at 24.8/25.8 line numbers.** The
   non-TLS rows were given per-pair numbers when 26.x was added, but the TLS
   blocks — which the new `LDAP_OPT_REFERRALS` block pushes down by eight
   lines — were not, and neither were the §4 call-chain, §6 source-of-value
   and §8 citations. Every `LDAPClient.cpp` citation in this document is now
   given as `24.8/25.8 → 26.3/26.8`. `LDAPClient.h` is the documented
   exception (§2.2): its blob differs between pairs, but every cited line is
   at an unchanged number, verified rather than assumed. Behavior-neutral,
   but this document's whole purpose is exact source auditing.

**Two defects this expansion surfaced upstream and in the suite**

1. **ClickHouse 26.8 maps `ACCESS_DENIED` to HTTP 403**, where
   24.8/25.8/26.3 map it to 500. Scenario H's negative control asserted 500
   outright and so failed on 26.8 even though propagation was correct and
   the response body was exactly the expected shape (`Code: 497 ... Received
   from clickhouse-remote:9000 ... (ACCESS_DENIED)`). The status is now a
   per-line recorded fact (`remote_access_denied_http_status_for`),
   fail-closed for an unrecorded prefix. Note the cost: on 26.8
   `ACCESS_DENIED` and `AUTHENTICATION_FAILED` share status 403, so the
   status no longer discriminates and the two body markers carry that
   weight — which they always did.
2. **`search_limit_overflow_wire_tuple` recorded `time_limit=0` on every
   line; the real value is 20.** The reasoning error was "this path has no
   `<search_timeout>` XML key, therefore 0"; with no per-call deadline
   requested, libldap sends the handle-wide `LDAP_OPT_TIMELIMIT` default,
   which §5 documents as 20s and §8.2 has always recorded as the Search's
   `timeLimit` outright. Corrected from two further independent directions:
   decoding `SearchRequest.timeLimit` out of the committed corpus (BER
   `02 01 14` = 20, identical on all four lines) and the helper's own live
   T2 telemetry during a real scenario G' run (`time_limit=20`). The field
   was recorded and logged but never asserted against telemetry, which is
   exactly how two committed records contradicted each other unnoticed. No
   behavior changed.
