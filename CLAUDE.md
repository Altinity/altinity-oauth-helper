# Contributor guide — altinity-oauth-helper

Go module providing OAuth/JWT helpers for ClickHouse-fronted deployments.
Two binaries ship today:

- `ch-jwt-verify`: a sidecar HTTP server that ClickHouse's
  `<http_authentication_servers>` calls to validate a JWT that upstream
  consumers have repacked as an HTTP Basic password (`base64(email:jwt)`).
- `ch-oauth-ldap`: a standalone LDAPv3 server where the simple-Bind password
  is the JWT; it authenticates via the same shared verifier and exposes the
  caller's mapped ClickHouse roles as synthetic LDAP groups over a
  same-connection restricted Search. Verified end to end against real
  ClickHouse (`altinity/clickhouse-server` 24.8 baseline and 25.8) by the
  manual suite in `integration/clickhouse/`; the working ClickHouse LDAP
  config and the per-version distributed-role caveats are documented in
  `README.md`.

See `README.md` for the full wire diagram and rationale (OSS ClickHouse has
no native Bearer/JWT auth path; Antalya does).

## Repo map

| Path | What |
|---|---|
| `cmd/ch-jwt-verify/` | the sidecar binary — `main.go` (CLI/server wiring), `config.go` (YAML config), `settings.go`, `verify.go` (the `/verify` handler: JWT validation, cache-key binding, identity policy), `verify_test.go` |
| `cmd/ch-oauth-ldap/` | the standalone LDAPv3 server binary — `main.go` (CLI/signal-context/lifecycle wiring: verifier + role pipeline + the LDAP backend behind the package-local `ldapServer` interface — `Serve(net.Listener) error`, `Stop()` — constructed via `newLDAPServer(...)`), `config.go` (YAML config, defaults, fail-startup validation, conversion into `verification.Config`/`identity.Config`/`roles.Config`; DN/backend validation delegates to `validateLDAPBackendConfig(cfg)`), `ldap_backend.go` (issue #33 phase 4's permanent, ordinary adapter — the sole file that imports `internal/ldap/profile`, with no build tag, runtime selector, or fallback: owns `toProfileConfig`, `validateLDAPBackendConfig` wrapping `profile.ValidateConfig`, `newLDAPServer` calling `profile.New`, and the `ldapServer` interface itself — `profile.Config` deliberately has no `Listen` field, so the command keeps owning `net.Listen`), `config_test.go` (incl. `testdata/operator-guide.yaml` loaded through production `LoadConfig` and strict-decoded with `KnownFields(true)` — the proof backing `docs/ch-oauth-ldap-operator-guide.md`'s YAML fences), `config_profile_test.go`/`main_profile_test.go` (untagged since Phase 4, renamed from their temporary `_phase3profile_test.go` names: exact profile config mapping, restricted user/group-base DN narrowing, `UserRDNAttribute` descriptor-grammar narrowing; `newLDAPServer` returns `*profile.Server`, the command still owns the listener, and a real `run()` composition test against the profile backend with the real verifier+role pipeline), `main_test.go`. There is exactly one production LDAP backend; the legacy adapter and its permissive-validation tests were deleted at cutover |
| `internal/ldap/` | now holds only test/tooling support and the production implementation's own subpackage — the direct legacy LDAP implementation this directory used to contain (`bind.go`/`controls.go`/`dn.go`/`entry.go`/`filter.go`/`search.go`/`server.go`/`session.go`/`unsupported.go` and their tests, plus `profile_compat_test.go`'s old/new parity harness) was deleted at issue #33 phase 4's cutover, once every assertion it still uniquely covered was transplanted into `internal/ldap/profile`'s own permanent tests. What remains: `profile/` (below) and `testdata/` (`phase1-baseline/`, the immutable pre-replacement dependency-closure snapshot from before any of issue #33 existed, and `clickhouse-wire/`, the committed sanitized ClickHouse LDAP request corpus — both frozen, never rewritten by normal verification) |
| `internal/ldap/profile/` | `cmd/ch-oauth-ldap`'s only, ordinary production LDAP implementation (package `profile`) since issue #33 phase 4's cutover — a first-party, bounded ClickHouse compatibility profile; its ASN.1/protocol implementation (`frame.go`/`protocol.go`) is stdlib plus `golang.org/x/crypto/cryptobyte` only — the package's own dependency closure is wider by design, since `config.go` directly depends on `internal/verification` and the upstream OAuth SDK's types for `Verifier`/`RoleResolver` (a deliberate, legitimate transitive dependency `internal/securitytest/profile_dependency_contract_test.go` documents rather than pins away); no `go-ldap`/vendored-goldap/vendored-ldapserver import either way (enforced below), and none of those five general-LDAP-stack modules exist anywhere in this repository's module graph any more. Production files: `config.go` (`Config`/`Verifier`/`RoleResolver`/`ValidateConfig`; deliberately no `Listen` — the command keeps owning the listener), `dn.go` (restricted RFC-4514-subset DN grammar, structural equality, synthetic-DN rendering — the narrowings versus the deleted legacy `go-ldap`-based parser are recorded in that file's own comments and in `docs/clickhouse-ldap-wire-profile.md` §11.3), `frame.go` (bounded-before-allocation BER framing, `cryptobyte` LDAPMessage envelope, minimal Controls-criticality scanner), `protocol.go` (application tags, result-code constants, the shared minimal-positive-INTEGER validator Abandon's implicit target integer reuses), `encode.go` (`cryptobyte.Builder` response encoders, the closed `diagnostic` enum + `addLDAPResultFields`, 64 KiB response-PDU preflight), `logging.go` (byte-identical `correlationID` re-derivation, the closed `reason` enum, log helpers), `session.go` (connection-owned `authState`/`connection`, no password/frame field retained), `bind.go` (LDAPv3-only simple-Bind decoder, clear-before-validate state policy, the sole `Verify`/`Roles` call sites), `search.go` (fixed ClickHouse Search shape, nonrecursive two-child membership-filter decode, sizeLimit/timeLimit, `cn`-only entries), `server.go` (lifecycle, 256-connection admission, the package's one production `go` statement, dispatch), `doc.go` (package-status doc comment: production since Phase 4, certified via a now-deleted temporary `phase3profile` build tag in Phase 3). Test files: a `*_test.go` beside each production file, plus `protocol_test.go`/`rawclient_test.go` (real-TCP black-box suite driven by a local, test-only raw-PDU LDAP client built on this package's own frame/bind/search builders — issue #33 phase 4 removed the `github.com/go-ldap/ldap/v3` test client this suite used through Phase 3), `clickhouse_wire_cryptobyte_test.go` ("Oracle A" — moved here from the deleted `internal/ldap` at cutover: a hand-written bounded BER cursor, independent of both cryptobyte and this package's own decoders, computing the cryptobyte-vs-local-cursor primitive-selection verdict `TestClickHouseWireCryptobyteDecision` records), `adversarial_test.go`/`midsearch_test.go` (framing-cap/deadline-stall/malformed-BER/partial-write adversarial suite), `conncap_test.go` (256/257-connection admission), `search_limits_test.go`/`hostile_dn_test.go`/`redaction_boundary_test.go` (Search-limit telemetry, hostile-Bind-DN, and marker-redaction proofs), `replay_test.go` (`TestProfileReplay` — real-TCP replay of every committed `internal/ldap/testdata/clickhouse-wire/**` session through this server), `fakes_test.go` (the canonical in-package `fakeVerifier`/`fakeResolver`/`fakeClock`), and five native fuzz targets: `frame_fuzz_test.go` (`FuzzLDAPFrame`), `bind_fuzz_test.go` (`FuzzBindRequest`), `search_fuzz_test.go` (`FuzzSearchRequest`), `dn_fuzz_test.go` (`FuzzRestrictedDN`, `FuzzMemberAssertionDN`) — every committed seed runs under ordinary `go test`, and since Phase 4 that `go test` run is production-code coverage, not pre-cutover certification; a short fuzz smoke beyond seeds is `go test ./internal/ldap/profile -run '^$' -fuzz=Fuzz<Name> -fuzztime=20s`, one target at a time (never wait for a real 20/30s production deadline in an ordinary unit test). `differential_test.go` (the old/new differential oracle against vendored goldap) and `profile_compat_test.go`'s duplicate-coverage half were both deleted at cutover once Oracle A/B (below) and the permanent profile test suite subsumed everything they proved. Registered in `internal/securitytest`'s redaction scope (`scopeDirs`, plus sink kind `ldap-profile-diagnostic` for direct `addLDAPResultFields(..., diagConstant)` calls) and covered by the general `internal/ldap/**` nested-package guard (`TestRedactionInventory_NestedLDAPPackagesAreRegistered`, registered outright rather than exempted). `internal/securitytest/profile_architecture_contract_test.go` mechanically enforces the syntactic invariants: exactly one production `go` statement (the admission spawn); no `sync.Map`; no old-LDAP/BER/`unsafe` import; `decodeMembershipFilter` nonrecursive with exactly two `decodeEquality` calls; `diagnostic`/`reason` bytes reachable only through their closed enums (no dynamic conversion). Its companion `internal/securitytest/profile_types_contract_test.go` enforces the four type-semantic invariants over the fully type-checked package (go/types on gc export data from a deterministic `go list -deps -export`, via stdlib `importer.ForCompiler` — not AST shape enumeration, which three review passes plus an architecture consultation showed is bypassable by ordinary Go): no map- or channel-typed declaration, signature, or value expression beyond `Server.active` (`map[net.Conn]struct{}`) and `serveDone`/`stopDone` (`chan struct{}`), and `Verifier.Verify`/`RoleResolver.Roles` each referenced — call, method value, or method expression — exactly once, both in `bind.go` (struct fields named `Roles` are excluded by selection kind, not naming convention); reflection/`unsafe` laundering is outside what the type checks see and is covered by the import bans. `internal/securitytest/profile_dependency_contract_test.go` mechanically enforces this package's PRESENCE in `./cmd/ch-oauth-ldap`'s live production dependency closure (`TestDependencyContract_ProfileIsProductionImplementation` — Amendment 5's Phase 4 inversion of the original Phase 2 "must be absent" contract), and that this package's own closure requires `golang.org/x/crypto/cryptobyte` while excluding the vendored/general LDAP stack (`vjeantet/ldapserver`, `vjeantet/goldap`, `go-ldap/ldap/v3`, `go-asn1-ber/asn1-ber`, `Azure/go-ntlmssp`, `internal/wirefixture`) |
| `internal/securitytest/` | phase-5 automated security verification, not itself security-relevant production code (see its `doc.go`) — `redaction_inventory_test.go` (AST-enumerates every log/error/response-construction sink across the explicit audited scope list named by `doc.go`'s `scopeDirs` — `cmd/ch-oauth-ldap`, `cmd/ch-jwt-verify`, `internal/ldap` (now just its `profile/` subpackage — the direct legacy implementation's sinks were removed at issue #33 phase 4's cutover), `internal/verification`, `internal/identity`, `internal/roles`, `internal/wirefixture`, `integration/clickhouse/wirecapture` — and cross-checks `testdata/redaction-sites.tsv`; the vendored `third_party/ldapserver` fork's separate Logger scan was removed along with the fork itself at cutover; `TestRedactionInventory_Phase1AuditedScopesRemainFlat` mechanically guards the two issue-#33 phase-1 scopes staying flat, since `discoverSites` only reads each scope directory's direct, non-test `.go` files and never recurses; `redaction-sites.tsv` was re-baselined at cutover — every `internal/ldap` direct-implementation row dropped, one new row added for `cmd/ch-oauth-ldap/ldap_backend.go`, every `internal/ldap/profile` sink/marker row unchanged), `sdk_contract_test.go` (pinned `go-mcp-oauth-sdk` version + no-replace + strict-entrypoint AST checks), `release_gate_test.go` (`-tags phase5release` only: fails while any manifest row is `blocked_external`, per amendment A1 — see "Build & test" below), `pr_gate_contract_test.go` (untagged, so it runs in both `go test ./...` and the gate's own `go test -race ./...` step: parses `.github/workflows/pr-gate.yml` and asserts the required PR gate's structure against literal expectations — unfiltered triggers, no path filters, `contents: read` only, exactly one unconditional job named `Required PR gate`, the five commands exactly once in order, SHA-pinned actions; an accidental-drift detector, not tamper resistance, since it lives in the same PR-controlled tree as the workflow), `docs_contract_test.go` (every `config-source`-marked YAML/XML fence in `README.md`/`docs/ch-oauth-ldap-operator-guide.md` — this repo's only two operator-facing narrative documents — is an exact contiguous excerpt of its real source file, with both files' `<clickhouse>` fence additionally required to equal the ClickHouse fixture's `<clickhouse>` element exactly, not just be a substring of the whole fixture file; required/forbidden HA-and-trust-boundary wording; `docs/clickhouse-ldap-wire-profile.md` is deliberately NOT in its scope — see `wire_profile_contract_test.go` below), `dependency_contract_test.go` (issue #33 phase 1, plan §5/§6/§31: deterministically invokes `go list -deps` against `./cmd/ch-oauth-ldap` and asserts the live non-standard closure exactly matches `testdata/production-nonstdlib-deps.txt` (regenerated at cutover: the whole general-LDAP stack and its vendored replaces are gone, `internal/ldap/profile`/`golang.org/x/crypto/cryptobyte` are now legitimate members) — the mutable *live* expectation, distinct from the immutable historical snapshot at `internal/ldap/testdata/phase1-baseline/production-nonstdlib-deps.txt`; `TestDependencyContract_NoNonStandardCryptobyte` is now a POSITIVE contract (issue #33 phase 4 inverted its original Phase 1 "must be absent" form: cryptobyte is production's chosen primitive and must stay present); `TestDependencyContract_WirefixtureIsNotProduction` is unchanged in intent; `TestDependencyContract_ProductionClosureHasNoGeneralLDAP` is now the permanent, unconditional five-prefix-denylist assertion — the staged `ldapClosureStage`/`legacyUntilPhase4`/`replacement` migration mechanism, and the three `TestDependencyContract_Phase3Replacement*` tagged-composition contracts it needed while `cmd/ch-oauth-ldap` still had two backends to choose between, were all deleted once ordinary `go build`/`go test ./...` began exercising the sole production composition directly; the shared `generalLDAPDenylistPrefixes`/`matchesGeneralLDAPPrefix`/`isGeneralLDAPDependency` five-prefix policy, and its own `TestGeneralLDAPDenylistPrefixes_ExactlyTheRequiredFive` self-guard, are also consumed by `profile_dependency_contract_test.go`), `profile_dependency_contract_test.go` (`TestDependencyContract_ProfileIsProductionImplementation` — Amendment 5's Phase 4 inversion of the original Phase 2 `TestDependencyContract_ProfileImplementationIsNotProduction`: `internal/ldap/profile` must now be PRESENT in `./cmd/ch-oauth-ldap`'s live closure; `TestDependencyContract_ProfileClosureHasRequiredPrimitiveAndNoGeneralLDAP` is unchanged in intent), `ch_oauth_ldap_build_contract_test.go` (issue #33 phase 4's permanent build-composition contract, direct successor of the retired `phase3_selector_contract_test.go`: the integration Dockerfile's `ch-oauth-ldap` build line is untagged and the sole writer of `/out/ch-oauth-ldap`, exactly one runtime `COPY` installs it at `/bin/ch-oauth-ldap`, and none of the published `Dockerfile.ch-oauth-ldap`, `scripts/build-ch-oauth-ldap-image.sh`, or `.github/workflows/build-ch-oauth-ldap.yml` ever mentions the retired `phase3profile` selector — retains the old file's full sabotage coverage for duplicate builds, `go install`, `cp`/`mv`, directory destinations, and JSON-array COPY/ADD forms; the tag-selection half of the old contract has no successor because there is no tag left to select), `wire_profile_contract_test.go` (issue #33 phase 1, plan §30: Docker-free anti-drift contract over the wire evidence — static ClickHouse/OpenLDAP source-provenance matrix cross-checked against `run-all-builds.sh`/the wire-profile doc/every `profile.json`, four-way tracked-line equality, the `<clickhouse>` config-hash + semantic contract, fixture inventory (orphan/sequence/SHA/`connection_count`/operation-coverage checks), the `*.ber binary` `.gitattributes` rule, an all-file JWT-shape scanner plus its own AST-derived positive control, the wire doc's exactly-one-decision-marker/no-XML-YAML-fence boundary, the constructed-MessageID-127/128 regenerate-and-compare proof, and the AST/`go list -deps` check that `integration/clickhouse/wirecapture` writes metadata only through `internal/wirefixture`; issue #33 phase 4 historicalized the entire `TestWireProfileContract_Phase3Evidence*`/`Section113NarrowingDispositions` family in place — each now checks the frozen §11.5 record against locally owned historical literals (the `phase3profile` selector string, historical image/digest/LOC/file-count values) instead of reading the live Dockerfile or recomputing against the current tree, and every vendored-goldap decode leg was replaced by calls into `wire_oracle_b_test.go`'s "Oracle B"), `wire_oracle_b_test.go` (issue #33 phase 4 — a second, independently written, test-only bounded BER cursor decoding only what the wire-profile evidence tests need: Bind DN, Search `derefAliases`, Controls presence/criticality, and the outer filter's AND/OR operator plus its two `equalityMatch` children; shares no decoding code with Oracle A (`internal/ldap/profile/clickhouse_wire_cryptobyte_test.go`), the production profile decoder, or `integration/clickhouse/wirecapture`'s producer-side parsing) |
| `internal/wirefixture/` | issue #33 phase 1 (plan §9, §25–§29) — the sole owner of the committed ClickHouse-LDAP-wire fixture schema: `schema.go` (`Profile`/`Session`/`PDU`, strict JSON decode, deterministic encode, `StableProfile`/`StableSession`/`StablePDU` verify-mode comparison projections), `root.go` (`ModuleRoot`, fixture-path helpers, `ValidateFixtureRoot`), `constructed.go` (`BuildConstructedSimpleBind`/`BuildConstructedMessageIDBoundarySession`, the deterministic MessageID-127/128 boundary generator), `confighash.go` (`ClickHouseConfigElementSHA256`, hashing only the trimmed `<clickhouse>...</clickhouse>` element). Test/tooling support only: `internal/securitytest/dependency_contract_test.go` asserts it is mechanically absent from `./cmd/ch-oauth-ldap`'s production closure. `integration/clickhouse/wirecapture` writes `profile.json`/`session.json` only through this package's `WriteProfile`/`WriteSession`; `internal/ldap/profile/clickhouse_wire_cryptobyte_test.go` (moved here from the deleted `internal/ldap` at issue #33 phase 4's cutover) and `internal/securitytest/wire_profile_contract_test.go` read through it too — see plan §9's "writer/reader ownership" |
| `docs/` | `ch-oauth-ldap-operator-guide.md` — consolidates (does not restate) the working ClickHouse config, OIDC/Auth0/JWKS field reference, identity/role-pipeline behavior, the cache invariant, measured ClickHouse Search-limit behavior (scenario G'), the plaintext-bearer trust boundary, HA/capacity incl. the Kubernetes runbook, and (§10) the compatibility profile's deliberate narrowings versus the deleted legacy server, now permanent, current behavior rather than a pending cutover. Every fence in it is enforced against its real source by `internal/securitytest/docs_contract_test.go`. `clickhouse-ldap-wire-profile.md` — issue #33 phase-1 engineering evidence (source-cited ClickHouse/OpenLDAP behavior, the wire corpus, the `cryptobyte` primitive decision), extended through Phase 3 with §11.1's corrected 2,682-LOC merged Phase 2 baseline, §11.3's eleven narrowing dispositions, §11.4a's frozen wire-capture policy, and §11.5's Phase 3 release-gate evidence record (tested commit, certified-surface digest, matrix/HA/wire/fuzz/LOC results) — issue #33 phase 4 froze §11.5 as immutable history: its recorded bytes are never rewritten to match later topology, and `internal/securitytest/wire_profile_contract_test.go`'s corresponding tests now check it against locally owned historical literals instead of the live tree. A later §11.6 records Phase 4's own cutover evidence (certified-surface digest, matrix/HA/wire/fuzz/LOC results for the untagged production composition) once that manual certification actually runs; owned by `internal/securitytest/wire_profile_contract_test.go`, not `docs_contract_test.go` |
| `integration/clickhouse/` | real-ClickHouse acceptance suite for `ch-oauth-ldap` — `run.sh` (4-service Docker fixture: synthetic IdP + helper + two ClickHouse nodes, preflight, sources `scenarios/*.sh` A–I plus phase-5 scenario G' Search-limit compatibility), `run-all-builds.sh` (every build in `lib/expectations.sh`), `lib/expectations.sh` (per-ClickHouse-version expected outcomes for the two tracked upstream bugs, #78791/#79099 and #116840, plus scenario G's per-build Search-limit-overflow outcome), `scenarios/65-ldap-search-limits.sh` (scenario G'), `tests/lib-tests.sh` (daemon-free bash unit tests for the harness's own shell libraries in `lib/`), `clickhouse/common/config.d/ldap.xml` (the working LDAP config `README.md` copies, incl. `<search_limit>256</search_limit>`), `compose-ha.yml`/`run-ha.sh`/`ha/` (phase-5 Docker HA harness: HAProxy frontend + two independent replicas + a persistent same-socket session probe — see `docs/ch-oauth-ldap-operator-guide.md` §8 for its exact claim boundary versus the Kubernetes runbook; `ha/session-probe` is credential-bearing integration tooling that stays outside `internal/securitytest`'s `scopeDirs` — a pre-existing, honestly-recorded gap, not a retroactive inventory expansion). The Docker suite is a manual/local gate, not CI, **but** `tests/lib-tests.sh` runs in `.github/workflows/pr-gate.yml` as the fifth command of the required PR gate — breaking anything under `lib/` turns `Required PR gate` red; see `integration/clickhouse/README.md`. `Dockerfile` builds all four test binaries into the suite's shared image; `ch-oauth-ldap` builds ordinarily and untagged, identically to the published `Dockerfile.ch-oauth-ldap` production image and an ordinary local `go build ./cmd/ch-oauth-ldap` (issue #33 phase 4 removed the temporary `-tags=phase3profile` this build line carried through Phase 3, along with the `COPY third_party` it no longer needs) — so `run.sh`, `run-all-builds.sh`, `run-ha.sh`, and `compose-wirecapture.yml`'s `ldap-helper-upstream` service (same shared image) all exercise the same `internal/ldap/profile` production composition every other build does; see `integration/clickhouse/README.md`'s phase-4 note. Issue #33 phase 1 added a second, also-manual wire-capture fixture: `wirecapture/` (the `ldap-wire-recorder` capture/sanitize/construct/compare tool, built into this suite's shared image), `compose-wirecapture.yml` (standalone 5-service `ch-wirecap` Compose topology interposing the recorder between ClickHouse and the real helper), `capture-ldap-wire.sh` (`--mode generate\|verify` driver — issue #33 phase 3 froze `--mode generate`, and it stays frozen after cutover: no committed `internal/ldap/testdata/clickhouse-wire/**` file may be regenerated/promoted; only `--mode verify` runs, as production-backed verification of the historical Phase 1 corpus, not new fixture provenance — a new request shape from a tracked client stops the unit rather than broadening the parser), `tests/cases/wirecapture-*.sh` (daemon-free compose/fallback/collision-preflight parity) — see `integration/clickhouse/README.md`'s "Wire capture" section for the generate/verify commands, the fixed query/token-claim recipe, and the three-fixture (`ch-phase3`/`ch-phase5-ha`/`ch-wirecap`) mutual-exclusion rule |
| `cmd/synthetic-idp/` | a controllable in-process test IdP (imported from altinity-mcp) used by examples/local dev and the integration suite (`/sign` mints RS256 JWTs, repeatable `role=` → `roles` claim) — not part of the shipped image |
| `helm/ch-jwt-verify/` | Helm chart — ConfigMaps (sidecar config, CH `http_authentication_servers` XML) + a reusable container fragment (`_helpers.tpl`) for sidecar mode, plus a standalone Deployment+Service mode; see `helm/ch-jwt-verify/README.md` |
| `helm/ch-oauth-ldap/` | standalone Helm chart for the environment-level LDAP deployment — two-replica Deployment, internal-only `ClusterIP` Service on 389, default-on source-restricting NetworkPolicy, PDB, and the two ConfigMaps (helper config, CH LDAP XML); committed local gate is `helm/ch-oauth-ldap/test.sh` (render/negative-matrix/embedded-content/packaging/actionlint checks, plus its own `ci/` fixtures) — see `helm/ch-oauth-ldap/README.md` |
| `examples/` | consumer × deploy-style recipes (`_platform` is the shared Dex+Postgres+ClickHouse+sidecar base every consumer overlay layers on); `examples/README.md` tracks the working/planned/broken matrix |
| `scripts/build-image.sh` | multi-arch (`amd64`+`arm64`) build & push for `ghcr.io/altinity/ch-jwt-verify`, legacy `DOCKER_BUILDKIT=0` |
| `scripts/build-ch-oauth-ldap-image.sh` | multi-arch (`amd64`+`arm64`) build & push for `ghcr.io/altinity/ch-oauth-ldap`, mirrors `build-image.sh`'s legacy `DOCKER_BUILDKIT=0` convention; never compiles into the checkout, and builds only from an exported `git archive HEAD` tree (never the live working tree); refuses to republish an already-existing tag (no force override) |
| `scripts/build-synthetic-idp-image.sh` | image build for the synthetic IdP used in examples |
| `Dockerfile` / `Dockerfile.synthetic-idp` / `Dockerfile.ch-oauth-ldap` | consumed by the three build scripts above (`Dockerfile.ch-oauth-ldap` by `scripts/build-ch-oauth-ldap-image.sh`) |
| `.github/workflows/build-ch-oauth-ldap.yml` | push-to-main image publication for `ghcr.io/altinity/ch-oauth-ldap` (tag `ldap-<short-sha>`), mirroring `build-ch-jwt-verify.yml`'s structure |
| `.github/workflows/pr-gate.yml` | the non-publishing PR/push verification workflow (`PR gate`) — one job, `Required PR gate`, running the five mandatory commands on every pull request and every push to `main`; publishes nothing and holds only `contents: read` |

JWKS fetching, JWT validation, and identity-policy helpers (verified-email,
allowed domains, `iss`/`aud` checks) live upstream in
[`github.com/altinity/go-mcp-oauth-sdk`](https://github.com/altinity/go-mcp-oauth-sdk).
This repo consumes that module via `go.mod` and should not re-implement or
fork that logic — extend the SDK instead when the need is generic (not
`ch-jwt-verify`-specific).

## Build & test

- `go build ./...` — compiles all binaries (`ch-jwt-verify`, `ch-oauth-ldap`, `synthetic-idp`).
- `go test ./...` — the test suite; `cmd/ch-jwt-verify/verify_test.go` spins
  up an in-process test IdP (RSA-signed JWTs against an httptest JWKS
  server) rather than depending on any shared fixture, since the sidecar is
  independent of any e2e test elsewhere. There is no coverage gate.
  `.github/workflows/pr-gate.yml` (workflow `PR gate`, single job
  `Required PR gate`) is the **mandatory PR-time verification gate**: it runs
  on every pull request and every push to `main`, with no path filters, and
  executes exactly these five commands in order —

  ```
  go build ./...
  go vet ./...
  go test -race ./...
  go test -tags phase5release ./internal/securitytest -count=1
  bash integration/clickhouse/tests/lib-tests.sh
  ```

  Any one of them failing fails the whole job, and `Required PR gate` is the
  stable check name branch protection on `main` requires for merges (protection
  is enabled as part of #23's rollout, immediately after this lands) — treat
  that job name as an externally consumed interface either way: renaming it
  means migrating branch protection in the same change. The real Docker
  ClickHouse suite (`integration/clickhouse/run.sh`, `run-all-builds.sh`, `run-ha.sh`)
  deliberately stays **out** of that gate and remains manual/local. Separately
  from verification there are still **two** push-to-main image-publication
  workflows — `.github/workflows/build-ch-jwt-verify.yml` (path-filtered to
  `cmd/ch-jwt-verify/**`, `go.mod`/`go.sum`, `Dockerfile`) and
  `.github/workflows/build-ch-oauth-ldap.yml` (path-filtered to
  `cmd/ch-oauth-ldap/**`, `internal/**`, `third_party/**`, `go.mod`/`go.sum`,
  `Dockerfile.ch-oauth-ldap`) — those two only build+push an image on push to
  `main` (plus manual `workflow_dispatch`) and are **not** verification gates;
  do not treat a green publish as a substitute for `Required PR gate`. Because
  that path filter includes `internal/**`, a change anywhere under
  `internal/` — including test/tooling-only additions like
  `internal/wirefixture` that never reach the production closure — triggers
  `build-ch-oauth-ldap.yml` on merge to `main` and publishes a new
  `ghcr.io/altinity/ch-oauth-ldap` image tag. That is expected publication
  behavior, not a signal that production behavior changed and not itself a
  verification gate (issue #33 plan §45); the image workflow builds the
  command binary into an isolated runner-temp context, so the committed wire
  fixture corpus is never part of that Docker build context. Run the
  gate locally yourself before
  calling a change done rather than discovering it in hosted CI; write tests
  for new behavior, especially around cache-key isolation and identity-policy
  edge cases, since those are the security-relevant surface.

  One limit on that gate's real reach is worth knowing before you rely on it:
  `integration/clickhouse/tests/lib-tests.sh` is Docker-*daemon*-free but
  still needs the `docker` CLI on `PATH`: `integration/clickhouse/lib/common.sh`
  calls `detect_compose_cmd` at source time and `die`s otherwise, so
  `env PATH=/usr/bin:/bin:/usr/sbin:/sbin bash
  integration/clickhouse/tests/lib-tests.sh` aborts with `neither 'docker
  compose' nor 'docker-compose' is available on PATH`. `ubuntu-latest` ships
  that CLI, so the hosted run is fine — but "needs only bash/coreutils" is
  imprecise, and this is exactly the kind of dependency that turns a
  runner-image change into a mystery red. (Issue #33 phase 4's cutover
  deleted the vendored `third_party/goldap`/`third_party/ldapserver` forks
  this bullet used to flag as a second gap the required gate never reached —
  there is no longer a second general-purpose LDAP/BER implementation in the
  tree for a gate to miss.)
- `go vet ./...` before sending a change, plus
  `go vet -tags phase5release ./internal/securitytest` (amendment A5) so the
  release-gate build tag itself never bit-rots even though `go vet ./...`
  alone does not compile it.
- `go test ./internal/securitytest -count=1` — the redaction/SDK/docs
  consistency gate (see `internal/securitytest/doc.go`); this must stay
  green in normal development. `go test -tags phase5release
  ./internal/securitytest -count=1` is the separate, stricter final release
  gate — it now **must pass**: `SDK_REDACTION_AUTHORIZATION_GATE` was closed
  by bumping to `go-mcp-oauth-sdk@v0.2.1` (which drops the raw `kid` field
  from the JWKS-rotation success log) and re-auditing every external-pinned
  manifest row (`fix(#19): consume go-mcp-oauth-sdk v0.2.1 and close
  SDK_REDACTION_AUTHORIZATION_GATE`). A failure of this gate from this point
  on is a real regression, not a known/expected condition — never silence it
  by relaxing the gate.
- `go test -race ./internal/ldap/profile` — the production LDAP implementation's
  own race gate; run it whenever touching connection-local session state or
  the critical-control guard. This package is now part of the ordinary
  `./cmd/ch-oauth-ldap` production closure, so `go test -race ./...` already
  compiles and exercises it as production code — this bullet names the
  narrower, faster command for a change confined to `internal/ldap/profile/**`.
  Its five native fuzz targets' committed seed corpora already run under
  ordinary `go test`; a short documented smoke beyond seeds, run one target
  at a time, is
  `go test ./internal/ldap/profile -run '^$' -fuzz=Fuzz<Name> -fuzztime=20s`
  for each of `FuzzLDAPFrame`, `FuzzBindRequest`, `FuzzSearchRequest`,
  `FuzzRestrictedDN`, `FuzzMemberAssertionDN` — never wait for a real
  20/30-second production deadline in an ordinary unit test.
- `./integration/clickhouse/run.sh` (or `run-all-builds.sh`) — the real-ClickHouse
  integration suite; manual and Docker-based, not run by any workflow. Its
  helper build is ordinary and untagged (issue #33 phase 4), identical to the
  published production image, so this suite exercises exactly the same
  `internal/ldap/profile` composition production runs — run it when touching
  `cmd/ch-oauth-ldap`, `internal/ldap/profile`, or ClickHouse-facing config.
  Both tracked images (`24.8.11.51285.altinitystable`,
  `25.8.28.10001.altinitystable`) were certified this way, first under Phase
  3's temporary tag and then against the untagged production composition;
  see `docs/clickhouse-ldap-wire-profile.md` §11.5/§11.6.
  `./integration/clickhouse/run-ha.sh` is the separate, also-manual Docker HA
  harness (`compose-ha.yml`/`ha/`, same shared image) — run it when touching
  `internal/ldap/profile`'s connection-local-state invariants or
  `cmd/ch-oauth-ldap`'s HA-relevant wiring; see
  `docs/ch-oauth-ldap-operator-guide.md` §8 for exactly what it does and does
  not prove versus the Kubernetes runbook. `capture-ldap-wire.sh` is frozen
  at `--mode verify`, and stays frozen after cutover — do not regenerate or
  promote any committed `internal/ldap/testdata/clickhouse-wire/**` fixture;
  a verify pass is production-backed verification of the historical Phase 1
  corpus, not new fixture provenance, and a new request shape from a tracked
  client stops the unit rather than broadening the parser (see
  `integration/clickhouse/README.md`'s phase-4 note).
- `helm/ch-oauth-ldap/test.sh` — the `ch-oauth-ldap` chart's committed local
  gate (render matrix, negative-render matrix, embedded-YAML/XML structural
  checks, kubeconform, packaging hygiene, and a pinned-actionlint validity
  check on `.github/workflows/build-ch-oauth-ldap.yml`, informational-only
  against `build-ch-jwt-verify.yml`). Unlike the Go gate, it is not run by any
  workflow — run it yourself when touching `helm/ch-oauth-ldap/**`.
- No Makefile and no linter configuration is committed. If `golangci-lint`
  or similar is added later, commit the agreed configuration and wire it into
  `.github/workflows/pr-gate.yml` in the same change — or document in that
  change why a deliberately separate CI gate is required instead. Do not add
  a local-only linter gate.

## Issue #33 status: production cutover complete

Issue #33 phased in `internal/ldap/profile` as `cmd/ch-oauth-ldap`'s LDAP
implementation and then made it the only one:

- **Phase 2** wrote the package inert (implemented and tested, but not
  linked into the command).
- **Phase 3** certified it end to end — real command composition, both
  tracked ClickHouse images, HA, wire-fixture verify, all five fuzz targets
  — behind a temporary, compile-time-only `phase3profile` Go build tag
  applied solely to `integration/clickhouse/Dockerfile`'s helper build.
  Ordinary production stayed on the legacy `internal/ldap`/vendored-fork
  stack throughout. See `docs/clickhouse-ldap-wire-profile.md` §11.5 for
  that certification's full, now-frozen evidence record.
- **Phase 4** performed the atomic cutover this file now describes
  throughout as current state: deleted the `phase3profile` selector and the
  legacy adapter it stood in for, promoted the profile composition to
  `cmd/ch-oauth-ldap`'s sole, ordinary backend (`ldap_backend.go`), deleted
  the direct legacy `internal/ldap` implementation and the vendored
  `third_party/goldap`/`third_party/ldapserver` forks plus their `replace`
  directives, inverted the profile/cryptobyte dependency contracts from
  negative to positive, made the general-LDAP-stack denylist unconditional,
  replaced the two vendored-goldap-backed independent decoder oracles with
  from-scratch bounded BER cursors (Oracle A under `internal/ldap/profile`,
  Oracle B under `internal/securitytest`), and froze §11.5 as immutable
  history rather than rewriting it to match the new topology.

There is no dual-parser mode, no runtime or build-time backend selector, and
no dormant legacy adapter kept for rollback — rollback is source/release
revert, not a retained second implementation. Full rationale, the invariant
map, and every sabotage case live in the Phase 3/4 plans and
`docs/clickhouse-ldap-wire-profile.md` §11.

## Conventions

- **Commit messages**: Conventional-Commits style, `type(scope): summary`
  (e.g. `fix(ch-jwt-verify): bind verification cache key to username`,
  `feat(helm): standalone Deployment+Service mode for ch-jwt-verify`,
  `test(ch-jwt-verify): cover symmetric direction of cache-key isolation`).
  Scope is usually the binary/chart/dir touched (`ch-jwt-verify`, `helm`,
  `examples`, etc.).
- **No secrets in git.** `examples/*/superset-secrets.yaml` is gitignored
  (see `.gitignore`); the platform's Dex/ClickHouse configs checked in under
  `examples/_platform/` and `examples/curl/config.yaml` are demo
  configuration for the synthetic IdP, not real credentials — don't treat
  that as precedent for committing anything issued by a real IdP.
- **Sidecar trust model is load-bearing.** `ch-jwt-verify` is the *only*
  cryptographic gate on the auth path; the Helm chart's default mode
  deliberately renders no Deployment/StatefulSet because the sidecar must
  share a pod with ClickHouse (loopback-only exposure). Don't add a
  network-exposed deployment mode without preserving that trust boundary —
  the standalone Deployment+Service mode added in `feat(helm)` is for
  scenarios where the caller explicitly accepts a different trust model
  (document why, in the chart README, when you touch it).
- **`ch-oauth-ldap`'s environment-level trust model is a distinct, separately
  accepted exception — it does not weaken the sidecar guidance above.**
  Unlike `ch-jwt-verify`'s loopback-only sidecar, `ch-oauth-ldap` runs as its
  own environment-level Deployment behind a `ClusterIP` Service, so the OAuth
  bearer necessarily crosses a real network hop (ClickHouse → helper) as the
  LDAP simple-bind password, in clear text (`ADR #16` deviation; named risk
  owner Boris Tyshkevich / `@BorisTyshkevich`; see `README.md`). The
  compensating controls are: the Service stays `ClusterIP`-only with no
  public-exposure knobs, and the chart renders a default-on
  source-restricting NetworkPolicy that fails closed on every allow-all
  ClickHouse selector shape (empty, nested-empty, and `DoesNotExist`/`NotIn`-
  only expressions, which match everything lacking the key) — but a
  NetworkPolicy is reachability control, not
  transport confidentiality, so don't describe it as one in docs or review.
  Removing the exception means TLS on the LDAP listener or moving to a
  loopback sidecar, not relaxing the NetworkPolicy default.
- **Cache-key correctness is a security property, not a perf detail.** The
  `/verify` response cache key must stay bound to the identity the JWT
  authenticates as (see `e2be32a fix(ch-jwt-verify): bind verification cache
  key to username` and its test in `a43aa3b`) — a change to caching here
  needs a test proving isolation in both directions, not just a happy path.

## Working discipline

- Keep `README.md`, `examples/README.md`'s capability matrix,
  `docs/ch-oauth-ldap-operator-guide.md`, and both Helm charts' own READMEs
  in sync with behavior changes in the same commit — this is the complete
  set of docs in this repo, and `internal/securitytest/docs_contract_test.go`
  only enforces that marked config fences don't drift from their source, not
  that prose elsewhere stays current — a stale unmarked paragraph is still a
  docs bug a test won't catch.
- `.github/workflows/pr-gate.yml` runs the five commands above on every pull
  request, and once branch protection on `main` requires `Required PR gate`
  (enabled as part of #23's rollout, immediately after this lands) that is what
  enforces them at merge time. Hosted CI is merge *enforcement* either way, not
  permission to skip local verification. Before calling a change done, actually
  run `go build ./...`, `go vet ./...`, `go test ./...` (and the
  `-race`/`phase5release`/shell-library
  gate commands the change touches) yourself, plus the manual gates hosted CI
  deliberately does not run — `helm/ch-oauth-ldap/test.sh` and the Docker
  ClickHouse suite. Discovering a break in `Required PR gate` instead of
  locally is a process failure, not a workflow success.
