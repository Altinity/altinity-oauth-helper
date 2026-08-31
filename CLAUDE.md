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
| `cmd/ch-oauth-ldap/` | the standalone LDAPv3 server binary — `main.go` (CLI/signal-context/lifecycle wiring: verifier + role pipeline + a build-selected LDAP backend behind the package-local `ldapServer` interface — `Serve(net.Listener) error`, `Stop()` — constructed via build-selected `newLDAPServer(...)`; no direct `internal/ldap` or `internal/ldap/profile` import here), `config.go` (backend-neutral YAML config, defaults, fail-startup validation, conversion into `verification.Config`/`identity.Config`/`roles.Config`; DN/backend validation delegates to a build-selected `validateLDAPBackendConfig(cfg)`; imports neither LDAP backend), `ldap_backend_legacy.go` (`//go:build !phase3profile` — the sole default-build importer of `internal/ldap`; owns exact legacy `validateLDAPBackendConfig`, `toLDAPConfig`, `newLDAPServer` calling `ldap.New`), `ldap_backend_phase3profile.go` (`//go:build phase3profile` — issue #33 phase 3's temporary adapter; imports only `internal/ldap/profile`; owns `toProfileConfig` — no `Listen` field, the command keeps owning the listener — `validateLDAPBackendConfig` wrapping `profile.ValidateConfig`, and `newLDAPServer` calling `profile.New`; no fallback to legacy), `config_test.go` (incl. `testdata/operator-guide.yaml` loaded through production `LoadConfig` and strict-decoded with `KnownFields(true)` — the proof backing `docs/ch-oauth-ldap-operator-guide.md`'s YAML fences), `config_legacy_test.go` (`!phase3profile` — legacy-type/permissive-validation assertions moved out of `config_test.go`), `config_phase3profile_test.go` (`phase3profile` — exact profile config mapping, restricted user/group-base DN narrowing, `UserRDNAttribute` descriptor-grammar narrowing), `main_test.go`, `main_phase3profile_test.go` (`phase3profile` — type-asserts `newLDAPServer` returns `*profile.Server`, proves the command still owns the listener, and a real `run()` composition test against the profile backend with the real verifier+role pipeline). The `phase3profile` tag is temporary Phase 3 certification scaffolding (see the `internal/ldap/profile/` row and Phase 4 handoff below); ordinary untagged builds — including the published production image — always select the legacy adapter |
| `internal/ldap/` | LDAP protocol package consumed by `cmd/ch-oauth-ldap` — `server.go` (lifecycle/handler-source wiring, dependency-logger suppression, connection cap, timeouts), `controls.go` (unsupported-critical-control guard), `session.go` (per-connection authenticated state), `dn.go` (RFC 4514 Bind-DN parsing/validation), `filter.go` (structural Search-filter authorization), `bind.go`/`search.go`/`unsupported.go` (the LDAP operation handlers, incl. Search sizeLimit/timeLimit/typesOnly enforcement and safe numeric-only Search telemetry), `entry.go` (synthetic `groupOfNames` rendering), plus `*_test.go` including a real-TCP `protocol_test.go` and `adversarial_test.go`; also `profile_compat_test.go` (`package ldap_test`, issue #33 phase 2 — shared old/new compatibility tests driving both `internal/ldap` and `internal/ldap/profile` over real TCP, asserting exact parity, incl. the `correlation_id` value itself, only where the plan actually claims parity) |
| `internal/ldap/profile/` | issue #33 phase 2 — a first-party, bounded ClickHouse LDAP compatibility profile (package `profile`) meant to eventually replace `internal/ldap` above; its ASN.1/protocol implementation (`frame.go`/`protocol.go`) is stdlib plus `golang.org/x/crypto/cryptobyte` only — the package's own dependency closure is wider by design, since `config.go` directly depends on `internal/verification` and the upstream OAuth SDK's types for `Verifier`/`RoleResolver` (a deliberate, legitimate transitive dependency `internal/securitytest/profile_dependency_contract_test.go` documents rather than pins away); no `go-ldap`/vendored-goldap/vendored-ldapserver import either way (enforced below). **Phase 3 status: certified via a temporary `phase3profile` Go build tag; `cmd/ch-oauth-ldap` still runs the legacy `internal/ldap` path in ordinary (untagged) builds and in the published production image — nothing production-reachable imports this package.** `cmd/ch-oauth-ldap/ldap_backend_phase3profile.go` (`//go:build phase3profile`) is the one command file that imports this package, and only `integration/clickhouse/Dockerfile`'s `ch-oauth-ldap` helper build passes that tag — `Dockerfile.ch-oauth-ldap`, `scripts/build-ch-oauth-ldap-image.sh`, and `.github/workflows/build-ch-oauth-ldap.yml` never do (enforced by `internal/securitytest/phase3_selector_contract_test.go`). Under that tagged composition, Phase 3 certified the real ClickHouse matrix (both tracked images), HA, wire-fixture verify, and all five fuzz targets — see `docs/clickhouse-ldap-wire-profile.md` §11.5. Phase 4 deletes the tag and the legacy adapter and makes this package's composition the only one (see "Phase 4 mandatory handoff" below). Production files: `config.go` (`Config`/`Verifier`/`RoleResolver`/`ValidateConfig`; deliberately no `Listen` — the command keeps owning the listener), `dn.go` (restricted RFC-4514-subset DN grammar, structural equality, synthetic-DN rendering), `frame.go` (bounded-before-allocation BER framing, `cryptobyte` LDAPMessage envelope, minimal Controls-criticality scanner), `protocol.go` (application tags, result-code constants, the shared minimal-positive-INTEGER validator Abandon's implicit target integer reuses), `encode.go` (`cryptobyte.Builder` response encoders, the closed `diagnostic` enum + `addLDAPResultFields`, 64 KiB response-PDU preflight), `logging.go` (byte-identical `correlationID` re-derivation, the closed `reason` enum, log helpers), `session.go` (connection-owned `authState`/`connection`, no password/frame field retained), `bind.go` (LDAPv3-only simple-Bind decoder, clear-before-validate state policy, the sole `Verify`/`Roles` call sites), `search.go` (fixed ClickHouse Search shape, nonrecursive two-child membership-filter decode, sizeLimit/timeLimit, `cn`-only entries), `server.go` (lifecycle, 256-connection admission, the package's one production `go` statement, dispatch), `doc.go` (package-status doc comment). Test files: a `*_test.go` beside each production file, plus `protocol_test.go` (real-TCP black-box suite ported from legacy `internal/ldap/protocol_test.go`), `adversarial_test.go`/`midsearch_test.go` (framing-cap/deadline-stall/malformed-BER/partial-write adversarial suite), `conncap_test.go` (256/257-connection admission), `search_limits_test.go`/`hostile_dn_test.go`/`redaction_boundary_test.go` (Search-limit telemetry, hostile-Bind-DN, and marker-redaction proofs), `replay_test.go` (`TestProfileReplay` — real-TCP replay of every committed `internal/ldap/testdata/clickhouse-wire/**` session through this server), `differential_test.go` (`TestProfile_DifferentialDecoder`, `package profile`, differential oracle against vendored goldap imported only from `_test.go` — Phase 4 **must delete this file**, see `docs/clickhouse-ldap-wire-profile.md` §11.4), `fakes_test.go` (the canonical in-package `fakeVerifier`/`fakeResolver`/`fakeClock`, per Amendment 7 duplicated — not shared via a non-test helper package — in `internal/ldap/profile_compat_test.go`), and five native fuzz targets: `frame_fuzz_test.go` (`FuzzLDAPFrame`), `bind_fuzz_test.go` (`FuzzBindRequest`), `search_fuzz_test.go` (`FuzzSearchRequest`), `dn_fuzz_test.go` (`FuzzRestrictedDN`, `FuzzMemberAssertionDN`) — every committed seed runs under ordinary `go test`; a short fuzz smoke beyond seeds is `go test ./internal/ldap/profile -run '^$' -fuzz=Fuzz<Name> -fuzztime=20s`, one target at a time (never wait for a real 20/30s production deadline in an ordinary unit test). Registered in `internal/securitytest`'s redaction scope (`scopeDirs`, plus sink kind `ldap-profile-diagnostic` for direct `addLDAPResultFields(..., diagConstant)` calls) and covered by the general `internal/ldap/**` nested-package guard (`TestRedactionInventory_NestedLDAPPackagesAreRegistered`, registered outright rather than exempted). `internal/securitytest/profile_architecture_contract_test.go` mechanically enforces the syntactic invariants: exactly one production `go` statement (the admission spawn); no `sync.Map`; no old-LDAP/BER/`unsafe` import; `decodeMembershipFilter` nonrecursive with exactly two `decodeEquality` calls; `diagnostic`/`reason` bytes reachable only through their closed enums (no dynamic conversion). Its companion `internal/securitytest/profile_types_contract_test.go` enforces the four type-semantic invariants over the fully type-checked package (go/types on gc export data from a deterministic `go list -deps -export`, via stdlib `importer.ForCompiler` — not AST shape enumeration, which three review passes plus an architecture consultation showed is bypassable by ordinary Go): no map- or channel-typed declaration, signature, or value expression beyond `Server.active` (`map[net.Conn]struct{}`) and `serveDone`/`stopDone` (`chan struct{}`), and `Verifier.Verify`/`RoleResolver.Roles` each referenced — call, method value, or method expression — exactly once, both in `bind.go` (struct fields named `Roles` are excluded by selection kind, not naming convention); reflection/`unsafe` laundering is outside what the type checks see and is covered by the import bans. `internal/securitytest/profile_dependency_contract_test.go` mechanically enforces this package's absence from `./cmd/ch-oauth-ldap`'s live dependency closure during Phase 2, and that this package's own closure requires `golang.org/x/crypto/cryptobyte` while excluding the vendored/general LDAP stack (`vjeantet/ldapserver`, `vjeantet/goldap`, `go-ldap/ldap/v3`, `go-asn1-ber/asn1-ber`, `Azure/go-ntlmssp`, `internal/wirefixture`) |
| `internal/securitytest/` | phase-5 automated security verification, not itself security-relevant production code (see its `doc.go`) — `redaction_inventory_test.go` (AST-enumerates every log/error/response-construction sink across the explicit audited scope list named by `doc.go`'s `scopeDirs` — `cmd/ch-oauth-ldap`, `cmd/ch-jwt-verify`, `internal/ldap`, `internal/verification`, `internal/identity`, `internal/roles`, `internal/wirefixture`, `integration/clickhouse/wirecapture` — plus the vendored `third_party/ldapserver` fork, and cross-checks `testdata/redaction-sites.tsv`; `TestRedactionInventory_Phase1AuditedScopesRemainFlat` mechanically guards the two issue-#33 scopes staying flat, since `discoverSites` only reads each scope directory's direct, non-test `.go` files and never recurses; `redaction-sites.tsv` was reconciled for issue #33 phase 3's `cmd/ch-oauth-ldap` backend seam — the two `config.go` sinks that moved to `ldap_backend_legacy.go` plus the one new sink in `ldap_backend_phase3profile.go`), `sdk_contract_test.go` (pinned `go-mcp-oauth-sdk` version + no-replace + strict-entrypoint AST checks), `release_gate_test.go` (`-tags phase5release` only: fails while any manifest row is `blocked_external`, per amendment A1 — see "Build & test" below), `pr_gate_contract_test.go` (untagged, so it runs in both `go test ./...` and the gate's own `go test -race ./...` step: parses `.github/workflows/pr-gate.yml` and asserts the required PR gate's structure against literal expectations — unfiltered triggers, no path filters, `contents: read` only, exactly one unconditional job named `Required PR gate`, the five commands exactly once in order, SHA-pinned actions; an accidental-drift detector, not tamper resistance, since it lives in the same PR-controlled tree as the workflow), `docs_contract_test.go` (every `config-source`-marked YAML/XML fence in `README.md`/`docs/ch-oauth-ldap-operator-guide.md` — this repo's only two operator-facing narrative documents — is an exact contiguous excerpt of its real source file, with both files' `<clickhouse>` fence additionally required to equal the ClickHouse fixture's `<clickhouse>` element exactly, not just be a substring of the whole fixture file; required/forbidden HA-and-trust-boundary wording; the stale-1-MiB-comment guard; `docs/clickhouse-ldap-wire-profile.md` is deliberately NOT in its scope — see `wire_profile_contract_test.go` below), `dependency_contract_test.go` (issue #33 phase 1, plan §5/§6/§31: deterministically invokes `go list -deps` against `./cmd/ch-oauth-ldap` and asserts the live non-standard closure exactly matches `testdata/production-nonstdlib-deps.txt`, that non-standard `golang.org/x/crypto/cryptobyte` is absent, and that `internal/wirefixture` is absent — the mutable *live* expectation, distinct from the immutable historical snapshot at `internal/ldap/testdata/phase1-baseline/production-nonstdlib-deps.txt`; issue #33 phase 3 extends this same file — the shared `generalLDAPDenylistPrefixes`/`matchesGeneralLDAPPrefix`/`isGeneralLDAPDependency` five-prefix policy also consumed by `profile_dependency_contract_test.go`; `TestDependencyContract_ProductionClosureHasNoGeneralLDAP` over the test-only `ldapClosureStage` enum, `productionLDAPClosureStage = legacyUntilPhase4` today — at `legacyUntilPhase4` it requires all five prefixes to currently match the ordinary closure, non-vacuously, honestly recording today's still-legacy dependency stack, and only at `replacement` (Phase 4 flips this one constant) does it require zero matches plus `internal/ldap/profile`/`cryptobyte`; `TestDependencyContract_Phase3ReplacementClosureHasNoGeneralLDAP` over `go list -tags=phase3profile -deps ./cmd/ch-oauth-ldap`, requiring profile+cryptobyte present and legacy `internal/ldap`/all five prefixes/`internal/wirefixture` absent; `TestDependencyContract_Phase3ReplacementCommandBuilds`, the untagged security contract that actually runs `go build -mod=readonly -tags=phase3profile -o <tempdir> ./cmd/ch-oauth-ldap` via `resolveGoBin`/`deterministicGoListEnv` — this is what makes `go test -race ./...`'s Required-PR-gate step a real compile-time backstop for the tagged composition, since closure checks alone can't catch a broken tagged function body), `phase3_selector_contract_test.go` (issue #33 phase 3, Docker-free: the integration Dockerfile's `ch-oauth-ldap` build line is the *only* `go build` line carrying `-tags=phase3profile`; `Dockerfile.ch-oauth-ldap`, `scripts/build-ch-oauth-ldap-image.sh`, and `.github/workflows/build-ch-oauth-ldap.yml` never mention the tag — prevents both accidental Docker-gate fallback to legacy and accidental production cutover), `wire_profile_contract_test.go` (issue #33 phase 1, plan §30: Docker-free anti-drift contract over the wire evidence — static ClickHouse/OpenLDAP source-provenance matrix cross-checked against `run-all-builds.sh`/the wire-profile doc/every `profile.json`, four-way tracked-line equality, the `<clickhouse>` config-hash + semantic contract, fixture inventory (orphan/sequence/SHA/`connection_count`/operation-coverage checks), the `*.ber binary` `.gitattributes` rule, an all-file JWT-shape scanner plus its own AST-derived positive control, the wire doc's exactly-one-decision-marker/no-XML-YAML-fence boundary, the constructed-MessageID-127/128 regenerate-and-compare proof, and the AST/`go list -deps` check that `integration/clickhouse/wirecapture` writes metadata only through `internal/wirefixture`; issue #33 phase 3 added the `TestWireProfileContract_Phase3Evidence*`/`TestWireProfileContract_Section113NarrowingDispositions` family — exactly one `<!-- phase3-release-gate-evidence -->` marker pair, no `PENDING`/`TBD` placeholders, selector/Dockerfile/image-set/fuzz-target-name/duration ground truth, the eleven narrowing IDs (`1`, `1a`, `2`–`10`) and their exact `ACCEPT`/`REJECT` tokens cross-checked between §11.3 and §11.5, the TLS/#31 row, final LOC recomputed fresh from the source tree (never compared against the pinned historical baseline), and the certified-surface SHA-256 digest independently recomputed in Go and required to equal the recorded value) |
| `internal/wirefixture/` | issue #33 phase 1 (plan §9, §25–§29) — the sole owner of the committed ClickHouse-LDAP-wire fixture schema: `schema.go` (`Profile`/`Session`/`PDU`, strict JSON decode, deterministic encode, `StableProfile`/`StableSession`/`StablePDU` verify-mode comparison projections), `root.go` (`ModuleRoot`, fixture-path helpers, `ValidateFixtureRoot`), `constructed.go` (`BuildConstructedSimpleBind`/`BuildConstructedMessageIDBoundarySession`, the deterministic MessageID-127/128 boundary generator), `confighash.go` (`ClickHouseConfigElementSHA256`, hashing only the trimmed `<clickhouse>...</clickhouse>` element). Test/tooling support only: `internal/securitytest/dependency_contract_test.go` asserts it is mechanically absent from `./cmd/ch-oauth-ldap`'s production closure. `integration/clickhouse/wirecapture` writes `profile.json`/`session.json` only through this package's `WriteProfile`/`WriteSession`; `internal/ldap/clickhouse_wire_cryptobyte_test.go` and `internal/securitytest/wire_profile_contract_test.go` read through it too — see plan §9's "writer/reader ownership" |
| `docs/` | `ch-oauth-ldap-operator-guide.md` — consolidates (does not restate) the working ClickHouse config, OIDC/Auth0/JWKS field reference, identity/role-pipeline behavior, the cache invariant, measured ClickHouse Search-limit behavior (scenario G'), the plaintext-bearer trust boundary, and HA/capacity incl. the Kubernetes runbook; §8.1 and §10 additionally record that the temporary `phase3profile`-selected replacement passed the Docker HA harness for both tracked images with the pre-existing claim boundary preserved verbatim. Every fence in it is enforced against its real source by `internal/securitytest/docs_contract_test.go`. `clickhouse-ldap-wire-profile.md` — issue #33 phase-1 engineering evidence (source-cited ClickHouse/OpenLDAP behavior, the wire corpus, the `cryptobyte` primitive decision), extended through Phase 3 with §11.1's corrected 2,682-LOC merged Phase 2 baseline, §11.3's eleven narrowing dispositions, §11.4a's frozen wire-capture policy, and §11.5's fully populated Phase 3 release-gate evidence record (tested commit, certified-surface digest, matrix/HA/wire/fuzz/LOC results) — for Phase 3/4's implementer, not a second operator-facing guide; owned by `internal/securitytest/wire_profile_contract_test.go`, not `docs_contract_test.go` |
| `third_party/goldap/`, `third_party/ldapserver/` | vendored, patched forks of `github.com/vjeantet/goldap`'s `message` package and `github.com/vjeantet/ldapserver`, pinned via `replace` directives in the root `go.mod` and consumed by `internal/ldap`; each fork's own `PATCHES.md` documents exactly what was changed from upstream and why |
| `integration/clickhouse/` | real-ClickHouse acceptance suite for `ch-oauth-ldap` — `run.sh` (4-service Docker fixture: synthetic IdP + helper + two ClickHouse nodes, preflight, sources `scenarios/*.sh` A–I plus phase-5 scenario G' Search-limit compatibility), `run-all-builds.sh` (every build in `lib/expectations.sh`), `lib/expectations.sh` (per-ClickHouse-version expected outcomes for the two tracked upstream bugs, #78791/#79099 and #116840, plus scenario G's per-build Search-limit-overflow outcome), `scenarios/65-ldap-search-limits.sh` (scenario G'), `tests/lib-tests.sh` (daemon-free bash unit tests for the harness's own shell libraries in `lib/`), `clickhouse/common/config.d/ldap.xml` (the working LDAP config `README.md` copies, incl. `<search_limit>256</search_limit>`), `compose-ha.yml`/`run-ha.sh`/`ha/` (phase-5 Docker HA harness: HAProxy frontend + two independent replicas + a persistent same-socket session probe — see `docs/ch-oauth-ldap-operator-guide.md` §8 for its exact claim boundary versus the Kubernetes runbook; `ha/session-probe` is credential-bearing integration tooling that stays outside `internal/securitytest`'s `scopeDirs` — a pre-existing, honestly-recorded gap, not a retroactive inventory expansion). The Docker suite is a manual/local gate, not CI, **but** `tests/lib-tests.sh` runs in `.github/workflows/pr-gate.yml` as the fifth command of the required PR gate — breaking anything under `lib/` turns `Required PR gate` red; see `integration/clickhouse/README.md`. `Dockerfile` builds all four test binaries into the suite's shared image; issue #33 phase 3 added `-tags=phase3profile` to only its `ch-oauth-ldap` build line (`synthetic-idp`, `ldap-session-probe`, and `ldap-wire-recorder` remain untagged) — so `run.sh`, `run-all-builds.sh`, `run-ha.sh`, and `compose-wirecapture.yml`'s `ldap-helper-upstream` service (same shared image) all now exercise `internal/ldap/profile` instead of legacy `internal/ldap`, while ordinary `go build` and the published `Dockerfile.ch-oauth-ldap` production image remain untagged/legacy until Phase 4; see `integration/clickhouse/README.md`'s phase-3 note. Issue #33 phase 1 added a second, also-manual wire-capture fixture: `wirecapture/` (the `ldap-wire-recorder` capture/sanitize/construct/compare tool, built into this suite's shared image), `compose-wirecapture.yml` (standalone 5-service `ch-wirecap` Compose topology interposing the recorder between ClickHouse and the real helper), `capture-ldap-wire.sh` (`--mode generate\|verify` driver — issue #33 phase 3 froze `--mode generate`: no committed `internal/ldap/testdata/clickhouse-wire/**` file may be regenerated/promoted; only `--mode verify` runs, as replacement-backed verification of the historical Phase 1 corpus, not new fixture provenance — a new request shape from a tracked client stops the unit rather than broadening the parser), `tests/cases/wirecapture-*.sh` (daemon-free compose/fallback/collision-preflight parity) — see `integration/clickhouse/README.md`'s "Wire capture" section for the generate/verify commands, the fixed query/token-claim recipe, and the three-fixture (`ch-phase3`/`ch-phase5-ha`/`ch-wirecap`) mutual-exclusion rule |
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

  Two limits on that gate's real reach are worth knowing before you rely on it.
  First, `integration/clickhouse/tests/lib-tests.sh` is Docker-*daemon*-free but
  still needs the `docker` CLI on `PATH`: `integration/clickhouse/lib/common.sh`
  calls `detect_compose_cmd` at source time and `die`s otherwise, so
  `env PATH=/usr/bin:/bin:/usr/sbin:/sbin bash
  integration/clickhouse/tests/lib-tests.sh` aborts with `neither 'docker
  compose' nor 'docker-compose' is available on PATH`. `ubuntu-latest` ships
  that CLI, so the hosted run is fine — but "needs only bash/coreutils" is
  imprecise, and this is exactly the kind of dependency that turns a
  runner-image change into a mystery red. Second, the gate does **not** reach
  `third_party/goldap` or `third_party/ldapserver`: they are separate modules
  the root `go.mod` only `replace`s in, so `go test -race ./...` never compiles
  them (that is where the LDAP parser lives). A "mandatory PR-time verification
  gate" does not mean everything in the tree is verified — run those forks' own
  suites explicitly, per the `third_party/goldap` bullet below.
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
- `go test -race ./internal/ldap` — the LDAP package's race gate; run it
  whenever touching connection-local session state or the critical-control
  guard.
- `go test -race ./internal/ldap/profile` — the issue #33 phase 2/3 compatibility
  profile's own race gate (this package is still absent from the ordinary
  production closure, so it is not covered by `go test -race ./...`'s pass
  over `internal/ldap` in spirit — it's a separate package, run separately).
  Its five native fuzz targets' committed seed corpora already run under
  ordinary `go test`; a short documented smoke beyond seeds, run one target
  at a time, is
  `go test ./internal/ldap/profile -run '^$' -fuzz=Fuzz<Name> -fuzztime=20s`
  for each of `FuzzLDAPFrame`, `FuzzBindRequest`, `FuzzSearchRequest`,
  `FuzzRestrictedDN`, `FuzzMemberAssertionDN` — never wait for a real
  20/30-second production deadline in an ordinary unit test.
- **Issue #33 phase 3's tagged replacement-composition gate.** `cmd/ch-oauth-ldap`
  carries a temporary `phase3profile` Go build tag (see its repo-map row
  above); run the normal Go gates with it selected across the module whenever
  touching that command, `internal/ldap/profile`, or the tagged adapter files:

  ```
  go build -tags=phase3profile ./...
  go vet -tags=phase3profile ./...
  go test -race -tags=phase3profile ./...
  ```

  `go test -race ./...` (untagged, part of `Required PR gate`) additionally
  runs `internal/securitytest`'s `TestDependencyContract_Phase3ReplacementCommandBuilds`,
  which itself performs a real, deterministic
  `go build -mod=readonly -tags=phase3profile -o <tempdir> ./cmd/ch-oauth-ldap`
  — so CI compiles the tagged composition even though the five required
  workflow commands themselves stay untagged and unchanged. Ordinary
  untagged builds, and the published `Dockerfile.ch-oauth-ldap` production
  image, always select the legacy `internal/ldap` adapter regardless of any
  of the above.
- `(cd third_party/goldap && go test ./...)` — the vendored, patched
  `github.com/vjeantet/goldap` fork's own test suite (BER integer
  sign-disambiguation, `ModifyDNResponse.SetResultCode`, and the Filter
  AND/OR/NOT nesting-depth guard — see `third_party/goldap/PATCHES.md`).
  `go test ./...` at the repo root does NOT reach it (it's a separate
  module the root `go.mod` only `replace`s in, not a subdirectory of the
  main module's own package tree) — run it explicitly whenever touching
  `third_party/goldap/**`.
- `./integration/clickhouse/run.sh` (or `run-all-builds.sh`) — the real-ClickHouse
  integration suite; manual and Docker-based, not run by any workflow. Since
  issue #33 phase 3 tagged `integration/clickhouse/Dockerfile`'s `ch-oauth-ldap`
  build line with `-tags=phase3profile`, this suite now exercises
  `internal/ldap/profile`, not legacy `internal/ldap` — run it when touching
  `cmd/ch-oauth-ldap`, `internal/ldap/profile`, or ClickHouse-facing config.
  Both tracked images (`24.8.11.51285.altinitystable`,
  `25.8.28.10001.altinitystable`) were certified this way for Phase 3; see
  `docs/clickhouse-ldap-wire-profile.md` §11.5. `./integration/clickhouse/run-ha.sh`
  is the separate, also-manual Docker HA harness (`compose-ha.yml`/`ha/`,
  same tagged image) — run it when touching `internal/ldap/profile`'s
  connection-local-state invariants or `cmd/ch-oauth-ldap`'s HA-relevant
  wiring; see `docs/ch-oauth-ldap-operator-guide.md` §8 for exactly what it
  does and does not prove versus the Kubernetes runbook. `capture-ldap-wire.sh`
  is frozen at `--mode verify` for Phase 3 — do not regenerate or promote any
  committed `internal/ldap/testdata/clickhouse-wire/**` fixture; a verify pass
  is replacement-backed verification of the historical Phase 1 corpus, not
  new fixture provenance, and a new request shape from a tracked client stops
  the unit rather than broadening the parser (see
  `integration/clickhouse/README.md`'s phase-3 note).
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

## Phase 4 handoff (issue #33)

Issue #33 Phase 3 certified `internal/ldap/profile` as a drop-in replacement
for the legacy `internal/ldap`/`third_party/goldap`/`third_party/ldapserver`
LDAP stack, gated entirely behind the temporary `phase3profile` Go build tag
described throughout this file — see `docs/clickhouse-ldap-wire-profile.md`
§11.5 for the full evidence record. Phase 3 leaves ordinary production on
legacy; nothing above changes until Phase 4 performs the cutover. Phase 4
must, in one coordinated change:

1. delete the `phase3profile` selector everywhere it appears —
   `cmd/ch-oauth-ldap/ldap_backend_phase3profile.go`'s build tag,
   `cmd/ch-oauth-ldap/ldap_backend_legacy.go` (deleted outright, its logic
   promoted to the profile adapter's file, minus the build constraint),
   `integration/clickhouse/Dockerfile`'s `ch-oauth-ldap` build line, and
   `internal/securitytest/phase3_selector_contract_test.go`'s selector-specific
   assertions;
2. flip `productionLDAPClosureStage` (in `internal/securitytest/dependency_contract_test.go`)
   from `legacyUntilPhase4` to `replacement`;
3. invert `TestDependencyContract_ProfileImplementationIsNotProduction`'s
   polarity (see that test's own Amendment 5 doc comment) now that the
   profile package is production-reachable;
4. flip the ordinary-closure `cryptobyte` contract from required-absent to
   required-present;
5. regenerate the live production dependency snapshot,
   `internal/securitytest/testdata/production-nonstdlib-deps.txt` (the
   *historical* snapshot at `internal/ldap/testdata/phase1-baseline/` stays
   untouched);
6. delete `TestDependencyContract_Phase3ReplacementCommandBuilds` once
   ordinary `go build ./...` itself compiles the replacement, and delete
   `TestDependencyContract_Phase3ReplacementCommandTests` once ordinary
   `go test ./...` itself runs the replacement's tests (both backstops exist
   only because the Required PR gate's untagged `go build ./...`/`go test
   -race ./...` steps don't add `-tags=phase3profile` on their own);
7. make the `phase3profile`-tagged command tests
   (`config_phase3profile_test.go`, `main_phase3profile_test.go`) ordinary,
   untagged test files;
8. delete legacy non-test `internal/ldap`, the vendored `third_party/goldap`
   and `third_party/ldapserver` forks, and their `replace` directives and
   now-unused dependencies from `go.mod`/`go.sum`;
9. delete the differential oracle
   (`internal/ldap/profile/differential_test.go`, `TestProfile_DifferentialDecoder`)
   and replace remaining independent goldap fixture decoding with the
   bounded test-only cursor described in
   `docs/clickhouse-ldap-wire-profile.md` §11.4;
10. reconcile now-stale `internal/securitytest/testdata/redaction-sites.tsv`
    rows for every source file actually deleted in this phase — not before;
11. rerun the complete matrix/HA/security/release gates on the untagged
    production path and record a final post-cutover reachable-production LOC
    accounting.

The temporary selector must not survive Phase 4. Full detail (rationale,
alternatives rejected, and the invariant map's sabotage cases) lives in the
Phase 3 plan and `docs/clickhouse-ldap-wire-profile.md` §11.

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
