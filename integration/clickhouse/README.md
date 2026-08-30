# Real-ClickHouse integration suite for `ch-oauth-ldap`

The phase-3 acceptance harness for issue #19: it brings up the **production
`ch-oauth-ldap` binary built from this checkout**, a synthetic OIDC IdP, and two
real ClickHouse servers, then proves end to end that an otherwise-undefined
ClickHouse user can authenticate with a JWT through LDAP, receive token-derived
local roles, and carry those roles across a distributed query.

This is a **manual, local gate** — the Docker suite is not wired into any CI
workflow. Run it before calling any change to `cmd/ch-oauth-ldap`,
`internal/ldap`, or the ClickHouse-facing configuration done. The one exception
in this directory is `tests/lib-tests.sh`, the daemon-free unit tests for the
harness's own shell libraries under `lib/`: that script **is** run by
`.github/workflows/pr-gate.yml` as part of the required `Required PR gate`
check, so a change under `lib/` that breaks it fails CI.

## Prerequisites

- Docker with Compose v2 (`docker compose`) or the standalone `docker-compose`
  binary — `lib/common.sh` auto-detects whichever is available. The HA
  harness (`run-ha.sh`, below) additionally uses a second compose file
  (`compose-ha.yml`) — no extra tooling beyond the same Compose binary.
  `compose-ha.yml` is self-contained, not a Compose multi-file
  (`-f compose.yml -f compose-ha.yml`) override layered on top of
  `compose.yml`: `run-ha.sh` passes it as the ONLY compose file
  (`COMPOSE_FILE=compose-ha.yml`), and it redefines all six of its own
  services (mirroring `compose.yml`'s two ClickHouse nodes' definitions
  rather than referencing or extending them).
- `curl` on the host. **No host `clickhouse-client` is needed** — all
  administrative SQL runs inside the containers via `compose exec`.
- `$TMPDIR`, if set, must point at a writable directory that is **not** `/tmp`
  (see the guard at the top of `run.sh`: this sandbox blocks `/tmp` bind
  mounts for Docker). If unset, `run.sh` defaults it to `$HOME/tmp` and
  creates that directory — most Linux dev/CI hosts leave `TMPDIR` unset, so
  this is the common case, not an error. All per-run private state — the
  generated interserver secret, the run transcript, temp credential files —
  lives under `$TMPDIR/ch-phase3-run.*` with mode 0700 and is removed by
  `run.sh`'s `EXIT` trap.
- Network access to pull `altinity/clickhouse-server` images and the Go module
  proxy (the helper/IdP image is built from source on first run).

### Concurrency: one run per Docker daemon at a time

This fixture is **single-instance per Docker daemon**. `run.sh` fixes
`COMPOSE_PROJECT_NAME="ch-phase3"`, and the sandbox-fallback path (see
below) hand-creates globally named networks `ch-phase3-auth-net` /
`ch-phase3-cluster-net`. Two concurrent invocations against the same Docker
daemon would collide on those fixed project/network names and interfere
with each other's containers, even though each run's private temp
directory and host ports could otherwise differ. This is why
`run-all-builds.sh` runs its builds sequentially rather than in parallel —
it is not a performance choice, it is a correctness requirement of this
fixture. If this suite ever runs in shared/concurrent CI, the project name
and the fallback network names must become run-specific first.

## Topology

Four services, two networks:

```
            auth-net                          cluster-net
  ┌──────────────────────────────┐    ┌────────────────────────────┐
  │ synthetic-idp   ch-oauth-ldap│    │                            │
  │      ▲               ▲       │    │                            │
  │      │ JWKS          │ LDAP  │    │  secret-authenticated      │
  │      │               │ Bind+ │    │  interserver (native :9000)│
  │      └── clickhouse-origin ──┼────┼──► clickhouse-remote       │
  └──────────────────────────────┘    └────────────────────────────┘
       host 127.0.0.1:18123 ──► origin :8123 (only published CH port)
       host 127.0.0.1:18080 ──► synthetic-idp :80 (token minting for the runner)
```

`clickhouse-remote` is **deliberately not on `auth-net`**: it has no route to
`ch-oauth-ldap` or the IdP. That is what makes scenario H a real proof — the
only way the remote node can learn who Alice is and which roles she holds is
via the initiating node pushing them across the secret-authenticated
interserver connection. Scenario A asserts this network shape, and scenario H
asserts (via the helper's own Bind log delta) that the remote never performed
an independent LDAP authentication.

Both ClickHouse nodes mount the same `clickhouse/common/config.d` (LDAP
directory, cluster/secret, listeners) and `users.d` (loopback-only `default`);
`bootstrap/*.sql` pre-creates the local roles/grants and the probe tables. The
OAuth test principal `alice@example.com` is **never** created as a ClickHouse
user — the point is that she doesn't exist until LDAP materializes her.

### Sandbox network-isolator fallback

On this repository's sandboxed Docker host, only the pre-approved
`$DOCKER_NETWORK` bridge may be attached at container-create time, so
`compose.yml`'s two real networks are rejected. `run.sh` detects that specific
rejection and falls back to starting all four services on the shared network,
then reshaping membership with `docker network connect/disconnect` into the
exact `auth-net`/`cluster-net` topology above. A normal, unrestricted Docker
host never takes this path — `compose.yml`'s own networks are what ship. Both
paths read the ClickHouse image from the single `PHASE3_CH_IMAGE` variable.

## Running

```bash
# Default: the issue's pinned 24.8 baseline
./integration/clickhouse/run.sh

# Any other build — the expected outcome per build is recorded in lib/expectations.sh
PHASE3_CH_IMAGE=altinity/clickhouse-server:25.8.28.10001.altinitystable ./integration/clickhouse/run.sh

# Every build with recorded expectations, sequentially, with a summary table
./integration/clickhouse/run-all-builds.sh
```

`run.sh` exits 0 only when every scenario's outcome matches its recorded
expectation for the build under test. A scenario logging `KNOWN LIMITATION …
failing as expected` is a pass (the tracked upstream defect reproduced as
recorded); a scenario dying with `BEHAVIOR CHANGED` is a failure that means
ClickHouse's behavior moved and `lib/expectations.sh` must be updated.

Host ports default to `18123` (origin HTTP) and `18080` (IdP); override with
`PHASE3_CH_HTTP_PORT` / `PHASE3_IDP_PORT` if they collide.

## Scenarios

`run.sh` runs the scenario-A preflight itself, then sources every
`scenarios/*.sh` in lexical order — scenarios A–I plus phase-5 scenario G'
(Search-limit compatibility), filename-numbered `65-*.sh` so it sorts
between G (`60-*.sh`) and H (`70-*.sh`) without renumbering either.

| Scenario | File | Proves |
|---|---|---|
| A — preflight | `run.sh` | Pinned `version()` on both nodes, host→origin and origin→remote reachability, passwordless `default` denied, `push_external_roles_in_interserver_queries` present and `=1` with no fixture override, Alice absent, roles present, network membership exactly as designed, IdP/helper healthy, remote's `phase3` grants exclusive to `ch_distributed_reader`, Alice has no local role grants. 14 points (A.1–A.14). |
| B — ephemeral user | `10-ephemeral-user.sh` | An undefined user authenticates with username + JWT via LDAP; `currentUser()` is the visible username. |
| C — dynamic roles | `20-dynamic-roles.sh` | `currentRoles()` reflects the mapped **local** roles; a mapped-but-unprovisioned role name confers nothing (ClickHouse stays the authority). |
| D — username mismatch | `30-username-mismatch.sh` | Bob's valid token presented as Alice is rejected. |
| E — invalid/expired | `40-invalid-expired.sh` | Malformed and correctly-signed-but-expired tokens are rejected. |
| F — role refresh | `50-role-refresh.sh` | A new token with different groups, on a new authentication, yields the new role set with nothing stale. |
| G — local precedence | `60-local-precedence.sh` | A locally defined user (`admin@example.com`, not the helper-denied literal `admin`) wins over LDAP: her real password works, a valid external JWT does not. |
| G' — Search-limit compatibility (phase 5) | `65-ldap-search-limits.sh` | A token mapping 257 roles against the fixture's `<search_limit>256</search_limit>`: the helper's own telemetry confirms `size_limit=256 entries=256 result=4` (sizeLimitExceeded), and ClickHouse's measured, per-build reaction to that non-success Search is enforced via `lib/expectations.sh`'s `search_limit_overflow_expectation_for`/`search_limit_overflow_wire_tuple` — see `docs/ch-oauth-ldap-operator-guide.md` §6 for what was actually measured. **Unlike the H/H' table below, these two functions only have recorded expectations for 24.8 and 25.8** — either `die`s (fail-closed, not silently inherited) for any other build prefix, including 25.3 and 26.3, so G' does not run end-to-end against those lines; measure and add an entry before running it there. The 257 grant-less, origin-only roles this scenario creates are dropped before scenario H runs, regardless of outcome. |
| H — distributed propagation (base-table oracle) | `70-distributed-propagation.sh` | With `push_external_roles_in_interserver_queries=0` the remote read is denied; with `=1` it succeeds and remote `system.query_log` shows `user = initial_user = alice@example.com`; the helper saw exactly `2 + OAUTH_RETRY_EXTRA_ATTEMPTS` new Binds — 2 in the common case, plus one per transient-transport retry the scenario itself made (remote never independently re-authenticated). Outcome is per build — see below. |
| H' — view canary (expected fail) | `75-distributed-propagation-view.sh` | The same propagation through a **normal VIEW** on the remote side. Currently fails on every ClickHouse line tested (ClickHouse #116840); kept as an expected-fail canary so it flips loudly when upstream fixes it. |
| I — JWT leak scan | `80-leak-scan.sh` | Scanner self-test (plant a real token, require detection), then every retained token (including G''s) is asserted absent from all three services' logs, both nodes' on-disk server logs, the runner transcript, and captured HTTP error bodies. |

## Per-build expectations and the two upstream ClickHouse bugs

Scenario H exposed two independent, real ClickHouse defects, each verified live
against containers and confirmed in ClickHouse source. `lib/expectations.sh`
records them per version line so the suite stays green for the *right*
reasons and screams when reality changes.

| ClickHouse line (upstream and Altinity Stable behave identically) | H: Distributed → base table | H': Distributed → normal VIEW |
|---|---|---|
| 24.8 (`altinity/clickhouse-server:24.8.11.51285.altinitystable`) | **expected_fail** — ACCESS_DENIED | expected_fail |
| 25.3 | **expected_fail** — ACCESS_DENIED | expected_fail |
| 25.8 (`altinity/clickhouse-server:25.8.28.10001.altinitystable`) | **must_pass** | expected_fail |
| 26.3 | **must_pass** | expected_fail |

1. **Pre-#79099 builds drop the pushed role entirely** (24.8, 25.3). The push
   feature itself ([ClickHouse #70332](https://github.com/ClickHouse/ClickHouse/pull/70332))
   is present, and the remote log even prints `has external_roles applied:
   [ch_distributed_reader]`, but `Context::setExternalRolesWithLock` stores the
   role in `current_roles`, which is filtered against the ephemeral user's
   (empty) local grants — so it never authorizes anything. Reported as
   [#78791](https://github.com/ClickHouse/ClickHouse/issues/78791) /
   [#52035](https://github.com/ClickHouse/ClickHouse/issues/52035), fixed by
   [#79099](https://github.com/ClickHouse/ClickHouse/pull/79099) (2025-06-09),
   which no 24.8 or 25.3 release contains. Having the #70332 backport is not
   sufficient.
2. **Every current build loses the role across a normal VIEW.** `StorageView`
   clones the query context (`Context::createCopy`), `ContextData`'s copy
   constructor copies `current_roles` but not `external_roles`, and the
   subsequent `setSettings()` forces an access recalculation with no external
   roles left. Filed as [#116840](https://github.com/ClickHouse/ClickHouse/issues/116840).
   Practical consequence for deployments: point `Distributed` tables at base
   tables, not views, when relying on pushed external roles.

### Flipping an expectation when ClickHouse fixes something

When a build with a recorded `expected_fail` starts succeeding,
`assert_propagation_outcome` in `lib/expectations.sh` dies with `BEHAVIOR
CHANGED …`. That is intentional: edit `expectation_for` to `must_pass` for that
`KEY:prefix`, and — for the view canary — flip `75-*.sh`'s assertions to require
success. Never silently accept a stale expectation. A build prefix with no
recorded expectation also dies loudly; add an explicit entry before running
against a new line. `run-all-builds.sh`'s `BUILDS` list must stay in sync with
the prefixes `expectation_for` recognizes.

The same fail-closed discipline applies separately to scenario G', via two
different functions in the same file: `search_limit_overflow_expectation_for`
and `search_limit_overflow_wire_tuple`. Each `die`s outright for any build
prefix without its own recorded entry — today that means only 24.8 and 25.8
are covered, not the full 24.8/25.3/25.8/26.3 line the H/H' table above
covers, so G' does not currently run end-to-end against 25.3 or 26.3. Add a
measured entry to *both* functions (never just one) before running G' against
a new build prefix.

## HA (phase 5)

```bash
./integration/clickhouse/run-ha.sh
```

A separate, manual, local gate (own `COMPOSE_PROJECT_NAME`, a
self-contained `compose-ha.yml` — not a Compose override layered on
`compose.yml`, see the Prerequisites section above — own
`ch-phase5-ha-*-net` networks) that runs `ch-oauth-ldap` as two independent
replicas behind an HAProxy TCP frontend (`ha/haproxy.cfg`) and proves, via a
persistent same-socket session probe (`ha/session-probe/`) and mechanical
HAProxy stats-socket observation — never a fixed sleep — the Docker-level
half of issue #19's two-replica-no-shared-state Definition-of-Done clause:
both replicas authenticate independently, no shared session/verifier/role
cache is required for correctness, a killed replica's existing session
fails outright rather than migrating to the survivor, fresh authentication
keeps working through the survivor, and a recreated replica is re-admitted
once DNS resolves it again.

**What this does not prove:** real Kubernetes ClusterIP/EndpointSlice
convergence, kube-proxy/CNI behavior, or any Kubernetes failover SLA — see
`docs/ch-oauth-ldap-operator-guide.md` §8 for the exact claim boundary and
the Kubernetes runbook to execute on a real cluster instead. It refuses to
run if this suite's own `run.sh` fixture is already up on the same Docker
daemon (same "one run per Docker daemon at a time" discipline as above,
just under a distinct project/network name).

## Wire capture (issue #33 phase 1)

```bash
# Regenerate the committed ClickHouse LDAP wire corpus (promotes on success)
./integration/clickhouse/capture-ldap-wire.sh --mode generate --output internal/ldap/testdata/clickhouse-wire

# Verify a fresh capture matches the committed corpus (never writes into --fixtures)
./integration/clickhouse/capture-ldap-wire.sh --mode verify --fixtures internal/ldap/testdata/clickhouse-wire
```

This is a separate, also-manual, also-local gate from `run.sh`/`run-ha.sh`
above. It does not test `ch-oauth-ldap` behavior — it produces and checks the
non-secret, byte-level ClickHouse LDAP request evidence that backs
[`docs/clickhouse-ldap-wire-profile.md`](../../docs/clickhouse-ldap-wire-profile.md)
and the `cryptobyte`-vs-bounded-parser decision for issue #33's later phases.
Run `--mode generate` only when re-deriving that evidence deliberately (a
ClickHouse/OpenLDAP source change, a new tracked line); run `--mode verify`
to prove the committed corpus is still reproducible against the images in
`run-all-builds.sh`'s `BUILDS`.

**Fixed query and token-claim recipe.** Both tracked lines (`24.8`, `25.8`)
each get exactly two fresh captures — `success` and `timeout-abandon` — built
from one fixed HTTP principal and one fixed SQL statement, never varied
between runs or lines:

```sh
token="$(oauth_mint alice@example.com idp-readers idp-unprovisioned)"  # fixed email + role list, exp=3600
# against clickhouse-origin only, no distributed query:
SELECT currentUser()
```

Fixing both is what makes verify-mode byte comparison meaningful: a fresh
token's *length* must equal the committed `placeholder_length` (its *value*
is always sanitized away — see below), and the Bind DN / Search filter /
attribute content never vary run to run. The determinism basis (libldap's
`ld_msgid` zero-init, the fixed principal, the synthetic IdP's fixed claim
shape) is spelled out in `capture-ldap-wire.sh`'s own header comment. This
same fixed recipe is what `sanitize --token-claim-recipe` writes verbatim
into every committed `session.json`'s `token_claim_recipe` field
(`internal/wirefixture.FixedTokenClaimRecipe`); each PDU's
`expected_semantics` field is likewise populated from one fixed
per-operation table (bind/search/abandon/unbind) rather than left blank.
Both fields are part of the same stable-comparison projection as the raw
PDU bytes (plan §27/§28), so a verify run that produced a different recipe
or semantics string would be reported as drift, not silently accepted.

**Topology.** A standalone five-service Compose fixture
(`compose-wirecapture.yml`, `COMPOSE_PROJECT_NAME=ch-wirecap`) interposes a
passive recording proxy — `ldap-wire-recorder`, built into this suite's
shared image and run under the *canonical* `ch-oauth-ldap` service name so
ClickHouse's unmodified LDAP config still resolves it — between
`clickhouse-origin` and the real helper binary (renamed
`ldap-helper-upstream` in this fixture only):

```
clickhouse-origin --[LDAP simple-bind, JWT-as-password]--> ch-oauth-ldap (recorder)
                                                                  |  forwards every PDU verbatim
                                                                  v
                                                           ldap-helper-upstream (real helper)
                                                                  |
                                                                  v
                                                           synthetic-idp (JWKS)
```

`ch-wirecap-auth-net` carries synthetic-idp / recorder / upstream helper /
`clickhouse-origin`; `ch-wirecap-cluster-net` carries `clickhouse-origin` /
`clickhouse-remote` — the same auth/cluster split as the base fixture above,
under fixture-specific names. On this sandbox's network-isolator host,
`capture-ldap-wire.sh` falls back to the same hand-reshaped-network pattern
`run.sh`/`run-ha.sh` use, giving the fallback recorder the identical private
tmpfs (below) and reproducing the same alias/network graph; both paths are
mechanically checked against each other and against `compose.yml` by
`tests/cases/wirecapture-compose-parity.sh` and
`tests/cases/wirecapture-fallback-parity.sh`.

**Recorder-private raw staging, and the sanitizer/export boundary.** The
recorder never writes raw request bytes to host storage. It holds them in a
container-private tmpfs at `/run/ldap-wirecapture` (mode `0700`, `raw/`
entries mode `0600`) that is never a host bind mount. The one credential
this driver ever handles — the minted JWT — reaches the recorder only over
`compose exec -T ch-oauth-ldap ldap-wire-recorder sanitize`'s **stdin**,
never argv, an exported environment variable, or a Docker `-e` literal.
Sanitization happens entirely inside that container: it requires the
credential to occur exactly once, inside the Bind PDU, replaces it with a
fixed-length run of ASCII `x`, and writes `session.json`/`profile.json`
(through `internal/wirefixture`, the same schema
`internal/securitytest/wire_profile_contract_test.go` and
`internal/ldap/clickhouse_wire_cryptobyte_test.go` read) plus the sanitized
`.ber` files under `/run/ldap-wirecapture/sanitized/`. **Only that
`sanitized/` subtree is ever exported** — via a `tar` stream over `compose
exec`, never `docker cp` of the raw tree — to private host staging under
`$RUN_TMP_DIR`, which this driver leak-scans (Amendment 3: transcript,
diagnostics, all five services' `compose logs`, and the exported staging
itself) before promoting or comparing it.

**Three-fixture concurrency rule.** Like the base fixture and the HA
harness, this one is single-instance per Docker daemon, and now there are
three mutually exclusive fixtures that must never run concurrently on the
same daemon:

| Fixture | Project | Networks |
|---|---|---|
| Normal | `ch-phase3` | `ch-phase3-auth-net`, `ch-phase3-cluster-net` |
| HA | `ch-phase5-ha` | `ch-phase5-ha-auth-net`, `ch-phase5-ha-cluster-net` |
| Wire capture | `ch-wirecap` | `ch-wirecap-auth-net`, `ch-wirecap-cluster-net` |

Each script preflights against the *other two* before mutating any Docker
state — `run.sh` and `run-ha.sh` each refuse a stale `ch-wirecap*` fixture
(and vice versa is symmetric), and `capture-ldap-wire.sh` refuses `ch-phase3`,
`ch-phase5-ha`, and a stale leftover `ch-wirecap` fixture of its own, in that
order, before creating anything. No preflight ever deletes another fixture's
resources — it only `die`s with the exact `docker rm -f`/`docker network rm`
commands to run by hand. `tests/cases/wirecapture-collision-preflight.sh`
proves all five pairwise refusals fire before any mutation, under a stub
`docker`, with no daemon needed.

## Diagnostics

- **Health gate timeout** (120 s): `run.sh` dumps `compose ps` and each
  service's logs before tearing down.
- **Per-run private state** is under `$TMPDIR/ch-phase3-run.XXXXXX/` (secret
  env file, fallback compose file, run transcript, temp SQL/credential files)
  and is deleted by the `EXIT` trap on every exit path. Nothing survives a run
  except what you `tee` yourself.
- **Never enable `set -x`** in `run.sh`, `lib/*.sh`, or any scenario file: JWTs
  pass through these scripts as function arguments and curl config files, and
  scenario I's leak scan treats the runner transcript as an artifact under test.
  Tokens are never placed in argv of an external process, an exported
  environment variable, or a `docker -e` literal.
- A transient `ALL_CONNECTION_TRIES_FAILED` between the two ClickHouse
  containers is retried a bounded number of times by
  `oauth_run_retry_transient`; it is distinct from, and never masks, the
  tracked `ACCESS_DENIED` outcomes.
- Leftover containers after an aborted run: `docker ps -a --filter
  name=ch-phase3` should be empty; if not, `docker rm -f` them and `docker
  network rm ch-phase3-auth-net ch-phase3-cluster-net`.
