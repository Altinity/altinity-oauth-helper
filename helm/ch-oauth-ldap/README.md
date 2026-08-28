# ch-oauth-ldap

A standalone Helm chart for the environment-level deployment of
`cmd/ch-oauth-ldap`: an internal-only Kubernetes `Deployment` plus a
`ClusterIP` `Service` exposing plain LDAP on port 389. ClickHouse's built-in
[LDAP external user directory][ch-ldap] talks to it over the cluster
network as its LDAP server; there is no HTTP surface, no Ingress, and no
externally reachable port anywhere in this chart.

This is a **different deployment model** from `helm/ch-jwt-verify/`. That
chart renders no Deployment at all — `ch-jwt-verify` is a sidecar that must
share a pod with ClickHouse so a loopback trust model holds. `ch-oauth-ldap`
is the opposite: ClickHouse reaches it as a normal environment-level network
service (its own pods, its own Service, its own scaling and disruption
behavior), because the LDAP protocol it speaks requires a real TCP
listener ClickHouse's LDAP client dials into, not a mounted socket. Do not
confuse the two charts' trust boundaries when reasoning about exposure.

See the root [`README.md`](../../README.md#ch-oauth-ldap) for the protocol
walkthrough, the working ClickHouse `ldap.xml` this chart's second
ConfigMap generates from, and — most importantly — **the ClickHouse
compatibility caveats** (the `verification_cooldown=0` requirement, the
`push_external_roles_in_interserver_queries` version gate, and the
`VIEW`-loses-external-roles defect) that apply to whatever ClickHouse
version you point at this chart's Service.

## Required values

Normal rendering (`helm template`/`install`/`upgrade`) fails closed if any
of these are missing, because the binary itself cannot run without them:

| Value | Why it's required |
| --- | --- |
| `image.tag` | No mutable default; you must pin an immutable published tag. |
| `oauth.expected_audiences` | At least one non-empty (non-whitespace) audience. |
| `oauth.expected_issuer` and/or `oauth.jwks_url` | At least one of the two must be set. |
| `networkPolicy.clickhousePodSelector` | Required substantive (see below) whenever `networkPolicy.enabled` is `true`, which is the chart default. |
| `ldap.user_base_dn`, `ldap.group_base_dn`, `ldap.user_rdn_attribute` | Non-empty/non-whitespace — the binary refuses to start without them (`cmd/ch-oauth-ldap/config.go`), so the chart rejects them before a broken ConfigMap ever ships. |

### `helm lint` does not enforce this

**`helm lint` is not the validation gate.** On both Helm 3 and Helm 4.1.4,
`fail`/`required` calls inside templates are non-fatal in lint mode — a
chart with every one of the required values above missing can still pass
`helm lint` cleanly. The only rendering paths that actually enforce the
table above are normal rendering: `helm template`, `helm install`, and
`helm upgrade`. Use `helm lint` for structural chart checks (YAML shape,
`Chart.yaml` metadata, values schema) and rely on `helm template` — not
lint — to prove that missing/invalid input actually fails a render.

## Image and pull policy

Published to `ghcr.io/altinity/ch-oauth-ldap`. The automatic tag scheme is:

```text
ldap-<7-character-git-sha>
```

There is no mutable `main`/`latest` alias — `image.tag` is required
precisely so nobody accidentally floats on a moving tag, and both
publication paths (the manual `scripts/build-ch-oauth-ldap-image.sh` and
the `.github/workflows/build-ch-oauth-ldap.yml` workflow) **refuse to
republish** a `ldap-<sha>` tag — or any of its per-arch `-amd64`/`-arm64`
sub-tags — that already exists in the registry. There is no force
override: re-running either path against the same commit fails loudly
rather than silently moving the tag to a different manifest.

That refusal is what you actually get, and it is **not** the same as
byte-for-byte reproducibility. Rebuilding the exact same commit is not
guaranteed to produce an identical image: `Dockerfile.ch-oauth-ldap`'s base
image (`alpine:3.24`) floats within its minor version, `apk add
ca-certificates` is unpinned, and the Go toolchain used to build it can
change over time. So "immutable" here means *this tag will not be
silently republished to point somewhere else* — not *rebuilding this
commit reproduces this exact manifest*. If you need a hard guarantee that
the image you deploy never changes underneath you, pin `image.tag` to a
resolved `@sha256:<digest>` reference rather than the `ldap-<sha>` tag.
`pullPolicy: IfNotPresent` (the chart default) is safe either way — it
only governs whether an already-cached local image is reused, not whether
a tag can ever be moved in the registry.

Set `imagePullSecrets` (a chart value, defaulting to `[]`) if your GHCR
package requires authenticated pulls. Do not assume the package is
anonymously pullable just because it lives on GHCR — anonymous access is a
package-visibility setting verified read-only against the real package
*after* first publication, never assumed in advance, and never mutated
automatically by this chart or its build tooling. If your organization's
GHCR policy is private-by-default, supply `imagePullSecrets` up front.

## Network surface

### Service: 389 in, 3389 in the container

The Service is fixed `type: ClusterIP`, exactly one TCP port, name `ldap`,
port `389`, `targetPort: ldap`, `sessionAffinity: None`. There are no
Service-type, NodePort, LoadBalancer, or externalIPs knobs — this chart
does not support public exposure at all.

The container process itself listens on **3389**, not 389. The Service
does the 389 → 3389 remap so the container never needs `NET_BIND_SERVICE`
to bind a privileged port; it runs as UID/GID 65532 with all capabilities
dropped.

### The listener address is chart-owned, not a value

`ldap.listen` is not a key that exists in `values.yaml`, and it is not one
you can set. The chart itself fixes the bind address to `:3389` when it
renders the helper's `config.yaml`, and its central validation helper
rejects rendering — with a fixed error message — the moment
`ldap.listen` is present in the supplied values at all, **even if you set
it to the chart's own fixed value**. This is deliberate: the binary passes
that field straight to `net.Listen`, and an operator-controlled listener
address would silently disagree with the Service, both probes, and the
NetworkPolicy target port, all of which assume 3389. If you need a
different in-container port, that is a chart change, not a values
override.

## Helper directory configuration

Three fields are required non-empty/non-whitespace because the binary's own
startup validation already refuses to run without them:

- `ldap.user_base_dn`
- `ldap.group_base_dn`
- `ldap.user_rdn_attribute`

The chart deliberately does **not** re-implement RFC 4514 Distinguished
Name syntax checking — it only rejects the empty/whitespace-only inputs
that would silently break the deployment, plus (see the next section) any
DN containing a line break. A syntactically malformed but non-empty DN
remains the binary's own startup-validation responsibility, not this
chart's.

## Value-shape validation (template injection guards)

Values are untrusted input to the templates. Two independent layers keep a
value from ever changing the *structure* of what the chart renders:

1. **Serialization by construction.** Both ConfigMap payloads (the helper's
   `config.yaml` and the ClickHouse `ldap.xml`) are built as one string by
   a helper and emitted through Helm's `toYaml`, so each is a single YAML
   scalar whatever characters it contains — a value cannot terminate the
   payload and add a sibling key or a further resource to the manifest.
   Every scalar the Deployment interpolates (`image`, `imagePullPolicy`,
   `priorityClassName`, `topologyKey`, resource names, label values) is
   emitted through `quote`; `replicas` and the anti-affinity `weight` are
   coerced with `int`; lists/maps go through `toYaml`.
2. **Fail-closed shape rules** in the central validation helper, each with a
   fixed error message:
   - no line break (`\n` or `\r`) in `ldap.user_base_dn`,
     `ldap.group_base_dn`, `ldap.user_rdn_attribute`, `ldap.role_cn_prefix`,
     `clusterDomain`, `nameOverride`, `fullnameOverride`, `image.repository`,
     `image.tag`, `priorityClassName`, or `podAntiAffinity.topologyKey`;
   - `nameOverride` / `fullnameOverride` must be RFC 1123 labels;
     `clusterDomain` and `priorityClassName` must be RFC 1123 subdomains;
     `podAntiAffinity.topologyKey` must be a Kubernetes label key
     (`[prefix/]name`);
   - `image.repository` must be a lowercase OCI repository reference,
     `image.tag` an OCI tag (`[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` — so a `"`
     can never close the quotes around `image:`), and `image.pullPolicy` one
     of `Always`, `IfNotPresent`, `Never`;
   - `replicaCount` and `podAntiAffinity.weight` must be real integers
     (`weight` in 1–100), not strings that merely start with digits;
   - `identity.require_email_verified` must be a real boolean — it is the
     one field the embedded `config.yaml` emits bare.

`helm/ch-oauth-ldap/test.sh` carries a negative render case for each of
these (a line break in `group_base_dn` that used to render an extra
`LoadBalancer` Service; a `priorityClassName` that used to inject
`hostNetwork: true`; a `"` in `image.tag`; `DoesNotExist`-only selectors;
and so on), each asserting the fixed message and that nothing was rendered.

## Invocation and log level

The Deployment always passes an explicit config path — never relying on the
binary's own default — and forwards the validated log level as an
environment variable:

```yaml
args:
  - --config=/etc/ch-oauth-ldap/config.yaml
env:
  - name: CH_OAUTH_LDAP_LOG_LEVEL
    value: <logLevel>
```

`logLevel` (default `info`) must be one of `debug`, `info`, `warn`, or
`error` — normal rendering fails on anything else. This matters because the
binary itself silently ignores an invalid log level rather than refusing to
start, so the chart-side check is the only place an operator typo gets
caught.

## Replicas, rollout, and disruption budget

Production default is **`replicaCount: 2`** for best-effort availability.
`values-dev.yaml` overrides only `replicaCount: 1` — nothing else — and, as
a direct consequence, the chart renders **no PodDisruptionBudget** at all
in dev mode (the PDB template only renders when `replicaCount > 1`). Every
other security/network/probe/resource rule is identical between the two;
dev mode is a scale override, not a relaxed one.

In production, the `PodDisruptionBudget` (`policy/v1`) sets
`minAvailable: 1`. This covers **voluntary disruption only** — node
drains, cluster upgrades, `kubectl drain` — the same category of event the
PDB API is designed for. It provides no protection against a node failing
outright; that is a placement concern, addressed only partially below.

The Deployment uses `RollingUpdate` with `maxUnavailable: 0` and
`maxSurge: 1`, so a rollout never drops below the configured replica count
before the new pod is healthy.

### Soft anti-affinity, and its limits

By default (`podAntiAffinity.enabled: true`) the chart renders a
**`preferredDuringSchedulingIgnoredDuringExecution`** pod anti-affinity
term, weight 100, topology key `kubernetes.io/hostname`, matching this
release's immutable selector labels. This is a *preference*, not a
requirement: the scheduler tries to spread the two replicas across nodes
but will still place both pods on the same node rather than leave one
unscheduled — for example, on a single-node cluster. It improves the odds
of surviving one node's disruption; it does **not** guarantee it. A
non-empty explicit `affinity` value replaces the generated preference
entirely rather than merging with it, so an operator who sets `affinity`
owns pod placement outright.

### Scheduling passthroughs

`nodeSelector`, `tolerations`, `priorityClassName`, and
`topologySpreadConstraints` are all optional, additive value blocks (each
defaulting to empty/unset) rendered straight into the pod spec when
non-empty — use them for taints, priority tiers, or your own topology
spread rules without needing a chart change.

## Graceful shutdown budget

```yaml
lifecycle:
  preStop:
    exec:
      command:
        - /bin/sleep
        - "5"
```

The `preStop` hook runs `/bin/sleep 5` before Kubernetes sends `SIGTERM`.
This gives kube-proxy/endpoint-slice propagation a best-effort five-second
window to stop routing new connections to a pod that's about to go away —
it is **not** a guaranteed Kubernetes convergence bound, just a heuristic
delay.

`terminationGracePeriodSeconds: 40` is not an arbitrary round number; it is
a budget built from three pieces:

- ~5 seconds for the `preStop` propagation heuristic above;
- up to the existing 30 seconds LDAP read/write timeout the server already
  enforces per connection (`internal/ldap/server.go`), so an
  in-flight connection has time to finish or time out on its own after
  `SIGTERM` closes the listener;
- roughly 5 seconds of margin on top.

`/bin/sleep` has to actually exist in the runtime image for this hook to
do anything — the Dockerfile pins `FROM alpine:3.24` and asserts
`/bin/sleep` is executable at build time specifically so this dependency
can't silently disappear on a base-image bump.

## TCP probes and their limitations

Both readiness and liveness are plain `tcpSocket` probes on the `ldap`
port — there is no other option, because the binary exposes no HTTP health
endpoint:

```yaml
readinessProbe:
  tcpSocket: {port: ldap}
  initialDelaySeconds: 1
  periodSeconds: 5
  timeoutSeconds: 1
  failureThreshold: 3
livenessProbe:
  tcpSocket: {port: ldap}
  initialDelaySeconds: 5
  periodSeconds: 30
  timeoutSeconds: 1
  failureThreshold: 3
```

A successful TCP probe proves exactly one thing: the process accepted a
TCP connection. It does **not** prove any of the following, and none of
these should be inferred from "Ready":

- it does not check JWT/JWKS health (a dead upstream IdP still probes Ready);
- it does not perform an LDAP Bind, so authentication itself is unverified;
- it does not expose the server's 256-connection-per-process saturation
  limit — a pod at capacity still answers a bare TCP handshake;
- a probe's TCP handshake can complete *before* the server closes the
  connection as excess, if the pod happens to be exactly at that
  connection-count boundary;
- every accepted probe connection briefly consumes one of the server's
  connection slots, even though it never performs an LDAP operation —
  under sustained near-saturation this is a small extra load, not a
  free health check.

### Operator checklist: probes under the default NetworkPolicy

The default-rendered ingress `NetworkPolicy` (see below) only admits
traffic from the selected ClickHouse pods/namespace. Kubelet-originated
`tcpSocket` probe traffic does not always come from a source the CNI
treats the same way as a normal pod-to-pod connection — on a CNI that does
not exempt host/kubelet traffic from `NetworkPolicy` enforcement, the
default policy can leave every replica **permanently NotReady** because the
probe itself gets blocked.

This is **CNI-dependent and unverified in this repository** — there is no
live Kubernetes cluster available to this phase's implementation, so no
claim is made about any specific CNI's behavior. `helm/ch-jwt-verify/values.yaml`
documents the same category of kubelet-probe gotcha for that chart's
sidecar TCP listener; the underlying cause here is analogous, just via
`NetworkPolicy` instead of a wrong bind address.

**If pods never become Ready after a fresh install, the documented remedy
is `networkPolicy.enabled=false`** — set it, confirm probes start
succeeding, and only then re-enable the policy once you've confirmed (or
worked around) your CNI's kubelet-traffic exemption. `networkPolicy.enabled=false`
is a deliberate, documented compatibility escape hatch for exactly this
situation; it is described in more detail below.

## Resources and capacity

```yaml
resources:
  requests: {cpu: 50m, memory: 64Mi}
  limits: {cpu: 500m, memory: 128Mi}
```

These are **initial engineering defaults**, not a measured sizing exercise
— treat them as a starting point to tune against your own traffic, not a
capacity guarantee.

The server enforces three fixed constraints that these resource values
budget against, and this chart does not change them:

- a **64 KiB** maximum declared LDAP message body;
- **256** concurrent connections per process;
- **30 seconds** read/write timeouts per connection.

From that, with the production default of two replicas:

- each pod can hold roughly 256 live connections before it starts closing
  new ones;
- for two reasonably balanced replicas, that's an aggregate of
  roughly **~512** connection slots across the release — this is an
  arithmetic implication of the per-process limit, **not** a distribution
  guarantee: Kubernetes Services do not promise even load balancing, and
  nothing here corrects for skew;
- TCP probe sockets (see above) briefly consume slots out of that same
  budget;
- when a pod is at its connection limit, the excess accepted socket is
  closed **before** any LDAP request handling occurs — this happens at the
  TCP/connection-accounting layer, not inside LDAP protocol logic;
- this chart does **not** claim any specific ClickHouse-observed error
  code or error text results from that saturation — no live-cluster
  behavior is asserted without cluster proof, and none is available here.

## NetworkPolicy

```yaml
networkPolicy:
  enabled: true
  clickhousePodSelector: {}
  clickhouseNamespaceSelector: {}
```

Rendered by default, because it is the only network-layer mitigation
available given the plaintext-bearer exception documented below — see
[Security exception](#security-exception-plaintext-oauth-bearer-over-ldap).

Both selector values are full Kubernetes `LabelSelector` objects, and the
chart's central validation applies different rules to each:

- **`clickhousePodSelector`** must be *substantive* whenever the policy is
  enabled — at least one `matchLabels` entry, or at least one
  `matchExpressions` entry. An empty `{}`, an empty `matchLabels: {}`, an
  empty `matchExpressions: []`, or both empty together, all fail rendering
  with a fixed error. There is no such thing as a valid "select nothing"
  pod selector here — it would defeat the point of the policy.
- It must also be *positive*: at least one `matchLabels` entry, or a
  `matchExpressions` entry whose operator is `In` or `Exists`. A selector
  made **only** of `DoesNotExist` / `NotIn` expressions (for example
  `{matchExpressions: [{key: bogus, operator: DoesNotExist}]}`) is
  syntactically non-empty but matches every pod that lacks the key — an
  allow-all peer in disguise — and fails rendering with its own fixed
  error. Unknown operators count as not positive.
- **`clickhouseNamespaceSelector`** treats an entirely empty outer `{}` as
  "not supplied" (meaning: no namespace restriction, ClickHouse must be in
  this release's own namespace) — that shape is valid. But once you supply
  *any* key at all (`matchLabels` and/or `matchExpressions`), the content
  must be substantive **and positive** by the same two rules as above; a
  non-empty-but-nested-empty shape like `{matchLabels: {}}` and a
  `NotIn`-only shape are both rejected, because they look like an
  intentional restriction that actually restricts nothing.

When the policy renders, it always combines a positive pod selector with
an optional, only-if-positive namespace selector in the **same** ingress
peer, allows only TCP to the named `ldap` target port, and sets
`policyTypes: [Ingress]` only (no egress rule is rendered). Every selector
shape the chart knows to be allow-all — empty, nested-empty, and
`DoesNotExist`/`NotIn`-only — fails rendering rather than producing an
allow-all source peer. (A selector that is positive but simply *wrong* —
labels no ClickHouse pod carries — is still your responsibility; the
chart cannot know your ClickHouse pods' labels.)

Example (the ClickHouse label below is a **placeholder** — substitute
your actual ClickHouse pod labels):

```yaml
networkPolicy:
  enabled: true
  clickhousePodSelector:
    matchLabels:
      your.example/clickhouse: "true"
  clickhouseNamespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: clickhouse
```

### `networkPolicy.enabled=false`

Setting `networkPolicy.enabled=false` is a documented compatibility escape
hatch. It omits **only** the `NetworkPolicy` resource — nothing else
changes. The Service stays exactly the same fixed internal-only
`ClusterIP` it always is; disabling the policy never opens, widens, or in
any way alters Service exposure. Use it when your cluster's CNI does not
support (or misbehaves under) `NetworkPolicy` enforcement, or — per the
probe operator checklist above — when the default policy is blocking
kubelet probe traffic and you need pods to reach Ready while you sort out
the underlying CNI behavior.

## Cluster DNS and the generated ClickHouse hostname

```yaml
clusterDomain: cluster.local
```

Required non-empty. It feeds the ClickHouse-facing hostname rendered into
the second ConfigMap's `ldap.xml`:

```text
<fullname>.<namespace>.svc.<clusterDomain>
```

Both `.Release.Namespace` and `clusterDomain` participate in that
generated host — neither is hard-coded, so a non-default Helm namespace or
a non-default `clusterDomain` both change the rendered value.

## The two ConfigMaps

The chart renders exactly two ConfigMaps, both guarded by the same central
validation helper:

1. **`<fullname>-config`** — the binary's own YAML, mounted read-only at
   `/etc/ch-oauth-ldap/config.yaml`. It mirrors `cmd/ch-oauth-ldap`'s four
   top-level families (`oauth`, `identity`, `roles`, `ldap`) exactly, plus
   the chart-fixed listen address appended once. Every value-derived
   scalar is emitted through Helm's `quote`; every list/map goes through
   `toYaml`; booleans render as real YAML booleans — never as
   interpolated raw strings — specifically so that a value containing a
   YAML-significant character (`#`, `: `, `&`, `*`, `!`) can't corrupt the
   binary's own config parse. The whole payload is then serialized into
   the ConfigMap with `toYaml` (not a hand-written `|` block scalar), so
   no value can escape it into the surrounding manifest either.
2. **`<fullname>-clickhouse-config`** — the ClickHouse-side `ldap.xml`,
   meant to be mounted into ClickHouse's own `config.d/` (ClickHouse is
   not deployed by this chart). The LDAP server identifier inside it is
   **fixed to `oauth_helper`** — it is not a value, so it can never drift
   from what the XML actually names. Structure, port `389`, bind DN shape,
   `verification_cooldown=0`, `enable_tls=no`, and a direct (unnested)
   `role_mapping` under `<ldap>` all mirror the proven working fixture at
   `integration/clickhouse/clickhouse/common/config.d/ldap.xml` — see the
   root README's [ClickHouse compatibility caveats][root-caveats] for what
   that fixture proved and did not prove per ClickHouse version.

Every value-derived XML text node (the generated host, the bind-DN
components, the group base DN, the role prefix) is escaped through one
fixed-order helper (`&` first, then `<`, then `>`) before being written
into the XML. The one exception is the group-membership search filter,
which is a fixed, already-escaped literal emitted verbatim exactly once —
running it back through the escape helper would double-escape it. The
finished XML is written into the ConfigMap through `toYaml` as a single
scalar, and every XML-bound value is additionally rejected at render if it
contains a line break (see [Value-shape validation](#value-shape-validation-template-injection-guards)).

## Security exception: plaintext OAuth bearer over LDAP

**The OAuth bearer token travels in clear text as the LDAP simple-bind password**
between ClickHouse and this helper. LDAP simple Bind carries no
transport encryption of its own, and this chart does not implement
TLS/LDAPS/StartTLS — `<enable_tls>no</enable_tls>` in the generated
ClickHouse XML is intentional, not an oversight.

This is a **deliberate MVP deviation from ADR #16**, not an unresolved
design gap: on August 28, 2026, Boris Tyshkevich (`@BorisTyshkevich`), as
the named risk owner, accepted the environment-level Deployment + ClusterIP
topology over plaintext LDAP on port 389 for this phase, with the
compensating controls this chart actually implements — internal-only
`ClusterIP` exposure (no Ingress/LoadBalancer/NodePort path exists at all)
and a default-on, source-restricting `NetworkPolicy`.

**`NetworkPolicy is not transport confidentiality.`** It restricts *who
can reach the Service* at the network layer; it does nothing to the bytes
on the wire. Anyone who can already reach the pod's network path — a
compromised neighbor workload inside the allowed source, a misconfigured
route, a CNI bug — can read the bearer token in the clear. Treat this
Service as **internal-only** in every sense: never place it behind a
public-facing anything, and scope the NetworkPolicy's ClickHouse selector
as tightly as your cluster's labeling allows.

The two paths that remove this exception entirely are:

- **TLS** — implementing LDAPS/StartTLS support in `cmd/ch-oauth-ldap` and
  `internal/ldap`, and setting `<enable_tls>yes</enable_tls>` (or the
  StartTLS equivalent) on the ClickHouse side, which this phase explicitly
  does not do;
- **a loopback sidecar redesign** — colocating the helper with ClickHouse
  the way `ch-jwt-verify` does, so the credential never crosses a network
  hop at all; this would require ClickHouse's LDAP client to support a
  loopback/unix-domain target, which is a different architecture from the
  environment-level Deployment this chart implements.

Neither is in scope for this phase. Until one of them lands, deploying
this chart means accepting that the OAuth bearer is exposed in clear text
to anything within its NetworkPolicy-permitted network path.

[ch-ldap]: https://clickhouse.com/docs/operations/external-authenticators/ldap
[root-caveats]: ../../README.md#wiring-clickhouse-to-ch-oauth-ldap
