#!/usr/bin/env bash
# helm/ch-oauth-ldap/ci/lib/chart-assertions.sh
#
# Sourced-only assertion library for the ch-oauth-ldap chart's committed
# verification gate. Exposes one entry point, run_chart_assertions, which
# implements:
#
#   * plan §37 — the full positive render matrix (10 cases), each rendered
#     with `helm template` and passed through G0's kubeconform_check;
#   * plan §38 — the full negative render matrix (24 numbered cases; case
#     23 is table-driven over the five reserved podLabels keys, so this
#     runs 28 distinct `helm template` invocations in total), each
#     asserting `helm template` exits non-zero AND emits the chart's exact
#     §5 fail-closed message;
#   * plan §41-46 — rendered-Kubernetes assertions on the production
#     render: exact resource inventory, every Deployment item, the
#     cross-resource immutable-selector-label equality proof (plus the
#     additive custom podLabel case), Service items, PDB/dev items, and
#     NetworkPolicy items (including the disabled-policy case);
#   * a direct check that values.yaml contains no `ldap.listen`.
#
# This file does NOT parse the embedded config.yaml/ldap.xml content
# (a sibling library owns that) and does NOT touch chart templates/values
# -- if an assertion here exposes a chart defect, it fails loudly with the
# exact repro rather than silently working around it.
#
# THIS FILE IS A LIBRARY. It must be `source`d, never executed directly,
# and it must be sourced *after* ci/lib/common.sh (it uses common.sh's
# pass/fail/note/skip/assert_* primitives and ensure_kubeconform/
# kubeconform_check, and shares its $GATE_FAILURES counter).
#
# Contract (env this library's entry point requires, set by the caller):
#   REPO_ROOT     absolute path to the repository root (unused for
#                 rendering itself, but required so callers/companion
#                 libraries share one contract -- kept as a required
#                 input rather than silently ignored).
#   CHART_DIR     absolute path to helm/ch-oauth-ldap.
#   RUN_TMP_DIR   an existing, owned, writable temp directory. Every
#                 render this library produces is written under
#                 "$RUN_TMP_DIR/render/".
#
# Usage (see helm/ch-oauth-ldap/test.sh for the real driver):
#   REPO_ROOT=... CHART_DIR=... RUN_TMP_DIR=$(mktemp -d ...) bash -c '
#     source ci/lib/common.sh
#     source ci/lib/chart-assertions.sh
#     run_chart_assertions
#   '

# --- sourced-only guard ------------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "chart-assertions.sh: this file is a library; source it, do not execute it" >&2
    exit 1
fi

# --- fixed test identity ------------------------------------------------------
# Every render in this library uses the same Helm release name so that
# expected label values (app.kubernetes.io/instance especially) are known
# literals rather than something re-derived per case.
_CA_RELEASE="t"

# ==============================================================================
# Internal helpers (prefixed _ca_ to avoid colliding with anything a driver
# script or sibling library defines).
# ==============================================================================

# _ca_slug STRING
# Turns an arbitrary case label into a filesystem-safe slug for render
# artifact filenames.
_ca_slug() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9' '-' | tr -s '-' '-' | sed -e 's/^-//' -e 's/-$//'
}

# _ca_kubeconform_pass FILE LABEL
# Runs the pinned kubeconform (already set up by ensure_kubeconform) against
# a rendered manifest and reports PASS/FAIL via the common.sh primitives.
_ca_kubeconform_pass() {
    local file="$1" label="$2" out rc
    out=$(kubeconform_check "$file" 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "kubeconform: $label -- $out"
    else
        fail "kubeconform: $label FAILED (exit $rc) -- $out"
    fi
}

# _ca_positive LABEL SLUG [helm template args...]
# Renders the chart with `helm template t $CHART_DIR <args>`, requires
# success, writes the render to $RUN_TMP_DIR/render/$SLUG.yaml, and runs it
# through kubeconform. Prints the render's absolute path on stdout so
# callers that need to reuse the render for further assertions can capture
# it; also always leaves it at the deterministic path for callers that
# already know the slug.
_ca_positive() {
    local label="$1" slug="$2" out err
    shift 2
    out="$RUN_TMP_DIR/render/${slug}.yaml"
    err="$RUN_TMP_DIR/render/${slug}.stderr"
    note "positive case: $label"
    if helm template "$_CA_RELEASE" "$CHART_DIR" "$@" >"$out" 2>"$err"; then
        pass "render OK: $label ($out)"
        _ca_kubeconform_pass "$out" "$label"
    else
        fail "render FAILED (expected success) for positive case '$label': $(cat "$err")"
    fi
    printf '%s\n' "$out"
}

# _ca_negative LABEL EXPECTED_MESSAGE [helm template args...]
# Starts from ci/valid-values.yaml, applies the given violation via extra
# helm template args, and requires `helm template` to exit non-zero AND
# emit EXPECTED_MESSAGE verbatim on stderr.
_ca_negative() {
    local label="$1" expected="$2" slug err
    shift 2
    slug=$(_ca_slug "neg-$label")
    err="$RUN_TMP_DIR/render/${slug}.stderr"
    note "negative case: $label (expect: \"$expected\")"
    if helm template "$_CA_RELEASE" "$CHART_DIR" -f "$CHART_DIR/ci/valid-values.yaml" "$@" >/dev/null 2>"$err"; then
        fail "negative case '$label': helm template unexpectedly SUCCEEDED (expected failure: $expected)"
    else
        assert_match "$err" "$expected" F
    fi
}

# _ca_extract_source_block RENDER_FILE TEMPLATE_SUFFIX OUT_FILE
# Isolates one rendered resource's block (everything from its
# "# Source: ch-oauth-ldap/templates/<TEMPLATE_SUFFIX>" marker up to, but
# not including, the next "# Source:" marker or EOF) into OUT_FILE, so
# later assertions can target a single resource without ambiguity against
# identically-indented content in other resources in the same multi-doc
# render.
_ca_extract_source_block() {
    local render_file="$1" suffix="$2" out_file="$3"
    awk -v want="# Source: ch-oauth-ldap/templates/${suffix}" '
        $0 == want { grab=1; next }
        grab && /^# Source: / { exit }
        grab { print }
    ' "$render_file" >"$out_file"
}

# _ca_pair_after_anchor FILE ANCHOR
# Finds the first line of FILE whose content equals ANCHOR (leading/trailing
# whitespace ignored), then returns (on two lines of stdout, trimmed) the
# next two lines matching /app\.kubernetes\.io\/(name|instance):/ found
# after it -- skipping any intervening structural line (e.g. "matchLabels:")
# so the same helper works whether the labels sit directly under the anchor
# (Service's flat `selector:`) or one level deeper (`selector:`/`matchLabels:`
# in Deployment/PDB, or `podSelector:`/`matchLabels:` in NetworkPolicy).
_ca_pair_after_anchor() {
    local file="$1" anchor="$2"
    awk -v anchor="$anchor" '
        {
            line = $0
            gsub(/^[ \t]+|[ \t]+$/, "", line)
        }
        found == 0 && line == anchor { found = 1; next }
        found == 1 {
            tl = $0
            gsub(/^[ \t]+|[ \t]+$/, "", tl)
            if (tl ~ /^app\.kubernetes\.io\/(name|instance):/) {
                print tl
                n++
                if (n == 2) exit
            }
        }
    ' "$file"
}

# _ca_assert_selector_pair LABEL PAIR_TEXT
# PAIR_TEXT is the two-line output of _ca_pair_after_anchor (or empty if the
# anchor was never found). Fails loudly with the exact repro (LABEL) if
# either the anchor was not found or the pair does not equal the one known-
# correct value for this release/chart.
_ca_assert_selector_pair() {
    local label="$1" pair="$2" expected
    expected=$'app.kubernetes.io/name: ch-oauth-ldap\napp.kubernetes.io/instance: '"${_CA_RELEASE}"
    assert_eq "$pair" "$expected" "selector labels for $label"
}

# ==============================================================================
# §37 Positive render matrix (10 cases)
# ==============================================================================

_ca_positive_matrix() {
    local valid="$CHART_DIR/ci/valid-values.yaml" dev="$CHART_DIR/values-dev.yaml"

    # 1. production default + valid CI values -- this is THE production
    # render every §41-46 assertion below operates on.
    CA_RENDER_PROD=$(_ca_positive "production default + valid CI values" "01-production" -f "$valid")

    # 2. dev override (replicaCount: 1, no PDB).
    CA_RENDER_DEV=$(_ca_positive "dev override" "02-dev" -f "$valid" -f "$dev")

    # 3. NetworkPolicy disabled.
    CA_RENDER_NETPOL_DISABLED=$(_ca_positive "NetworkPolicy disabled" "03-networkpolicy-disabled" \
        -f "$valid" --set networkPolicy.enabled=false)

    # 4. imagePullSecret + non-reserved podLabel/podAnnotation + nodeSelector
    # + toleration + priorityClassName + topologySpreadConstraints. Also
    # doubles as the §43 "additive custom podLabel" proof render.
    CA_RENDER_SCHEDULING=$(_ca_positive "imagePullSecret + non-reserved labels/annotations + scheduling knobs" "04-scheduling-knobs" \
        -f "$valid" \
        --set-json 'imagePullSecrets=[{"name":"regcred"}]' \
        --set-json 'podLabels={"team":"data-platform"}' \
        --set-json 'podAnnotations={"example.com/note":"hello"}' \
        --set-json 'nodeSelector={"disktype":"ssd"}' \
        --set-json 'tolerations=[{"key":"dedicated","operator":"Equal","value":"ldap","effect":"NoSchedule"}]' \
        --set priorityClassName=high-priority \
        --set-json 'topologySpreadConstraints=[{"maxSkew":1,"topologyKey":"kubernetes.io/hostname","whenUnsatisfiable":"ScheduleAnyway","labelSelector":{"matchLabels":{"app.kubernetes.io/name":"ch-oauth-ldap"}}}]')
    assert_match "$CA_RENDER_SCHEDULING" 'name: regcred' F
    assert_match "$CA_RENDER_SCHEDULING" 'team: data-platform' F
    assert_match "$CA_RENDER_SCHEDULING" 'example.com/note: hello' F
    assert_match "$CA_RENDER_SCHEDULING" 'disktype: ssd' F
    assert_match "$CA_RENDER_SCHEDULING" 'key: dedicated' F
    assert_match "$CA_RENDER_SCHEDULING" 'priorityClassName: high-priority' F
    assert_match "$CA_RENDER_SCHEDULING" 'topologySpreadConstraints:' F
    assert_match "$CA_RENDER_SCHEDULING" 'maxSkew: 1' F

    # 5. Explicit affinity replacement: the generated soft anti-affinity
    # must be fully replaced, not merged.
    CA_RENDER_AFFINITY=$(_ca_positive "explicit affinity replacement" "05-explicit-affinity" \
        -f "$valid" \
        --set-json 'affinity={"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/arch","operator":"In","values":["amd64"]}]}]}}}')
    assert_match "$CA_RENDER_AFFINITY" 'nodeAffinity:' F
    assert_not_match "$CA_RENDER_AFFINITY" 'podAntiAffinity:' F

    # 6. Substantive namespace selector.
    CA_RENDER_NS_SELECTOR=$(_ca_positive "substantive namespace selector" "06-namespace-selector" \
        -f "$valid" \
        --set-json 'networkPolicy.clickhouseNamespaceSelector={"matchLabels":{"kubernetes.io/metadata.name":"clickhouse"}}')
    assert_match "$CA_RENDER_NS_SELECTOR" 'kubernetes.io/metadata.name: clickhouse' F

    # 7. Custom clusterDomain with --namespace analytics -- proves both
    # .Release.Namespace and clusterDomain participate in the generated
    # ClickHouse Service host.
    CA_RENDER_CUSTOM_DOMAIN=$(_ca_positive "custom clusterDomain with --namespace analytics" "07-custom-domain" \
        -f "$valid" --namespace analytics --set clusterDomain=k8s.example.internal)
    assert_match "$CA_RENDER_CUSTOM_DOMAIN" "${_CA_RELEASE}-ch-oauth-ldap.analytics.svc.k8s.example.internal" F

    # 8. Valid non-default logLevel.
    CA_RENDER_LOGLEVEL=$(_ca_positive "valid non-default logLevel" "08-loglevel-debug" \
        -f "$valid" --set logLevel=debug)
    assert_match "$CA_RENDER_LOGLEVEL" 'value: "debug"' F

    # 9. YAML-significant helper strings (#, ": ", leading "!") in
    # value-derived config fields that carry no chart-side content
    # restriction. This only needs to prove `helm template` still renders a
    # structurally valid Kubernetes ConfigMap (the quote/toYaml
    # serialization convention keeps these YAML-safe inside the embedded
    # config; a sibling library owns parsing that embedded content).
    _ca_positive "YAML-significant helper strings (#, \": \", leading !)" "09-yaml-significant-strings" \
        -f "$valid" \
        --set-string 'identity.username_match=weird: value' \
        --set-string 'roles.roles_transform=#comment-like' \
        --set-string 'ldap.role_cn_prefix=!bang' >/dev/null

    # 10. Directory value containing a literal & (XML-escaping input case;
    # the embedded XML's escaping correctness is a sibling library's
    # concern -- here we only need the Kubernetes ConfigMap itself to still
    # render and validate).
    _ca_positive "directory value containing literal &" "10-ampersand-directory-value" \
        -f "$valid" --set-string 'ldap.user_base_dn=ou=a&b,dc=x,dc=y' >/dev/null
}

# ==============================================================================
# §38 Negative render matrix (24 numbered cases; #23 is table-driven over 5
# reserved podLabels keys, so this runs 28 `helm template` invocations)
# ==============================================================================

_ca_negative_matrix() {
    # 1
    _ca_negative "replicaCount: 0" \
        "replicaCount must be at least 1" \
        --set replicaCount=0

    # 2
    _ca_negative "empty image tag" \
        "image.tag is required; pin a published ch-oauth-ldap image" \
        --set image.tag=""

    # 3
    _ca_negative "empty audiences" \
        "oauth.expected_audiences must contain at least one non-empty audience" \
        --set-json 'oauth.expected_audiences=[]'

    # 4
    _ca_negative "audiences containing only whitespace" \
        "oauth.expected_audiences must contain at least one non-empty audience" \
        --set-json 'oauth.expected_audiences=[" "]'

    # 5
    _ca_negative "issuer and JWKS both empty" \
        "set oauth.expected_issuer and/or oauth.jwks_url" \
        --set oauth.expected_issuer="" --set oauth.jwks_url=""

    # 6
    _ca_negative "invalid log level" \
        "logLevel must be one of debug, info, warn, error" \
        --set logLevel=trace

    # 7
    _ca_negative "empty clusterDomain" \
        "clusterDomain must not be empty" \
        --set clusterDomain=""

    # 8
    _ca_negative "empty pod selector {}" \
        "networkPolicy.clickhousePodSelector must select at least one label or expression" \
        --set-json 'networkPolicy.clickhousePodSelector={}'

    # 9
    _ca_negative "pod selector {matchLabels:{}}" \
        "networkPolicy.clickhousePodSelector must select at least one label or expression" \
        --set-json 'networkPolicy.clickhousePodSelector={"matchLabels":{}}'

    # 10
    _ca_negative "pod selector {matchExpressions:[]}" \
        "networkPolicy.clickhousePodSelector must select at least one label or expression" \
        --set-json 'networkPolicy.clickhousePodSelector={"matchExpressions":[]}'

    # 11
    _ca_negative "pod selector both nested fields empty" \
        "networkPolicy.clickhousePodSelector must select at least one label or expression" \
        --set-json 'networkPolicy.clickhousePodSelector={"matchLabels":{},"matchExpressions":[]}'

    # 12
    _ca_negative "namespace selector {matchLabels:{}}" \
        "networkPolicy.clickhouseNamespaceSelector must contain at least one label or expression when set" \
        --set-json 'networkPolicy.clickhouseNamespaceSelector={"matchLabels":{}}'

    # 13
    _ca_negative "namespace selector {matchExpressions:[]}" \
        "networkPolicy.clickhouseNamespaceSelector must contain at least one label or expression when set" \
        --set-json 'networkPolicy.clickhouseNamespaceSelector={"matchExpressions":[]}'

    # 14
    _ca_negative "namespace selector both nested fields empty" \
        "networkPolicy.clickhouseNamespaceSelector must contain at least one label or expression when set" \
        --set-json 'networkPolicy.clickhouseNamespaceSelector={"matchLabels":{},"matchExpressions":[]}'

    # 15
    _ca_negative 'ldap.listen: ":389"' \
        "ldap.listen is fixed to :3389 by the chart; remove this value" \
        --set ldap.listen=":389"

    # 16
    _ca_negative 'ldap.listen: ":3389"' \
        "ldap.listen is fixed to :3389 by the chart; remove this value" \
        --set ldap.listen=":3389"

    # 17
    _ca_negative "empty ldap.user_base_dn" \
        "ldap.user_base_dn must not be empty" \
        --set ldap.user_base_dn=""

    # 18
    _ca_negative "whitespace-only ldap.user_base_dn" \
        "ldap.user_base_dn must not be empty" \
        --set ldap.user_base_dn="   "

    # 19
    _ca_negative "empty ldap.group_base_dn" \
        "ldap.group_base_dn must not be empty" \
        --set ldap.group_base_dn=""

    # 20
    _ca_negative "whitespace-only ldap.group_base_dn" \
        "ldap.group_base_dn must not be empty" \
        --set ldap.group_base_dn="   "

    # 21
    _ca_negative "empty ldap.user_rdn_attribute" \
        "ldap.user_rdn_attribute must not be empty" \
        --set ldap.user_rdn_attribute=""

    # 22
    _ca_negative "whitespace-only ldap.user_rdn_attribute" \
        "ldap.user_rdn_attribute must not be empty" \
        --set ldap.user_rdn_attribute="   "

    # 23 -- table-driven over the five reserved common-label keys that
    # podLabels must never be able to shadow.
    local key json
    for key in "helm.sh/chart" "app.kubernetes.io/name" "app.kubernetes.io/instance" \
        "app.kubernetes.io/version" "app.kubernetes.io/managed-by"; do
        json=$(printf '{"%s":"x"}' "$key")
        _ca_negative "reserved podLabels key: $key" \
            "podLabels must not override chart-managed label $key" \
            --set-json "podLabels=$json"
    done

    # 24
    _ca_negative "reserved checksum annotation in podAnnotations" \
        "podAnnotations must not override checksum/ch-oauth-ldap-config" \
        --set-json 'podAnnotations={"checksum/ch-oauth-ldap-config":"x"}'
}

# ==============================================================================
# §41 Production resource inventory
# ==============================================================================

_ca_inventory() {
    local f="$CA_RENDER_PROD"
    note "§41 production resource inventory"
    assert_count "$f" '^kind: ConfigMap$' 2 E
    assert_count "$f" '^kind: Deployment$' 1 E
    assert_count "$f" '^kind: Service$' 1 E
    assert_count "$f" '^kind: PodDisruptionBudget$' 1 E
    assert_count "$f" '^kind: NetworkPolicy$' 1 E
    assert_not_match "$f" '^kind: Ingress$' E
    assert_not_match "$f" '^kind: StatefulSet$' E
    assert_not_match "$f" '^kind: DaemonSet$' E
    assert_not_match "$f" '^kind: Secret$' E
    assert_not_match "$f" '^kind: ServiceAccount$' E
}

# ==============================================================================
# §42 Deployment assertions (production render)
# ==============================================================================

_ca_deployment_assertions() {
    local block="$RUN_TMP_DIR/render/_deployment-block.txt"
    _ca_extract_source_block "$CA_RENDER_PROD" "deployment.yaml" "$block"
    note "§42 Deployment assertions"

    assert_match "$block" 'replicas: 2' F
    assert_match "$block" 'image: "ghcr.io/altinity/ch-oauth-ldap:ldap-0123abc"' F
    assert_match "$block" 'imagePullPolicy: IfNotPresent' F
    assert_match "$block" '--config=/etc/ch-oauth-ldap/config.yaml' F
    assert_match "$block" 'name: CH_OAUTH_LDAP_LOG_LEVEL' F
    assert_match "$block" 'value: "info"' F
    assert_count "$block" 'containerPort:' 1 F
    assert_match "$block" 'containerPort: 3389' F
    assert_match "$block" 'name: ldap' F
    assert_count "$block" 'tcpSocket:' 2 F
    assert_not_match "$block" 'httpGet:' F
    assert_match "$block" 'cpu: 50m' F
    assert_match "$block" 'memory: 64Mi' F
    assert_match "$block" 'cpu: 500m' F
    assert_match "$block" 'memory: 128Mi' F
    assert_match "$block" 'runAsUser: 65532' F
    assert_match "$block" 'runAsGroup: 65532' F
    assert_match "$block" 'runAsNonRoot: true' F
    assert_match "$block" 'readOnlyRootFilesystem: true' F
    assert_match "$block" 'allowPrivilegeEscalation: false' F
    assert_match "$block" '- ALL' F
    assert_match "$block" 'automountServiceAccountToken: false' F
    assert_match "$block" 'type: RuntimeDefault' F
    assert_match "$block" 'type: RollingUpdate' F
    assert_match "$block" 'maxUnavailable: 0' F
    assert_match "$block" 'maxSurge: 1' F
    assert_match "$block" 'terminationGracePeriodSeconds: 40' F
    assert_match "$block" '- /bin/sleep' F
    assert_match "$block" '"5"' F
    assert_match "$block" 'checksum/ch-oauth-ldap-config:' F
    assert_match "$block" 'podAntiAffinity:' F
    assert_match "$block" 'preferredDuringSchedulingIgnoredDuringExecution:' F
}

# ==============================================================================
# §43 Selector ownership: cross-resource immutable-selector-label equality
# ==============================================================================

_ca_selector_ownership() {
    local f="$CA_RENDER_PROD"
    note "§43 cross-resource selector-label equality (production render)"

    # Deployment .spec.selector.matchLabels, PDB .spec.selector.matchLabels,
    # and NetworkPolicy .spec.podSelector.matchLabels all render the same
    # immutable selector-labels helper at the same (6-space) indent -- prove
    # they are byte-identical to each other and to the one known-correct
    # value by requiring the exact literal to occur exactly 3 times across
    # the whole production render. Uses E-mode with ^/$ anchors: F-mode
    # (plain substring) matching would also count deeper-indented lines
    # (8-space pod-template, 20-space anti-affinity peer) since a shorter
    # indent string is a substring of a longer one at a non-zero offset.
    assert_count "$f" '^      app\.kubernetes\.io/name: ch-oauth-ldap$' 3 E
    assert_count "$f" "^      app\\.kubernetes\\.io/instance: ${_CA_RELEASE}\$" 3 E

    # Deployment pod-template metadata.labels (8-space indent, per
    # `nindent 8` in templates/deployment.yaml).
    assert_count "$f" '^        app\.kubernetes\.io/name: ch-oauth-ldap$' 1 E
    assert_count "$f" "^        app\\.kubernetes\\.io/instance: ${_CA_RELEASE}\$" 1 E

    # Default anti-affinity peer's labelSelector.matchLabels (20-space
    # indent, per `nindent 20` in templates/deployment.yaml).
    assert_count "$f" '^                    app\.kubernetes\.io/name: ch-oauth-ldap$' 1 E
    assert_count "$f" "^                    app\\.kubernetes\\.io/instance: ${_CA_RELEASE}\$" 1 E

    # Service's selector is a flat map directly under `selector:` (no
    # `matchLabels:` wrapper), rendered at the same 4-space indent as every
    # resource's own chart-label metadata block -- isolate the Service
    # resource first, then anchor on its unique `selector:` line so this
    # cannot accidentally read the Service's own metadata.labels instead.
    local svc_block pair
    svc_block="$RUN_TMP_DIR/render/_service-block.txt"
    _ca_extract_source_block "$f" "service.yaml" "$svc_block"
    pair=$(_ca_pair_after_anchor "$svc_block" "selector:")
    _ca_assert_selector_pair "Service .spec.selector" "$pair"

    # §43's positive custom-podLabels case: an unrelated additive key must
    # appear exactly once in the whole render (inside the pod template) and
    # must never appear in any of the five selector locations above (which
    # render only from the immutable selectorLabels helper, never from
    # podLabels) -- proven by requiring a single occurrence anywhere.
    assert_count "$CA_RENDER_SCHEDULING" 'team: data-platform' 1 F
}

# ==============================================================================
# §44 Service assertions (production render)
# ==============================================================================

_ca_service_assertions() {
    local block="$RUN_TMP_DIR/render/_service-block-44.txt"
    _ca_extract_source_block "$CA_RENDER_PROD" "service.yaml" "$block"
    note "§44 Service assertions"

    assert_match "$block" 'type: ClusterIP' F
    assert_match "$block" 'sessionAffinity: None' F
    assert_count "$block" 'protocol: TCP' 1 F
    assert_match "$block" 'name: ldap' F
    assert_match "$block" 'port: 389' F
    assert_match "$block" 'targetPort: ldap' F
    assert_not_match "$block" 'nodePort:' F
    assert_not_match "$block" 'externalIPs:' F
    assert_not_match "$block" 'type: NodePort' F
    assert_not_match "$block" 'type: LoadBalancer' F
}

# ==============================================================================
# §45 PDB / dev assertions
# ==============================================================================

_ca_pdb_and_dev_assertions() {
    note "§45 PDB (production) / dev assertions"

    local pdb_block="$RUN_TMP_DIR/render/_pdb-block.txt"
    _ca_extract_source_block "$CA_RENDER_PROD" "pdb.yaml" "$pdb_block"
    assert_match "$pdb_block" 'minAvailable: 1' F

    # Dev: one replica, no PDB, all security/network/probe/resource rules
    # retained.
    assert_match "$CA_RENDER_DEV" 'replicas: 1' F
    assert_not_match "$CA_RENDER_DEV" '^kind: PodDisruptionBudget$' E
    assert_match "$CA_RENDER_DEV" 'runAsUser: 65532' F
    assert_match "$CA_RENDER_DEV" 'runAsNonRoot: true' F
    assert_match "$CA_RENDER_DEV" 'readOnlyRootFilesystem: true' F
    assert_count "$CA_RENDER_DEV" '^kind: NetworkPolicy$' 1 E
    assert_count "$CA_RENDER_DEV" 'tcpSocket:' 2 F
    assert_match "$CA_RENDER_DEV" 'cpu: 50m' F
    assert_match "$CA_RENDER_DEV" 'memory: 64Mi' F
    assert_match "$CA_RENDER_DEV" 'cpu: 500m' F
    assert_match "$CA_RENDER_DEV" 'memory: 128Mi' F
}

# ==============================================================================
# §46 NetworkPolicy assertions
# ==============================================================================

_ca_networkpolicy_assertions() {
    note "§46 NetworkPolicy assertions"

    local block="$RUN_TMP_DIR/render/_networkpolicy-block.txt"
    _ca_extract_source_block "$CA_RENDER_PROD" "networkpolicy.yaml" "$block"

    assert_match "$block" '  podSelector:' F
    assert_count "$block" '- Ingress' 1 F
    assert_not_match "$block" 'Egress' F
    assert_count "$block" '^  policyTypes:$' 1 E
    # The ClickHouse peer's selector, as configured in ci/valid-values.yaml.
    assert_match "$block" 'app.kubernetes.io/name: clickhouse' F
    assert_count "$block" 'port: ldap' 1 F
    assert_count "$block" 'protocol: TCP' 1 F

    # networkPolicy.enabled=false: policy absent, production PDB remains,
    # Service remains fixed ClusterIP.
    assert_not_match "$CA_RENDER_NETPOL_DISABLED" '^kind: NetworkPolicy$' E
    assert_match "$CA_RENDER_NETPOL_DISABLED" '^kind: PodDisruptionBudget$' E
    assert_match "$CA_RENDER_NETPOL_DISABLED" 'type: ClusterIP' F
}

# ==============================================================================
# values.yaml must not contain ldap.listen (plan §7)
# ==============================================================================

_ca_values_yaml_no_listen() {
    note "values.yaml has no ldap.listen"
    assert_not_match "$CHART_DIR/values.yaml" 'listen:' F
    assert_not_match "$CHART_DIR/values.yaml" 'ldap.listen' F
}

# ==============================================================================
# Public entry point
# ==============================================================================

# run_chart_assertions
# Runs the complete positive matrix, negative matrix, and rendered-
# Kubernetes assertions described above. Returns 0 iff every assertion
# (across this call and anything else sharing $GATE_FAILURES) has passed so
# far; returns 1 otherwise. Never exits the calling shell.
run_chart_assertions() {
    local missing=""
    [ -n "${REPO_ROOT:-}" ] || missing="${missing} REPO_ROOT"
    [ -n "${CHART_DIR:-}" ] || missing="${missing} CHART_DIR"
    [ -n "${RUN_TMP_DIR:-}" ] || missing="${missing} RUN_TMP_DIR"
    if [ -n "$missing" ]; then
        fail "run_chart_assertions: required env var(s) not set:${missing}"
        return 1
    fi
    if [ ! -d "$CHART_DIR" ]; then
        fail "run_chart_assertions: CHART_DIR '$CHART_DIR' is not a directory"
        return 1
    fi

    mkdir -p "$RUN_TMP_DIR/render"

    note "chart-assertions: REPO_ROOT=$REPO_ROOT CHART_DIR=$CHART_DIR RUN_TMP_DIR=$RUN_TMP_DIR"
    print_gate_pins
    ensure_kubeconform "$RUN_TMP_DIR/bin"

    _ca_positive_matrix
    _ca_negative_matrix
    _ca_inventory
    _ca_deployment_assertions
    _ca_selector_ownership
    _ca_service_assertions
    _ca_pdb_and_dev_assertions
    _ca_networkpolicy_assertions
    _ca_values_yaml_no_listen

    note "chart-assertions: done, GATE_FAILURES=$GATE_FAILURES"
    if [ "$GATE_FAILURES" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}
