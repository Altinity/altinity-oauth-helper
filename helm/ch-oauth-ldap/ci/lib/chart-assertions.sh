#!/usr/bin/env bash
# helm/ch-oauth-ldap/ci/lib/chart-assertions.sh
#
# Sourced-only assertion library for the ch-oauth-ldap chart's committed
# verification gate. Exposes one entry point, run_chart_assertions, which
# implements:
#
#   * plan §37 — the full positive render matrix (11 cases), each rendered
#     with `helm template` and passed through common.sh's kubeconform_check;
#   * plan §38 — the full negative render matrix (40 numbered cases; case
#     23 is table-driven over the five reserved podLabels keys, so this
#     runs 44 distinct `helm template` invocations in total), each
#     asserting `helm template` exits non-zero, emits NOTHING on stdout,
#     AND emits the chart's exact §5 fail-closed message on stderr. Cases
#     25-40 are the injection guards: line breaks / YAML-significant
#     characters in every value the templates interpolate, non-integer
#     integers, allow-all-in-disguise NetworkPolicy selectors, and a string
#     where the embedded config expects a boolean;
#   * plan §41-46 — rendered-Kubernetes assertions on the production
#     render: exact resource inventory, every Deployment item (including
#     the absence of hostNetwork/hostPID/hostIPC), the cross-resource
#     immutable-selector-label equality proof (plus the additive custom
#     podLabel case), Service items, PDB/dev items, and NetworkPolicy items
#     (including the disabled-policy case);
#   * a direct check that values.yaml contains no `ldap.listen`.
#
# This file does NOT parse the embedded config.yaml/ldap.xml content
# (ci/lib/embedded-assertions.sh owns that) and does NOT touch chart
# templates/values -- if an assertion here exposes a chart defect, it fails
# loudly with the exact repro rather than silently working around it.
#
# THIS FILE IS A LIBRARY. It must be `source`d, never executed directly,
# and it must be sourced *after* ci/lib/common.sh (it uses common.sh's
# pass/fail/note/skip/assert_* primitives and ensure_kubeconform/
# kubeconform_check, and shares its $GATE_FAILURES counter).
#
# Gate-soundness rule for this file: no function that may call `fail`
# (directly or through an assert_* helper) is ever invoked inside a `$(...)`
# command substitution or a pipeline. Both run in a subshell, so the
# subshell's increment of $GATE_FAILURES would be lost and the failure would
# never reach the gate's exit code. Render paths are therefore deterministic
# ($RUN_TMP_DIR/render/<slug>.yaml, see _ca_render_path) and never returned
# on stdout.
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
# script or another ci/lib library defines).
# ==============================================================================

# _ca_slug STRING
# Turns an arbitrary case label into a filesystem-safe slug for render
# artifact filenames. Pure text transformation: never calls fail.
_ca_slug() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9' '-' | tr -s '-' '-' | sed -e 's/^-//' -e 's/-$//'
}

# _ca_render_path SLUG
# The deterministic path a positive case's render is written to. Pure
# string function (safe to use in $(...)): never calls fail.
_ca_render_path() {
    printf '%s/render/%s.yaml\n' "$RUN_TMP_DIR" "$1"
}

# _ca_kubeconform_pass FILE LABEL
# Runs the pinned kubeconform (already set up by ensure_kubeconform) against
# a rendered manifest and reports PASS/FAIL via the common.sh primitives.
# kubeconform_check itself is an external command with no fail calls, so
# capturing ITS output is safe.
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
# success, writes the render to $(_ca_render_path SLUG), and runs it through
# kubeconform. Prints NOTHING on stdout (see the gate-soundness rule in the
# file header): callers that need the render read it from
# "$(_ca_render_path SLUG)".
_ca_positive() {
    local label="$1" slug="$2" out err
    shift 2
    out=$(_ca_render_path "$slug")
    err="$RUN_TMP_DIR/render/${slug}.stderr"
    note "positive case: $label"
    if helm template "$_CA_RELEASE" "$CHART_DIR" "$@" >"$out" 2>"$err"; then
        pass "render OK: $label ($out)"
        _ca_kubeconform_pass "$out" "$label"
    else
        fail "render FAILED (expected success) for positive case '$label': $(cat "$err")"
    fi
}

# _ca_negative LABEL EXPECTED_MESSAGE [helm template args...]
# Starts from ci/valid-values.yaml, applies the given violation via extra
# helm template args, and requires `helm template` to exit non-zero, emit
# EXPECTED_MESSAGE verbatim on stderr, AND emit nothing on stdout (a failed
# render must never leak a partial manifest). The captured stdout is left at
# "$RUN_TMP_DIR/render/neg-<slug>.stdout" so a caller can additionally
# prove a specific injected string is absent.
_ca_negative() {
    local label="$1" expected="$2" slug err out
    shift 2
    slug=$(_ca_slug "neg-$label")
    err="$RUN_TMP_DIR/render/${slug}.stderr"
    out="$RUN_TMP_DIR/render/${slug}.stdout"
    note "negative case: $label (expect: \"$expected\")"
    if helm template "$_CA_RELEASE" "$CHART_DIR" -f "$CHART_DIR/ci/valid-values.yaml" "$@" >"$out" 2>"$err"; then
        fail "negative case '$label': helm template unexpectedly SUCCEEDED (expected failure: $expected)"
    else
        assert_match "$err" "$expected" F
        if [ -s "$out" ]; then
            fail "negative case '$label': helm template failed but still wrote $(wc -c <"$out" | tr -d ' ') byte(s) to stdout ($out)"
        else
            pass "negative case '$label': nothing rendered on stdout"
        fi
    fi
}

# _ca_negative_stdout LABEL
# Path of the stdout capture _ca_negative left for LABEL. Pure string
# function.
_ca_negative_stdout() {
    printf '%s/render/%s.stdout\n' "$RUN_TMP_DIR" "$(_ca_slug "neg-$1")"
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
# Pure awk: never calls fail.
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
# correct value for this release/chart. Label values are emitted quoted by
# the chart's selectorLabels helper (defense in depth against
# YAML-significant characters), so the expected literal is quoted too.
_ca_assert_selector_pair() {
    local label="$1" pair="$2" expected
    expected=$'app.kubernetes.io/name: "ch-oauth-ldap"\napp.kubernetes.io/instance: "'"${_CA_RELEASE}"'"'
    assert_eq "$pair" "$expected" "selector labels for $label"
}

# ==============================================================================
# §37 Positive render matrix (11 cases)
# ==============================================================================

_ca_positive_matrix() {
    local valid="$CHART_DIR/ci/valid-values.yaml" dev="$CHART_DIR/values-dev.yaml"

    # 1. production default + valid CI values -- this is THE production
    # render every §41-46 assertion below operates on.
    _ca_positive "production default + valid CI values" "01-production" -f "$valid"
    CA_RENDER_PROD=$(_ca_render_path "01-production")

    # 2. dev override (replicaCount: 1, no PDB).
    _ca_positive "dev override" "02-dev" -f "$valid" -f "$dev"
    CA_RENDER_DEV=$(_ca_render_path "02-dev")

    # 3. NetworkPolicy disabled.
    _ca_positive "NetworkPolicy disabled" "03-networkpolicy-disabled" \
        -f "$valid" --set networkPolicy.enabled=false
    CA_RENDER_NETPOL_DISABLED=$(_ca_render_path "03-networkpolicy-disabled")

    # 4. imagePullSecret + non-reserved podLabel/podAnnotation + nodeSelector
    # + toleration + priorityClassName + topologySpreadConstraints. Also
    # doubles as the §43 "additive custom podLabel" proof render and the
    # positive complement of the priorityClassName injection case (§38 #29):
    # a legitimate priorityClassName renders quoted and adds no host-*
    # keys.
    _ca_positive "imagePullSecret + non-reserved labels/annotations + scheduling knobs" "04-scheduling-knobs" \
        -f "$valid" \
        --set-json 'imagePullSecrets=[{"name":"regcred"}]' \
        --set-json 'podLabels={"team":"data-platform"}' \
        --set-json 'podAnnotations={"example.com/note":"hello"}' \
        --set-json 'nodeSelector={"disktype":"ssd"}' \
        --set-json 'tolerations=[{"key":"dedicated","operator":"Equal","value":"ldap","effect":"NoSchedule"}]' \
        --set priorityClassName=high-priority \
        --set-json 'topologySpreadConstraints=[{"maxSkew":1,"topologyKey":"kubernetes.io/hostname","whenUnsatisfiable":"ScheduleAnyway","labelSelector":{"matchLabels":{"app.kubernetes.io/name":"ch-oauth-ldap"}}}]'
    CA_RENDER_SCHEDULING=$(_ca_render_path "04-scheduling-knobs")
    assert_match "$CA_RENDER_SCHEDULING" 'name: regcred' F
    assert_match "$CA_RENDER_SCHEDULING" 'team: data-platform' F
    assert_match "$CA_RENDER_SCHEDULING" 'example.com/note: hello' F
    assert_match "$CA_RENDER_SCHEDULING" 'disktype: ssd' F
    assert_match "$CA_RENDER_SCHEDULING" 'key: dedicated' F
    assert_match "$CA_RENDER_SCHEDULING" 'priorityClassName: "high-priority"' F
    assert_match "$CA_RENDER_SCHEDULING" 'topologySpreadConstraints:' F
    assert_match "$CA_RENDER_SCHEDULING" 'maxSkew: 1' F
    assert_not_match "$CA_RENDER_SCHEDULING" 'hostNetwork' F
    assert_not_match "$CA_RENDER_SCHEDULING" 'hostPID' F
    assert_not_match "$CA_RENDER_SCHEDULING" 'hostIPC' F

    # 5. Explicit affinity replacement: the generated soft anti-affinity
    # must be fully replaced, not merged.
    _ca_positive "explicit affinity replacement" "05-explicit-affinity" \
        -f "$valid" \
        --set-json 'affinity={"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/arch","operator":"In","values":["amd64"]}]}]}}}'
    CA_RENDER_AFFINITY=$(_ca_render_path "05-explicit-affinity")
    assert_match "$CA_RENDER_AFFINITY" 'nodeAffinity:' F
    assert_not_match "$CA_RENDER_AFFINITY" 'podAntiAffinity:' F

    # 6. Substantive namespace selector.
    _ca_positive "substantive namespace selector" "06-namespace-selector" \
        -f "$valid" \
        --set-json 'networkPolicy.clickhouseNamespaceSelector={"matchLabels":{"kubernetes.io/metadata.name":"clickhouse"}}'
    CA_RENDER_NS_SELECTOR=$(_ca_render_path "06-namespace-selector")
    assert_match "$CA_RENDER_NS_SELECTOR" 'kubernetes.io/metadata.name: clickhouse' F

    # 7. Custom clusterDomain with --namespace analytics -- proves both
    # .Release.Namespace and clusterDomain participate in the generated
    # ClickHouse Service host.
    _ca_positive "custom clusterDomain with --namespace analytics" "07-custom-domain" \
        -f "$valid" --namespace analytics --set clusterDomain=k8s.example.internal
    CA_RENDER_CUSTOM_DOMAIN=$(_ca_render_path "07-custom-domain")
    assert_match "$CA_RENDER_CUSTOM_DOMAIN" "${_CA_RELEASE}-ch-oauth-ldap.analytics.svc.k8s.example.internal" F

    # 8. Valid non-default logLevel.
    _ca_positive "valid non-default logLevel" "08-loglevel-debug" \
        -f "$valid" --set logLevel=debug
    CA_RENDER_LOGLEVEL=$(_ca_render_path "08-loglevel-debug")
    assert_match "$CA_RENDER_LOGLEVEL" 'value: "debug"' F

    # 9. YAML-significant helper strings (#, ": ", leading "!") in
    # value-derived config fields that carry no chart-side content
    # restriction. This only needs to prove `helm template` still renders a
    # structurally valid Kubernetes ConfigMap (the quote/toYaml
    # serialization convention keeps these YAML-safe inside the embedded
    # config; ci/lib/embedded-assertions.sh parses that embedded content).
    _ca_positive "YAML-significant helper strings (#, \": \", leading !)" "09-yaml-significant-strings" \
        -f "$valid" \
        --set-string 'identity.username_match=weird: value' \
        --set-string 'roles.roles_transform=#comment-like' \
        --set-string 'ldap.role_cn_prefix=!bang'

    # 10. Directory value containing a literal & (XML-escaping input case;
    # the embedded XML's escaping correctness is
    # ci/lib/embedded-assertions.sh's concern -- here we only need the
    # Kubernetes ConfigMap itself to still render and validate).
    _ca_positive "directory value containing literal &" "10-ampersand-directory-value" \
        -f "$valid" --set-string 'ldap.user_base_dn=ou=a&b,dc=x,dc=y'

    # 11. A matchExpressions-only pod selector using a *positive* operator
    # (In) is accepted -- the complement of §38 #36/#37, which reject the
    # DoesNotExist/NotIn-only allow-all shapes. Also exercises a slash-
    # qualified topologyKey, the complement of §38 #34.
    _ca_positive "In-expression pod selector + qualified topologyKey" "11-in-expression-selector" \
        -f "$valid" \
        --set-json 'networkPolicy.clickhousePodSelector={"matchExpressions":[{"key":"app.kubernetes.io/name","operator":"In","values":["clickhouse"]}]}' \
        --set podAntiAffinity.topologyKey=topology.kubernetes.io/zone
    CA_RENDER_IN_SELECTOR=$(_ca_render_path "11-in-expression-selector")
    assert_match "$CA_RENDER_IN_SELECTOR" 'operator: In' F
    assert_match "$CA_RENDER_IN_SELECTOR" 'topologyKey: "topology.kubernetes.io/zone"' F
}

# ==============================================================================
# §38 Negative render matrix (40 numbered cases; #23 is table-driven over 5
# reserved podLabels keys, so this runs 44 `helm template` invocations)
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

    # ------------------------------------------------------------------------
    # 25-40: injection guards (validate rules 0 and 16-20). Each payload is
    # the shape that, before those rules and the quoting/`toYaml` fixes in
    # the templates, actually escaped its YAML context; see the chart's
    # templates/_helpers.tpl for the two independent layers now in place.
    # ------------------------------------------------------------------------

    # 25 -- a line break in the group base DN used to terminate the
    # ClickHouse ConfigMap's `ldap.xml: |` block scalar and render a whole
    # extra resource (a public LoadBalancer Service selecting the helper
    # pods). Beyond the stable message, prove nothing of the payload was
    # rendered.
    local lb_payload
    lb_payload=$'dc=x\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: pwn-public-ldap\nspec:\n  type: LoadBalancer\n  selector:\n    app.kubernetes.io/name: ch-oauth-ldap\n  ports:\n  - port: 389\n    targetPort: 3389\n  junk: '
    _ca_negative "line break in ldap.group_base_dn (block-scalar breakout to a LoadBalancer Service)" \
        "ldap.group_base_dn must not contain line breaks" \
        --set-string "ldap.group_base_dn=$lb_payload"
    assert_not_match "$(_ca_negative_stdout "line break in ldap.group_base_dn (block-scalar breakout to a LoadBalancer Service)")" 'pwn-public-ldap' F
    assert_not_match "$(_ca_negative_stdout "line break in ldap.group_base_dn (block-scalar breakout to a LoadBalancer Service)")" 'LoadBalancer' F

    # 26 -- carriage return, not just \n.
    _ca_negative "carriage return in ldap.user_base_dn" \
        "ldap.user_base_dn must not contain line breaks" \
        --set-string "ldap.user_base_dn=$(printf 'dc=x\rdc=y')"

    # 27
    _ca_negative "line break in ldap.user_rdn_attribute" \
        "ldap.user_rdn_attribute must not contain line breaks" \
        --set-string "ldap.user_rdn_attribute=$(printf 'uid\ncn')"

    # 28
    _ca_negative "line break in ldap.role_cn_prefix" \
        "ldap.role_cn_prefix must not contain line breaks" \
        --set-string "ldap.role_cn_prefix=$(printf 'a\nb')"

    # 29 -- the pod-spec injection: an unquoted priorityClassName used to
    # add `hostNetwork: true` to the pod spec. Prove the payload is absent
    # from whatever was rendered (nothing, per _ca_negative).
    _ca_negative "line break in priorityClassName (pod-spec hostNetwork injection)" \
        "priorityClassName must not contain line breaks" \
        --set-string "priorityClassName=$(printf 'x\n      hostNetwork: true')"
    assert_not_match "$(_ca_negative_stdout "line break in priorityClassName (pod-spec hostNetwork injection)")" 'hostNetwork' F

    # 30
    _ca_negative "priorityClassName with a double quote" \
        "priorityClassName must be a lowercase RFC 1123 subdomain" \
        --set-string 'priorityClassName=a"b'

    # 31 -- a `"` in image.tag used to close the hand-written quotes around
    # `image:` and inject sibling container keys.
    _ca_negative "double quote in image.tag" \
        "image.tag must be an OCI tag ([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})" \
        --set-string 'image.tag=a"b'

    # 32
    _ca_negative "line break in image.repository" \
        "image.repository must not contain line breaks" \
        --set-string "image.repository=$(printf 'ghcr.io/x\ny')"

    # 33
    _ca_negative "invalid image.pullPolicy" \
        "image.pullPolicy must be one of Always, IfNotPresent, Never" \
        --set-string 'image.pullPolicy=Sometimes'

    # 34
    _ca_negative "line break in podAntiAffinity.topologyKey" \
        "podAntiAffinity.topologyKey must not contain line breaks" \
        --set-string "podAntiAffinity.topologyKey=$(printf 'kubernetes.io/hostname\n                hostIPC: true')"

    # 35 -- a "number" that is really a string with a trailing injected key.
    _ca_negative "non-integer podAntiAffinity.weight" \
        "podAntiAffinity.weight must be an integer between 1 and 100" \
        --set-string "podAntiAffinity.weight=$(printf '1\n              hostIPC: true')"

    # 36
    _ca_negative "DoesNotExist-only pod selector (allow-all in disguise)" \
        "networkPolicy.clickhousePodSelector must include a positive term" \
        --set-json 'networkPolicy.clickhousePodSelector={"matchExpressions":[{"key":"bogus","operator":"DoesNotExist"}]}'

    # 37
    _ca_negative "NotIn-only namespace selector (allow-all in disguise)" \
        "networkPolicy.clickhouseNamespaceSelector must include a positive term" \
        --set-json 'networkPolicy.clickhouseNamespaceSelector={"matchExpressions":[{"key":"bogus","operator":"NotIn","values":["x"]}]}'

    # 38 -- a string where the embedded config.yaml emits a bare boolean.
    _ca_negative "identity.require_email_verified as a string" \
        "identity.require_email_verified must be a boolean (true/false), not a string" \
        --set-string 'identity.require_email_verified=true'

    # 39
    _ca_negative "non-integer replicaCount" \
        "replicaCount must be an integer" \
        --set-string "replicaCount=$(printf '2\n  hostIPC: true')"

    # 40 -- the name overrides feed labels and resource names.
    _ca_negative "line break in nameOverride" \
        "nameOverride must not contain line breaks" \
        --set-string "nameOverride=$(printf 'a\n    evil: x')"
    _ca_negative "invalid fullnameOverride" \
        "fullnameOverride must be a lowercase RFC 1123 label" \
        --set-string 'fullnameOverride=Not_A_Label'
    _ca_negative "invalid clusterDomain characters" \
        "clusterDomain must be a lowercase DNS domain" \
        --set-string 'clusterDomain=k8s_local'
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
    assert_match "$block" 'imagePullPolicy: "IfNotPresent"' F
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
    assert_match "$block" 'weight: 100' F
    assert_match "$block" 'topologyKey: "kubernetes.io/hostname"' F
    # No host namespace sharing, ever -- the positive complement of the
    # pod-spec injection cases in §38 (#29, #34, #35, #39).
    assert_not_match "$block" 'hostNetwork' F
    assert_not_match "$block" 'hostPID' F
    assert_not_match "$block" 'hostIPC' F
    assert_not_match "$block" 'hostPort' F
    assert_not_match "$block" 'privileged' F
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
    # Values are quoted (the helper emits them through `quote`).
    assert_count "$f" '^      app\.kubernetes\.io/name: "ch-oauth-ldap"$' 3 E
    assert_count "$f" "^      app\\.kubernetes\\.io/instance: \"${_CA_RELEASE}\"\$" 3 E

    # Deployment pod-template metadata.labels (8-space indent, per
    # `nindent 8` in templates/deployment.yaml).
    assert_count "$f" '^        app\.kubernetes\.io/name: "ch-oauth-ldap"$' 1 E
    assert_count "$f" "^        app\\.kubernetes\\.io/instance: \"${_CA_RELEASE}\"\$" 1 E

    # Default anti-affinity peer's labelSelector.matchLabels (20-space
    # indent, per `nindent 20` in templates/deployment.yaml).
    assert_count "$f" '^                    app\.kubernetes\.io/name: "ch-oauth-ldap"$' 1 E
    assert_count "$f" "^                    app\\.kubernetes\\.io/instance: \"${_CA_RELEASE}\"\$" 1 E

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
