{{/*
ch-oauth-ldap Helm helpers: names, labels, the ClickHouse Service host, XML
escaping, and the one centralized fail-closed validation helper every
emitted resource template must invoke.

`helm lint` does NOT enforce `fail`/`required` (true on Helm 4.1.4 and on
Helm 3) — only normal rendering (`helm template`/install/upgrade) does.
Verify validation with `helm template`, not lint.
*/}}

{{- define "ch-oauth-ldap.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ch-oauth-ldap.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Immutable selector labels. Service/Deployment-selector/PDB/NetworkPolicy
templates (and default anti-affinity) must all use exactly this, never
arbitrary pod labels, so a `podLabels` value can never make the pod
template disagree with what those resources select on.
*/}}
{{- define "ch-oauth-ldap.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ch-oauth-ldap.name" . | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{/*
Full common labels. Every one of these keys is chart-managed and reserved
(see ch-oauth-ldap.reservedLabelKeys below) — `podLabels` may only add keys,
never these.
*/}}
{{- define "ch-oauth-ldap.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | quote }}
{{ include "ch-oauth-ldap.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}

{{/*
The reserved config-checksum pod-template annotation key. The Deployment
template (templates/deployment.yaml) sets this itself from the rendered
config ConfigMap to force a rolling replacement on config change;
`podAnnotations` must never be allowed to define it.
*/}}
{{- define "ch-oauth-ldap.configChecksumAnnotationKey" -}}
checksum/ch-oauth-ldap-config
{{- end -}}

{{/*
The ClickHouse-facing Service DNS name, rendered into the LDAP XML
ConfigMap's <host>. Proves both .Release.Namespace and clusterDomain
participate — do not hardcode either.
*/}}
{{- define "ch-oauth-ldap.clickhouseServiceHost" -}}
{{- printf "%s.%s.svc.%s" (include "ch-oauth-ldap.fullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- end -}}

{{/*
The full image reference the Deployment pulls: image.repository joined to
image.tag. image.tag is validated above (ch-oauth-ldap.re.imageTag) to be
EITHER a normal OCI tag, joined with ":" (repository:tag — the
ldap-<sha> default), OR the digest-pinned form the README recommends for a
hard-immutability guarantee, an "@sha256:<digest>" string that already
carries its own "@" separator and must be concatenated with NO colon
(repository@sha256:digest — "repository:@sha256:digest" is not valid OCI
syntax and no registry resolves it).
*/}}
{{- define "ch-oauth-ldap.imageRef" -}}
{{- $repository := toString .Values.image.repository }}
{{- $tag := toString .Values.image.tag }}
{{- if hasPrefix "@" $tag }}
{{- printf "%s%s" $repository $tag -}}
{{- else }}
{{- printf "%s:%s" $repository $tag -}}
{{- end }}
{{- end -}}

{{/*
XML-escape a value-derived text node. Fixed replacement order: & first,
then <, then >, so entities the first pass introduces are never
re-escaped. Do NOT run the fixed, already-escaped membership-filter
literal through this — it must appear exactly once, verbatim.
*/}}
{{- define "ch-oauth-ldap.xmlEscape" -}}
{{- $s := . | toString }}
{{- $s = $s | replace "&" "&amp;" }}
{{- $s = $s | replace "<" "&lt;" }}
{{- $s = $s | replace ">" "&gt;" }}
{{- $s -}}
{{- end -}}

{{/*
True ("true") iff a Kubernetes LabelSelector-shaped value has at least one
non-empty matchLabels entry or at least one matchExpressions entry. Context
is the selector value itself (not the root), so call as e.g.:
  {{ include "ch-oauth-ldap.selectorSubstantive" .Values.networkPolicy.clickhousePodSelector }}
*/}}
{{- define "ch-oauth-ldap.selectorSubstantive" -}}
{{- $sel := . | default dict }}
{{- $ok := false }}
{{- if $sel }}
{{- $ml := $sel.matchLabels | default dict }}
{{- $me := $sel.matchExpressions | default list }}
{{- if or (gt (len $ml) 0) (gt (len $me) 0) }}
{{- $ok = true }}
{{- end }}
{{- end }}
{{- if $ok }}true{{- end -}}
{{- end -}}

{{/*
True ("true") iff a LabelSelector-shaped value contains at least one term
that can only match a *subset* of pods/namespaces: a matchLabels entry, or
a matchExpressions entry whose operator is In or Exists. A selector built
solely from DoesNotExist / NotIn expressions (e.g. `{key: bogus, operator:
DoesNotExist}`) is syntactically substantive but matches every object that
lacks the key — an allow-all NetworkPolicy peer in disguise — so it is NOT
positive. Unknown operators are not positive either (fail closed). Context
is the selector value itself, as for selectorSubstantive.
*/}}
{{- define "ch-oauth-ldap.selectorPositive" -}}
{{- $sel := . | default dict }}
{{- $ok := false }}
{{- if $sel }}
{{- $ml := $sel.matchLabels | default dict }}
{{- if gt (len $ml) 0 }}
{{- $ok = true }}
{{- end }}
{{- range ($sel.matchExpressions | default list) }}
{{- if kindIs "map" . }}
{{- if has (toString (index . "operator" | default "")) (list "In" "Exists") }}
{{- $ok = true }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if $ok }}true{{- end -}}
{{- end -}}

{{/*
Regex vocabulary for the validation rules below. Names/keys interpolated
into Kubernetes fields are constrained to the shapes the API server itself
accepts, which as a side effect excludes every YAML-significant character
(newline, quote, `: `, `#`, ...) from those fields.
*/}}
{{- define "ch-oauth-ldap.re.dnsLabel" -}}^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?${{- end -}}
{{- define "ch-oauth-ldap.re.dnsSubdomain" -}}^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$
{{- end -}}
{{- define "ch-oauth-ldap.re.topologyKey" -}}^[a-z0-9]([-a-z0-9.]*[a-z0-9])?(/[a-zA-Z0-9]([-a-zA-Z0-9_.]*[a-zA-Z0-9])?)?$
{{- end -}}
{{- define "ch-oauth-ldap.re.imageRepository" -}}^[a-z0-9]([-a-z0-9._]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]([-a-z0-9._]*[a-z0-9])?)*$
{{- end -}}
{{- /*
Accepts either a normal OCI tag, or the digest-pinned form the README
recommends for a hard-immutability guarantee: an `@sha256:<64 lowercase
hex>` reference, which ch-oauth-ldap.imageRef below joins onto
image.repository WITHOUT a colon (repository@sha256:... — never
repository:@sha256:...).
*/ -}}
{{- define "ch-oauth-ldap.re.imageTag" -}}^(@sha256:[0-9a-f]{64}|[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$
{{- end -}}
{{- define "ch-oauth-ldap.re.integer" -}}^[0-9]+$
{{- end -}}

{{/*
Centralized fail-closed validation (plan §5). Every emitted resource
template invokes this exactly once, e.g.:
  {{- include "ch-oauth-ldap.validate" . }}
It renders nothing when every rule passes; on a violation it calls `fail`
with one of the fixed, stable messages below, which halts rendering with a
non-zero `helm template`/install/upgrade exit. Rule order follows the
plan's numbered list; sabotage/negative-render-matrix cases are one
violation at a time from otherwise-valid values, so ordering does not
affect which message a given case gets.

Two families of rules exist purely to keep the rendered YAML injection-
proof (rules 16-20 below): (a) no value that is written into a YAML block
scalar (the two ConfigMaps' embedded payloads) may contain a line break,
and (b) every value interpolated as a bare Kubernetes scalar must match
the shape the API server accepts for that field. The templates ALSO quote
or `toYaml` every such interpolation, so these rules are the first of two
independent layers, not the only one.
*/}}
{{- define "ch-oauth-ldap.validate" -}}

{{- /* 0. replicaCount must be an integer (not a string that merely starts with digits). */ -}}
{{- if not (regexMatch (include "ch-oauth-ldap.re.integer" .) (toString .Values.replicaCount)) }}
{{- fail "replicaCount must be an integer" }}
{{- end }}

{{- /* 1. replicaCount must be at least 1. */ -}}
{{- if lt (.Values.replicaCount | int) 1 }}
{{- fail "replicaCount must be at least 1" }}
{{- end }}

{{- /* 2. image.tag is required — no mutable default, no `main`. */ -}}
{{- if eq (trim (.Values.image.tag | default "")) "" }}
{{- fail "image.tag is required; pin a published ch-oauth-ldap image" }}
{{- end }}

{{- /*
3 & 4. oauth.expected_audiences: empty list, or a list containing only
whitespace-only entries, share one message — both mean "no usable
audience".
*/ -}}
{{- $hasAudience := false }}
{{- range .Values.oauth.expected_audiences }}
{{- if ne (trim (toString .)) "" }}
{{- $hasAudience = true }}
{{- end }}
{{- end }}
{{- if not $hasAudience }}
{{- fail "oauth.expected_audiences must contain at least one non-empty audience" }}
{{- end }}

{{- /* 5. At least one of issuer/jwks_url must be set. */ -}}
{{- if and (eq (trim (.Values.oauth.expected_issuer | default "")) "") (eq (trim (.Values.oauth.jwks_url | default "")) "") }}
{{- fail "set oauth.expected_issuer and/or oauth.jwks_url" }}
{{- end }}

{{- /* 6. logLevel must be one the binary's CH_OAUTH_LDAP_LOG_LEVEL accepts. */ -}}
{{- if not (has .Values.logLevel (list "debug" "info" "warn" "error")) }}
{{- fail "logLevel must be one of debug, info, warn, error" }}
{{- end }}

{{- /* 7. clusterDomain feeds the generated ClickHouse Service host. */ -}}
{{- if eq (trim (.Values.clusterDomain | default "")) "" }}
{{- fail "clusterDomain must not be empty" }}
{{- end }}

{{- /*
8. NetworkPolicy pod selector: required substantive whenever the policy is
enabled (and therefore renders) — an empty/absent selector here would mean
"select nothing", which is never valid input, unlike the namespace
selector's "not supplied" case below.
*/ -}}
{{- if .Values.networkPolicy.enabled }}
{{- if ne (include "ch-oauth-ldap.selectorSubstantive" .Values.networkPolicy.clickhousePodSelector) "true" }}
{{- fail "networkPolicy.clickhousePodSelector must select at least one label or expression" }}
{{- end }}
{{- end }}

{{- /*
9. NetworkPolicy namespace selector: an outer `{}` (no keys at all) means
"not supplied" and is valid (no namespace restriction). Once any key
(matchLabels and/or matchExpressions) is present at all, the selector must
be substantive — a nested-empty form such as `{matchLabels: {}}` is a
supplied-but-match-nothing shape and is rejected.
*/ -}}
{{- $nsSel := .Values.networkPolicy.clickhouseNamespaceSelector | default dict }}
{{- if gt (len $nsSel) 0 }}
{{- if ne (include "ch-oauth-ldap.selectorSubstantive" $nsSel) "true" }}
{{- fail "networkPolicy.clickhouseNamespaceSelector must contain at least one label or expression when set" }}
{{- end }}
{{- end }}

{{- /*
10. ldap.listen is chart-fixed to the container's published port; the
binary passes it straight to net.Listen, so an operator-supplied value —
even the chart's own ":3389" — would change the real production listener
out from under the Service/probes/NetworkPolicy that assume it. Reject the
key's mere presence, not just a "wrong" value.
*/ -}}
{{- $ldap := .Values.ldap | default dict }}
{{- if hasKey $ldap "listen" }}
{{- fail "ldap.listen is fixed to :3389 by the chart; remove this value" }}
{{- end }}

{{- /*
11-13. These three mirror fields cmd/ch-oauth-ldap's own config.go already
refuses to start without (see validateConfig) — Helm rejecting them early
just fails closed before a broken ConfigMap ever ships. No RDN/DN syntax
parsing here; only the empty/whitespace-only cases the binary would also
reject as unset.
*/ -}}
{{- if eq (trim ($ldap.user_base_dn | default "")) "" }}
{{- fail "ldap.user_base_dn must not be empty" }}
{{- end }}
{{- if eq (trim ($ldap.group_base_dn | default "")) "" }}
{{- fail "ldap.group_base_dn must not be empty" }}
{{- end }}
{{- if eq (trim ($ldap.user_rdn_attribute | default "")) "" }}
{{- fail "ldap.user_rdn_attribute must not be empty" }}
{{- end }}

{{- /*
14. podLabels is additive only — never let an operator-supplied label
shadow a chart-managed one and silently disagree with the
Deployment/Service/PDB/NetworkPolicy selector labels.
*/ -}}
{{- $podLabels := .Values.podLabels | default dict }}
{{- range (list "helm.sh/chart" "app.kubernetes.io/name" "app.kubernetes.io/instance" "app.kubernetes.io/version" "app.kubernetes.io/managed-by") }}
{{- if hasKey $podLabels . }}
{{- fail (printf "podLabels must not override chart-managed label %s" .) }}
{{- end }}
{{- end }}

{{- /* 15. podAnnotations must not shadow the chart-managed checksum annotation. */ -}}
{{- $podAnnotations := .Values.podAnnotations | default dict }}
{{- if hasKey $podAnnotations (include "ch-oauth-ldap.configChecksumAnnotationKey" .) }}
{{- fail "podAnnotations must not override checksum/ch-oauth-ldap-config" }}
{{- end }}

{{- /*
16. No line breaks in any value written into an embedded block scalar or a
resource name/label. The ClickHouse ldap.xml and the helper config.yaml are
emitted as YAML scalars built by `toYaml` (injection-proof by construction);
this rule is the independent second layer, and it also keeps the XML text
nodes single-line as ClickHouse's config expects.
*/ -}}
{{- range $name, $value := (dict
      "ldap.user_base_dn" $ldap.user_base_dn
      "ldap.group_base_dn" $ldap.group_base_dn
      "ldap.user_rdn_attribute" $ldap.user_rdn_attribute
      "ldap.role_cn_prefix" $ldap.role_cn_prefix
      "clusterDomain" .Values.clusterDomain
      "nameOverride" .Values.nameOverride
      "fullnameOverride" .Values.fullnameOverride
      "image.repository" .Values.image.repository
      "image.tag" .Values.image.tag
      "priorityClassName" .Values.priorityClassName
      "podAntiAffinity.topologyKey" .Values.podAntiAffinity.topologyKey) }}
{{- $s := $value | default "" | toString }}
{{- if or (contains "\n" $s) (contains "\r" $s) }}
{{- fail (printf "%s must not contain line breaks" $name) }}
{{- end }}
{{- end }}

{{- /*
17. Names interpolated into Kubernetes metadata/labels/pod-spec fields
must be exactly the shapes the API server accepts (RFC 1123 label for the
chart-name overrides, RFC 1123 subdomain for clusterDomain and
priorityClassName, the qualified-name shape for topologyKey).
*/ -}}
{{- if .Values.nameOverride }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.dnsLabel" .) (toString .Values.nameOverride)) }}
{{- fail "nameOverride must be a lowercase RFC 1123 label (a-z, 0-9, '-'; max 63 chars)" }}
{{- end }}
{{- end }}
{{- if .Values.fullnameOverride }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.dnsLabel" .) (toString .Values.fullnameOverride)) }}
{{- fail "fullnameOverride must be a lowercase RFC 1123 label (a-z, 0-9, '-'; max 63 chars)" }}
{{- end }}
{{- end }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.dnsSubdomain" .) (toString .Values.clusterDomain)) }}
{{- fail "clusterDomain must be a lowercase DNS domain (e.g. cluster.local)" }}
{{- end }}
{{- if .Values.priorityClassName }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.dnsSubdomain" .) (toString .Values.priorityClassName)) }}
{{- fail "priorityClassName must be a lowercase RFC 1123 subdomain" }}
{{- end }}
{{- end }}
{{- if .Values.podAntiAffinity.enabled }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.topologyKey" .) (toString .Values.podAntiAffinity.topologyKey)) }}
{{- fail "podAntiAffinity.topologyKey must be a Kubernetes label key (e.g. kubernetes.io/hostname)" }}
{{- end }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.integer" .) (toString .Values.podAntiAffinity.weight)) }}
{{- fail "podAntiAffinity.weight must be an integer between 1 and 100" }}
{{- end }}
{{- if or (lt (.Values.podAntiAffinity.weight | int) 1) (gt (.Values.podAntiAffinity.weight | int) 100) }}
{{- fail "podAntiAffinity.weight must be an integer between 1 and 100" }}
{{- end }}
{{- end }}

{{- /* 18. Image reference components: an OCI repository path and an OCI tag. */ -}}
{{- if not (regexMatch (include "ch-oauth-ldap.re.imageRepository" .) (toString .Values.image.repository)) }}
{{- fail "image.repository must be a lowercase OCI repository reference (registry[:port]/path)" }}
{{- end }}
{{- if not (regexMatch (include "ch-oauth-ldap.re.imageTag" .) (toString .Values.image.tag)) }}
{{- fail "image.tag must be an OCI tag ([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}) or a digest reference (@sha256:<64 lowercase hex>)" }}
{{- end }}
{{- if not (has (toString .Values.image.pullPolicy) (list "Always" "IfNotPresent" "Never")) }}
{{- fail "image.pullPolicy must be one of Always, IfNotPresent, Never" }}
{{- end }}

{{- /*
19. NetworkPolicy selectors must be *positive*: a selector whose only terms
are DoesNotExist/NotIn expressions matches every pod/namespace lacking the
key, i.e. it is allow-all in disguise. Rules 8-9 reject the empty shapes;
this rejects the non-empty-but-allow-all ones.
*/ -}}
{{- if .Values.networkPolicy.enabled }}
{{- if ne (include "ch-oauth-ldap.selectorPositive" .Values.networkPolicy.clickhousePodSelector) "true" }}
{{- fail "networkPolicy.clickhousePodSelector must include a positive term (a matchLabels entry or an In/Exists matchExpression); DoesNotExist/NotIn-only selectors match every pod" }}
{{- end }}
{{- if gt (len $nsSel) 0 }}
{{- if ne (include "ch-oauth-ldap.selectorPositive" $nsSel) "true" }}
{{- fail "networkPolicy.clickhouseNamespaceSelector must include a positive term (a matchLabels entry or an In/Exists matchExpression); DoesNotExist/NotIn-only selectors match every namespace" }}
{{- end }}
{{- end }}
{{- end }}

{{- /*
20. The one boolean the helper config.yaml emits bare must really be a
boolean — a string here would be interpolated unquoted into the embedded
YAML.
*/ -}}
{{- if not (kindIs "bool" .Values.identity.require_email_verified) }}
{{- fail "identity.require_email_verified must be a boolean (true/false), not a string" }}
{{- end }}

{{- end -}}

{{/*
The ClickHouse-side ldap.xml payload, as one multi-line string. The
ConfigMap template emits `include "ch-oauth-ldap.ldapXML" . | toYaml`, so
the payload is serialized as a YAML scalar by construction — a value can
never terminate the block scalar and start a new resource, whatever it
contains. Every value-derived text node is XML-escaped (& before < before
>); the membership filter is already escaped in the fixture and is emitted
verbatim, exactly once — do not run it through the escape helper. Ends
with a newline so the decoded payload is byte-identical to the former
`ldap.xml: |` (clip) block-scalar form.
*/}}
{{- define "ch-oauth-ldap.ldapXML" -}}
<clickhouse>
    <ldap_servers>
        <oauth_helper>
            <host>{{ include "ch-oauth-ldap.xmlEscape" (include "ch-oauth-ldap.clickhouseServiceHost" .) }}</host>
            <port>389</port>
            <bind_dn>{{ include "ch-oauth-ldap.xmlEscape" .Values.ldap.user_rdn_attribute }}={user_name},{{ include "ch-oauth-ldap.xmlEscape" .Values.ldap.user_base_dn }}</bind_dn>
            <verification_cooldown>0</verification_cooldown>
            <enable_tls>no</enable_tls>
        </oauth_helper>
    </ldap_servers>

    <user_directories>
        <ldap>
            <server>oauth_helper</server>
            <role_mapping>
                <base_dn>{{ include "ch-oauth-ldap.xmlEscape" .Values.ldap.group_base_dn }}</base_dn>
                <scope>subtree</scope>
                <search_filter>(&amp;(objectClass=groupOfNames)(member={bind_dn}))</search_filter>
                <attribute>cn</attribute>
                <prefix>{{ include "ch-oauth-ldap.xmlEscape" .Values.ldap.role_cn_prefix }}</prefix>
            </role_mapping>
        </ldap>
    </user_directories>
</clickhouse>
{{ end -}}

{{/*
The helper's own config.yaml payload, as one multi-line string; emitted by
templates/configmap.yaml through `toYaml` for the same by-construction
reason as ldapXML above. Mirrors cmd/ch-oauth-ldap/config.go's Config
exactly: the four top-level families oauth/identity/roles/ldap plus the
chart-fixed `listen`. Every value-derived scalar goes through `quote`;
lists/maps through `toYaml`; the one boolean renders bare (validate rule 20
guarantees it is a real boolean).
*/}}
{{- define "ch-oauth-ldap.configYAML" -}}
oauth:
  expected_issuer: {{ .Values.oauth.expected_issuer | quote }}
  jwks_url: {{ .Values.oauth.jwks_url | quote }}
  expected_audiences: {{- toYaml .Values.oauth.expected_audiences | nindent 4 }}
  username_claim: {{ .Values.oauth.username_claim | quote }}
  groups_claim: {{ .Values.oauth.groups_claim | quote }}
  verifier_leeway: {{ .Values.oauth.verifier_leeway | quote }}
  required_scopes: {{- toYaml .Values.oauth.required_scopes | nindent 4 }}
  jwks_cache_lifetime: {{ .Values.oauth.jwks_cache_lifetime | quote }}
  token_cache_lifetime: {{ .Values.oauth.token_cache_lifetime | quote }}
identity:
  username_match: {{ .Values.identity.username_match | quote }}
  require_email_verified: {{ .Values.identity.require_email_verified }}
  allowed_email_domains: {{- toYaml .Values.identity.allowed_email_domains | nindent 4 }}
  allowed_hosted_domains: {{- toYaml .Values.identity.allowed_hosted_domains | nindent 4 }}
  denied_usernames: {{- toYaml .Values.identity.denied_usernames | nindent 4 }}
roles:
  roles_mapping: {{- toYaml .Values.roles.roles_mapping | nindent 4 }}
  roles_filter: {{ .Values.roles.roles_filter | quote }}
  roles_transform: {{ .Values.roles.roles_transform | quote }}
ldap:
  user_base_dn: {{ .Values.ldap.user_base_dn | quote }}
  group_base_dn: {{ .Values.ldap.group_base_dn | quote }}
  user_rdn_attribute: {{ .Values.ldap.user_rdn_attribute | quote }}
  role_cn_prefix: {{ .Values.ldap.role_cn_prefix | quote }}
  listen: ":3389"
{{ end -}}
