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
app.kubernetes.io/name: {{ include "ch-oauth-ldap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Full common labels. Every one of these keys is chart-managed and reserved
(see ch-oauth-ldap.reservedLabelKeys below) — `podLabels` may only add keys,
never these.
*/}}
{{- define "ch-oauth-ldap.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ch-oauth-ldap.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The reserved config-checksum pod-template annotation key. The Deployment
template (owned elsewhere) sets this itself from the rendered ConfigMaps to
force a rolling replacement on config change; `podAnnotations` must never
be allowed to define it.
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
Centralized fail-closed validation (plan §5). Every emitted resource
template invokes this exactly once, e.g.:
  {{- include "ch-oauth-ldap.validate" . }}
It renders nothing when every rule passes; on a violation it calls `fail`
with one of the fixed, stable messages below, which halts rendering with a
non-zero `helm template`/install/upgrade exit. Rule order follows the
plan's numbered list; sabotage/negative-render-matrix cases are one
violation at a time from otherwise-valid values, so ordering does not
affect which message a given case gets.
*/}}
{{- define "ch-oauth-ldap.validate" -}}

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

{{- end -}}
