# integration/clickhouse/Dockerfile
#
# Multi-stage build producing a single repository-local runtime image that
# contains `ch-oauth-ldap`, `synthetic-idp`, the HA fixture's
# `ldap-session-probe` (phase-5 §15.1/§18.1), AND the phase-1 wire-capture
# fixture's `ldap-wire-recorder` (issue #33 phase 1 §12), built from this
# repo's own source tree — never a published/prebuilt helper image (see
# "Repository-local helper/IdP image" in the phase-3 plan). compose.yml
# selects which binary a given service actually runs via its `command:`;
# the HA runner instead reaches ldap-session-probe with `compose exec -T`
# inside the stable synthetic-idp container (see the phase-5 plan §18.1),
# so it must be present in the same image that container runs.
#
# The runtime stage deliberately is NOT `scratch`:
#   - `curl`            backs the synthetic-idp HTTP healthcheck;
#   - `netcat-openbsd`  backs the ch-oauth-ldap TCP-readiness healthcheck
#                        (`nc -z 127.0.0.1 389` — LDAP has no HTTP endpoint,
#                        see "Mechanically defined service readiness");
#   - `ca-certificates` is included on general principle even though this
#                        fixture's synthetic-idp is loopback plain HTTP.
#
# ldap-wire-recorder's OWN capture-fixture healthcheck is deliberately NOT
# `nc -z`: an accepted-but-unauthenticated TCP probe every 2s would itself
# count as a captured LDAP session and break the fixture's required N == 1
# session invariant (issue #33 phase 1 plan, Amendment 1). Its readiness is
# instead a plain FILE the recorder process creates once listening, under
# `/run/ldap-wirecapture/`, polled by the capture Compose's healthcheck —
# no network connection, no session. See
# `integration/clickhouse/compose-wirecapture.yml` and
# `integration/clickhouse/capture-ldap-wire.sh` for that wiring.

FROM golang:1.26-alpine AS build
WORKDIR /src

# go.mod's replace directives point at ./third_party (a local path, not a
# proxy-fetchable module), so third_party must be present before `go mod
# download` — it cannot be deferred behind go.mod/go.sum the way a normal
# proxy-only dependency layer would be.
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY integration/clickhouse/ha ./integration/clickhouse/ha
COPY integration/clickhouse/wirecapture ./integration/clickhouse/wirecapture

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=integration-test" -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap
# synthetic-idp, ldap-session-probe, and ldap-wire-recorder have no
# main.version symbol to stamp.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/synthetic-idp ./cmd/synthetic-idp
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/ldap-session-probe ./integration/clickhouse/ha/session-probe
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/ldap-wire-recorder ./integration/clickhouse/wirecapture

FROM alpine:3.24
RUN apk add --no-cache ca-certificates curl netcat-openbsd
COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap
COPY --from=build /out/synthetic-idp /bin/synthetic-idp
COPY --from=build /out/ldap-session-probe /bin/ldap-session-probe
COPY --from=build /out/ldap-wire-recorder /bin/ldap-wire-recorder
# No ENTRYPOINT: each compose.yml service supplies its own `command:`.
# No USER: the phase-1 plan's capture Compose relies on the runtime stage
# staying root (issue #33 phase 1 plan §14).
