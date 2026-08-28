# integration/clickhouse/Dockerfile
#
# Multi-stage build producing a single repository-local runtime image that
# contains BOTH `ch-oauth-ldap` and `synthetic-idp`, built from this repo's
# own source tree — never a published/prebuilt helper image (see
# "Repository-local helper/IdP image" in the phase-3 plan). compose.yml
# selects which binary a given service actually runs via its `command:`.
#
# The runtime stage deliberately is NOT `scratch`:
#   - `curl`            backs the synthetic-idp HTTP healthcheck;
#   - `netcat-openbsd`  backs the ch-oauth-ldap TCP-readiness healthcheck
#                        (`nc -z 127.0.0.1 389` — LDAP has no HTTP endpoint,
#                        see "Mechanically defined service readiness");
#   - `ca-certificates` is included on general principle even though this
#                        fixture's synthetic-idp is loopback plain HTTP.

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

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=integration-test" -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap
# synthetic-idp has no main.version symbol to stamp.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/synthetic-idp ./cmd/synthetic-idp

FROM alpine:3.24
RUN apk add --no-cache ca-certificates curl netcat-openbsd
COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap
COPY --from=build /out/synthetic-idp /bin/synthetic-idp
# No ENTRYPOINT: each compose.yml service supplies its own `command:`.
