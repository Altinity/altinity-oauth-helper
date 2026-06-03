# Multi-stage Grafana image that bakes a locally-patched build of the
# Altinity ClickHouse plugin (vertamedia-clickhouse-datasource).
#
# The patch (plugin/0001-jwt-as-password.patch, ~30 LoC) teaches the
# plugin to substitute the logged-in Grafana user's OAuth access token
# as the HTTP Basic-auth password on every outbound query, so OSS
# ClickHouse + the ch-jwt-verify sidecar can authenticate the request
# as the actual user (not a shared service account). Tracked upstream
# at https://github.com/Altinity/clickhouse-grafana/issues/622.
#
# First build is ~3-5 minutes (Go module fetch + frontend bundle).
# Subsequent builds are cached.

# ---- 1. backend: clone, patch, mage build ----
FROM golang:1.26 AS plugin-go-builder
ARG ALTINITY_PLUGIN_TAG=v3.4.11
RUN git clone --depth 1 --branch ${ALTINITY_PLUGIN_TAG} \
        https://github.com/Altinity/clickhouse-grafana /src
WORKDIR /src
COPY plugin/0001-jwt-as-password.patch /tmp/0001-jwt-as-password.patch
RUN git apply --verbose /tmp/0001-jwt-as-password.patch
RUN go install github.com/magefile/mage@latest
RUN mage -v buildAll

# ---- 2. frontend: webpack bundle ----
FROM node:20 AS plugin-js-builder
COPY --from=plugin-go-builder /src /src
WORKDIR /src
RUN npm ci --no-audit --no-fund --legacy-peer-deps
RUN npm run build:frontend

# ---- 3. Grafana with the built plugin layered in ----
FROM grafana/grafana:13.0.2
COPY --from=plugin-js-builder /src/dist \
        /var/lib/grafana/plugins/vertamedia-clickhouse-datasource
COPY provisioning /etc/grafana/provisioning
# The base image's /etc/grafana/provisioning is mode 0750 root:root and
# the plugins dir gets COPY'd in as root — switch ownership so the
# unprivileged `grafana` runtime user can read both. (Without this,
# provisioned datasources silently fail to load.)
USER root
RUN chown -R grafana:root /etc/grafana/provisioning /var/lib/grafana/plugins/vertamedia-clickhouse-datasource \
    && chmod -R u+rX,g+rX /etc/grafana/provisioning /var/lib/grafana/plugins/vertamedia-clickhouse-datasource
USER grafana
# The plugin's signature is invalidated by the patch (the dist tree
# changed), so Grafana refuses to load it unless we whitelist the id.
ENV GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=vertamedia-clickhouse-datasource
