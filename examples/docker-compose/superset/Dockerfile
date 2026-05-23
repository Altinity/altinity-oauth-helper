# Superset + the Python drivers our config wires up. Same recipe as
# /Users/Workspaces/altinity/superset-jwt-overlay/Dockerfile but
# self-contained so the example does not depend on a separate published
# image (whose -arm64 / -amd64 tag scheme also doesn't cover both arches
# yet).
ARG SUPERSET_VERSION=5.0.0
FROM apache/superset:${SUPERSET_VERSION}

USER root

# Superset 5.0.0 ships a `uv`-managed venv at /app/.venv; use `uv pip`
# (not system pip) so the install lands in the venv the gunicorn
# entrypoint actually uses.
ENV VIRTUAL_ENV=/app/.venv
RUN uv pip install --no-cache \
        "psycopg2-binary>=2.9,<3" \
        "clickhouse-connect>=0.8.0,<1.0" \
        "authlib>=1.2,<2"

USER superset
