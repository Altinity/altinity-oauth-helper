#!/usr/bin/env bash
# One-shot init for the Superset metadata DB.
#
# Runs `superset db upgrade` (creates / migrates the schema) and then
# `fab create-admin` (idempotent — re-runs do nothing if the user
# already exists). The main superset service depends on this completing
# successfully before it starts gunicorn.
set -euo pipefail

echo "→ superset db upgrade"
superset db upgrade

echo "→ superset fab create-admin"
superset fab create-admin \
    --username "${ADMIN_USERNAME:-admin}" \
    --firstname Superset \
    --lastname Admin \
    --email "${ADMIN_EMAIL:-admin@superset.local}" \
    --password "${ADMIN_PASSWORD:-admin}"

echo "→ superset init (load default roles + perms)"
superset init

echo "→ register ClickHouse (oauth) database connection"
# Pre-seed the CH connection so the manual walkthrough is "log in → SQL
# Lab → type SELECT 1". Without this the user has to add the database
# manually (the "+ Database" modal currently isn't scriptable via the
# chrome-devtools MCP without JS). The DB_CONNECTION_MUTATOR rewrites
# username/password at engine-creation time from g.user, so the
# placeholder `default` user here is replaced per-request with the
# logged-in OAuth user + their JWT.
python <<'PYEOF'
import sys
from superset.app import create_app
app = create_app()
with app.app_context():
    from superset.extensions import db
    from superset.models.core import Database

    NAME = "ClickHouse (oauth)"
    ENGINE_URL = "clickhousedb://default@clickhouse:8123/default"
    existing = db.session.query(Database).filter_by(database_name=NAME).first()
    if existing:
        print(f"  {NAME} already registered (id={existing.id})")
        sys.exit(0)
    cnx = Database(
        database_name=NAME,
        sqlalchemy_uri=ENGINE_URL,
        expose_in_sqllab=True,
        allow_dml=False,
        allow_ctas=False,
        allow_cvas=False,
    )
    db.session.add(cnx)
    db.session.commit()
    print(f"  registered {NAME} (id={cnx.id})")
PYEOF

echo "✓ superset init complete"
