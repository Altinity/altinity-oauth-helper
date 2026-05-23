-- Bootstrap the metadata databases the stack needs.
--
-- Postgres is shared between Dex (storage backend) and Superset
-- (FAB metadata DB). The official postgres image runs every .sql file in
-- docker-entrypoint-initdb.d on first boot, so both databases exist
-- before either dependent container connects.
CREATE USER dex WITH ENCRYPTED PASSWORD 'dex';
CREATE DATABASE dex OWNER dex;

CREATE USER superset WITH ENCRYPTED PASSWORD 'superset';
CREATE DATABASE superset OWNER superset;
