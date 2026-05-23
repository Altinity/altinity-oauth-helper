-- Bootstrap the Dex storage database.
--
-- The platform owns only the Dex metadata DB. Consumer overlays that
-- need their own metadata DB in Postgres (Superset, Grafana, etc.)
-- create it from their own init step — `docker-entrypoint-initdb.d`
-- runs once on first boot, so consumers can't bolt extra init files in
-- here without re-initialising the volume.
CREATE USER dex WITH ENCRYPTED PASSWORD 'dex';
CREATE DATABASE dex OWNER dex;
