-- integration/clickhouse/bootstrap/common.sql
--
-- Applied to BOTH clickhouse-origin and clickhouse-remote via the
-- container-local `default` administrative user (no JWT ever touches this
-- path — see "Administrative versus OAuth client paths" in the phase-3
-- plan). Creates the shared database and the local RBAC roles that give
-- externally-mapped role NAMES their only authority.
--
-- Never create `ch_unprovisioned` here (or anywhere): its entire purpose
-- is to exist as a helper-emitted mapped role with NO matching local
-- ClickHouse role, proving the helper cannot invent authorization
-- (acceptance scenario C). Never create `alice@example.com` (or any OAuth
-- principal) here either — the "no CREATE USER for the OAuth principal"
-- condition is an explicit phase-3 requirement, and scenario A's preflight
-- asserts her absence before any OAuth testing begins.

CREATE DATABASE IF NOT EXISTS phase3;

CREATE ROLE IF NOT EXISTS ch_readonly;
CREATE ROLE IF NOT EXISTS ch_engineer;
CREATE ROLE IF NOT EXISTS ch_distributed_reader;
