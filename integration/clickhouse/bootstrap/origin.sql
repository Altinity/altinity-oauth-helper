-- integration/clickhouse/bootstrap/origin.sql
--
-- Applied ONLY to clickhouse-origin, after bootstrap/common.sql, via the
-- container-local `default` administrative user (no JWT on this path).
--
-- __CH_LOCAL_ADMIN_SHA256_HEX__ is a placeholder run.sh substitutes with a
-- runtime-generated password's SHA-256 hex digest using pure bash string
-- substitution (never `sed -e` with the secret as an argv-visible
-- expression, and never the plaintext password itself) before piping this
-- file to clickhouse-client over stdin. The plaintext password is kept
-- only in an unexported runner variable for later use as an HTTP Basic
-- password proving real local authentication (acceptance scenario G).
--
-- admin@example.com, not literal `admin`, is deliberate: the helper's
-- denied_usernames list already rejects the literal `admin`, so a
-- precedence test built on that name would pass vacuously at the helper's
-- deny policy rather than by actually exercising ClickHouse's
-- local-user-before-LDAP precedence (see "Local-precedence user" in the
-- plan).

CREATE ROLE IF NOT EXISTS ch_local_admin;

CREATE USER IF NOT EXISTS `admin@example.com`
    IDENTIFIED WITH sha256_hash BY '__CH_LOCAL_ADMIN_SHA256_HEX__'
    DEFAULT ROLE ch_local_admin;

GRANT ch_local_admin TO `admin@example.com`;

-- Explicit-column Distributed table. Deliberately NOT
--   CREATE TABLE phase3.distributed_auth_probe AS phase3.remote_auth_probe
--   ENGINE = Distributed(...);
-- `AS db.table` copies the referenced table's structure as resolved on the
-- server executing the DDL (origin) — but remote_auth_probe only exists on
-- clickhouse-remote, not on origin (see "Origin Distributed table" in the
-- plan). The schema is therefore spelled out explicitly instead.
--
-- This VIEW-based oracle is now owned by acceptance scenario H's
-- expected-fail sibling, scenarios/75-distributed-propagation-view.sh — it
-- reproduces a real upstream ClickHouse bug (StorageView's context clone
-- drops the pushed external role) on every currently known build. See
-- lib/expectations.sh's H_view_propagation entry.
CREATE TABLE IF NOT EXISTS phase3.distributed_auth_probe
(
    n UInt64,
    remote_user String,
    remote_roles String
)
ENGINE = Distributed(
    phase3_remote,
    phase3,
    remote_auth_probe
);

GRANT SELECT ON phase3.distributed_auth_probe TO ch_distributed_reader;

-- Direct base-table Distributed oracle — no view in the read path. This is
-- scenario H's primary authorization proof
-- (scenarios/70-distributed-propagation.sh): it isolates the propagation
-- question from the separate view-context-copy bug the VIEW-based oracle
-- above reproduces (see lib/expectations.sh's H_base_table_propagation vs.
-- H_view_propagation entries — the two are independent ClickHouse defects,
-- and this table exists specifically so scenario H's own pass/fail doesn't
-- depend on which one happens to be present on a given build).
CREATE TABLE IF NOT EXISTS phase3.distributed_probe
(
    n UInt64
)
ENGINE = Distributed(
    phase3_remote,
    phase3,
    remote_probe
);

GRANT SELECT ON phase3.distributed_probe TO ch_distributed_reader;
