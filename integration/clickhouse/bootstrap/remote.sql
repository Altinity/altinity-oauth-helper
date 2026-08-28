-- integration/clickhouse/bootstrap/remote.sql
--
-- Applied ONLY to clickhouse-remote, after bootstrap/common.sql, via the
-- container-local `default` administrative user (no JWT on this path).
--
-- remote_probe (base table) is the authorization oracle acceptance scenario
-- H (scenarios/70) reads through a Distributed table; remote identity for
-- that proof is asserted separately via system.query_log, not through a
-- view. remote_auth_probe (the view) exposes currentUser()/currentRoles()
-- in the REMOTE execution context and is read ONLY by the expected-fail
-- view-oracle canary (scenarios/75), which tracks a separate ClickHouse
-- defect (ClickHouse/ClickHouse#116840). Grants are scoped to
-- ch_distributed_reader only — no broader grant, and run.sh's scenario
-- A.13 asserts that exclusivity against the live server — so that
-- disabling push_external_roles_in_interserver_queries in either negative
-- control genuinely removes authority rather than merely changing which
-- role is reported while still allowing the read.
--
-- remote_probe (the base table) is read two ways from origin:
--   - directly, via phase3.distributed_probe (bootstrap/origin.sql) — the
--     primary scenario H oracle (scenarios/70), no view in the path;
--   - through remote_auth_probe (this view) via
--     phase3.distributed_auth_probe (bootstrap/origin.sql) — the
--     expected-fail sibling oracle (scenarios/75) that reproduces a
--     separate, view-specific ClickHouse defect. See lib/expectations.sh.
-- Both grants below already cover both paths; no additional grant is
-- needed for the base-table oracle.

CREATE TABLE IF NOT EXISTS phase3.remote_probe
(
    n UInt64
)
ENGINE = MergeTree
ORDER BY n;

INSERT INTO phase3.remote_probe VALUES (1), (2), (3);

CREATE VIEW IF NOT EXISTS phase3.remote_auth_probe AS
SELECT
    n,
    currentUser() AS remote_user,
    arrayStringConcat(arraySort(currentRoles()), ',') AS remote_roles
FROM phase3.remote_probe;

GRANT SELECT ON phase3.remote_probe TO ch_distributed_reader;
GRANT SELECT ON phase3.remote_auth_probe TO ch_distributed_reader;
