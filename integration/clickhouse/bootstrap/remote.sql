-- integration/clickhouse/bootstrap/remote.sql
--
-- Applied ONLY to clickhouse-remote, after bootstrap/common.sql, via the
-- container-local `default` administrative user (no JWT on this path).
--
-- remote_auth_probe forces currentUser()/currentRoles() to be evaluated in
-- the REMOTE execution context, which is what makes acceptance scenario H
-- (distributed external-role propagation) a real proof rather than an
-- origin-side assumption. Grants are scoped to ch_distributed_reader only
-- — no broader grant — so that disabling
-- push_external_roles_in_interserver_queries in scenario H's negative
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
