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
