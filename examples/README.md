# Examples

Worked examples of consuming `ch-jwt-verify` from real deployments.

| Directory | What it shows |
|---|---|
| [`curl-smoke-test/`](curl-smoke-test/) | Smallest possible end-to-end test: run the sidecar locally, hit `/verify` with `curl` carrying a real JWT. Use this when bringing the sidecar up against a new IdP. |
| [`superset-otel/`](superset-otel/) | A non-MCP consumer (Apache Superset) reusing the sidecar with no source patch. Demonstrates the per-user `CREATE USER … IDENTIFIED WITH http` pattern with Auth0 as the IdP. Snapshot of an internal Altinity deployment — illustrative, not the live source of truth. |
