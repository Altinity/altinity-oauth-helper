# Repo footguns — operational knowledge that cost a debugging session each

Read once per `/ship` run (step 1). Every item here was learned the hard way on this
repo; when one bites anyway, update this file in the same change.

## Claude Code tool shell

- `grep`/`find` are **shadowed shell functions** in the Claude Code tool shell (not
  the real binaries) — observed misbehaving ad hoc in this environment. Use
  `command grep`/`command find`, or the absolute `/usr/bin/grep`, when running either
  ad hoc from the tool shell. This shadowing does **not** propagate into child bash
  scripts (e.g. a script invoked via `bash foo.sh`, or CI) — those see the real
  `grep`/`find` on `PATH` and need no workaround.

## Go build/test and the gate

- No lifecycle-script gate to worry about (no `package.json`/`.npmrc` in this repo) —
  the gate is simply `go build ./... && go vet ./... && go test ./...`
  (`per-issue-cycle.md` step 2). There is no coverage floor enforced anywhere; write
  tests for new behavior on your own judgment, especially cache-key/identity-policy
  edge cases (security-relevant surface — see `CLAUDE.md`).
- `cmd/ch-jwt-verify/verify_test.go` spins up its own in-process test IdP
  (`newTestIdP`, RSA-signed JWTs over an `httptest` JWKS server) rather than sharing a
  fixture with anything else — it's a self-contained unit test file, not a client of
  some other package's test harness.
- `go test ./...` output is normally compact; a `-v` run or many packages can still be
  large enough to be worth capturing to a file and reading the tail rather than
  letting it fill context.

## examples/ sanity checks

There is no automated e2e suite in this repo — the closest equivalent is manually
exercising the relevant recipe under `examples/`:

- `examples/curl/verify.sh` is the fastest smoke check for a change to the `/verify`
  handler itself — no compose stack needed, just `go run ./cmd/ch-jwt-verify -c
  examples/curl/config.yaml` plus a hand-minted JWT.
- `examples/_platform/docker` is the shared Dex + Postgres + ClickHouse + sidecar base
  every consumer overlay (`examples/superset/docker`, `examples/grafana/docker`, …)
  layers on — bring it up per `examples/_platform/docker/README.md` when a change
  touches the wire contract, the Helm chart, or cross-component wiring.
- `examples/README.md`'s capability matrix (✅/🟡/🔴 per consumer × deploy style) is the
  state of record for what's actually working — update it in the same change if your
  work changes a row's status.

## GitHub CLI

- Never the GitHub connector MCP — its collaborator preflight fails for this org
  (observed on `altinity-sql-browser`; the org-level cause is likely shared here).
- As a safe default, read issues/PRs with `--json` and edit bodies with
  `gh api -X PATCH … -F body=@<file>` rather than bare `gh issue view`/`gh pr edit` —
  those two errored outright on another Altinity org repo with this account. Verify
  locally the first time on this repo; simplify if bare `gh issue view` turns out fine
  here. Never `$(cat …)`/`sed` inside a quoted heredoc to build a body.
- **CI waits must key on the head SHA**: `gh run list --limit 1` right after a push
  reports the *previous* head's run. Match on `headSha` — always, for every workflow
  in this repo, without exception.
- **`Required PR gate` is this repo's PR verification status** (workflow `PR gate`,
  `.github/workflows/pr-gate.yml`, one job). It runs unfiltered on every pull request
  and every push to `main` and executes `go build ./...`, `go vet ./...`,
  `go test -race ./...`, `go test -tags phase5release ./internal/securitytest
  -count=1`, and `bash integration/clickhouse/tests/lib-tests.sh`. When waiting on it,
  resolve the run/check for the **exact current head SHA** of the branch you are about
  to merge; treat missing, pending, cancelled, or failed gate state as *not ready*.
  Never accept a run whose `headSha` is an earlier push.
- **The two image-publication workflows are not that gate.**
  `build-ch-jwt-verify.yml` (path-filtered to
  `cmd/ch-jwt-verify/**`/`go.mod`/`go.sum`/`Dockerfile`) and
  `build-ch-oauth-ldap.yml` (path-filtered to `cmd/ch-oauth-ldap/**`/`internal/**`/
  `third_party/**`/`go.mod`/`go.sum`/`Dockerfile.ch-oauth-ldap`) only build+publish an
  image on push to `main`. They verify nothing and are never a substitute for
  `Required PR gate` — a green publish is not a green gate, and a *skipped* publish
  (path filters) is not a failure. The `headSha`-keying rule applies to them too if
  you ever wait on one (e.g. to confirm a post-merge publish actually ran).
- **Local verification is still required before handoff.** Hosted CI is merge
  enforcement, not a substitute: run the five gate commands plus the gates CI
  deliberately does not run (`helm/ch-oauth-ldap/test.sh`, the Docker ClickHouse
  suite) yourself before calling a unit done.
- A present-but-expired `GITHUB_TOKEN` breaks `git push` and `gh` identically — it
  looks like a network/allowlist failure but isn't; tell the user.

## Git, worktrees, and workers

- In a worktree, local `main` is stale: branch off `origin/main` and scope diffs to
  `origin/main...HEAD`.
- A **resumed worker commits on whatever branch is currently checked out**, not on its
  named branch — check out its branch before `SendMessage`.
- Worktree-isolated agents are pinned to their base commit: untracked files and
  mid-run pushes are invisible to them; `git ls-files` before handing one a relative
  script path.
- Subagents have reverted other workers' edits with `git checkout --` despite
  report-only prompts — diff the tree after every batch.
- Restore a sabotaged *uncommitted* file by writing the saved bytes back, never with
  `git checkout --` (it deletes the uncommitted fix).
- Never `git stash` mid-merge — it silently deletes `MERGE_HEAD` and the next commit
  stops being a merge.

## ChatGPT review (`chatgpt-review`)

- Agent Chrome is **one session**: the only permitted `chatgpt-review` invocations
  live inside the selected plan workflow and code-review workflow
  (`references/review-loops.md`), launched
  by the coordinator one at a time. Parallel workers must never invoke the skill —
  two concurrent runs corrupt each other's conversation.
- A plan session's identity includes the plan file's **absolute path** (`plan:<path>`
  for review or `plan-author:<issue>:<path>` for authoring). Every loop keeps that
  canonical path unchanged; moving or renaming it loses the conversation history.
- The 3-pass cap is script-enforced for `pr` mode only; the 5-pass plan cap is a loop
  bound in the selected plan workflow — do not add passes around either.
- Review workflows run in the **background**: launch, then wait for the task
  notification — never poll, never start a second review workflow meanwhile. Before
  diagnosing an empty or odd workflow return, Read the run's `journal.jsonl` (path in
  the Workflow tool result); a `pr`-mode pass may have published its PR comment even
  when the run errored.

## Running the sidecar locally (`go run ./cmd/ch-jwt-verify`)

- If the port is held, kill **your tracked PID** or the process bound to the port —
  never `pkill -f "<command>"`, which kills other sessions' servers.
- `go run` builds to a temp binary each invocation; there's no stale-artifact risk
  like a served `dist/` — but a backgrounded `go run` process itself can be left
  running across sessions, so track and kill it explicitly rather than assuming a
  restart is a no-op.

## Issue and phase state

- PR titles with phase counts (`(2/3)`) go stale when a phase count is re-scoped
  mid-flight (observed on `altinity-sql-browser`'s issue #427, which shipped `(1/3)`
  then `(2/2)` for the same issue); the `<!-- ship-log -->` comment is
  the only state of record. One PR per unit is now the default shape of a `/ship` run,
  not an exception — check the ship log, never the PR title, before deciding what's
  next.
- The per-phase `## Tests` subsection often lives *outside* the phase heading — missing
  it is the most common way to under-deliver a phase.
