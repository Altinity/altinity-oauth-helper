package securitytest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This file turns three invariants of issue #23's plan that were otherwise
// enforced only by "static review" into an executable contract over
// .github/workflows/pr-gate.yml: (1) every pull request and every push to
// `main` enters verification, (2) all five gate commands control one merge
// result, and (3) pull-request code receives minimal repository authority.
//
// What each assertion protects, and what breaks if it is lost:
//
//   - Trigger set is exactly `pull_request` (with `types` restricted to
//     `opened`, `synchronize`, `reopened`, `edited` — no other key, e.g. no
//     `branches`/`paths`) plus `push` on `main`.
//
//     Two DIFFERENT failure modes hide behind "the gate did not run", and they
//     are not equally dangerous — do not conflate them:
//
//     A `paths:`/`paths-ignore:` filter that skips the whole WORKFLOW fails
//     CLOSED: GitHub documents that when a workflow is skipped by path or
//     branch filtering, its associated required check stays *Pending* and
//     blocks merging. So a path filter does not smuggle an unverified change
//     through — it deadlocks the PR instead, and the realistic hazard is that
//     someone then drops the requirement to unblock a stuck merge, or that
//     coverage silently becomes a judgement call about which paths "matter"
//     when a shared file or dependency changes the LDAP/security boundary in
//     a non-obvious way (issue #23's own reason for forbidding filters).
//     That is why this file forbids them: universal coverage and no stuck
//     required checks, NOT because a filtered PR would merge green.
//
//     A skipped JOB is the opposite and is the genuinely dangerous case:
//     GitHub reports a job skipped by a conditional as *Success*, which
//     satisfies a required check. That is what
//     TestPRGateContract_JobIsUnconditionalAndFailsClosed exists for.
//
//     A narrowed `types` list is dangerous in its own third way: the run
//     never happens AND no new check is expected, so an existing green check
//     on an unchanged head SHA continues to satisfy the requirement.
//     `edited` specifically is load-bearing, not
//     decorative: a base-branch retarget is delivered as an `edited`
//     activity (not a new `synchronize`) and keeps the same head SHA, so
//     without it a PR proven green against base A can be retargeted onto
//     protected `main` and keep that same green required check without the
//     new merge result ever being tested — GitHub's required-check rule
//     falls back to the head SHA's existing check when the test-merge commit
//     has none of its own.
//   - `pull_request_target` is absent. That trigger runs the BASE repository's
//     workflow with a writable token and repository secrets in the context of
//     an untrusted fork head; adding it to a job that then builds and tests
//     that head is a straightforward supply-chain compromise of this repo.
//   - Top-level `permissions` is exactly `{contents: read}`, AND the job
//     carries no `permissions:` override that isn't the same exact mapping
//     (job-level permissions REPLACE, not merge with, the top-level grant).
//     The gate only needs to read source. Any broader grant hands the token
//     that runs PR-authored test code the authority to write to the
//     repository.
//   - Exactly one job, with no `if`, no `needs`, and no `continue-on-error`
//     anywhere. A conditional or skipped job reports *success* to branch
//     protection, so an aggregator or a job condition is a silent waiver
//     rather than a visible failure; `continue-on-error` turns a red security
//     test into an advisory note that still merges.
//   - The five contractual commands appear exactly once each, in order. A
//     dropped step is a whole class of verification silently no longer gating
//     merges (most acutely `go test -tags phase5release ./internal/securitytest
//     -count=1`, the redaction/SDK release gate, which plain `go test ./...`
//     does not compile).
//   - Every external `uses:` is pinned to a full 40-hex commit SHA. A floating
//     tag (`@v4`) is mutable by the action's owner, so the gate that decides
//     what may merge would execute code chosen after review.
//   - Every pin's trailing `# <identity>@vX.Y.Z` comment names that step's own
//     action and a version at or above the first release declaring the
//     `node24` runtime (`actions/checkout` >= v5.0.0, `actions/setup-go` >=
//     v6.2.0 — setup-go's node24 line starts mid-v6, not at a major bump; see
//     prGateNode24FloorByAction below for how each floor was verified).
//     Read the scope limit in that check's own doc comment before relying on
//     it: it verifies the COMMENT, because a commit SHA cannot be resolved to
//     a version or a declared runtime offline.
//     GitHub Actions runners stop shipping Node 20 on 2026-09-23 (still
//     ahead as of this writing, 2026-08-30);
//     a `node20`-declared action only keeps working because the runner
//     silently re-executes it on Node 24 in the meantime — a compatibility
//     shim, not a contract. Pinning below the node24 line means the gate
//     depends on that shim and breaks outright once it is withdrawn.
//
// The job name `Required PR gate` is an externally consumed interface, not an
// internal label: it is the exact check-run context that branch protection on
// `main` requires. Renaming the job means migrating branch protection in the
// same change — otherwise the required context is simply never reported, and
// every pull request stalls (or, if protection is dropped instead, merges
// unverified). TestPRGateContract_ExactlyOneJobNamedForBranchProtection pins
// that literal string here so a rename cannot happen quietly.
//
// Honest scope: this is an ACCIDENTAL-DRIFT DETECTOR, NOT A TAMPER-RESISTANCE
// MECHANISM. This test file lives in the same pull-request-controlled tree as
// the workflow it inspects, and it runs only because that same workflow runs
// it. A pull request that neuters, skips, or deletes the job therefore also
// neuters, skips, or deletes this test — nothing here can detect that. Real
// tamper resistance would require an enforcement authority outside the
// PR-controlled workflow, i.e. an organization-level required-workflow
// ruleset. What this file does buy is that an *honest* edit which quietly
// weakens the gate (a path filter added for speed, a step marked advisory to
// unblock a merge, a job renamed during a refactor) fails a test with a
// message naming the consequence, instead of being noticed months later.
//
// Every expectation below is a LITERAL in this source file. None is read out
// of pr-gate.yml and compared against itself: a test that derives the job name
// or the command list from the file under test detects nothing at all (see
// skills/ship/references/per-issue-cycle.md step 3, item 6). Conversely, the
// action SHAs are deliberately NOT hardcoded — the invariant is pin
// *immutability* (a 40-hex ref for a known action identity), so a legitimate
// action upgrade is not test churn.

// prGateWorkflowRelPath is the workflow this file is the contract for.
const prGateWorkflowRelPath = ".github/workflows/pr-gate.yml"

// prGateRequiredCheckName is the exact check-run context branch protection on
// `main` requires. Literal on purpose — see this file's header comment.
const prGateRequiredCheckName = "Required PR gate"

// prGateRequiredCommands is the five-command gate, in contractual order.
// Literal on purpose: these are the commands the plan promises control one
// merge result.
var prGateRequiredCommands = []string{
	"go build ./...",
	"go vet ./...",
	"go test -race ./...",
	"go test -tags phase5release ./internal/securitytest -count=1",
	"bash integration/clickhouse/tests/lib-tests.sh",
}

// prGateExpectedTriggers is the complete, exact set of `on:` keys allowed.
var prGateExpectedTriggers = []string{"pull_request", "push"}

// prGateExpectedPullRequestTypes is the complete, exact `on.pull_request.types`
// list. `edited` is the load-bearing addition over GitHub's own default
// (opened/synchronize/reopened): a base-branch retarget is delivered as an
// `edited` activity, not a new `synchronize`, and keeps the same head SHA —
// see this file's header comment for why omitting it is a fail-open path,
// not a cosmetic gap.
var prGateExpectedPullRequestTypes = []string{"opened", "synchronize", "reopened", "edited"}

// prGateExpectedPushBranches is the complete, exact `on.push.branches` list.
var prGateExpectedPushBranches = []string{"main"}

// prGateExpectedPermissions is the complete, exact top-level `permissions`
// mapping.
var prGateExpectedPermissions = map[string]string{"contents": "read"}

// prGateExpectedActions is the complete, exact set of external action
// identities (the part before `@`) the gate is allowed to run. The pinned
// commit each resolves to is deliberately absent: see prGatePinnedRefRE.
var prGateExpectedActions = []string{"actions/checkout", "actions/setup-go"}

// prGateForbiddenTriggers are triggers that would grant PR-authored code
// privileged repository context.
var prGateForbiddenTriggers = []string{"pull_request_target", "workflow_run"}

// prGatePathFilterKeys are the keys whose presence anywhere in the workflow
// would let some pull requests skip verification.
var prGatePathFilterKeys = []string{"paths", "paths-ignore"}

// prGatePinnedRefRE matches a full 40-character lowercase-hex commit SHA — the
// only immutable form of an action reference. A tag or branch ref does not
// match by construction.
var prGatePinnedRefRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// prGateNode24FloorByAction is the first release of each pinned action that
// declares `using: node24` in its action.yml, keyed by action identity
// (verified by fetching each action.yml at the tag boundary from the real
// actions/checkout and actions/setup-go repositories: checkout v4.3.1 is
// node20 and v5.0.0 is node24; setup-go v6.1.0 is node20 and v6.2.0 is
// node24 — note it is v6.2.0, NOT v7.0.0, so setup-go's node24 line starts
// mid-v6 rather than at the major bump). A pin below this floor
// only runs because GitHub's runners currently re-execute node20-declared
// actions on the Node 24 runtime as a compatibility shim; that shim is
// withdrawn with Node 20's removal from runner images on 2026-09-23, at
// which point a below-floor pin breaks the gate outright rather than merely
// running on borrowed time.
var prGateNode24FloorByAction = map[string][3]int{
	"actions/checkout": {5, 0, 0},
	"actions/setup-go": {6, 2, 0},
}

// prGateVersionCommentRE extracts the pinned action's identity and semantic
// version from a pin's trailing `# <identity>@vX.Y.Z` comment, the only
// place the human-readable version lives (the invariant is SHA immutability,
// so the version cannot be read back out of the pin itself — see this
// file's header comment). Capturing the identity (group 1) rather than only
// the version numbers is deliberate: without cross-checking it against the
// step's real `uses:` identity, a stale or copy-pasted comment next to a
// regressed node20 SHA would still report a passing version and clear the
// floor check below — see TestPRGateContract_ActionPinVersionCommentsAreAtOrAboveTheNode24Floor.
var prGateVersionCommentRE = regexp.MustCompile(`^#\s*(\S+)@v(\d+)\.(\d+)\.(\d+)\s*$`)

// loadPRGateWorkflow reads and parses pr-gate.yml into its top-level mapping
// node. yaml.Node rather than a typed struct or map[string]any is deliberate:
// GitHub's `on:` key resolves to a boolean under YAML 1.1 schemas, and node
// walking compares the key's literal scalar text, so nothing here depends on
// how a particular decoder resolves it.
func loadPRGateWorkflow(t *testing.T) *yaml.Node {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(prGateWorkflowRelPath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("securitytest: read %s: %v — the required PR verification gate must exist. Once branch protection requires `%s`, deleting this workflow does NOT let pull requests merge unverified: the required context is simply never reported, so every PR stalls. The hazard is the follow-on action — dropping the requirement to unblock a stuck queue — and that is what actually permits unverified merging. Restore the workflow rather than relaxing protection", prGateWorkflowRelPath, err, prGateRequiredCheckName)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("securitytest: parse %s: %v — an unparseable gate workflow cannot verify anything, but it fails CLOSED rather than open: GitHub generates a FAILED workflow run for an invalid workflow file on new commits, and a required check that is failing or unreported blocks the merge either way. Fix the YAML; do not relax protection to route around it", prGateWorkflowRelPath, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		t.Fatalf("securitytest: %s must be exactly one YAML document, got kind=%v with %d document(s)", prGateWorkflowRelPath, doc.Kind, len(doc.Content))
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s top level must be a mapping, got kind=%v", prGateWorkflowRelPath, top.Kind)
	}
	return top
}

// yamlMapValue returns the value node for key in a mapping node, or nil.
func yamlMapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// yamlMapKeys returns a mapping node's keys in source order.
func yamlMapKeys(n *yaml.Node) []string {
	var keys []string
	if n == nil || n.Kind != yaml.MappingNode {
		return keys
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	return keys
}

// walkYAMLNodes visits n and every node beneath it.
func walkYAMLNodes(n *yaml.Node, fn func(*yaml.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for _, c := range n.Content {
		walkYAMLNodes(c, fn)
	}
}

// findMappingKeysAnywhere reports every occurrence of any of the named keys
// at any depth, as "<key> (line N)" strings, so a failure names a line a
// reviewer can open.
func findMappingKeysAnywhere(n *yaml.Node, keys ...string) []string {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	var found []string
	walkYAMLNodes(n, func(node *yaml.Node) {
		if node.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := node.Content[i]
			if want[k.Value] {
				found = append(found, fmt.Sprintf("%s (line %d)", k.Value, k.Line))
			}
		}
	})
	return found
}

// prGateSingleJob asserts pr-gate.yml declares exactly one job and returns its
// key and mapping node. Exactly-one is itself an invariant: multi-job layouts
// invite an aggregator job whose *skipped* state reports success to branch
// protection.
func prGateSingleJob(t *testing.T, top *yaml.Node) (string, *yaml.Node) {
	t.Helper()
	jobs := yamlMapValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s has no `jobs:` mapping — a gate with no job reports nothing and verifies nothing", prGateWorkflowRelPath)
	}
	ids := yamlMapKeys(jobs)
	if len(ids) != 1 {
		t.Fatalf("securitytest: %s declares %d jobs (%v), want exactly 1 — additional jobs invite an aggregator or conditional job, and a SKIPPED job reports success to branch protection, silently waiving the gate", prGateWorkflowRelPath, len(ids), ids)
	}
	job := yamlMapValue(jobs, ids[0])
	if job == nil || job.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s job %q is not a mapping", prGateWorkflowRelPath, ids[0])
	}
	return ids[0], job
}

// prGateStepRuns returns each step's `run:` script in step order, plus each
// step's `name:` for use in failure messages.
func prGateStepRuns(t *testing.T, job *yaml.Node) (runs []string, names []string) {
	t.Helper()
	steps := yamlMapValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		t.Fatalf("securitytest: %s job has no `steps:` sequence — a job with no steps passes trivially and verifies nothing", prGateWorkflowRelPath)
	}
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		name := ""
		if nv := yamlMapValue(step, "name"); nv != nil {
			name = nv.Value
		}
		if rv := yamlMapValue(step, "run"); rv != nil {
			runs = append(runs, rv.Value)
			names = append(names, name)
		}
	}
	return runs, names
}

func TestPRGateContract_TriggersAreUnfilteredPRAndMainPush(t *testing.T) {
	top := loadPRGateWorkflow(t)

	on := yamlMapValue(top, "on")
	if on == nil {
		t.Fatalf("securitytest: %s has no `on:` trigger block — a workflow with no trigger never runs, so no pull request is ever verified", prGateWorkflowRelPath)
	}
	if on.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s `on:` must be a mapping so `push` can be branch-scoped, got kind=%v", prGateWorkflowRelPath, on.Kind)
	}

	got := yamlMapKeys(on)
	if strings.Join(got, ",") != strings.Join(prGateExpectedTriggers, ",") {
		t.Fatalf("securitytest: %s triggers are %v, want exactly %v — narrowing or extending this set changes which changes are verified before merge; a removed `pull_request` means PRs merge with no gate result at all", prGateWorkflowRelPath, got, prGateExpectedTriggers)
	}

	// `pull_request:` must carry exactly one key, `types:`, with exactly the
	// expected activity list — no `branches`/`paths`/`paths-ignore` filter,
	// which would exclude some PR from verification outright. Unlike those,
	// `types` is REQUIRED here (not forbidden): GitHub's own default
	// (opened/synchronize/reopened) omits `edited`, and a base-branch
	// retarget — which changes the merge/comparison target but is delivered
	// as an `edited` activity on the same head SHA, not a new `synchronize`
	// — must not silently skip verification. See this file's header comment.
	pr := yamlMapValue(on, "pull_request")
	if pr == nil || pr.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s `on.pull_request` must be a mapping with exactly `types: %v`, got %v — without an explicit `types` list a base-branch retarget (delivered as `edited`, not `synchronize`) never re-triggers the gate, letting a PR keep a green required check while merging an untested new base", prGateWorkflowRelPath, prGateExpectedPullRequestTypes, pr)
	}
	if keys := yamlMapKeys(pr); strings.Join(keys, ",") != "types" {
		t.Errorf("securitytest: %s `on.pull_request` keys are %v, want exactly [types] — a `branches`/`paths`/`paths-ignore` filter here means some pull requests never run the gate. That fails closed rather than green (a required check whose workflow was filtered out stays Pending and blocks merging), but it still costs universal coverage and leaves those PRs deadlocked; see this file's header comment for why the three skip modes are not equivalent", prGateWorkflowRelPath, keys)
	}
	typesNode := yamlMapValue(pr, "types")
	var gotTypes []string
	if typesNode != nil && typesNode.Kind == yaml.SequenceNode {
		for _, ty := range typesNode.Content {
			gotTypes = append(gotTypes, ty.Value)
		}
	}
	if strings.Join(gotTypes, ",") != strings.Join(prGateExpectedPullRequestTypes, ",") {
		t.Errorf("securitytest: %s `on.pull_request.types` is %v, want exactly %v — dropping `edited` reopens the base-retarget fail-open path described in this file's header comment; do not special-case skip title/body-only edits to narrow this back down", prGateWorkflowRelPath, gotTypes, prGateExpectedPullRequestTypes)
	}

	push := yamlMapValue(on, "push")
	if push == nil || push.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s `on.push` must be a mapping with `branches`, got %v — an unscoped push trigger burns runner time on every branch, and a missing one means `main` itself is never re-verified after merge", prGateWorkflowRelPath, push)
	}
	if keys := yamlMapKeys(push); strings.Join(keys, ",") != "branches" {
		t.Errorf("securitytest: %s `on.push` keys are %v, want exactly [branches] — any other key here (notably paths/paths-ignore) can skip post-merge verification of main", prGateWorkflowRelPath, keys)
	}
	branches := yamlMapValue(push, "branches")
	var gotBranches []string
	if branches != nil && branches.Kind == yaml.SequenceNode {
		for _, b := range branches.Content {
			gotBranches = append(gotBranches, b.Value)
		}
	}
	if strings.Join(gotBranches, ",") != strings.Join(prGateExpectedPushBranches, ",") {
		t.Errorf("securitytest: %s `on.push.branches` is %v, want exactly %v", prGateWorkflowRelPath, gotBranches, prGateExpectedPushBranches)
	}
}

func TestPRGateContract_NoPrivilegedTriggers(t *testing.T) {
	top := loadPRGateWorkflow(t)
	on := yamlMapValue(top, "on")
	for _, forbidden := range prGateForbiddenTriggers {
		if yamlMapValue(on, forbidden) != nil {
			t.Errorf("securitytest: %s declares the `%s` trigger, which must never appear here — it runs the base repository's workflow with a writable token and repository secrets while checking out untrusted pull-request code, turning the merge gate itself into a supply-chain attack surface", prGateWorkflowRelPath, forbidden)
		}
	}
}

func TestPRGateContract_NoPathFiltersAnywhere(t *testing.T) {
	top := loadPRGateWorkflow(t)
	if found := findMappingKeysAnywhere(top, prGatePathFilterKeys...); len(found) > 0 {
		t.Errorf("securitytest: %s contains path filter(s) %v, but the gate must be unfiltered. A path filter does NOT let a PR merge green — GitHub keeps a required check whose workflow was skipped by path/branch filtering in a Pending state, which blocks merging. It deadlocks those PRs instead, and the pressure that follows is to drop the requirement to unblock them. It also turns coverage into a judgement call about which paths matter, which issue #23 forbids precisely because a shared file, a dependency bump or a generated fixture can move the LDAP/security boundary in a non-obvious way. Remove the filter; the gate is cheap enough to run for every pull request", prGateWorkflowRelPath, found)
	}
}

// permissionsMapping reads a `permissions:` mapping node into a
// scope->access map. ok is false when n is nil (the key is absent
// entirely) or n is not a mapping node.
func permissionsMapping(n *yaml.Node) (got map[string]string, ok bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	got = map[string]string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		got[n.Content[i].Value] = n.Content[i+1].Value
	}
	return got, true
}

// permissionsMatch reports whether got is exactly want — same scopes, same
// access levels, nothing more and nothing missing. Shared by the top-level
// and job-level checks below: GitHub Actions job-level permissions REPLACE
// rather than merge with the workflow-level grant, so both locations must
// independently equal the same minimal mapping for the gate to stay
// read-only end to end.
func permissionsMatch(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for scope, w := range want {
		if got[scope] != w {
			return false
		}
	}
	return true
}

func TestPRGateContract_TopLevelPermissionsAreReadOnly(t *testing.T) {
	top := loadPRGateWorkflow(t)

	got, ok := permissionsMapping(yamlMapValue(top, "permissions"))
	if !ok {
		t.Fatalf("securitytest: %s has no top-level `permissions:` mapping — without an explicit grant the job inherits the repository default, which may be write, handing PR-authored test code repository authority", prGateWorkflowRelPath)
	}
	if !permissionsMatch(got, prGateExpectedPermissions) {
		t.Errorf("securitytest: %s top-level permissions are %v, want exactly %v — every scope beyond `contents: read` is authority granted to code an outside contributor wrote", prGateWorkflowRelPath, got, prGateExpectedPermissions)
	}

	// GitHub Actions job-level `permissions:` REPLACES (not merges with)
	// the workflow-level grant for that job — so the top-level check above,
	// on its own, cannot catch a `jobs.<id>.permissions:` block added to the
	// gate job that grants (e.g.) `contents: write`. Every existing test in
	// this file would still pass in that scenario, so this job-level check
	// is not redundant with the one above.
	_, job := prGateSingleJob(t, top)
	jobPermsNode := yamlMapValue(job, "permissions")
	if jobPermsNode == nil {
		return // no job-level override: the read-only top-level grant applies
	}
	gotJob, ok := permissionsMapping(jobPermsNode)
	if !ok {
		t.Fatalf("securitytest: %s job-level `permissions:` is not a mapping, got kind=%v", prGateWorkflowRelPath, jobPermsNode.Kind)
	}
	if !permissionsMatch(gotJob, prGateExpectedPermissions) {
		t.Errorf("securitytest: %s job-level permissions are %v, want exactly %v (or no job-level `permissions:` at all) — a job-level grant REPLACES the workflow-level one for that job, so this can hand PR-authored test code broader repository authority even though the top-level block stays read-only", prGateWorkflowRelPath, gotJob, prGateExpectedPermissions)
	}
}

func TestPRGateContract_ExactlyOneJobNamedForBranchProtection(t *testing.T) {
	top := loadPRGateWorkflow(t)
	id, job := prGateSingleJob(t, top)

	nameNode := yamlMapValue(job, "name")
	if nameNode == nil {
		t.Fatalf("securitytest: %s job %q has no `name:` — without it the reported check context is the job id, so branch protection's required context %q would never be satisfied and every PR would stall", prGateWorkflowRelPath, id, prGateRequiredCheckName)
	}
	if nameNode.Value != prGateRequiredCheckName {
		t.Errorf("securitytest: %s job %q is named %q, want exactly %q — that string is the check-run context branch protection on `main` requires, i.e. an externally consumed interface. Renaming it requires migrating branch protection in the SAME change; otherwise the required context is never reported and merges stall (or, if protection is dropped to unblock them, PRs merge unverified)", prGateWorkflowRelPath, id, nameNode.Value, prGateRequiredCheckName)
	}
}

func TestPRGateContract_JobIsUnconditionalAndFailsClosed(t *testing.T) {
	top := loadPRGateWorkflow(t)
	id, job := prGateSingleJob(t, top)

	if n := yamlMapValue(job, "if"); n != nil {
		t.Errorf("securitytest: %s job %q carries an `if:` condition (%q) — a job whose condition is false is reported as SKIPPED, and branch protection treats a skipped required check as satisfied, so the gate would be silently waived rather than visibly red", prGateWorkflowRelPath, id, n.Value)
	}
	if n := yamlMapValue(job, "needs"); n != nil {
		t.Errorf("securitytest: %s job %q declares `needs:` — a dependency means this job can be skipped when its dependency is skipped or fails, which reports as a satisfied (not failed) required check", prGateWorkflowRelPath, id)
	}
	if found := findMappingKeysAnywhere(top, "continue-on-error"); len(found) > 0 {
		t.Errorf("securitytest: %s sets continue-on-error at %v — that makes a failing verification step advisory, so a red security test still merges. Every one of the five gate commands must be able to fail the whole job", prGateWorkflowRelPath, found)
	}
	steps := yamlMapValue(job, "steps")
	if steps != nil {
		for i, step := range steps.Content {
			if yamlMapValue(step, "if") != nil {
				t.Errorf("securitytest: %s job %q step %d carries an `if:` condition — a conditionally skipped verification step is verification that does not happen, while the job still reports green", prGateWorkflowRelPath, id, i)
			}
		}
	}
}

// prGateSafeScriptPrefixLines are non-command lines a `run:` step's script
// may carry ahead of (or around) its single contractual command without
// defeating the exact-match reduction in prGateScriptCommand — a shebang or
// a shell strict-mode header, not a command in its own right.
var prGateSafeScriptPrefixLines = map[string]bool{
	"#!/usr/bin/env bash": true,
	"#!/bin/bash":         true,
	"#!/bin/sh":           true,
	"set -e":              true,
	"set -eu":             true,
	"set -eo pipefail":    true,
	"set -euo pipefail":   true,
}

// prGateScriptCommand reduces a `run:` step's script to the single command
// it actually executes — after stripping blank lines, comment-only lines,
// and known-safe shebang/strict-mode headers — or reports ok=false when the
// script does not reduce to exactly one remaining line.
//
// This is a deliberate EXACT match against a contractual command, not
// substring search: a `run: echo 'go build ./...'` step must not satisfy
// the contract for `go build ./...` merely because that text appears
// somewhere in the script — it runs `echo`, never the Go toolchain.
func prGateScriptCommand(script string) (cmd string, ok bool) {
	var remaining []string
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || prGateSafeScriptPrefixLines[trimmed] {
			continue
		}
		remaining = append(remaining, trimmed)
	}
	if len(remaining) != 1 {
		return "", false
	}
	return remaining[0], true
}

func TestPRGateContract_FiveCommandsRunExactlyOnceInOrder(t *testing.T) {
	top := loadPRGateWorkflow(t)
	_, job := prGateSingleJob(t, top)
	runs, names := prGateStepRuns(t, job)

	// Reduce every run: step to the single command it actually executes.
	// stepCmdOK[si] is false when the step's script does not reduce
	// cleanly to one line — see prGateScriptCommand.
	stepCmd := make([]string, len(runs))
	stepCmdOK := make([]bool, len(runs))
	for si, script := range runs {
		stepCmd[si], stepCmdOK[si] = prGateScriptCommand(script)
	}

	// For each contractual command: find the steps whose ENTIRE reduced
	// script exactly equals it, and record the index of the first. Exact
	// equality (not substring containment) is deliberate: a step's script
	// containing the command text inside a string literal — e.g.
	// `run: echo 'go build ./...'` — must not count as running it.
	positions := make([]int, len(prGateRequiredCommands))
	for ci, cmd := range prGateRequiredCommands {
		total := 0
		positions[ci] = -1
		for si := range runs {
			if !stepCmdOK[si] || stepCmd[si] != cmd {
				continue
			}
			if positions[ci] == -1 {
				positions[ci] = si
			}
			total++
		}
		switch {
		case total == 0:
			t.Errorf("securitytest: %s never runs %q as a step's entire script — that entire class of verification no longer gates merges. (%q in particular is not compiled by plain `go test ./...`, so dropping it means the redaction/SDK release gate stops running anywhere in CI.)", prGateWorkflowRelPath, cmd, prGateRequiredCommands[3])
		case total > 1:
			t.Errorf("securitytest: %s runs %q %d times (steps %v) — the contract is exactly once, so a duplicate hides which invocation actually gates the merge and masks a removed sibling command", prGateWorkflowRelPath, cmd, total, names)
		}
	}

	for ci := 1; ci < len(positions); ci++ {
		if positions[ci-1] < 0 || positions[ci] < 0 {
			continue // already reported above
		}
		if positions[ci] <= positions[ci-1] {
			t.Errorf("securitytest: %s runs %q (step %d) at or before %q (step %d), but the contractual order is %v — order matters because the cheap compile/vet steps must fail fast before the expensive ones, and a reordering is usually the visible symptom of a rewritten gate", prGateWorkflowRelPath, prGateRequiredCommands[ci], positions[ci], prGateRequiredCommands[ci-1], positions[ci-1], prGateRequiredCommands)
		}
	}

	// Every run: step in this job must reduce to exactly one of the five
	// contractual commands. A step whose script contains a command's text
	// without actually consisting of just that command (the exact bypass
	// above), or that runs something outside the five-command contract
	// entirely, must fail here even if the counts and ordering above look
	// satisfied.
	for si, script := range runs {
		if !stepCmdOK[si] {
			t.Errorf("securitytest: %s step %q (index %d) script does not reduce to a single command line: %q — every run: step in this job must consist of exactly one contractual command, optionally preceded by a shebang/strict-mode header line", prGateWorkflowRelPath, names[si], si, script)
			continue
		}
		found := false
		for _, cmd := range prGateRequiredCommands {
			if stepCmd[si] == cmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("securitytest: %s step %q (index %d) runs %q, which is not one of the five contractual commands %v", prGateWorkflowRelPath, names[si], si, stepCmd[si], prGateRequiredCommands)
		}
	}
}

func TestPRGateContract_ExternalActionsArePinnedToFullCommitSHA(t *testing.T) {
	top := loadPRGateWorkflow(t)
	_, job := prGateSingleJob(t, top)

	steps := yamlMapValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		t.Fatalf("securitytest: %s job has no `steps:` sequence", prGateWorkflowRelPath)
	}

	var identities []string
	for _, step := range steps.Content {
		uses := yamlMapValue(step, "uses")
		if uses == nil {
			continue
		}
		ref := uses.Value
		at := strings.LastIndex(ref, "@")
		if at < 0 {
			t.Errorf("securitytest: %s uses %q with no `@ref` at all — an unpinned action resolves to whatever its default branch holds at run time, so the job deciding what may merge would execute code nobody reviewed", prGateWorkflowRelPath, ref)
			continue
		}
		identity, pin := ref[:at], ref[at+1:]
		identities = append(identities, identity)
		if !prGatePinnedRefRE.MatchString(pin) {
			t.Errorf("securitytest: %s pins %s to %q, which is not a full 40-character commit SHA — a tag or branch ref is mutable by the action's owner, so the gate that authorizes merges to `main` could silently start executing different code. Pin the commit and keep the human-readable version in a trailing comment", prGateWorkflowRelPath, identity, pin)
		}
	}

	if strings.Join(identities, ",") != strings.Join(prGateExpectedActions, ",") {
		t.Errorf("securitytest: %s uses actions %v, want exactly %v — the gate deliberately runs only first-party checkout/setup-go; any additional third-party action is new code with access to the verification job", prGateWorkflowRelPath, identities, prGateExpectedActions)
	}
}

// pinVersionComment parses a pin's trailing `# <identity>@vX.Y.Z` comment
// into the identity and version it names. ok is false when the comment does
// not match that shape at all (e.g. missing, or arbitrary text). Extracted
// as its own function — rather than inlined into the loop below — so
// TestPinVersionComment can exercise the parsing directly, including the
// case a plain version-only regex would have missed: a comment naming a
// DIFFERENT identity than the one it is attached to.
func pinVersionComment(lineComment string) (identity string, version [3]int, ok bool) {
	m := prGateVersionCommentRE.FindStringSubmatch(lineComment)
	if m == nil {
		return "", [3]int{}, false
	}
	major, _ := strconv.Atoi(m[2])
	minor, _ := strconv.Atoi(m[3])
	patch, _ := strconv.Atoi(m[4])
	return m[1], [3]int{major, minor, patch}, true
}

// checkVersionCommentNode24Floor validates one pinned action's identity + trailing
// version comment against prGateNode24FloorByAction. tracked reports
// whether identity is one of the two actions this invariant tracks at all —
// an untracked identity is not this function's concern (a wrong or
// unexpected identity is TestPRGateContract_ExternalActionsArePinnedToFullCommitSHA's
// job) and yields tracked=false with no problems.
//
// Pulled out of TestPRGateContract_ActionPinVersionCommentsAreAtOrAboveTheNode24Floor as a
// pure function — no *testing.T, no file I/O — so
// TestCheckVersionCommentNode24Floor can exercise every branch (missing comment,
// mismatched identity, below-floor version, at-floor version) directly with
// literal inputs, including the exact bypass pass-2 review flagged: a
// version comment that parses cleanly but names a DIFFERENT action than the
// one actually pinned.
func checkVersionCommentNode24Floor(identity, lineComment string) (tracked bool, problems []string) {
	floor, tracked := prGateNode24FloorByAction[identity]
	if !tracked {
		return false, nil
	}

	commentIdentity, got, ok := pinVersionComment(lineComment)
	if !ok {
		return true, []string{fmt.Sprintf("has no trailing `# %s@vX.Y.Z` comment — that comment is the only place the human-readable version lives once the ref itself is a bare commit SHA, so without it there is no way to confirm the pin is not a floating-to-node20 release", identity)}
	}
	// The comment's own identity (the text before `@vX.Y.Z`) must match the
	// step's real `uses:` identity. Without this check a stale or
	// copy-pasted comment sitting next to a regressed node20-era SHA would
	// still parse a passing version out of the comment text alone and clear
	// the floor check below despite pinning the wrong action's version —
	// the exact bypass this function exists to close.
	if commentIdentity != identity {
		return true, []string{fmt.Sprintf("carries a version comment naming %q instead of its own identity — a comment that doesn't match its own `uses:` identity proves nothing about which action's version was actually pinned, so a regression to a node20 SHA with a stale/mismatched comment would pass this check undetected", commentIdentity)}
	}
	if versionLess(got, floor) {
		return true, []string{fmt.Sprintf("version comment claims v%d.%d.%d, below the node24 floor v%d.%d.%d — a release below this floor is still declared `using: node20` in its action.yml and only runs today because GitHub's runners re-execute node20 actions on Node 24 as a compatibility shim; that shim is withdrawn with Node 20's removal from runner images on 2026-09-23, at which point this step stops running at all", got[0], got[1], got[2], floor[0], floor[1], floor[2])}
	}
	return true, nil
}

// TestPRGateContract_ActionPinVersionCommentsAreAtOrAboveTheNode24Floor guards against
// re-pinning either action back onto a `node20`-declared release, by checking
// the trailing human-readable comment every pin carries: that it names the
// step's OWN action identity, and a version at or above
// prGateNode24FloorByAction's literal floor for that action. See
// checkVersionCommentNode24Floor for the logic.
//
// SCOPE LIMIT, stated plainly: this verifies the COMMENT, not the pin. A
// commit SHA cannot be resolved to a version — let alone to the runtime its
// action.yml declares — without network access, which a unit test must not
// have. So a pin whose SHA was regressed to a node20 release but whose
// comment was updated to a plausible above-floor version for the same action
// still passes here.
//
// That residual gap is accepted deliberately rather than closed, and the
// alternatives were considered: hardcoding an approved identity -> SHA ->
// runtime table would make the binding real, but it converts every legitimate
// action upgrade into unrelated test churn, and it re-introduces the
// exact-SHA coupling that pinning-for-immutability deliberately avoids (the
// invariant issue #23 actually requires is immutability, which
// TestPRGateContract_ExternalActionsArePinnedToFullCommitSHA proves
// independently and completely). Treat this check as version-comment hygiene
// with a floor — genuinely useful against the realistic accident of someone
// bumping a pin downward or pasting the wrong action's comment, and honestly
// not a runtime oracle. The Node 20 removal date in
// prGateNode24FloorByAction's comment is the real deadline; a human reading a
// pin is still the thing that confirms a SHA is what its comment claims.
func TestPRGateContract_ActionPinVersionCommentsAreAtOrAboveTheNode24Floor(t *testing.T) {
	top := loadPRGateWorkflow(t)
	_, job := prGateSingleJob(t, top)

	steps := yamlMapValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		t.Fatalf("securitytest: %s job has no `steps:` sequence", prGateWorkflowRelPath)
	}

	checked := map[string]bool{}
	for _, step := range steps.Content {
		uses := yamlMapValue(step, "uses")
		if uses == nil {
			continue
		}
		ref := uses.Value
		at := strings.LastIndex(ref, "@")
		if at < 0 {
			continue // already reported by TestPRGateContract_ExternalActionsArePinnedToFullCommitSHA
		}
		identity := ref[:at]

		tracked, problems := checkVersionCommentNode24Floor(identity, uses.LineComment)
		if !tracked {
			continue // not one of the two actions this invariant tracks
		}
		checked[identity] = true
		for _, problem := range problems {
			t.Errorf("securitytest: %s pin for %s (line %d) %s", prGateWorkflowRelPath, identity, uses.Line, problem)
		}
	}

	for identity := range prGateNode24FloorByAction {
		if !checked[identity] {
			t.Errorf("securitytest: %s never pins %s at all — TestPRGateContract_ExternalActionsArePinnedToFullCommitSHA should also have caught this", prGateWorkflowRelPath, identity)
		}
	}
}

// versionLess reports whether a is a strictly earlier semantic version than
// b, comparing major, then minor, then patch.
func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Direct unit tests for the pure helpers behind the pass-2 review findings.
// These deliberately bypass loadPRGateWorkflow (there is only one real
// pr-gate.yml to read, and it does not currently exhibit any of the
// bypasses below) and instead feed literal, adversarial inputs straight to
// the extracted logic, proving each closed gap would actually be caught.
// ---------------------------------------------------------------------------

func TestPinVersionComment(t *testing.T) {
	cases := []struct {
		name         string
		lineComment  string
		wantIdentity string
		wantVersion  [3]int
		wantOK       bool
	}{
		{
			name:         "well-formed checkout comment",
			lineComment:  "# actions/checkout@v7.0.1",
			wantIdentity: "actions/checkout",
			wantVersion:  [3]int{7, 0, 1},
			wantOK:       true,
		},
		{
			name:         "well-formed setup-go comment",
			lineComment:  "# actions/setup-go@v7.0.0",
			wantIdentity: "actions/setup-go",
			wantVersion:  [3]int{7, 0, 0},
			wantOK:       true,
		},
		{
			name:        "empty comment",
			lineComment: "",
			wantOK:      false,
		},
		{
			name:        "comment with no version at all",
			lineComment: "# pinned for stability",
			wantOK:      false,
		},
		{
			name:        "comment missing the leading hash",
			lineComment: "actions/checkout@v7.0.1",
			wantOK:      false,
		},
		{
			// The parser reports whatever identity the comment names, even
			// when that identity differs from the pin it is attached to —
			// cross-checking against the real `uses:` identity is the
			// caller's job (checkVersionCommentNode24Floor), not this parser's.
			name:         "comment naming a different action than its own uses: line",
			lineComment:  "# actions/setup-go@v7.0.1",
			wantIdentity: "actions/setup-go",
			wantVersion:  [3]int{7, 0, 1},
			wantOK:       true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			identity, version, ok := pinVersionComment(tc.lineComment)
			if ok != tc.wantOK {
				t.Fatalf("pinVersionComment(%q): ok = %v, want %v", tc.lineComment, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if identity != tc.wantIdentity || version != tc.wantVersion {
				t.Errorf("pinVersionComment(%q) = (%q, %v), want (%q, %v)", tc.lineComment, identity, version, tc.wantIdentity, tc.wantVersion)
			}
		})
	}
}

// TestCheckVersionCommentNode24Floor_MismatchedIdentityCommentIsRejected is the
// regression test for the pass-2 finding: a version comment that parses
// cleanly, and even names a real tracked action, but does not match the
// identity it is actually attached to (e.g. copy-pasted from the sibling
// step, or left stale after a `uses:` edit) must be rejected rather than
// silently validated against the WRONG action's floor. Before this fix,
// the version-only regex would extract v7.0.1 from this exact comment and
// compare it against actions/checkout's floor, passing incorrectly.
func TestCheckVersionCommentNode24Floor_MismatchedIdentityCommentIsRejected(t *testing.T) {
	tracked, problems := checkVersionCommentNode24Floor("actions/checkout", "# actions/setup-go@v7.0.1")
	if !tracked {
		t.Fatalf("checkVersionCommentNode24Floor(%q, ...): tracked = false, want true", "actions/checkout")
	}
	if len(problems) != 1 {
		t.Fatalf("checkVersionCommentNode24Floor: got %d problem(s), want exactly 1: %v", len(problems), problems)
	}
	if !strings.Contains(problems[0], "actions/setup-go") {
		t.Errorf("checkVersionCommentNode24Floor: problem %q does not name the mismatched comment identity", problems[0])
	}
}

// TestCheckVersionCommentNode24Floor_BelowFloorSHAWithStaleHighVersionCommentIsCaught
// covers the same bypass from the opposite direction named in the finding's
// own suggested repro: a SHA regressed to a real node20-era release, paired
// with a comment that still names the CORRECT identity but an
// out-of-date/incorrect version number below the floor, must still fail.
func TestCheckVersionCommentNode24Floor_BelowFloorVersionIsCaught(t *testing.T) {
	tracked, problems := checkVersionCommentNode24Floor("actions/checkout", "# actions/checkout@v4.2.2")
	if !tracked {
		t.Fatalf("checkVersionCommentNode24Floor: tracked = false, want true")
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "below the node24 floor") {
		t.Fatalf("checkVersionCommentNode24Floor: got problems %v, want exactly one below-floor problem", problems)
	}
}

// TestCheckVersionCommentNode24Floor_AtOrAboveFloorAndUntracked covers the two
// non-error paths: a version at/above the floor with a correctly matching
// identity comment produces no problems, and an identity this invariant
// does not track (e.g. a third action never added to
// prGateNode24FloorByAction) is reported untracked rather than validated.
func TestCheckVersionCommentNode24Floor_AtOrAboveFloorAndUntracked(t *testing.T) {
	if tracked, problems := checkVersionCommentNode24Floor("actions/checkout", "# actions/checkout@v7.0.1"); !tracked || len(problems) != 0 {
		t.Errorf("checkVersionCommentNode24Floor(at floor): tracked=%v problems=%v, want tracked=true problems=[]", tracked, problems)
	}
	if tracked, problems := checkVersionCommentNode24Floor("actions/checkout", "# actions/checkout@v5.0.0"); !tracked || len(problems) != 0 {
		t.Errorf("checkVersionCommentNode24Floor(exactly at floor): tracked=%v problems=%v, want tracked=true problems=[]", tracked, problems)
	}
	if tracked, problems := checkVersionCommentNode24Floor("actions/some-other-action", "# actions/some-other-action@v1.0.0"); tracked || len(problems) != 0 {
		t.Errorf("checkVersionCommentNode24Floor(untracked identity): tracked=%v problems=%v, want tracked=false problems=nil", tracked, problems)
	}
}

func TestPermissionsMapping(t *testing.T) {
	var readOnly yaml.Node
	if err := yaml.Unmarshal([]byte("contents: read\n"), &readOnly); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	got, ok := permissionsMapping(readOnly.Content[0])
	if !ok {
		t.Fatalf("permissionsMapping: ok = false, want true")
	}
	if len(got) != 1 || got["contents"] != "read" {
		t.Errorf("permissionsMapping = %v, want {contents: read}", got)
	}

	if _, ok := permissionsMapping(nil); ok {
		t.Errorf("permissionsMapping(nil): ok = true, want false (absent key)")
	}

	var scalar yaml.Node
	if err := yaml.Unmarshal([]byte("write-all\n"), &scalar); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if _, ok := permissionsMapping(scalar.Content[0]); ok {
		t.Errorf("permissionsMapping(scalar): ok = true, want false (not a mapping)")
	}
}

// TestPermissionsMatch_JobLevelEscalationIsRejected is the regression test
// for the pass-2 finding: job-level `permissions:` REPLACES rather than
// merges with the top-level grant, so a job-level block granting broader
// access than the read-only contract must fail permissionsMatch even
// though the top-level block, checked in isolation, is still exactly
// {contents: read}.
func TestPermissionsMatch_JobLevelEscalationIsRejected(t *testing.T) {
	want := map[string]string{"contents": "read"}

	cases := []struct {
		name string
		got  map[string]string
		ok   bool
	}{
		{"exact match", map[string]string{"contents": "read"}, true},
		{"escalated to write", map[string]string{"contents": "write"}, false},
		{"extra scope added", map[string]string{"contents": "read", "issues": "write"}, false},
		{"empty mapping", map[string]string{}, false},
	}
	for _, tc := range cases {
		if got := permissionsMatch(tc.got, want); got != tc.ok {
			t.Errorf("permissionsMatch(%v, %v) = %v, want %v", tc.got, want, got, tc.ok)
		}
	}
}

func TestPRGateScriptCommand(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		wantCmd string
		wantOK  bool
	}{
		{
			name:    "bare contractual command",
			script:  "go build ./...",
			wantCmd: "go build ./...",
			wantOK:  true,
		},
		{
			name:    "command with a safe strict-mode prefix line",
			script:  "set -euo pipefail\ngo test -race ./...",
			wantCmd: "go test -race ./...",
			wantOK:  true,
		},
		{
			// The exact bypass the finding describes: the command text
			// appears, but only inside a string literal argument to echo —
			// the script actually executes `echo`, never the Go toolchain.
			name:    "command text embedded in an echo string literal",
			script:  "echo 'go build ./...'",
			wantCmd: "echo 'go build ./...'",
			wantOK:  true,
		},
		{
			name:   "two real commands on separate lines",
			script: "go build ./...\ngo vet ./...",
			wantOK: false,
		},
		{
			name:   "blank script",
			script: "",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, ok := prGateScriptCommand(tc.script)
			if ok != tc.wantOK {
				t.Fatalf("prGateScriptCommand(%q): ok = %v, want %v (cmd=%q)", tc.script, ok, tc.wantOK, cmd)
			}
			if ok && cmd != tc.wantCmd {
				t.Errorf("prGateScriptCommand(%q) = %q, want %q", tc.script, cmd, tc.wantCmd)
			}
		})
	}
}

// TestPRGateContract_FiveCommandsRunExactlyOnceInOrder_RejectsEchoedCommandText
// is the end-to-end regression test for the finding: a workflow whose gate
// job runs `echo 'go build ./...'` instead of the real command must fail
// the contract test, not pass it merely because the command text appears
// somewhere in a `run:` script. This builds a synthetic single-job workflow
// document in memory — it never touches the real pr-gate.yml — and drives
// the exact same helpers (prGateSingleJob, prGateStepRuns, prGateScriptCommand)
// the production test uses.
func TestPRGateContract_FiveCommandsRunExactlyOnceInOrder_RejectsEchoedCommandText(t *testing.T) {
	const doc = `
jobs:
  required-pr-gate:
    steps:
      - name: Build
        run: echo 'go build ./...'
      - name: Vet
        run: go vet ./...
      - name: Race tests
        run: go test -race ./...
      - name: Phase 5 security tests
        run: go test -tags phase5release ./internal/securitytest -count=1
      - name: ClickHouse shell library tests
        run: bash integration/clickhouse/tests/lib-tests.sh
`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	top := root.Content[0]

	_, job := prGateSingleJob(t, top)
	runs, _ := prGateStepRuns(t, job)

	total := 0
	for _, script := range runs {
		got, ok := prGateScriptCommand(script)
		if ok && got == "go build ./..." {
			total++
		}
	}
	if total != 0 {
		t.Errorf("exact-match reduction counted %q %d time(s) from a step that only echoes it inside a string literal — the pre-fix substring-based check would have counted this as 1 and passed", "go build ./...", total)
	}
}
