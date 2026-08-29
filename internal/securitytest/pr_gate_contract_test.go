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
//   - Trigger set is exactly unfiltered `pull_request` plus `push` on `main`.
//     A `paths:`/`paths-ignore:` filter anywhere, or a narrowed trigger, means
//     some pull requests never run the gate at all — and a required check that
//     never runs on a documentation-only-looking PR is how an unverified change
//     reaches `main` looking green.
//   - `pull_request_target` is absent. That trigger runs the BASE repository's
//     workflow with a writable token and repository secrets in the context of
//     an untrusted fork head; adding it to a job that then builds and tests
//     that head is a straightforward supply-chain compromise of this repo.
//   - Top-level `permissions` is exactly `{contents: read}`. The gate only
//     needs to read source. Any broader grant hands the token that runs
//     PR-authored test code the authority to write to the repository.
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
//   - Every pinned action is at or above the first release that declares the
//     `node24` runtime (`actions/checkout` >= v6.0.0, `actions/setup-go` >=
//     v7.0.0). GitHub Actions runners stopped shipping Node 20 on 2026-09-23;
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
// (verified against the real actions/checkout and actions/setup-go
// repositories: v6.0.0 and v7.0.0 respectively — setup-go v6.x is still
// node20). A pin below this floor only runs because GitHub's runners
// currently re-execute node20-declared actions on the Node 24 runtime as a
// compatibility shim; that shim is withdrawn with Node 20's removal from
// runner images on 2026-09-23, at which point a below-floor pin breaks the
// gate outright rather than merely running on borrowed time.
var prGateNode24FloorByAction = map[string][3]int{
	"actions/checkout": {6, 0, 0},
	"actions/setup-go": {7, 0, 0},
}

// prGateVersionCommentRE extracts the semantic version from a pin's trailing
// `# actions/<name>@vX.Y.Z` comment, the only place the human-readable
// version lives (the invariant is SHA immutability, so the version cannot be
// read back out of the pin itself — see this file's header comment).
var prGateVersionCommentRE = regexp.MustCompile(`@v(\d+)\.(\d+)\.(\d+)\s*$`)

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
		t.Fatalf("securitytest: read %s: %v — the required PR verification gate must exist; with this workflow gone, nothing verifies a pull request before it merges to main", prGateWorkflowRelPath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("securitytest: parse %s: %v — an unparseable gate workflow does not run, so PRs would merge unverified", prGateWorkflowRelPath, err)
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

	// `pull_request:` must carry no configuration whatsoever (null value):
	// every filter form (paths, branches, types) can exclude some PR from
	// verification.
	pr := yamlMapValue(on, "pull_request")
	if pr != nil && pr.Kind != yaml.ScalarNode {
		t.Errorf("securitytest: %s `on.pull_request` has configuration (keys %v) but must be unfiltered — any branch/paths/types filter there means some pull requests merge without ever running the gate", prGateWorkflowRelPath, yamlMapKeys(pr))
	} else if pr != nil && pr.Value != "" && pr.Value != "null" && pr.Value != "~" {
		t.Errorf("securitytest: %s `on.pull_request` must be an empty (unfiltered) value, got %q", prGateWorkflowRelPath, pr.Value)
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
		t.Errorf("securitytest: %s contains path filter(s) %v, but the gate must be unfiltered — a path filter means some pull requests merge unverified (the check is simply never reported for them, which branch protection cannot distinguish from a change that needs no verification)", prGateWorkflowRelPath, found)
	}
}

func TestPRGateContract_TopLevelPermissionsAreReadOnly(t *testing.T) {
	top := loadPRGateWorkflow(t)
	perms := yamlMapValue(top, "permissions")
	if perms == nil || perms.Kind != yaml.MappingNode {
		t.Fatalf("securitytest: %s has no top-level `permissions:` mapping — without an explicit grant the job inherits the repository default, which may be write, handing PR-authored test code repository authority", prGateWorkflowRelPath)
	}
	got := map[string]string{}
	for i := 0; i+1 < len(perms.Content); i += 2 {
		got[perms.Content[i].Value] = perms.Content[i+1].Value
	}
	if len(got) != len(prGateExpectedPermissions) {
		t.Fatalf("securitytest: %s top-level permissions are %v, want exactly %v — every scope beyond `contents: read` is authority granted to code an outside contributor wrote", prGateWorkflowRelPath, got, prGateExpectedPermissions)
	}
	for scope, want := range prGateExpectedPermissions {
		if got[scope] != want {
			t.Errorf("securitytest: %s permission `%s` is %q, want %q — the gate only reads source; anything broader lets PR-authored test code act on this repository", prGateWorkflowRelPath, scope, got[scope], want)
		}
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

func TestPRGateContract_FiveCommandsRunExactlyOnceInOrder(t *testing.T) {
	top := loadPRGateWorkflow(t)
	_, job := prGateSingleJob(t, top)
	runs, names := prGateStepRuns(t, job)

	// For each contractual command: count its occurrences across every `run:`
	// script, and record the index of the step that carries it. The five
	// commands are mutually non-overlapping strings, so substring counting is
	// unambiguous while still tolerating a step that wraps a command (e.g. a
	// `set -euo pipefail` prefix).
	positions := make([]int, len(prGateRequiredCommands))
	for ci, cmd := range prGateRequiredCommands {
		total := 0
		positions[ci] = -1
		for si, script := range runs {
			n := strings.Count(script, cmd)
			if n > 0 && positions[ci] == -1 {
				positions[ci] = si
			}
			total += n
		}
		switch {
		case total == 0:
			t.Errorf("securitytest: %s never runs %q — that entire class of verification no longer gates merges. (%q in particular is not compiled by plain `go test ./...`, so dropping it means the redaction/SDK release gate stops running anywhere in CI.)", prGateWorkflowRelPath, cmd, prGateRequiredCommands[3])
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

// TestPRGateContract_ActionPinsAreAtOrAboveTheNode24Floor guards against
// re-pinning either action back onto a `node20`-declared release. The SHA
// itself carries no version information (that is the point of pinning to a
// commit rather than a tag), so the check reads the trailing human-readable
// comment every pin in this file already carries and compares it against
// prGateNode24FloorByAction's literal floor per action identity.
func TestPRGateContract_ActionPinsAreAtOrAboveTheNode24Floor(t *testing.T) {
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
		floor, tracked := prGateNode24FloorByAction[identity]
		if !tracked {
			continue // not one of the two actions this invariant tracks
		}

		m := prGateVersionCommentRE.FindStringSubmatch(uses.LineComment)
		if m == nil {
			t.Errorf("securitytest: %s pin for %s (line %d) has no trailing `# %s@vX.Y.Z` comment — that comment is the only place the human-readable version lives once the ref itself is a bare commit SHA, so without it there is no way to confirm the pin is not a floating-to-node20 release", prGateWorkflowRelPath, identity, uses.Line, identity)
			continue
		}
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		patch, _ := strconv.Atoi(m[3])
		got := [3]int{major, minor, patch}

		checked[identity] = true
		if versionLess(got, floor) {
			t.Errorf("securitytest: %s pins %s to v%d.%d.%d (line %d), below the node24 floor v%d.%d.%d — a pin below this floor is still declared `using: node20` in its action.yml and only runs today because GitHub's runners re-execute node20 actions on Node 24 as a compatibility shim; that shim is withdrawn with Node 20's removal from runner images on 2026-09-23, at which point this step stops running at all", prGateWorkflowRelPath, identity, major, minor, patch, uses.Line, floor[0], floor[1], floor[2])
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
