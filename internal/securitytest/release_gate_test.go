//go:build phase5release

package securitytest

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// This file is the plan §5.10/§24 "Final redaction release gate", built
// only with -tags phase5release:
//
//	go test -tags phase5release ./internal/securitytest -count=1
//
// Normal development (go test ./internal/securitytest, no build tag) must
// stay green while the known, externally-owned go-mcp-oauth-sdk@v0.2.0
// kid-rotation defect remains open — that's what lets SDK-independent
// phase-5 work proceed per amendment A1. This file is the opposite: it is
// the ONE place that must fail while that defect's manifest row is still
// blocked_external, so the phase can never be silently certified complete
// while SDK_REDACTION_AUTHORIZATION_GATE is open.
//
// Per plan §4/A1/§28, this test is EXPECTED to fail right now, naming
// exactly the go-mcp-oauth-sdk@v0.2.0 / parseAndFetchKeys row — that is a
// correct report of a real, known, externally-owned blocker, not a defect
// in this test or in this sub-task. Resolving it requires either (a) a
// separately authorized go-mcp-oauth-sdk release that drops the raw `kid`
// field (plan §4.4: bump go.mod/go.sum, re-audit every external row, flip
// this row's state to safe, update the rotation test to require the kid
// marker's ABSENCE), or (b) a recorded decision that `kid` is allowed
// non-credential metadata, flipping the row to safe on that basis instead.
// Neither resolution is this sub-task's to make — see plan-19p5.md's
// coordinator amendment A1.

// TestReleaseGate_NoBlockedExternalRowsRemain fails while any manifest row
// is classified blocked_external — currently exactly the SDK kid-rotation
// row. The failure message intentionally names only that row (or whatever
// set of rows is actually blocked at the time this runs); it does not fail
// for any other reason.
func TestReleaseGate_NoBlockedExternalRowsRemain(t *testing.T) {
	var blocked []string
	for _, r := range loadRealManifest(t) {
		if r.State != "blocked_external" {
			continue
		}
		blocked = append(blocked, fmt.Sprintf("%s | %s | %s | %s | %s (gate=%s)", r.Scope, r.Path, r.Function, r.SinkKind, r.Fingerprint, r.Gate))
	}
	if len(blocked) == 0 {
		return
	}
	sort.Strings(blocked)
	t.Fatalf("release gate: %d blocked_external redaction row(s) remain — phase 5 cannot be certified complete "+
		"until each is resolved (bump+re-audit the SDK, or record kid as allowed non-credential metadata):\n%s",
		len(blocked), strings.Join(blocked, "\n"))
}

// TestReleaseGate_ResolvedSDKVersionMatchesAudited re-runs the sdk_contract
// version check under the release tag. It passes today (go.mod already
// pins the audited v0.2.0) — this test exists so a version bump made
// without also updating auditedSDKVersion and re-auditing the external
// rows fails release closure too, not just normal development.
func TestReleaseGate_ResolvedSDKVersionMatchesAudited(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	version, _, source, err := resolvedSDKModule(root)
	if err != nil {
		t.Fatalf("securitytest: resolve %s version: %v", sdkModulePath, err)
	}
	if version != auditedSDKVersion {
		t.Fatalf("release gate: %s resolved to %s (via %s), want the audited version %s", sdkModulePath, version, source, auditedSDKVersion)
	}
}
