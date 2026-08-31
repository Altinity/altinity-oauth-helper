package securitytest

// This file implements issue #33 phase 1's production dependency contract
// (plan §5, §6, §31): it is the LIVE gate on ./cmd/ch-oauth-ldap's
// non-standard-library import closure, kept deliberately separate from the
// wire-evidence contract in wire_profile_contract_test.go.
//
// Two files named "production-nonstdlib-deps.txt" exist in this repository
// and they are NOT interchangeable:
//
//   - internal/ldap/testdata/phase1-baseline/production-nonstdlib-deps.txt
//     is an IMMUTABLE historical snapshot recorded once, before any Phase-1
//     change, so later phases can compare the replacement to the actual
//     pre-rewrite closure. This test file must never read it.
//   - internal/securitytest/testdata/production-nonstdlib-deps.txt (see
//     liveExpectationRelPath below) is the LIVE expected closure this file
//     enforces. It started Phase 1 byte-identical to the historical
//     snapshot (plan §5), but — unlike the historical file — it is
//     intentionally updated whenever an approved later phase changes
//     production dependencies (e.g. Phase 4's dependency deletions).
//
// Phase 1 claims exactly three tests here:
//
//   - TestDependencyContract_ProductionClosureMatchesExpected: the live
//     closure equals the committed live expectation, byte-for-byte after
//     normalization.
//   - TestDependencyContract_NoNonStandardCryptobyte: the plan §1 non-goal
//     "add golang.org/x/crypto/cryptobyte to ./cmd/ch-oauth-ldap's
//     production closure" never silently happens.
//   - TestDependencyContract_WirefixtureIsNotProduction: internal/wirefixture
//     (test/tooling support introduced alongside this contract, plan §8.1)
//     stays mechanically outside the shipped command's closure.
//
// Issue #33 phase 3 extends this same file (plan §31 "Later-phase handoff",
// "Dependency closure contract") with the staged general-purpose-LDAP-library
// denylist and the temporary phase3profile tagged-replacement contracts, at
// the bottom of this file:
//
//   - TestDependencyContract_ProductionClosureHasNoGeneralLDAP: the staged,
//     test-only-enum-gated policy over the ordinary (untagged)
//     ./cmd/ch-oauth-ldap closure. At productionLDAPClosureStage ==
//     legacyUntilPhase4 (today's value) it requires — rather than forbids —
//     at least one dependency matching EACH of the five general-LDAP
//     prefixes, so the staged contract stays an honest proof that the known
//     legacy dependency problem is really present, never a vacuously-passing
//     no-op. Phase 4 flips the single stage constant to replacement, which
//     inverts the assertion to zero matches plus profile/cryptobyte
//     presence.
//   - TestDependencyContract_Phase3ReplacementClosureHasNoGeneralLDAP: the
//     same denylist applied to the -tags=phase3profile closure of the same
//     command, which is already expected to be general-LDAP-free today.
//   - TestDependencyContract_Phase3ReplacementCommandBuilds: a real
//     deterministic `go build -tags=phase3profile ./cmd/ch-oauth-ldap`,
//     because `go list -deps` alone proves closure membership, not that the
//     tagged function bodies still type-check.
//
// The five-prefix denylist and its prefix matcher (generalLDAPDenylistPrefixes,
// matchesGeneralLDAPPrefix, isGeneralLDAPDependency) are defined once, here,
// and reused verbatim by profile_dependency_contract_test.go's own
// profile-closure policy — never forked into a second, independently
// drifting list.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// liveExpectationRelPath is internal/securitytest/testdata's live production
// dependency expectation, relative to the module root. It is checked at
// runtime (see liveExpectationPath) to guard the "Historical baseline never
// used as live expectation" invariant: this string must live under
// internal/securitytest/testdata and must never reference
// internal/ldap/testdata/phase1-baseline.
const liveExpectationRelPath = "internal/securitytest/testdata/production-nonstdlib-deps.txt"

// forbiddenCryptobyteImport is the plan §1 non-goal import path that must
// never appear in ./cmd/ch-oauth-ldap's production closure during Phase 1.
const forbiddenCryptobyteImport = "golang.org/x/crypto/cryptobyte"

// forbiddenWirefixtureImport is internal/wirefixture's full import path —
// test/tooling support (plan §8.1) that must stay mechanically outside the
// shipped command's production closure.
const forbiddenWirefixtureImport = "github.com/altinity/altinity-oauth-helper/internal/wirefixture"

// productionClosureTarget is the exact package the dependency contract
// evaluates, matching plan §4.2/§6's committed commands.
const productionClosureTarget = "./cmd/ch-oauth-ldap"

// TestDependencyContract_ProductionClosureMatchesExpected requires the live,
// deterministically re-derived non-standard-library import closure of
// ./cmd/ch-oauth-ldap to equal the committed live expectation at
// liveExpectationRelPath, exactly (plan §5, §6).
func TestDependencyContract_ProductionClosureMatchesExpected(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}

	got := liveProductionNonstdlibDeps(t, root)

	expPath := liveExpectationPath(t, root)
	expBytes, err := os.ReadFile(expPath)
	if err != nil {
		t.Fatalf("dependency_contract: read live expectation %s: %v", expPath, err)
	}
	want := normalizeDepsOutput(string(expBytes))

	added, removed := diffStringSets(got, want)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("dependency_contract: live %s non-standard dependency closure does not match %s\n"+
			"in live closure but not in expectation (%d):\n  %s\n"+
			"in expectation but not in live closure (%d):\n  %s\n"+
			"If this is an approved, reviewed dependency change, update the live expectation file at %s — never internal/ldap/testdata/phase1-baseline's immutable historical snapshot.",
			productionClosureTarget, expPath,
			len(added), strings.Join(added, "\n  "),
			len(removed), strings.Join(removed, "\n  "),
			expPath)
	}
}

// TestDependencyContract_NoNonStandardCryptobyte requires
// golang.org/x/crypto/cryptobyte to stay absent from ./cmd/ch-oauth-ldap's
// live production closure (plan §1 non-goal: "add non-standard
// golang.org/x/crypto/cryptobyte to ./cmd/ch-oauth-ldap's production
// closure"). cryptobyte may be used freely in test-only code (see
// internal/ldap/clickhouse_wire_cryptobyte_test.go) — this test asserts only
// that the released binary never links it.
func TestDependencyContract_NoNonStandardCryptobyte(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}
	got := liveProductionNonstdlibDeps(t, root)
	for _, dep := range got {
		if dep == forbiddenCryptobyteImport {
			t.Fatalf("dependency_contract: %s must not appear in %s's production closure (plan §1 non-goal)", forbiddenCryptobyteImport, productionClosureTarget)
		}
	}
}

// TestDependencyContract_WirefixtureIsNotProduction requires
// internal/wirefixture to stay absent from ./cmd/ch-oauth-ldap's live
// production closure — it is test/tooling support only (plan §8.1: "is
// mechanically absent from the production command closure").
func TestDependencyContract_WirefixtureIsNotProduction(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}
	got := liveProductionNonstdlibDeps(t, root)
	for _, dep := range got {
		if dep == forbiddenWirefixtureImport {
			t.Fatalf("dependency_contract: %s must stay test/tooling-only and outside %s's production closure (plan §8.1)", forbiddenWirefixtureImport, productionClosureTarget)
		}
	}
}

// liveExpectationPath resolves liveExpectationRelPath against root and
// asserts, as a test-local invariant check, that it names a file under
// internal/securitytest/testdata and never the immutable historical
// snapshot under internal/ldap/testdata/phase1-baseline ("Historical
// baseline never used as live expectation" — plan §5). This guards against a
// future edit accidentally repointing this file at the historical snapshot.
func liveExpectationPath(t *testing.T, root string) string {
	t.Helper()
	const requiredPrefix = "internal/securitytest/testdata/"
	const forbiddenSubstring = "phase1-baseline"
	if !strings.HasPrefix(liveExpectationRelPath, requiredPrefix) {
		t.Fatalf("dependency_contract: internal invariant violated: live expectation path %q must be under %s", liveExpectationRelPath, requiredPrefix)
	}
	if strings.Contains(liveExpectationRelPath, forbiddenSubstring) {
		t.Fatalf("dependency_contract: internal invariant violated: live expectation path %q must never reference the immutable historical %s snapshot", liveExpectationRelPath, forbiddenSubstring)
	}
	return filepath.Join(root, filepath.FromSlash(liveExpectationRelPath))
}

// liveProductionNonstdlibDeps runs the deterministic `go list` invocation
// specified by plan §6 against productionClosureTarget and returns the
// normalized non-standard-library import closure.
func liveProductionNonstdlibDeps(t *testing.T, root string) []string {
	t.Helper()

	goBin := resolveGoBin(t)

	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"list", "-mod=readonly", "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}",
		productionClosureTarget)
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("dependency_contract: %s list -deps %s failed: %v\nstderr:\n%s", filepath.Base(goBin), productionClosureTarget, err, stderr.String())
	}
	return normalizeDepsOutput(stdout.String())
}

// resolveGoBin resolves the exact go tool binary this test invokes, per plan
// §6:
//
//	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
//
// with a ".exe" suffix on a Windows host.
//
// runtime.GOROOT() has been deprecated since Go 1.24 (this module's go.mod
// pins go 1.26) and is documented to return "" when the running test binary
// was built with -trimpath. Per coordinator amendment 7, this test
// deliberately chooses NO fallback for that case — no `go env GOROOT`
// shell-out, no PATH lookup, nothing. The plan's rule for this gate is fail,
// never skip (§6: "If runtime.GOROOT() is empty, the binary is absent, or
// execution fails: fail the test; never skip. This test is an enforcement
// mechanism in the Required PR gate."), and a silent fallback would let a
// future toolchain or -trimpath change quietly swap in an unaudited go
// binary instead of surfacing as a visible, diagnosable gate failure. If
// this ever starts failing here on a legitimate toolchain change, that is
// the signal to make a deliberate, reviewed decision about a fallback — not
// to add one implicitly.
func resolveGoBin(t *testing.T) string {
	t.Helper()
	bin, err := resolveGoBinPath()
	if err != nil {
		t.Fatalf("dependency_contract: %v", err)
	}
	return bin
}

// resolveGoBinPath is resolveGoBin's non-testing core, shared with
// profile_types_contract_test.go's export-data loader (which resolves the
// binary inside a sync.Once, where no *testing.T is available). Same
// no-fallback rule, same failure modes — only the reporting differs.
func resolveGoBinPath() (string, error) {
	goroot := runtime.GOROOT()
	if goroot == "" {
		return "", errors.New("runtime.GOROOT() returned an empty string (deprecated since Go 1.24; also empty under -trimpath) and this check has no fallback by design (amendment 7) — see resolveGoBin's doc comment")
	}
	bin := filepath.Join(goroot, "bin", "go")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	info, err := os.Stat(bin)
	if err != nil {
		return "", fmt.Errorf("go binary not found at %s (resolved from runtime.GOROOT()): %w", bin, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("resolved go binary path %s is a directory, not an executable", bin)
	}
	return bin, nil
}

// deterministicGoListEnv builds the environment for the `go list` invocation
// per plan §6: start from os.Environ() (so GOFLAGS/GOTOOLCHAIN/GOMODCACHE/
// GOPROXY and normal module-cache configuration keep working), remove any
// inherited GOOS/GOARCH/CGO_ENABLED/GOWORK, and append the fixed
// GOOS=linux/GOARCH=amd64/CGO_ENABLED=0/GOWORK=off quadruple so the
// resulting closure is host-independent and matches exactly how both
// internal/ldap/testdata/phase1-baseline's historical snapshot and this
// package's own live expectation were generated (plan §4.2).
func deterministicGoListEnv() []string {
	drop := map[string]bool{
		"GOOS":        true,
		"GOARCH":      true,
		"CGO_ENABLED": true,
		"GOWORK":      true,
	}
	base := os.Environ()
	out := make([]string, 0, len(base)+4)
	for _, kv := range base {
		key, _, hasEq := strings.Cut(kv, "=")
		if hasEq && drop[key] {
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"GOOS=linux",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
		"GOWORK=off",
	)
}

// normalizeDepsOutput reproduces the exact normalization plan §4.2/§6
// specify for the committed expectation file: drop blank lines, de-duplicate,
// and sort with a byte-wise (LC_ALL=C-equivalent) comparison — which is
// exactly what Go's sort.Strings already does, since Go string comparison is
// itself byte-wise.
func normalizeDepsOutput(raw string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// diffStringSets returns the elements of got missing from want (added) and
// the elements of want missing from got (removed), each in the order they
// first appear in their source slice. Used only to render a readable,
// environment-value-free diff in a test failure message.
func diffStringSets(got, want []string) (added, removed []string) {
	gotSet := make(map[string]bool, len(got))
	for _, g := range got {
		gotSet[g] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range got {
		if !wantSet[g] {
			added = append(added, g)
		}
	}
	for _, w := range want {
		if !gotSet[w] {
			removed = append(removed, w)
		}
	}
	return added, removed
}

// --- Phase 3: general-LDAP denylist + tagged-replacement contracts ------
//
// phase3ReplacementTag is the temporary Phase 3 compile-time selector (plan
// "Central design: temporary phase3profile compile-time selection") that
// switches ./cmd/ch-oauth-ldap's LDAP backend from legacy internal/ldap to
// internal/ldap/profile. Phase 4 deletes it; until then it must appear
// nowhere except integration/clickhouse/Dockerfile's ch-oauth-ldap build
// line (see phase3_selector_contract_test.go) and must never become a
// runtime selector.
const phase3ReplacementTag = "phase3profile"

// legacyLDAPImportPath is this module's own legacy general-purpose LDAP
// server package. It must be present in the ordinary (untagged) production
// closure and absent from the -tags=phase3profile closure throughout
// Phase 3 (Phase 4 deletes the package and inverts both expectations).
const legacyLDAPImportPath = "github.com/altinity/altinity-oauth-helper/internal/ldap"

// generalLDAPDenylistPrefixes are the production general-purpose LDAP-stack
// import-path prefixes the issue's dependency policy forbids everywhere it
// applies (plan "Dependency closure contract"). Defined once, here, and
// reused verbatim by profile_dependency_contract_test.go's own
// profile-closure policy — never forked into a second, independently
// drifting list. The production snapshot contains
// github.com/vjeantet/goldap/message (not github.com/vjeantet/goldap
// itself), which is exactly why matching is prefix-based
// (matchesGeneralLDAPPrefix) rather than bare equality.
var generalLDAPDenylistPrefixes = []string{
	"github.com/vjeantet/ldapserver",
	"github.com/vjeantet/goldap",
	"github.com/go-ldap/ldap/v3",
	"github.com/go-asn1-ber/asn1-ber",
	"github.com/Azure/go-ntlmssp",
}

// matchesGeneralLDAPPrefix reports whether dep is prefix itself or one of
// its subpackages, using exactly the rule plan "Dependency closure contract"
// requires: "dep == prefix || strings.HasPrefix(dep, prefix+"/")".
func matchesGeneralLDAPPrefix(dep, prefix string) bool {
	return dep == prefix || strings.HasPrefix(dep, prefix+"/")
}

// isGeneralLDAPDependency reports whether dep matches any
// generalLDAPDenylistPrefixes entry.
func isGeneralLDAPDependency(dep string) bool {
	for _, prefix := range generalLDAPDenylistPrefixes {
		if matchesGeneralLDAPPrefix(dep, prefix) {
			return true
		}
	}
	return false
}

// ldapClosureStage is the test-only closed enum gating
// TestDependencyContract_ProductionClosureHasNoGeneralLDAP's assertion
// direction (plan "Staged production state"). It has exactly two valid
// values; anything else fails the test rather than silently defaulting.
type ldapClosureStage string

const (
	// legacyUntilPhase4 is today's honest state: the ordinary production
	// closure still contains the full general-LDAP stack, and the staged
	// contract requires — never forbids — evidence of that fact, so the
	// contract cannot pass vacuously while quietly proving nothing.
	legacyUntilPhase4 ldapClosureStage = "legacyUntilPhase4"
	// replacement is Phase 4's post-cutover state: zero general-LDAP
	// matches, plus profile and cryptobyte present. Phase 4 flips
	// productionLDAPClosureStage to this value only after the cutover is
	// actually present.
	replacement ldapClosureStage = "replacement"
)

// productionLDAPClosureStage is the single flag Phase 4 flips once the
// production cutover has actually landed (plan "Staged production state").
// Do not flip it ahead of the real cutover: at legacyUntilPhase4 (today's
// value) this is a truthful staged denylist over a known-bad closure, not an
// aspirational one.
const productionLDAPClosureStage = legacyUntilPhase4

// TestDependencyContract_ProductionClosureHasNoGeneralLDAP is the staged
// general-LDAP dependency policy over ./cmd/ch-oauth-ldap's ordinary
// (untagged) live production closure (plan "Staged production state").
//
// At legacyUntilPhase4 (today's stage) it requires at least one dependency
// matching EACH of the five generalLDAPDenylistPrefixes entries in the
// ordinary closure — a deliberately non-vacuous proof that the staged
// contract is honestly observing today's known legacy dependency problem,
// not a no-op dressed up as a policy. At replacement it requires zero
// matches for all five prefixes, plus internal/ldap/profile and
// golang.org/x/crypto/cryptobyte both present. An unknown stage value fails
// the test outright.
func TestDependencyContract_ProductionClosureHasNoGeneralLDAP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}
	got := liveProductionNonstdlibDeps(t, root)

	switch productionLDAPClosureStage {
	case legacyUntilPhase4:
		for _, prefix := range generalLDAPDenylistPrefixes {
			found := false
			for _, dep := range got {
				if matchesGeneralLDAPPrefix(dep, prefix) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("dependency_contract: staged denylist stage %q requires at least one dependency matching prefix %s in %s's live closure, but none was found — the staged contract must observe today's known legacy dependency honestly and must never become vacuous",
					productionLDAPClosureStage, prefix, productionClosureTarget)
			}
		}
	case replacement:
		for _, dep := range got {
			if isGeneralLDAPDependency(dep) {
				t.Fatalf("dependency_contract: staged denylist stage %q requires zero general-LDAP matches in %s's live closure, but found %s",
					productionLDAPClosureStage, productionClosureTarget, dep)
			}
		}
		requireDepPresent(t, got, profileImportPath, "stage "+string(productionLDAPClosureStage))
		requireDepPresent(t, got, forbiddenCryptobyteImport, "stage "+string(productionLDAPClosureStage))
	default:
		t.Fatalf("dependency_contract: unknown productionLDAPClosureStage %q — must be %q or %q", productionLDAPClosureStage, legacyUntilPhase4, replacement)
	}
}

// requireDepPresent fails the test unless want appears in got, reporting
// context in the failure message.
func requireDepPresent(t *testing.T, got []string, want, context string) {
	t.Helper()
	for _, dep := range got {
		if dep == want {
			return
		}
	}
	t.Fatalf("dependency_contract: %s requires %s present in the live closure, but it is absent", context, want)
}

// liveTaggedProductionNonstdlibDeps runs the same deterministic `go list`
// invocation liveProductionNonstdlibDeps uses, with -tags=phase3profile
// added, against productionClosureTarget (plan "Tagged replacement
// contract": "go list -mod=readonly -tags=phase3profile -deps
// ./cmd/ch-oauth-ldap").
func liveTaggedProductionNonstdlibDeps(t *testing.T, root string) []string {
	t.Helper()

	goBin := resolveGoBin(t)

	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"list", "-mod=readonly", "-tags="+phase3ReplacementTag, "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}",
		productionClosureTarget)
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("dependency_contract: %s list -tags=%s -deps %s failed: %v\nstderr:\n%s", filepath.Base(goBin), phase3ReplacementTag, productionClosureTarget, err, stderr.String())
	}
	return normalizeDepsOutput(stdout.String())
}

// TestDependencyContract_Phase3ReplacementClosureHasNoGeneralLDAP requires
// the -tags=phase3profile live closure of ./cmd/ch-oauth-ldap to already
// satisfy the final (post-cutover) dependency policy today (plan "Tagged
// replacement contract"): internal/ldap/profile present, cryptobyte
// present, legacy internal/ldap absent, all five general-LDAP prefixes
// absent, and internal/wirefixture (test/tooling support) absent. This is a
// closure proof only — the separate
// TestDependencyContract_Phase3ReplacementCommandBuilds test proves the
// tagged composition also actually compiles.
func TestDependencyContract_Phase3ReplacementClosureHasNoGeneralLDAP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}
	got := liveTaggedProductionNonstdlibDeps(t, root)

	requireDepPresent(t, got, profileImportPath, "the -tags="+phase3ReplacementTag+" closure")
	requireDepPresent(t, got, forbiddenCryptobyteImport, "the -tags="+phase3ReplacementTag+" closure")

	for _, dep := range got {
		if dep == legacyLDAPImportPath {
			t.Fatalf("dependency_contract: the -tags=%s closure of %s must not contain the legacy %s, but it does", phase3ReplacementTag, productionClosureTarget, legacyLDAPImportPath)
		}
		if dep == forbiddenWirefixtureImport {
			t.Fatalf("dependency_contract: the -tags=%s closure of %s must not contain %s (test/tooling support only), but it does", phase3ReplacementTag, productionClosureTarget, forbiddenWirefixtureImport)
		}
		if isGeneralLDAPDependency(dep) {
			t.Fatalf("dependency_contract: the -tags=%s closure of %s must not contain the general-LDAP stack, but found %s", phase3ReplacementTag, productionClosureTarget, dep)
		}
	}
}

// TestDependencyContract_Phase3ReplacementCommandBuilds performs a real
// deterministic `go build -tags=phase3profile ./cmd/ch-oauth-ldap` (plan "CI
// compilation of the tagged composition"). `go list -deps` alone proves
// dependency-closure membership but not that the tagged function bodies
// still type-check — a renamed profile.Config field, a changed profile.New
// signature, or a tagged syntax/type error would all pass the closure
// contracts above while failing to compile. This test is deliberately
// untagged so the Required PR gate's `go test -race ./...` step executes it
// on every pull request and every push to main, without ever touching
// .github/workflows/pr-gate.yml's pinned five-command contract.
//
// The build output goes to t.TempDir(), which the testing package removes
// automatically — no build artifact is ever left in the checkout.
func TestDependencyContract_Phase3ReplacementCommandBuilds(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}

	goBin := resolveGoBin(t)
	outBin := filepath.Join(t.TempDir(), "ch-oauth-ldap-phase3")

	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"build",
		"-mod=readonly",
		"-tags="+phase3ReplacementTag,
		"-o", outBin,
		productionClosureTarget)
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("dependency_contract: %s build -tags=%s -o %s %s failed: %v\nstdout:\n%s\nstderr:\n%s",
			filepath.Base(goBin), phase3ReplacementTag, outBin, productionClosureTarget, err, stdout.String(), stderr.String())
	}
	if info, err := os.Stat(outBin); err != nil || info.IsDir() {
		t.Fatalf("dependency_contract: expected a built binary at %s after a successful build, stat: %v", outBin, err)
	}
}
