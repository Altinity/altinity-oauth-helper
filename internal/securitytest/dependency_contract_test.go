package securitytest

// This file implements the production dependency contract for
// ./cmd/ch-oauth-ldap's non-standard-library import closure (originally
// issue #33 phase 1, plan §5, §6, §31), kept deliberately separate from the
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
//     production dependencies (issue #33 phase 4's cutover regenerated it:
//     the whole general-LDAP stack and its vendored replaces are gone,
//     internal/ldap/profile and golang.org/x/crypto/cryptobyte are now
//     legitimate members).
//
// Three tests here enforce the live closure directly:
//
//   - TestDependencyContract_ProductionClosureMatchesExpected: the live
//     closure equals the committed live expectation, byte-for-byte after
//     normalization.
//   - TestDependencyContract_NoNonStandardCryptobyte: NOW A POSITIVE
//     CONTRACT (issue #33 phase 4 inverted this from its original Phase 1
//     "must be absent" form, per profile_dependency_contract_test.go's
//     Amendment 5 note): golang.org/x/crypto/cryptobyte is production's
//     chosen ASN.1 primitive and must stay present in
//     ./cmd/ch-oauth-ldap's live production closure.
//   - TestDependencyContract_WirefixtureIsNotProduction: internal/wirefixture
//     (test/tooling support) stays mechanically outside the shipped
//     command's closure — unchanged in intent since Phase 1.
//
// TestDependencyContract_ProductionClosureHasNoGeneralLDAP, below, is the
// permanent, unconditional form of what issue #33 phase 3 introduced as a
// staged, test-enum-gated policy: the ordinary (and, since Phase 4, only)
// ./cmd/ch-oauth-ldap production closure must contain zero dependencies
// matching any of the five general-purpose-LDAP-library prefixes, plus
// internal/ldap/profile and golang.org/x/crypto/cryptobyte both present. The
// staging mechanism itself (ldapClosureStage/legacyUntilPhase4/replacement/
// productionLDAPClosureStage and the switch between them) was removed once
// the cutover landed — there is no migration state left to gate on, and no
// new "postPhase4" identifier replaces it. The temporary
// -tags=phase3profile tagged-replacement contracts
// (TestDependencyContract_Phase3ReplacementClosureHasNoGeneralLDAP/
// CommandBuilds/CommandTests) are deleted for the same reason: ordinary
// `go build`/`go test ./cmd/ch-oauth-ldap` now exercises exactly the
// composition those tagged tests used to certify ahead of cutover.
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
	"reflect"
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

// cryptobyteImportPath is golang.org/x/crypto/cryptobyte's import path — the
// chosen ASN.1 primitive internal/ldap/profile's production framing/encode
// code uses, and therefore a required member of
// ./cmd/ch-oauth-ldap's live production closure since issue #33 phase 4's
// cutover (see TestDependencyContract_NoNonStandardCryptobyte's own doc
// comment for its Phase 1 -> Phase 4 inversion history).
const cryptobyteImportPath = "golang.org/x/crypto/cryptobyte"

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
// golang.org/x/crypto/cryptobyte to be PRESENT in ./cmd/ch-oauth-ldap's live
// production closure. This is issue #33 phase 4's inversion of the original
// Phase 1 "must be absent" contract, flipped in lockstep with
// profile_dependency_contract_test.go's
// TestDependencyContract_ProfileIsProductionImplementation (Amendment 5):
// cryptobyte is internal/ldap/profile's chosen ASN.1 primitive, and
// internal/ldap/profile is now this command's only, ordinary LDAP backend,
// so cryptobyte is a legitimate, required member of the production closure —
// its absence would mean the profile backend silently stopped being linked
// in.
func TestDependencyContract_NoNonStandardCryptobyte(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}
	got := liveProductionNonstdlibDeps(t, root)
	requireDepPresent(t, got, cryptobyteImportPath, productionClosureTarget+"'s live production closure")
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

// --- Permanent general-LDAP denylist -------------------------------------

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

// TestGeneralLDAPDenylistPrefixes_ExactlyTheRequiredFive guards
// generalLDAPDenylistPrefixes itself, independent of any of its real
// consumers (TestDependencyContract_ProductionClosureHasNoGeneralLDAP below,
// isGeneralLDAPDependency, and — through isGeneralLDAPDependency —
// profile_dependency_contract_test.go's TestDependencyContract_
// ProfileClosureHasRequiredPrimitiveAndNoGeneralLDAP). Both derive their
// entire check from ranging over this one mutable package-level slice, so a
// one-line edit shortening or emptying it would silently defang every one of
// them with no compile error: an emptied slice makes
// TestDependencyContract_ProductionClosureHasNoGeneralLDAP's loop body never
// execute (vacuously passing — checking nothing) and makes
// isGeneralLDAPDependency unconditionally return false (recognizing
// nothing). This test is the independent assertion that closes that gap by
// comparing the literal
// against a separately declared want-list, non-emptiness, and uniqueness —
// not by re-deriving expectations from generalLDAPDenylistPrefixes itself,
// which could never detect a change to it.
func TestGeneralLDAPDenylistPrefixes_ExactlyTheRequiredFive(t *testing.T) {
	want := []string{
		"github.com/vjeantet/ldapserver",
		"github.com/vjeantet/goldap",
		"github.com/go-ldap/ldap/v3",
		"github.com/go-asn1-ber/asn1-ber",
		"github.com/Azure/go-ntlmssp",
	}
	if len(generalLDAPDenylistPrefixes) != len(want) {
		t.Fatalf("generalLDAPDenylistPrefixes: expected exactly %d prefixes, got %d: %v",
			len(want), len(generalLDAPDenylistPrefixes), generalLDAPDenylistPrefixes)
	}
	if !reflect.DeepEqual(generalLDAPDenylistPrefixes, want) {
		t.Fatalf("generalLDAPDenylistPrefixes: expected exactly %v (in this order), got %v",
			want, generalLDAPDenylistPrefixes)
	}
	seen := make(map[string]bool, len(generalLDAPDenylistPrefixes))
	for _, prefix := range generalLDAPDenylistPrefixes {
		if prefix == "" {
			t.Fatalf("generalLDAPDenylistPrefixes: contains an empty prefix, which would match every non-empty dependency string via matchesGeneralLDAPPrefix's HasPrefix(dep, \"\"+\"/\") branch")
		}
		if seen[prefix] {
			t.Fatalf("generalLDAPDenylistPrefixes: prefix %q is duplicated — every entry must be unique", prefix)
		}
		seen[prefix] = true
	}
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

// TestDependencyContract_ProductionClosureHasNoGeneralLDAP is the permanent,
// unconditional general-LDAP dependency policy over ./cmd/ch-oauth-ldap's
// ordinary (and, since issue #33 phase 4's cutover, only) live production
// closure: zero dependencies may match any of the five
// generalLDAPDenylistPrefixes entries, and internal/ldap/profile and
// golang.org/x/crypto/cryptobyte must both be present. There is no staging
// enum and no migration state left to gate on — this replaces what used to
// be a two-stage, test-enum-gated contract (legacyUntilPhase4/replacement)
// during the migration window; that mechanism was removed entirely once the
// cutover landed, and there is no new "postPhase4" identifier in its place.
func TestDependencyContract_ProductionClosureHasNoGeneralLDAP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependency_contract: resolve module root: %v", err)
	}
	got := liveProductionNonstdlibDeps(t, root)

	for _, dep := range got {
		if isGeneralLDAPDependency(dep) {
			t.Fatalf("dependency_contract: %s's live production closure must contain zero general-LDAP matches, but found %s", productionClosureTarget, dep)
		}
	}
	requireDepPresent(t, got, profileImportPath, productionClosureTarget+"'s live production closure")
	requireDepPresent(t, got, cryptobyteImportPath, productionClosureTarget+"'s live production closure")
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
