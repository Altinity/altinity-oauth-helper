package securitytest

// This file implements issue #33 phase 2's dependency contracts for the new
// internal/ldap/profile package (plan "Dependency contracts › Production
// closure / Profile dependency policy", plan L1255-1310), reusing the
// deterministic `go list` mechanism already defined in
// dependency_contract_test.go (resolveGoBin, deterministicGoListEnv,
// normalizeDepsOutput, moduleRoot) rather than duplicating it. Neither this
// file nor the tests it adds modify dependency_contract_test.go.
//
// Two tests are added here:
//
//   - TestDependencyContract_ProfileImplementationIsNotProduction: during
//     Phase 2, internal/ldap/profile must stay mechanically absent from
//     ./cmd/ch-oauth-ldap's live production import closure (plan "Explicitly
//     deferred › no import from cmd/ch-oauth-ldap, unchanged production
//     baseline", L39-45). Phase 4 cuts production over to the profile
//     implementation and, at that point, MUST INVERT this test (assert the
//     import IS present) rather than delete it — see the Amendment 5 note on
//     the test itself.
//   - TestDependencyContract_ProfileClosureHasRequiredPrimitiveAndNoGeneralLDAP:
//     internal/ldap/profile's own live closure must contain the Phase 1
//     primitive decision (golang.org/x/crypto/cryptobyte) and must not
//     contain any of the old/general LDAP stack's packages, nor
//     internal/wirefixture (test/tooling support, not a profile production
//     dependency). This is a required-primitive-plus-denylist policy,
//     deliberately NOT a pinned "minimal" closure enumerating every
//     transitive dependency the profile is allowed to have — the profile
//     intentionally depends on verification/OAuth types and their
//     legitimate transitive SDK dependencies, and pinning an exact closure
//     here would merely justify the word "minimal" without adding real
//     security value. Phase 3 applies the production denylist to the actual
//     ./cmd/ch-oauth-ldap command closure after composition, not to this
//     package in isolation.
//
// Issue #33 phase 3 ("Dependency closure contract › Shared policy") refactored
// the general-LDAP prefix list this second test uses to consume
// dependency_contract_test.go's generalLDAPDenylistPrefixes/
// isGeneralLDAPDependency instead of maintaining its own copy — the two
// files must never carry two independently drifting module lists. The
// internal/wirefixture check stays a separate, local assertion here (it was
// never a general-LDAP-stack entry; it is test/tooling support).
//
// Amendment 5 also requires recording, in test comments (not yet in code),
// that TestDependencyContract_NoNonStandardCryptobyte and the committed
// internal/securitytest/testdata/production-nonstdlib-deps.txt expectation
// both flip/regenerate in Phase 4: once cmd/ch-oauth-ldap imports
// internal/ldap/profile, cryptobyte becomes a legitimate member of the
// production closure (TestDependencyContract_NoNonStandardCryptobyte's
// current "must be absent" assertion inverts to "must be present", exactly
// mirroring TestDependencyContract_ProfileImplementationIsNotProduction's own
// Phase 4 inversion), and the live expectation file must be regenerated to
// include the profile's transitive closure and to drop whichever
// old/general-LDAP-stack entries Phase 4's cutover removes. Neither flip
// happens in this sub-task; both tests keep behaving exactly as Phase 1 left
// them.

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"
)

// profileImportPath is internal/ldap/profile's full import path — the new
// Phase 2 ClickHouse LDAP compatibility profile implementation.
const profileImportPath = "github.com/altinity/altinity-oauth-helper/internal/ldap/profile"

// profileClosureTarget is the package the profile dependency-policy test
// evaluates: the profile package itself, not the shipped command.
const profileClosureTarget = "./internal/ldap/profile"

// TestDependencyContract_ProfileImplementationIsNotProduction requires
// internal/ldap/profile to stay absent from ./cmd/ch-oauth-ldap's live
// production import closure during Phase 2 (plan "Explicitly deferred › no
// import from cmd/ch-oauth-ldap, unchanged production baseline", L39-45;
// "Dependency contracts › Production closure", L1255-1310: "Keep the
// existing exact ./cmd/ch-oauth-ldap expectation unchanged. Add
// TestDependencyContract_ProfileImplementationIsNotProduction that fails if
// internal/ldap/profile appears in the command closure during Phase 2.").
//
// AMENDMENT 5 — Phase 4 inversion: when Phase 4 cuts cmd/ch-oauth-ldap over
// to import internal/ldap/profile in production, this test's assertion must
// be INVERTED (require the import path IS present in the live closure), not
// deleted — the inverted test remains the mechanical proof that the cutover
// actually happened, symmetric with how TestDependencyContract_
// NoNonStandardCryptobyte and the committed production-nonstdlib-deps.txt
// expectation must also flip/regenerate at that same point (see this file's
// package-level doc comment above).
func TestDependencyContract_ProfileImplementationIsNotProduction(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("profile_dependency_contract: resolve module root: %v", err)
	}
	got := liveDeps(t, root, productionClosureTarget)
	for _, dep := range got {
		if dep == profileImportPath {
			t.Fatalf("profile_dependency_contract: %s must not appear in %s's production closure during Phase 2 (plan L39-45; Phase 4 inverts this test rather than deleting it)", profileImportPath, productionClosureTarget)
		}
	}
}

// TestDependencyContract_ProfileClosureHasRequiredPrimitiveAndNoGeneralLDAP
// requires internal/ldap/profile's own live import closure to contain
// golang.org/x/crypto/cryptobyte (the Phase 1 primitive decision, plan §1:
// "use golang.org/x/crypto/cryptobyte for ASN.1 primitives") and to exclude
// every old/general LDAP-stack package plus internal/wirefixture (plan
// "Profile dependency policy", L1255-1310).
//
// This is a required-primitive-plus-denylist policy, deliberately NOT a
// pinned "minimal" closure: the profile intentionally depends on
// verification/OAuth types and their legitimate transitive SDK
// dependencies, so this test does not attempt to enumerate or bound the
// full closure. Phase 3 applies the production denylist to the actual
// ./cmd/ch-oauth-ldap command closure after composition — this test governs
// only the profile package in isolation, ahead of that composition.
func TestDependencyContract_ProfileClosureHasRequiredPrimitiveAndNoGeneralLDAP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("profile_dependency_contract: resolve module root: %v", err)
	}
	got := liveDeps(t, root, profileClosureTarget)

	found := false
	for _, dep := range got {
		if dep == forbiddenCryptobyteImport {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("profile_dependency_contract: %s's live import closure must contain %s (the Phase 1 ASN.1 primitive decision) but it does not", profileClosureTarget, forbiddenCryptobyteImport)
	}

	for _, dep := range got {
		if isGeneralLDAPDependency(dep) {
			t.Fatalf("profile_dependency_contract: %s's live import closure must not contain the old/general LDAP stack, but found %s", profileClosureTarget, dep)
		}
		if dep == forbiddenWirefixtureImport {
			t.Fatalf("profile_dependency_contract: %s's live import closure must not contain %s (test/tooling support only, not a profile production dependency)", profileClosureTarget, forbiddenWirefixtureImport)
		}
	}
}

// liveDeps runs the same deterministic `go list -mod=readonly -deps`
// invocation dependency_contract_test.go's liveProductionNonstdlibDeps uses
// (resolveGoBin + deterministicGoListEnv + normalizeDepsOutput), generalized
// to an arbitrary target package so this file can reuse it for both
// ./cmd/ch-oauth-ldap and ./internal/ldap/profile without modifying that
// file.
func liveDeps(t *testing.T, root, target string) []string {
	t.Helper()

	goBin := resolveGoBin(t)

	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"list", "-mod=readonly", "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}",
		target)
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("profile_dependency_contract: %s list -deps %s failed: %v\nstderr:\n%s", filepath.Base(goBin), target, err, stderr.String())
	}
	return normalizeDepsOutput(stdout.String())
}
