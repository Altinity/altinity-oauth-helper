package securitytest

// This file implements the dependency contracts for the internal/ldap/profile
// package (originally issue #33 phase 2, plan "Dependency contracts ›
// Production closure / Profile dependency policy", plan L1255-1310), reusing
// the deterministic `go list` mechanism already defined in
// dependency_contract_test.go (resolveGoBin, deterministicGoListEnv,
// normalizeDepsOutput, moduleRoot) rather than duplicating it. Neither this
// file nor the tests it adds modify dependency_contract_test.go.
//
// Two tests are defined here:
//
//   - TestDependencyContract_ProfileIsProductionImplementation: a permanent
//     POSITIVE production-presence contract — internal/ldap/profile must be
//     present in ./cmd/ch-oauth-ldap's live production import closure. This
//     is issue #33 phase 4's inversion (per the coordinator's Amendment 5)
//     of the original Phase 2 contract
//     (TestDependencyContract_ProfileImplementationIsNotProduction), which
//     required the opposite — the import stayed mechanically absent while
//     the profile was still production-inert. The rename makes today's
//     assertion direction the name, rather than leaving a name that reads
//     backwards from what the test now checks.
//   - TestDependencyContract_ProfileClosureHasRequiredPrimitiveAndNoGeneralLDAP:
//     internal/ldap/profile's own live closure must contain the chosen
//     primitive (golang.org/x/crypto/cryptobyte) and must not contain any of
//     the old/general LDAP stack's packages, nor internal/wirefixture
//     (test/tooling support, not a profile production dependency). This is a
//     required-primitive-plus-denylist policy, deliberately NOT a pinned
//     "minimal" closure enumerating every transitive dependency the profile
//     is allowed to have — the profile intentionally depends on
//     verification/OAuth types and their legitimate transitive SDK
//     dependencies, and pinning an exact closure here would merely justify
//     the word "minimal" without adding real security value.
//     dependency_contract_test.go's TestDependencyContract_
//     ProductionClosureHasNoGeneralLDAP separately applies the same
//     denylist, plus profile/cryptobyte presence, to the actual
//     ./cmd/ch-oauth-ldap command closure after composition — the two are
//     complementary, not redundant.
//
// The general-LDAP prefix list the second test uses is
// dependency_contract_test.go's own generalLDAPDenylistPrefixes/
// isGeneralLDAPDependency — the two files must never carry two independently
// drifting module lists. The internal/wirefixture check stays a separate,
// local assertion here (it was never a general-LDAP-stack entry; it is
// test/tooling support).
//
// dependency_contract_test.go's TestDependencyContract_NoNonStandardCryptobyte
// and the committed internal/securitytest/testdata/production-nonstdlib-
// deps.txt expectation were inverted/regenerated in the same cutover this
// file's own inversion landed in — cryptobyte is now a legitimate,
// required member of ./cmd/ch-oauth-ldap's production closure.

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"
)

// profileImportPath is internal/ldap/profile's full import path — the
// ClickHouse LDAP compatibility profile implementation, and (since issue #33
// phase 4's cutover) this command's only, ordinary production LDAP backend.
const profileImportPath = "github.com/altinity/altinity-oauth-helper/internal/ldap/profile"

// profileClosureTarget is the package the profile dependency-policy test
// evaluates: the profile package itself, not the shipped command.
const profileClosureTarget = "./internal/ldap/profile"

// TestDependencyContract_ProfileIsProductionImplementation requires
// internal/ldap/profile to be PRESENT in ./cmd/ch-oauth-ldap's live
// production import closure — the mechanical proof that the issue #33
// phase 4 production cutover actually happened, and stays that way. This is
// the coordinator's Amendment-5 inversion of the original Phase 2 contract
// (then named TestDependencyContract_ProfileImplementationIsNotProduction),
// which required the opposite while the profile was still production-inert;
// see this file's package-level doc comment for the full history.
func TestDependencyContract_ProfileIsProductionImplementation(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("profile_dependency_contract: resolve module root: %v", err)
	}
	got := liveDeps(t, root, productionClosureTarget)
	requireDepPresent(t, got, profileImportPath, productionClosureTarget+"'s live production closure")
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
		if dep == cryptobyteImportPath {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("profile_dependency_contract: %s's live import closure must contain %s (the Phase 1 ASN.1 primitive decision) but it does not", profileClosureTarget, cryptobyteImportPath)
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
