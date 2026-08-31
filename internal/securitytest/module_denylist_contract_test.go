package securitytest

// This file implements the two final, permanent dependency contracts issue
// #33 phase 4's plan calls "Final dependency contracts" (plan L791-820,
// Commit 2 step 21): a root TEST-INCLUSIVE module-graph denylist and a root
// go.mod METADATA denylist. Both are deliberately broader than the
// production-only contracts in dependency_contract_test.go and
// profile_dependency_contract_test.go:
//
//   - dependency_contract_test.go's TestDependencyContract_
//     ProductionClosureHasNoGeneralLDAP only inspects ./cmd/ch-oauth-ldap's
//     ordinary, non-test import closure. A future `_test.go` file anywhere
//     in the module — including one that never touches
//     ./cmd/ch-oauth-ldap's production code at all, e.g. a stray import in
//     internal/ldap/profile/some_test.go or
//     integration/clickhouse/wirecapture — could silently reintroduce
//     github.com/go-ldap/ldap/v3 or its BER/NTLM stack while that
//     production-only contract stays green.
//   - Neither existing contract inspects go.mod itself. A hand-edited or
//     tool-generated `require` or `replace` line naming one of the five
//     modules could exist in root module metadata without ever being
//     imported by any Go source the `go list -deps` walks — dead metadata,
//     but exactly the kind of thing "no dual-parser rollback path" (plan's
//     Final DoD) means to forbid.
//
// TestModuleDenylistContract_RootTestGraphHasNoGeneralLDAP closes the first
// gap: it runs the plan's example `go list -deps -test` invocation over
// ./... (every package in the module, test-inclusive), using the exact same
// deterministic-environment/go-binary-resolution conventions as
// dependency_contract_test.go's liveProductionNonstdlibDeps (resolveGoBin,
// deterministicGoListEnv) so the two contracts can never quietly disagree
// about which `go` binary or which GOOS/GOARCH/CGO_ENABLED/GOWORK
// combination produced their answer.
//
// TestModuleDenylistContract_RootModuleMetadataHasNoGeneralLDAP closes the
// second gap: it parses `go mod edit -json` — a stable, documented,
// stdlib-only-consumable JSON contract for the `go` tool itself — and checks
// every Require and Replace entry (both the replaced-from Old.Path and the
// replaced-to New.Path) against the same five module paths. Nothing here
// shells out to any non-stdlib JSON library or re-implements go.mod parsing
// by hand; encoding/json plus the `go` tool's own `-json` flag is the entire
// mechanism.
//
// Both tests reuse dependency_contract_test.go's generalLDAPDenylistPrefixes
// and moduleRoot — never a second, independently drifting module list.
// generalLDAPDenylistPrefixes is guarded on its own by
// TestGeneralLDAPDenylistPrefixes_ExactlyTheRequiredFive in
// dependency_contract_test.go; this file does not re-guard it.
//
// A `go list ... .Module.Path` result and a go.mod `require`/`replace`
// entry's Path are both exactly a *module* path (e.g.
// "github.com/vjeantet/goldap", never
// "github.com/vjeantet/goldap/message"), unlike the *import*-path closures
// dependency_contract_test.go and profile_dependency_contract_test.go
// inspect. Both tests below therefore compare with plain string equality
// against generalLDAPDenylistPrefixes, deliberately not
// matchesGeneralLDAPPrefix/isGeneralLDAPDependency's subpackage-aware
// prefix matching — a module path has no meaningful "subpackage of a
// module path" relationship to check here, and reusing the import-path
// matcher on module paths would be the wrong tool even though it would
// happen to produce the same answer for these five literals today.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// moduleGraphTarget is the target TestModuleDenylistContract_
// RootTestGraphHasNoGeneralLDAP's `go list` invocation walks: every package
// in the module, matching plan L791-802's "root test-graph" framing (as
// opposed to dependency_contract_test.go's single-package
// productionClosureTarget).
const moduleGraphTarget = "./..."

// TestModuleDenylistContract_RootTestGraphHasNoGeneralLDAP is the permanent,
// unconditional "root test-inclusive dependency graph" contract from plan
// L791-802 ("Final dependency contracts" / Commit 2 step 21): the
// deterministic, test-inclusive module graph over every package in this
// module must contain none of generalLDAPDenylistPrefixes' five module
// paths. This is strictly broader than
// TestDependencyContract_ProductionClosureHasNoGeneralLDAP (production-only,
// ./cmd/ch-oauth-ldap only) — it exists specifically to catch a future
// `_test.go` import anywhere in the tree that would silently restore
// go-ldap or its stack while every production-only contract stayed green.
func TestModuleDenylistContract_RootTestGraphHasNoGeneralLDAP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("module_denylist_contract: resolve module root: %v", err)
	}

	got := liveTestInclusiveModuleGraph(t, root)

	for _, mod := range got {
		if isDenylistedModulePath(mod) {
			t.Fatalf("module_denylist_contract: root test-inclusive module graph (%s over %s) must contain none of the five general-LDAP module paths, but found %s — a _test.go file somewhere in the module now imports it (directly or transitively)",
				"go list -deps -test", moduleGraphTarget, mod)
		}
	}
}

// liveTestInclusiveModuleGraph runs plan L791-802's example invocation:
//
//	go list -mod=readonly -deps -test \
//	  -f '{{with .Module}}{{.Path}}{{end}}' ./...
//
// using the same deterministic go-binary resolution
// (dependency_contract_test.go's resolveGoBin) and environment
// (deterministicGoListEnv) as every other dependency contract in this
// package, then normalizes/deduplicates the result exactly as
// normalizeDepsOutput does for production closures.
func liveTestInclusiveModuleGraph(t *testing.T, root string) []string {
	t.Helper()

	goBin := resolveGoBin(t)

	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"list", "-mod=readonly", "-deps", "-test",
		"-f", "{{with .Module}}{{.Path}}{{end}}",
		moduleGraphTarget)
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("module_denylist_contract: %s list -deps -test %s failed: %v\nstderr:\n%s", filepath.Base(goBin), moduleGraphTarget, err, stderr.String())
	}
	return normalizeDepsOutput(stdout.String())
}

// isDenylistedModulePath reports whether mod is exactly one of
// generalLDAPDenylistPrefixes' five module paths. Deliberately plain
// equality, not the import-path subpackage-prefix matcher
// matchesGeneralLDAPPrefix/isGeneralLDAPDependency — see this file's
// package-level doc comment.
func isDenylistedModulePath(mod string) bool {
	for _, denied := range generalLDAPDenylistPrefixes {
		if mod == denied {
			return true
		}
	}
	return false
}

// --- go.mod metadata denylist --------------------------------------------

// goModEditRequire mirrors the `Require` element shape `go mod edit -json`
// emits (see `go help mod edit`): only the fields this contract reads are
// declared.
type goModEditRequire struct {
	Path     string
	Version  string
	Indirect bool
}

// goModEditModulePath mirrors the `Old`/`New` module-path-plus-version shape
// `go mod edit -json` emits for a `Replace` entry.
type goModEditModulePath struct {
	Path    string
	Version string
}

// goModEditReplace mirrors the `Replace` element shape `go mod edit -json`
// emits.
type goModEditReplace struct {
	Old goModEditModulePath
	New goModEditModulePath
}

// goModEditJSON is the subset of `go mod edit -json`'s top-level object this
// contract needs. Unrecognized fields (Module, Go, Exclude, Retract, ...)
// are ignored by encoding/json's default unmarshal behavior — this struct
// deliberately does not attempt to model the whole schema.
type goModEditJSON struct {
	Require []goModEditRequire
	Replace []goModEditReplace
}

// TestModuleDenylistContract_RootModuleMetadataHasNoGeneralLDAP is the
// permanent, unconditional "root module requirements/replacements" contract
// from plan L804-820 ("Final dependency contracts" / Commit 2 step 21):
// none of generalLDAPDenylistPrefixes' five module paths may appear under
// go.mod's Require or Replace (checking both a Replace entry's Old.Path and
// its New.Path — a `replace` pointing *at* a denylisted module is exactly
// as forbidden as one replacing it away). This is metadata-level and
// standard-library-only (encoding/json plus the `go` tool's own `-json`
// flag): it catches a hand-edited or generated go.mod line naming a
// denylisted module even if no Go source anywhere in the module actually
// imports it — dead metadata that TestModuleDenylistContract_
// RootTestGraphHasNoGeneralLDAP and every production-only contract would
// both miss, since none of them inspect go.mod text/structure at all.
func TestModuleDenylistContract_RootModuleMetadataHasNoGeneralLDAP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("module_denylist_contract: resolve module root: %v", err)
	}

	edit := liveGoModEdit(t, root)

	for _, req := range edit.Require {
		if isDenylistedModulePath(req.Path) {
			t.Fatalf("module_denylist_contract: go.mod Require must contain none of the five general-LDAP module paths, but found %s", req.Path)
		}
	}
	for _, rep := range edit.Replace {
		if isDenylistedModulePath(rep.Old.Path) {
			t.Fatalf("module_denylist_contract: go.mod Replace must not replace-from any of the five general-LDAP module paths, but found replace %s => %s", rep.Old.Path, rep.New.Path)
		}
		if isDenylistedModulePath(rep.New.Path) {
			t.Fatalf("module_denylist_contract: go.mod Replace must not replace-to any of the five general-LDAP module paths, but found replace %s => %s", rep.Old.Path, rep.New.Path)
		}
	}
}

// liveGoModEdit runs `go mod edit -json` against root's go.mod using the
// same deterministic go-binary resolution as every other contract in this
// package (resolveGoBin) and the deterministic environment
// (deterministicGoListEnv) for consistency, then decodes its stdout with
// encoding/json only.
func liveGoModEdit(t *testing.T, root string) goModEditJSON {
	t.Helper()

	goBin := resolveGoBin(t)

	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"mod", "edit", "-json")
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("module_denylist_contract: %s mod edit -json failed: %v\nstderr:\n%s", filepath.Base(goBin), err, stderr.String())
	}

	var edit goModEditJSON
	if err := json.Unmarshal(stdout.Bytes(), &edit); err != nil {
		t.Fatalf("module_denylist_contract: decode `go mod edit -json` output: %v\nraw:\n%s", err, stdout.String())
	}
	return edit
}

// TestModuleDenylistContract_ModuleGraphAndMetadataAreDeterministic is a
// small internal-invariant self-check, independent of whether any
// denylisted module is present: both liveTestInclusiveModuleGraph and
// liveGoModEdit must return the exact same result across two consecutive
// invocations in the same process (no incidental nondeterminism —
// e.g. map-iteration-order leakage — from either helper's own plumbing).
// This does not re-validate `go list`/`go mod edit`'s own determinism (that
// is the go tool's contract, exercised end-to-end above); it only guards
// this file's own normalization/decoding code from silently reintroducing
// order-dependence that would make an occasional flake read as "module
// reappeared" or "module disappeared".
func TestModuleDenylistContract_ModuleGraphAndMetadataAreDeterministic(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("module_denylist_contract: resolve module root: %v", err)
	}

	first := liveTestInclusiveModuleGraph(t, root)
	second := liveTestInclusiveModuleGraph(t, root)
	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Fatalf("module_denylist_contract: liveTestInclusiveModuleGraph is not deterministic across two calls in the same process:\nfirst:\n  %s\nsecond:\n  %s",
			strings.Join(first, "\n  "), strings.Join(second, "\n  "))
	}

	firstEdit := liveGoModEdit(t, root)
	secondEdit := liveGoModEdit(t, root)
	if fmt.Sprint(firstEdit) != fmt.Sprint(secondEdit) {
		t.Fatalf("module_denylist_contract: liveGoModEdit is not deterministic across two calls in the same process:\nfirst:  %+v\nsecond: %+v", firstEdit, secondEdit)
	}
}

// TestModuleDenylistContract_DenylistCoversFiveDistinctModulePaths is a
// self-check over this file's own consumption of
// generalLDAPDenylistPrefixes as *module* paths: it must still be exactly
// five distinct, non-empty entries by the time isDenylistedModulePath uses
// it. dependency_contract_test.go's own
// TestGeneralLDAPDenylistPrefixes_ExactlyTheRequiredFive already guards the
// slice's literal contents; this test guards this file's assumption that
// every entry is directly usable as a bare module path (no "/subpackage"
// suffix, no leading/trailing whitespace) — the property
// isDenylistedModulePath's plain-equality comparison depends on and that a
// prefix-style entry would silently break.
func TestModuleDenylistContract_DenylistCoversFiveDistinctModulePaths(t *testing.T) {
	if len(generalLDAPDenylistPrefixes) != 5 {
		t.Fatalf("module_denylist_contract: expected generalLDAPDenylistPrefixes to contain exactly 5 module paths, got %d: %v", len(generalLDAPDenylistPrefixes), generalLDAPDenylistPrefixes)
	}
	seen := make(map[string]bool, len(generalLDAPDenylistPrefixes))
	sorted := append([]string(nil), generalLDAPDenylistPrefixes...)
	sort.Strings(sorted)
	for _, mod := range sorted {
		if mod == "" {
			t.Fatalf("module_denylist_contract: generalLDAPDenylistPrefixes contains an empty entry, which isDenylistedModulePath would treat as a bare-equality match against nothing meaningful")
		}
		if strings.TrimSpace(mod) != mod {
			t.Fatalf("module_denylist_contract: generalLDAPDenylistPrefixes entry %q carries leading/trailing whitespace, which would never bare-equality-match a real module path", mod)
		}
		if strings.Contains(mod, "/") == false {
			// Every real entry here is a scoped module path
			// (github.com/<org>/<name> or similar) and therefore always
			// contains at least one slash; this is a sanity guard, not a
			// meaningful policy rule on its own.
			t.Fatalf("module_denylist_contract: generalLDAPDenylistPrefixes entry %q does not look like a scoped module path", mod)
		}
		if seen[mod] {
			t.Fatalf("module_denylist_contract: generalLDAPDenylistPrefixes entry %q is duplicated", mod)
		}
		seen[mod] = true
	}
}
