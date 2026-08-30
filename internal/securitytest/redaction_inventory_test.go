package securitytest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// nestedLDAPModuleRoot is internal/ldap/**'s owning module import path —
// the same value profile_dependency_contract_test.go's profileImportPath
// constant is built from, spelled out here so this file's general nested-
// package guard (below) does not depend on that file's own constant.
const nestedLDAPModuleImportPath = "github.com/altinity/altinity-oauth-helper"

// This file implements plan-19p5.md §5.1/§5.2's AST redaction inventory: it
// AST-enumerates every log/error/response-construction sink in doc.go's
// explicit scopeDirs list (originally six first-party packages; issue #33
// phase 1, plan §10/§35, added internal/wirefixture and
// integration/clickhouse/wirecapture once the ClickHouse-wire-capture
// tooling gave them non-test sinks of their own) plus the vendored
// third_party/ldapserver fork (see doc.go), and cross-checks the result
// against testdata/redaction-sites.tsv. None of these tests capture logs or
// set zerolog's global level, so — unlike the marker matrices in
// internal/verification and cmd/ch-jwt-verify — nothing here needs the A2
// non-parallel-capture discipline.
//
// TestRedactionInventory_Phase1AuditedScopesRemainFlat (below) guards the
// specific gap discoverSites' non-recursive directory read leaves open:
// every entry in scopeDirs is read one level deep only (doc.go's
// discoverSites walks os.ReadDir on the directory itself, never descending
// into a subdirectory), so a future nested Go package added under an
// audited root would be silently invisible to every other test in this
// file. That test exists to catch exactly that before it happens, for the
// two directories issue #33 phase 1 added.
// TestRedactionInventory_NestedLDAPPackagesAreRegistered generalizes that
// same non-recursive-discovery limitation to every directory under
// internal/ldap/** — the root issue #33 phase 2's internal/ldap/profile
// itself lives under — rather than only the two issue #33 phase 1 scopes.

func loadRealManifest(t *testing.T) []ManifestRow {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	rows, err := loadManifest(filepath.Join(root, "internal", "securitytest", manifestRelPath))
	if err != nil {
		t.Fatalf("securitytest: load manifest: %v", err)
	}
	return rows
}

func discoverAllSites(t *testing.T) []DiscoveredSite {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	sites, err := discoverSites(root)
	if err != nil {
		t.Fatalf("securitytest: discover sites: %v", err)
	}
	vendored, err := discoverVendoredLoggerSites(root)
	if err != nil {
		t.Fatalf("securitytest: discover vendored logger sites: %v", err)
	}
	return append(sites, vendored...)
}

func manifestByKey(rows []ManifestRow) map[string][]ManifestRow {
	m := make(map[string][]ManifestRow, len(rows))
	for _, r := range rows {
		m[r.Key()] = append(m[r.Key()], r)
	}
	return m
}

// TestRedactionInventory_NoUnmappedSinks fails when a real AST-discovered
// sink has no corresponding manifest row — the exact case a sabotage-style
// unregistered `log.Info().Msg(...)` addition is designed to trip.
func TestRedactionInventory_NoUnmappedSinks(t *testing.T) {
	sites := discoverAllSites(t)
	byKey := manifestByKey(loadRealManifest(t))

	var unmapped []string
	for _, s := range sites {
		if _, ok := byKey[s.Key()]; !ok {
			unmapped = append(unmapped, fmt.Sprintf("%s | %s | %s | %s | %q (detail=%s)",
				s.Scope, s.Path, s.Function, s.SinkKind, s.Fingerprint, s.Detail))
		}
	}
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		t.Fatalf("discovered %d sink(s) with no manifest row in testdata/redaction-sites.tsv — "+
			"add a row classifying each (credential reachability, data class, ownership, proof, state) "+
			"before this can pass:\n%s", len(unmapped), strings.Join(unmapped, "\n"))
	}
}

// TestRedactionInventory_NoStaleManifestRows fails when a manifest row no
// longer corresponds to any real, AST-discoverable sink (the source moved,
// was renamed, or was deleted without updating the manifest).
// external-pinned rows describe a sink in a separate module's source this
// repo cannot AST-enumerate, so they are exempt — sdk_contract_test.go and
// release_gate_test.go are what keep those honest instead.
func TestRedactionInventory_NoStaleManifestRows(t *testing.T) {
	sites := discoverAllSites(t)
	discovered := make(map[string]bool, len(sites))
	for _, s := range sites {
		discovered[s.Key()] = true
	}

	var stale []string
	for _, r := range loadRealManifest(t) {
		if r.Scope == externalScope {
			continue
		}
		if !discovered[r.Key()] {
			stale = append(stale, fmt.Sprintf("line %d: %s | %s | %s | %s | %q", r.sourceLine, r.Scope, r.Path, r.Function, r.SinkKind, r.Fingerprint))
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Fatalf("manifest has %d row(s) with no matching discovered sink (stale — source moved/renamed/deleted "+
			"without updating testdata/redaction-sites.tsv):\n%s", len(stale), strings.Join(stale, "\n"))
	}
}

// TestRedactionInventory_NoDuplicateManifestRows fails on two manifest rows
// sharing the same five-part key (plan §5.2's "duplicate fingerprint"
// failure condition) — every row must be uniquely addressable.
func TestRedactionInventory_NoDuplicateManifestRows(t *testing.T) {
	seen := make(map[string]int)
	for _, r := range loadRealManifest(t) {
		seen[r.Key()]++
	}
	var dupes []string
	for key, n := range seen {
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%s (x%d)", strings.ReplaceAll(key, "\x1f", " | "), n))
		}
	}
	if len(dupes) > 0 {
		sort.Strings(dupes)
		t.Fatalf("manifest has %d duplicate row key(s):\n%s", len(dupes), strings.Join(dupes, "\n"))
	}
}

// TestRedactionInventory_ManifestRowsWellFormed enforces the enum/consistency
// contract documented in the manifest's own header comment, so a row can't
// silently drift into an unrecognized or self-contradictory state (e.g. a
// blocked_external row with no gate name, or a gate name on a safe row).
func TestRedactionInventory_ManifestRowsWellFormed(t *testing.T) {
	validCredentialReachable := map[string]bool{"yes": true, "no": true}
	validOwnership := map[string]bool{"local": true, "external-pinned": true}
	validState := map[string]bool{"safe": true, "unreachable": true, "blocked_external": true}
	validProofType := map[string]bool{"non-credential": true, "structural": true, "structural-discarded-by-caller": true, "marker": true, "characterization": true}

	var bad []string
	for _, r := range loadRealManifest(t) {
		loc := fmt.Sprintf("line %d (%s)", r.sourceLine, r.Key())
		if !validCredentialReachable[r.CredentialReachable] {
			bad = append(bad, loc+": credential_reachable must be yes/no, got "+r.CredentialReachable)
		}
		if !validOwnership[r.Ownership] {
			bad = append(bad, loc+": ownership must be local/external-pinned, got "+r.Ownership)
		}
		if !validState[r.State] {
			bad = append(bad, loc+": state must be safe/unreachable/blocked_external, got "+r.State)
		}
		if !validProofType[r.ProofType] {
			bad = append(bad, loc+": unrecognized proof_type "+r.ProofType)
		}
		if r.ProofType == "non-credential" && r.ProofTest != "n/a" {
			bad = append(bad, loc+": proof_type=non-credential should have proof_test=n/a, got "+r.ProofTest)
		}
		if r.State == "blocked_external" {
			if r.Gate == "" || r.Gate == "-" {
				bad = append(bad, loc+": state=blocked_external requires a non-empty gate name")
			}
		} else if r.Gate != "-" {
			bad = append(bad, loc+": gate must be \"-\" unless state=blocked_external, got "+r.Gate)
		}
		if r.State == "blocked_external" && r.Scope != externalScope {
			bad = append(bad, loc+": state=blocked_external is only permitted for scope=external-pinned rows")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("manifest has %d malformed row(s):\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// TestRedactionInventory_CredentialReachableLocalSinksHaveMarkerProof
// enforces plan §5.2's strongest requirement: a local sink attacker/
// credential content could realistically reach must be backed by a marker
// test, not merely asserted safe by description.
func TestRedactionInventory_CredentialReachableLocalSinksHaveMarkerProof(t *testing.T) {
	var missing []string
	for _, r := range loadRealManifest(t) {
		if r.CredentialReachable != "yes" || r.Ownership != "local" {
			continue
		}
		if r.ProofType != "marker" || strings.TrimSpace(r.ProofTest) == "" || r.ProofTest == "n/a" {
			missing = append(missing, fmt.Sprintf("line %d (%s): proof_type=%q proof_test=%q", r.sourceLine, r.Key(), r.ProofType, r.ProofTest))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d credential-reachable local sink(s) lack a marker-based proof:\n%s", len(missing), strings.Join(missing, "\n"))
	}
}

// TestRedactionInventory_ProofTestsExist fails when a manifest row names a
// proof_test that doesn't exist anywhere in the repo's *_test.go corpus
// (plan §5.2's "referenced proof test disappearing" failure condition).
// external-pinned rows are NOT exempt: this repo's own *_test.go corpus
// (cmd/ch-jwt-verify, internal/verification) is exactly where T3/T6/T7's
// marker/characterization proofs for those SDK-adjacent sinks live, and
// those sub-tasks have since merged (see e.g.
// TestJWKSRotation_KidNeverLogged,
// TestVerifyDebugLogRedaction_MalformedHeaderMarker,
// TestVerifyDebugLogRedaction_UnknownKidMarker) — an earlier version of
// this test exempted external-pinned rows because those sibling sub-tasks
// were still running on disjoint, not-yet-merged worktrees; that carve-out
// is stale now that they are on this tree, and keeping it would let a
// future rename/deletion of one of those proof tests go undetected for
// exactly the rows plan §5.2 cares most about (credential_reachable=yes,
// ownership=external-pinned). sdk_contract_test.go/release_gate_test.go
// still separately guard the SDK-pinned VERSION and the
// SDK_REDACTION_AUTHORIZATION_GATE itself; this test only checks that the
// named proof functions exist.
func TestRedactionInventory_ProofTestsExist(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	testNames, err := collectTestFuncNames(root)
	if err != nil {
		t.Fatalf("securitytest: collect test function names: %v", err)
	}

	var missing []string
	for _, r := range loadRealManifest(t) {
		if r.ProofTest == "" || r.ProofTest == "n/a" {
			continue
		}
		for _, name := range strings.Split(r.ProofTest, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !testNames[name] {
				missing = append(missing, fmt.Sprintf("line %d (%s): proof test %q not found in any *_test.go", r.sourceLine, r.Key(), name))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d manifest row(s) reference a proof test that no longer exists:\n%s", len(missing), strings.Join(missing, "\n"))
	}
}

// phase1AuditedFlatScopes is the exact issue-#33-phase-1 subset of doc.go's
// scopeDirs that TestRedactionInventory_Phase1AuditedScopesRemainFlat
// guards (plan §10/§35/§49's "Wirefixture/wirecapture redaction coverage
// cannot silently lose nested packages" row). It deliberately does not
// include the pre-existing six first-party command/internal scopes or
// third_party/ldapserver — those are long-established, hand-maintained
// production layouts this sub-task did not touch; this list is specifically
// the safety net for the two new scopes issue #33 phase 1 added.
var phase1AuditedFlatScopes = []string{
	"internal/wirefixture",
	"integration/clickhouse/wirecapture",
}

// TestRedactionInventory_Phase1AuditedScopesRemainFlat fails, with
// actionable instructions, the moment either phase1AuditedFlatScopes root
// stops being flat (plan §10's "No nested Go subpackages in this unit").
// discoverSites (doc.go) reads only a scope directory's own immediate
// entries via os.ReadDir and never descends into a subdirectory, so a
// non-test .go file later added under a NESTED subdirectory of an audited
// root would be completely invisible to every other test in this file —
// TestRedactionInventory_NoUnmappedSinks would stay green even though a
// brand-new, entirely unclassified sink had shipped. This test is the
// mechanical trip-wire that catches that gap directly, rather than relying
// on a reviewer noticing a new subdirectory landed under one of these two
// roots.
func TestRedactionInventory_Phase1AuditedScopesRemainFlat(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	for _, scope := range phase1AuditedFlatScopes {
		dir := filepath.Join(root, filepath.FromSlash(scope))
		var nested []string
		walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == dir || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				return relErr
			}
			if strings.ContainsRune(rel, filepath.Separator) {
				// A non-test .go file that is NOT a direct child of the
				// scope root — i.e. it lives inside a nested subdirectory
				// discoverSites' os.ReadDir(dir) call can never see.
				nested = append(nested, scope+"/"+filepath.ToSlash(rel))
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("securitytest: walk audited scope %s: %v", scope, walkErr)
		}
		if len(nested) > 0 {
			sort.Strings(nested)
			t.Fatalf("audited scope %q stopped being flat: found %d non-test .go file(s) inside a "+
				"nested subdirectory, which discoverSites (doc.go) cannot see because it reads only "+
				"%s's own immediate directory entries, never descending into subdirectories:\n%s\n\n"+
				"fix: either move the file(s) directly into %s (keeping the scope flat), or "+
				"explicitly register the new nested subpackage's own path as its own entry in "+
				"doc.go's scopeDirs (adding a redaction-sites.tsv row for every sink it discovers) "+
				"so redaction_inventory_test.go actually enumerates it — never leave a nested "+
				"package silently unaudited.",
				scope, len(nested), scope, strings.Join(nested, "\n"), scope)
		}
	}
}

// nestedLDAPTestOnlyAllowlist is the general nested-LDAP-package guard's
// (below) explicit, documented exception list: a scope path here is exempt
// from the "must be a scopeDirs entry" requirement ONLY because it is
// mechanically proven (via nestedLDAPScopeIsTestOnly, using the same
// deterministic `go list -deps` mechanism dependency_contract_test.go/
// profile_dependency_contract_test.go already use) to be imported by no
// production (non-test) package anywhere in this module — i.e. it is test-
// only tooling, never a production sink this inventory could miss.
//
// Empty today: internal/ldap/profile — the one nested directory under
// internal/ldap that carries non-test .go files as of issue #33 phase 2 —
// is registered outright as its own doc.go scopeDirs entry instead of
// exempted here, so every one of its production log/error/diagnostic sinks
// gets a real redaction-sites.tsv row. A future nested internal/ldap/**
// directory that is genuinely test-only tooling (never imported by
// production code) may be added here instead of scopeDirs, but adding an
// entry that IS imported by production code fails
// TestRedactionInventory_NestedLDAPPackagesAreRegistered immediately.
var nestedLDAPTestOnlyAllowlist = []string{}

// nestedLDAPScopeIsTestOnly mechanically verifies one
// nestedLDAPTestOnlyAllowlist entry's claim: it checks every OTHER non-test
// Go package directory in the module (found by walking the module tree for
// directories containing a non-test .go file, skipping .git and
// third_party — a separate module the root go.mod only replace's in — and
// scope itself) and fails if any of them imports scope's package in its
// live production closure (via liveDeps, the same deterministic
// `go list -deps` helper profile_dependency_contract_test.go defines). A
// package genuinely reachable only from *_test.go files never shows up in
// any of these production closures, since `go list -deps` (without -test)
// never traverses a target's own test-file imports either.
func nestedLDAPScopeIsTestOnly(t *testing.T, root, scope string) bool {
	t.Helper()
	scopeImportPath := nestedLDAPModuleImportPath + "/" + scope

	var otherProductionScopes []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == ".git" || base == "third_party" {
			return filepath.SkipDir
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == scope {
			return nil
		}
		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return readErr
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				otherProductionScopes = append(otherProductionScopes, rel)
				break
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("securitytest: walk module tree checking %q's test-only claim: %v", scope, walkErr)
	}

	for _, other := range otherProductionScopes {
		deps := liveDeps(t, root, "./"+other)
		for _, dep := range deps {
			if dep == scopeImportPath {
				t.Logf("securitytest: %q is imported by %q's production closure — not test-only", scope, other)
				return false
			}
		}
	}
	return true
}

// TestRedactionInventory_NestedLDAPPackagesAreRegistered generalizes
// TestRedactionInventory_Phase1AuditedScopesRemainFlat's specific two-scope
// flatness guard to every directory under internal/ldap/** (which is where
// internal/ldap/profile itself lives, issue #33 phase 2): every nested
// directory containing a non-test .go file must be either its own doc.go
// scopeDirs entry (so redaction_inventory_test.go actually enumerates its
// sinks) or an explicitly documented, mechanically verified test-only-
// tooling exception in nestedLDAPTestOnlyAllowlist above. Sabotage: adding
// a temporary non-test .go file under an unregistered internal/ldap/**
// subdirectory (e.g. internal/ldap/tmpx/x.go) must fail this test.
func TestRedactionInventory_NestedLDAPPackagesAreRegistered(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}

	ldapRoot := filepath.Join(root, "internal", "ldap")
	registered := make(map[string]bool, len(scopeDirs))
	for _, s := range scopeDirs {
		registered[s] = true
	}
	allowed := make(map[string]bool, len(nestedLDAPTestOnlyAllowlist))
	for _, s := range nestedLDAPTestOnlyAllowlist {
		allowed[s] = true
	}

	var unregistered []string
	walkErr := filepath.WalkDir(ldapRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "internal/ldap" {
			// The already-registered root scope itself, not a nested
			// package.
			return nil
		}

		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return readErr
		}
		hasNonTestGo := false
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				hasNonTestGo = true
				break
			}
		}
		if !hasNonTestGo {
			return nil
		}

		if registered[rel] {
			return nil
		}
		if allowed[rel] {
			if !nestedLDAPScopeIsTestOnly(t, root, rel) {
				unregistered = append(unregistered, rel+" (allow-listed as test-only, but a production package imports it — remove it from the allow-list and register it in doc.go's scopeDirs instead)")
			}
			return nil
		}
		unregistered = append(unregistered, rel)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("securitytest: walk internal/ldap: %v", walkErr)
	}

	if len(unregistered) > 0 {
		sort.Strings(unregistered)
		t.Fatalf("found %d nested internal/ldap/** director(y/ies) with non-test .go file(s) that are "+
			"neither a doc.go scopeDirs entry nor a mechanically-verified test-only entry in "+
			"nestedLDAPTestOnlyAllowlist — discoverSites never sees these, so their sinks are silently "+
			"unaudited:\n%s\n\n"+
			"fix: register the directory in doc.go's scopeDirs (adding a redaction-sites.tsv row for "+
			"every sink it discovers), or, only if it is genuinely test-only tooling never imported by "+
			"production code, add it to nestedLDAPTestOnlyAllowlist here.",
			len(unregistered), strings.Join(unregistered, "\n"))
	}
}
