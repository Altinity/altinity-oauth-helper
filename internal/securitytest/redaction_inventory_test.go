package securitytest

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

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
