package securitytest

// This file implements issue #33 phase 4's §11.6 evidence record contract
// (plan "Phase 4 §11.6 evidence record" / "Phase 4 live digest contract" /
// "Commit 4 — attested evidence only"): the populated, machine-checked
// record of Phase 4's own manual certification, added to
// docs/clickhouse-ldap-wire-profile.md strictly AFTER the frozen §11.5
// marker pair (wire_profile_contract_test.go's Phase3Evidence* family owns
// §11.5 itself and is never touched here).
//
// Unlike §11.5's historical family, §11.6 is checked for LIVE equality with
// the current certified-surface source tree, not merely internal
// shape/self-consistency: TestPhase4Evidence_LiveCertifiedSurfaceDigestMatches
// recomputes computeCertifiedSurfaceDigest (owned by
// wire_profile_contract_test.go, reused here unmodified per the plan's
// explicit "reuse the existing certified-surface pathset and hashing
// algorithm for continuity") against today's tree and requires it to equal
// §11.6's recorded digest. If a later change alters any certified-surface
// file without updating §11.6, this test — not merely a human proofreader
// — fails, closing exactly the "Commit 4 changes the certified-surface
// digest" stop condition (plan stop condition 9): such a change would make
// §11.6's attestation void, and this is the mechanical proof of that.
//
// That live-tree check alone cannot prove the recorded digest corresponds
// to the recorded tested_behavior_head, only that it corresponds to
// *some* tree — namely whatever tree happens to be checked out when the
// test runs. A later commit can edit a certified-surface file, recompute
// the live digest against its own new tree, and overwrite §11.6's
// recorded digest field while leaving tested_behavior_head untouched;
// TestPhase4Evidence_TestedBehaviorHead's plain
// `^[0-9a-f]{40}$` shape check does not catch this either. Two tests
// close that specific gap: TestPhase4Evidence_TestedBehaviorHead also
// requires the recorded head to name a real commit reachable from HEAD
// (via gitCommitIsReachable), and
// TestPhase4Evidence_DigestBoundToTestedBehaviorHead independently
// recomputes the digest from the git objects actually recorded AT that
// commit (via computeCertifiedSurfaceDigestAtCommit, also owned by
// wire_profile_contract_test.go) and requires it equal the recorded
// digest — proving the digest is bound to the named head, not merely to
// whatever tree the suite happened to run against.
//
// This file also owns phase4FreshProductionLDAPLOC, the plan's required
// mechanical Phase 4 LOC helper (internal/ldap/profile/*.go non-test +
// cmd/ch-oauth-ldap/ldap_backend.go) — deliberately NOT a reuse of
// wire_profile_contract_test.go's phase3FreshProfileLOC as the final total
// (the plan: "Do not reuse Phase 3's profile-only helper as the final
// Phase 4 total"), though it does call that helper for its own
// profile-only component, which the plan explicitly permits.
//
// None of this file's tests re-derive or duplicate the underlying
// certifications themselves (the production dependency-closure contracts
// in dependency_contract_test.go/profile_dependency_contract_test.go, the
// root test-graph/module-metadata denylist contracts in
// module_denylist_contract_test.go, or phase5release's own release gate) —
// they check only that §11.6's recorded prose accurately reflects what
// those contracts already independently prove, plus the digest/LOC/marker
// shape unique to this evidence record.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// §11.6 marker/section/field helpers
// ---------------------------------------------------------------------

const phase4EvidenceMarkerStart = "<!-- phase4-release-gate-evidence:start -->"
const phase4EvidenceMarkerEnd = "<!-- phase4-release-gate-evidence:end -->"

// phase4EvidenceSection returns the exact text strictly between one
// well-formed §11.6 marker pair, failing the test if the pair is missing,
// duplicated, out of order, or does not appear strictly after the §11.5
// marker pair (§11.6 must be "added after §11.5", never interleaved with
// or preceding it).
func phase4EvidenceSection(t *testing.T, doc string) string {
	t.Helper()
	startCount := strings.Count(doc, phase4EvidenceMarkerStart)
	endCount := strings.Count(doc, phase4EvidenceMarkerEnd)
	if startCount != 1 || endCount != 1 {
		t.Fatalf("phase4_evidence_contract: %s: found %d %q and %d %q, want exactly one §11.6 marker pair", wireProfileDocRelPath, startCount, phase4EvidenceMarkerStart, endCount, phase4EvidenceMarkerEnd)
	}
	start := strings.Index(doc, phase4EvidenceMarkerStart)
	end := strings.Index(doc, phase4EvidenceMarkerEnd)
	if end < start {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 end marker appears before its start marker", wireProfileDocRelPath)
	}

	phase3End := strings.Index(doc, phase3EvidenceMarkerEnd)
	if phase3End < 0 {
		t.Fatalf("phase4_evidence_contract: %s: no §11.5 end marker found — §11.6 must be added after §11.5, and §11.5 must still exist", wireProfileDocRelPath)
	}
	if start < phase3End {
		t.Fatalf("phase4_evidence_contract: %s: §11.6's start marker appears before §11.5's end marker — §11.6 must be added strictly after §11.5", wireProfileDocRelPath)
	}

	return doc[start+len(phase4EvidenceMarkerStart) : end]
}

// phase4EvidenceField extracts the value of a "- **Label:** `value`"
// recorded field from an already-isolated §11.6 section, failing the test
// if that exact label is not present in that exact form.
func phase4EvidenceField(t *testing.T, section, label string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta("**"+label+":**") + "\\s*`([^`]+)`")
	m := re.FindStringSubmatch(section)
	if m == nil {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 has no %q field in the required `- **%s:** `value`` form", wireProfileDocRelPath, label, label)
	}
	return m[1]
}

const phase4EvidenceHAMarker = "**HA**"

// phase4SplitOnHAHeading splits section into everything before
// phase4EvidenceHAMarker (the Supported ClickHouse matrix subsection) and
// everything from the marker onward (the HA subsection) — mirrors
// wire_profile_contract_test.go's phase3SplitOnHAHeading for §11.6's own
// section text, since wireProfileExtractTable's "first line containing
// every needle" locator would otherwise only ever reach the first
// "Image"/"Result" table.
func phase4SplitOnHAHeading(t *testing.T, section string) (matrixPart, haPart string) {
	t.Helper()
	idx := strings.Index(section, phase4EvidenceHAMarker)
	if idx < 0 {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 has no %q heading to split the Supported ClickHouse matrix from the HA subsection", wireProfileDocRelPath, phase4EvidenceHAMarker)
	}
	return section[:idx], section[idx:]
}

// phase4CollapseWhitespace mirrors wire_profile_contract_test.go's
// phase3CollapseWhitespace (reused directly here instead — that function
// is generic over any input string, not §11.5-specific, so this file calls
// it rather than defining a second identical implementation).

// ---------------------------------------------------------------------
// Marker, placeholder, and ordering shape
// ---------------------------------------------------------------------

func TestPhase4Evidence_MarkerAndPlaceholders(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	if m := phase3EvidencePlaceholderRE.FindString(section); m != "" {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 contains placeholder token %q — every field must be populated with a real recorded value", wireProfileDocRelPath, m)
	}
	if strings.TrimSpace(section) == "" {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 marker pair encloses no content", wireProfileDocRelPath)
	}
}

// ---------------------------------------------------------------------
// Certification identity
// ---------------------------------------------------------------------

var phase4TestedBehaviorHeadRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestPhase4Evidence_TestedBehaviorHead(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	head := phase4EvidenceField(t, section, "tested_behavior_head")
	if !phase4TestedBehaviorHeadRE.MatchString(head) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 tested_behavior_head is %q, want a full 40-character lowercase hex commit SHA", wireProfileDocRelPath, head)
	}

	// Syntactic SHA shape alone proves nothing about the commit actually
	// existing: gitCommitIsReachable resolves the object and requires it
	// be an ancestor of (or equal to) HEAD, so a fabricated, dangling, or
	// wrong-branch hex string that merely happens to look like a SHA is
	// rejected here rather than silently accepted.
	if !gitCommitIsReachable(t, root, head) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 tested_behavior_head %q does not resolve to a commit reachable from HEAD in this repository", wireProfileDocRelPath, head)
	}
}

// TestPhase4Evidence_DigestBoundToTestedBehaviorHead is the mechanical
// binding the plan's stop condition 9 requires and
// TestPhase4Evidence_LiveCertifiedSurfaceDigestMatches alone cannot
// provide: that test recomputes the certified-surface digest against
// whatever tree the test happens to run against (the current working
// tree), so a later commit can edit a certified-surface file, recompute
// the digest to match its own new tree, and overwrite §11.6's recorded
// digest — all while leaving tested_behavior_head frozen at the older,
// no-longer-matching commit; nothing catches the resulting decoupling
// (exactly what happened between commits 76e8bcc/3c12ab7 and 0ccbd43 on
// this branch). This test closes that gap by recomputing the digest via
// computeCertifiedSurfaceDigestAtCommit — reading blobs straight out of
// the git object database at the recorded tested_behavior_head, never the
// working tree — and requiring it equal §11.6's recorded digest. A commit
// that changes a certified-surface file without also advancing
// tested_behavior_head to (at minimum) a commit that contains that change
// fails this test, regardless of what the live working-tree digest reads.
func TestPhase4Evidence_DigestBoundToTestedBehaviorHead(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	head := phase4EvidenceField(t, section, "tested_behavior_head")
	if !phase4TestedBehaviorHeadRE.MatchString(head) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 tested_behavior_head is %q, want a full 40-character lowercase hex commit SHA", wireProfileDocRelPath, head)
	}
	recordedDigest := phase4EvidenceField(t, section, "Certified-surface digest (SHA-256)")

	headDigest, headCount := computeCertifiedSurfaceDigestAtCommit(t, root, head)
	if headDigest != recordedDigest {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 records certified-surface digest %s for tested_behavior_head %s, but recomputing the digest from the git objects actually recorded AT that commit yields %s — the recorded digest does not correspond to the recorded head; per stop condition 9 this attestation is void and must be re-certified (either recompute the digest at the truly attested head, or advance tested_behavior_head to a commit whose tree really does hash to the recorded digest)", wireProfileDocRelPath, recordedDigest, head, headDigest)
	}

	flat := phase3CollapseWhitespace(section)
	wantFileCountNeedle := "reproduced 3× identically over " + strconv.Itoa(headCount) + " tracked files"
	if !strings.Contains(flat, wantFileCountNeedle) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 must record %q (the tracked-file count at tested_behavior_head %s)", wireProfileDocRelPath, wantFileCountNeedle, head)
	}
}

func TestPhase4Evidence_SelectorAbsenceAndComposition(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)
	flat := phase3CollapseWhitespace(section)

	composition := phase4EvidenceField(t, section, "Integration Dockerfile")
	if composition != phase3HistoricalIntegrationDockerfileRelPath {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 Integration Dockerfile is %q, want %q", wireProfileDocRelPath, composition, phase3HistoricalIntegrationDockerfileRelPath)
	}

	for _, needle := range []string{
		"**Selector/composition:** ordinary, untagged production",
		"**Phase 3 selector absence:**",
		"internal/ldap/profile.Server",
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 must record %q", wireProfileDocRelPath, needle)
		}
	}
}

// ---------------------------------------------------------------------
// Live certified-surface digest contract
// ---------------------------------------------------------------------

// TestPhase4Evidence_LiveCertifiedSurfaceDigestMatches is the Phase 4 live
// digest contract the plan requires: unlike every §11.5 historical test, it
// recomputes computeCertifiedSurfaceDigest against the CURRENT tree (not a
// frozen literal) and requires equality with §11.6's recorded digest and
// tracked-file count. A later change to any certifiedSurfacePatterns file
// without a matching §11.6 update fails this test.
func TestPhase4Evidence_LiveCertifiedSurfaceDigestMatches(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	recordedDigest := phase4EvidenceField(t, section, "Certified-surface digest (SHA-256)")

	liveDigest, liveCount := computeCertifiedSurfaceDigest(t, root)
	if liveDigest != recordedDigest {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 records certified-surface digest %s, but the CURRENT tree recomputes to %s — §11.6's attestation is void per the plan's stop condition 9 (\"Commit 4 changes the certified-surface digest\"); either the tree drifted from tested_behavior_head or §11.6 was never updated to match it", wireProfileDocRelPath, recordedDigest, liveDigest)
	}

	flat := phase3CollapseWhitespace(section)
	wantFileCountNeedle := "reproduced 3× identically over " + strconv.Itoa(liveCount) + " tracked files"
	if !strings.Contains(flat, wantFileCountNeedle) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 must record %q (the live tracked-file count for the current certified surface)", wireProfileDocRelPath, wantFileCountNeedle)
	}

	// third_party/** must remain in the pathset even though the directory
	// no longer exists, so a future reintroduction would again change the
	// digest (plan: "Do not remove third_party/** from the pathset simply
	// because the directory is deleted").
	found := false
	for _, pat := range certifiedSurfacePatterns {
		if pat == "third_party/**" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("phase4_evidence_contract: certifiedSurfacePatterns dropped \"third_party/**\" — the plan requires keeping it even after cutover deletes the directory")
	}
}

// ---------------------------------------------------------------------
// Supported matrix / HA / session probe
// ---------------------------------------------------------------------

func TestPhase4Evidence_SupportedMatrixAndHA(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)
	matrixPart, haPart := phase4SplitOnHAHeading(t, section)

	wantImages := append([]string(nil), phase3HistoricalImages...)
	sort.Strings(wantImages)

	assertImageResultTable := func(tableName, scopeLabel, scope string) {
		_, rows, err := wireProfileExtractTable(scope, tableName)
		if err != nil {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 %s %s table: %v", wireProfileDocRelPath, scopeLabel, tableName, err)
		}
		var gotImages []string
		for _, row := range rows {
			if len(row) != 2 {
				t.Fatalf("phase4_evidence_contract: %s: §11.6 %s %s table row %v has %d cells, want 2", wireProfileDocRelPath, scopeLabel, tableName, row, len(row))
			}
			image := wireProfileStripCell(row[0])
			result := wireProfileStripCell(row[1])
			if result != "PASS" {
				t.Fatalf("phase4_evidence_contract: %s: §11.6 %s %s table: image %s has result %q, want exactly PASS", wireProfileDocRelPath, scopeLabel, tableName, image, result)
			}
			gotImages = append(gotImages, image)
		}
		sort.Strings(gotImages)
		if !stringSlicesEqual(gotImages, wantImages) {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 %s %s table names images %v, want exactly the tracked set %v", wireProfileDocRelPath, scopeLabel, tableName, gotImages, wantImages)
		}
	}

	assertImageResultTable("Image", "Supported ClickHouse matrix", matrixPart)
	assertImageResultTable("Image", "HA", haPart)

	const sessionProbeNeedle = "**Session-probe result:** `PASS`"
	if !strings.Contains(phase3CollapseWhitespace(haPart), sessionProbeNeedle) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 must record a session-probe result", wireProfileDocRelPath)
	}
}

// ---------------------------------------------------------------------
// Wire verify / Search-before-Abandon
// ---------------------------------------------------------------------

func TestPhase4Evidence_WireVerify(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)
	flat := phase3CollapseWhitespace(section)

	const wantCommand = "bash integration/clickhouse/capture-ldap-wire.sh --mode verify --fixtures internal/ldap/testdata/clickhouse-wire"
	for _, needle := range []string{
		wantCommand,
		"generation: frozen",
		"**Result:** `PASS` for both tracked lines",
		"Search-before-Abandon",
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 wire-capture verification must record %q", wireProfileDocRelPath, needle)
		}
	}
	if !strings.Contains(flat, "Search precedes Abandon") && !strings.Contains(flat, "confirmed for both tracked lines") {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 must record the Search-before-Abandon observation for the tracked timeout-abandon session", wireProfileDocRelPath)
	}
}

// ---------------------------------------------------------------------
// Fuzz table
// ---------------------------------------------------------------------

func TestPhase4Evidence_FuzzTable(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	_, rows, err := wireProfileExtractTable(section, "Fuzz target", "Duration")
	if err != nil {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 fuzz table: %v", wireProfileDocRelPath, err)
	}
	if len(rows) != len(phase3FuzzTargetNames) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 fuzz table has %d rows, want exactly %d", wireProfileDocRelPath, len(rows), len(phase3FuzzTargetNames))
	}
	var gotTargets []string
	for _, row := range rows {
		if len(row) != 3 {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 fuzz table row %v has %d cells, want 3", wireProfileDocRelPath, row, len(row))
		}
		target := wireProfileStripCell(row[0])
		duration := wireProfileStripCell(row[1])
		result := wireProfileStripCell(row[2])
		if duration != "20s" {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 fuzz table: target %s has duration %q, want exactly \"20s\"", wireProfileDocRelPath, target, duration)
		}
		if result != "PASS" {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 fuzz table: target %s has result %q, want exactly PASS", wireProfileDocRelPath, target, result)
		}
		gotTargets = append(gotTargets, target)
	}
	sort.Strings(gotTargets)
	wantTargets := append([]string(nil), phase3FuzzTargetNames...)
	sort.Strings(wantTargets)
	if !stringSlicesEqual(gotTargets, wantTargets) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 fuzz table names targets %v, want exactly %v", wireProfileDocRelPath, gotTargets, wantTargets)
	}
}

// ---------------------------------------------------------------------
// LOC accounting
// ---------------------------------------------------------------------

// phase4FreshProductionLDAPLOC is the plan's required mechanical Phase 4
// LOC helper: internal/ldap/profile/*.go non-test files (the profile-only
// component, reusing wire_profile_contract_test.go's phase3FreshProfileLOC
// for that component only) plus cmd/ch-oauth-ldap/ldap_backend.go (the
// permanent command LDAP-wiring file). Per the plan ("Do not reuse Phase
// 3's profile-only helper as the final Phase 4 total"), this function's
// own return value — not phase3FreshProfileLOC's — is the final total.
func phase4FreshProductionLDAPLOC(t *testing.T, root string) (profileOnly, backendWiring, total int) {
	t.Helper()
	profileOnly = phase3FreshProfileLOC(t, root)

	data := wireProfileReadFile(t, root, "cmd/ch-oauth-ldap/ldap_backend.go")
	backendWiring = strings.Count(string(data), "\n")

	total = profileOnly + backendWiring
	return profileOnly, backendWiring, total
}

const phase4ArchitectureReviewLOCTrigger = 3500

func TestPhase4Evidence_LOCAccounting(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	profileOnly, backendWiring, total := phase4FreshProductionLDAPLOC(t, root)

	if total >= phase4ArchitectureReviewLOCTrigger {
		t.Fatalf("phase4_evidence_contract: final Phase 4 production LDAP LOC is %d, at or above ADR #32's ~%d architecture-review trigger — stop and return to architecture review (plan stop condition 6) rather than certifying this head", total, phase4ArchitectureReviewLOCTrigger)
	}

	profileOnlyStr := phase4EvidenceField(t, section, "Phase 4 profile-only LOC")
	if profileOnlyStr != strconv.Itoa(profileOnly) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 Phase 4 profile-only LOC is %q, but the current tree recomputes to %q", wireProfileDocRelPath, profileOnlyStr, strconv.Itoa(profileOnly))
	}

	backendStr := phase4EvidenceField(t, section, "cmd/ch-oauth-ldap/ldap_backend.go LDAP-wiring LOC")
	if backendStr != strconv.Itoa(backendWiring) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 cmd/ch-oauth-ldap/ldap_backend.go LDAP-wiring LOC is %q, but the current tree recomputes to %q", wireProfileDocRelPath, backendStr, strconv.Itoa(backendWiring))
	}

	totalStr := phase4EvidenceField(t, section, "Final Phase 4 production LDAP LOC")
	if totalStr != strconv.Itoa(total) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 Final Phase 4 production LDAP LOC is %q, but profile-only (%d) + backend wiring (%d) = %d", wireProfileDocRelPath, totalStr, profileOnly, backendWiring, total)
	}

	flat := phase3CollapseWhitespace(section)
	if !strings.Contains(flat, "Phase 3 profile-only historical LOC:** `2702`") {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 must cite the unchanged §11.5 historical Phase 3 profile-only LOC \"2702\" for comparison", wireProfileDocRelPath)
	}
}

// ---------------------------------------------------------------------
// Narrowing dispositions (unchanged from §11.5)
// ---------------------------------------------------------------------

func TestPhase4Evidence_NarrowingDispositionsUnchanged(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	_, rows, err := wireProfileExtractTable(section, "ID", "Disposition")
	if err != nil {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 narrowing-disposition table: %v", wireProfileDocRelPath, err)
	}
	if len(rows) != len(phase3NarrowingIDs) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 narrowing-disposition table has %d rows, want exactly %d (the same eleven IDs §11.3/§11.5 record)", wireProfileDocRelPath, len(rows), len(phase3NarrowingIDs))
	}
	for i, row := range rows {
		if len(row) != 2 {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 narrowing-disposition row %v has %d cells, want 2", wireProfileDocRelPath, row, len(row))
		}
		id := wireProfileStripCell(row[0])
		disposition := wireProfileStripCell(row[1])
		wantID := phase3NarrowingIDs[i]
		if id != wantID {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 narrowing-disposition row %d has ID %q, want %q in that exact order", wireProfileDocRelPath, i, id, wantID)
		}
		if disposition != "ACCEPT" {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 narrowing-disposition %s is %q — Phase 4 did not revisit any §11.3 narrowing, so every row must still read exactly ACCEPT", wireProfileDocRelPath, id, disposition)
		}
	}
}

// ---------------------------------------------------------------------
// Dependency closure / module graph / release gate / TLS / rollback /
// coordinator attestation
// ---------------------------------------------------------------------

func TestPhase4Evidence_DependencyClosureAndModuleGraph(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)
	flat := phase3CollapseWhitespace(section)

	for _, needle := range []string{
		"**Production dependency closure:** `PASS`",
		"TestDependencyContract_ProductionClosureHasNoGeneralLDAP",
		"**Root test/module graph:** `PASS`",
		"TestModuleDenylistContract_RootTestGraphHasNoGeneralLDAP",
		"TestModuleDenylistContract_RootModuleMetadataHasNoGeneralLDAP",
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 must record %q", wireProfileDocRelPath, needle)
		}
	}
}

func TestPhase4Evidence_TLSRow(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	const want = "N/A — issue #31 is a separate open unit and is out of scope for #33 Phase 4"
	if !strings.Contains(phase3CollapseWhitespace(section), want) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 TLS applicability must read exactly %q", wireProfileDocRelPath, want)
	}
}

func TestPhase4Evidence_RedactionAndReleaseGate(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)
	flat := phase3CollapseWhitespace(section)

	for _, needle := range []string{
		"**`phase5release` vet:** `PASS`",
		"**`phase5release` test:** `PASS`",
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 must record %q", wireProfileDocRelPath, needle)
		}
	}
}

func TestPhase4Evidence_RollbackAndCoordinatorAttestation(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)
	flat := phase3CollapseWhitespace(section)

	for _, needle := range []string{
		"**Rollback:**",
		"no dual parser is retained",
		"**Coordinator attestation:**",
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("phase4_evidence_contract: %s: §11.6 must record %q", wireProfileDocRelPath, needle)
		}
	}

	idx := strings.Index(flat, "**Coordinator attestation:**")
	attestation := strings.TrimSpace(flat[idx+len("**Coordinator attestation:**"):])
	if attestation == "" {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 coordinator attestation field is empty", wireProfileDocRelPath)
	}
}

// phase4AttestationHeadRE captures the exact commit SHA the Coordinator
// attestation sentence claims the manual Docker/fuzz/wire-capture suites
// were "run to completion against". It requires a literal 40-hex SHA (never
// a bare field name like `tested_behavior_head`) so the claim is checkable
// against a recorded field's actual value, not merely present as prose.
var phase4AttestationHeadRE = regexp.MustCompile("run to completion against `([0-9a-f]{40})`")

// TestPhase4Evidence_ManualVerificationHead requires §11.6 to separately
// record manual_verification_head — the commit the Docker/fuzz/wire-capture
// suites were actually run against — as a real commit reachable from HEAD,
// exactly like TestPhase4Evidence_TestedBehaviorHead does for
// tested_behavior_head. The two fields are allowed to diverge (see
// TestPhase4Evidence_CoordinatorAttestationBoundToManualVerificationHead for
// why), but both must independently name real history.
func TestPhase4Evidence_ManualVerificationHead(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	head := phase4EvidenceField(t, section, "manual_verification_head")
	if !phase4TestedBehaviorHeadRE.MatchString(head) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 manual_verification_head is %q, want a full 40-character lowercase hex commit SHA", wireProfileDocRelPath, head)
	}
	if !gitCommitIsReachable(t, root, head) {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 manual_verification_head %q does not resolve to a commit reachable from HEAD in this repository", wireProfileDocRelPath, head)
	}
}

// TestPhase4Evidence_CoordinatorAttestationBoundToManualVerificationHead
// closes the exact gap pass 3 review found: the Coordinator attestation
// sentence must name the commit the manual suites were actually run
// against (manual_verification_head), never tested_behavior_head — a
// separate field that §11.6 explicitly documents can advance past
// manual_verification_head for a behavior-preserving certified-surface
// edit (see the tested_behavior_head paragraph above) without the manual
// suites having been re-run against the newer commit. Prose alone said
// this correctly once already and drifted; this test makes it mechanical
// by extracting the literal SHA the attestation sentence cites — via the
// required "run to completion against `<sha>`" phrasing — and requiring it
// equal the recorded manual_verification_head field, not merely be present
// somewhere in the section.
func TestPhase4Evidence_CoordinatorAttestationBoundToManualVerificationHead(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase4_evidence_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase4EvidenceSection(t, doc)

	manualHead := phase4EvidenceField(t, section, "manual_verification_head")

	idx := strings.Index(section, "**Coordinator attestation:**")
	if idx < 0 {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 has no Coordinator attestation sentence", wireProfileDocRelPath)
	}
	attestation := section[idx:]

	m := phase4AttestationHeadRE.FindStringSubmatch(attestation)
	if m == nil {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 Coordinator attestation does not name the exact commit the manual suites were run to completion against, in the required \"run to completion against `<sha>`\" form — a claim naming a field by name instead of a literal SHA (or naming none at all) cannot be checked against manual_verification_head", wireProfileDocRelPath)
	}
	if m[1] != manualHead {
		t.Fatalf("phase4_evidence_contract: %s: §11.6 Coordinator attestation certifies the manual suites were run to completion against %q, but manual_verification_head records %q as the commit they were actually run against — these must be the same commit, or the attestation certifies work against a head nobody actually tested (this is the exact defect pass 3 review found: tested_behavior_head can legitimately advance past manual_verification_head, and the attestation must track the latter, not the former)", wireProfileDocRelPath, m[1], manualHead)
	}
}
