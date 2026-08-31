package securitytest

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file implements plan-19p5.md §21.4/A3's "docs contract": it keeps
// docs/ch-oauth-ldap-operator-guide.md and the root README's ClickHouse XML
// fence honest against their real sources, and enforces the T13b false-claim
// guards (§21.14) so this repository's only two "operator-facing narrative"
// documents (README.md and docs/ch-oauth-ldap-operator-guide.md) can never
// silently drift into an invented or stale claim.
//
// docs/clickhouse-ldap-wire-profile.md (issue #33 phase 1) is deliberately
// NOT a docsContractMarkdownFiles entry and this file enforces nothing about
// it — README.md and the operator guide remain the only two
// "operator-facing narrative" documents this repo asks an operator to read
// for "how do I configure and run this," and that pair is what this file's
// fence/phrase contract exists to protect. The wire-profile doc is a
// different kind of artifact: engineering evidence (exact ClickHouse/OpenLDAP
// source citations, the committed wire corpus, and the cryptobyte-vs-bounded-
// parser decision) for Phase 2/3's implementer, not a second configuration
// narrative — README.md links it, but only as a pointer, never by
// duplicating canonical config into it (plan §35). Its own internal
// consistency (exactly one decision marker, no XML/YAML configuration
// fences, static source-provenance matrix, JWT-shape scan) is owned entirely
// by internal/securitytest/wire_profile_contract_test.go, a separate file
// with a separate mandate; do not fold its checks into this one or add it to
// docsContractMarkdownFiles.
//
// Every YAML/XML configuration fence this repo's docs show an operator is
// meant to be an EXACT, byte-for-byte contiguous excerpt of a real,
// executable/loaded source file — never hand-retyped, never "close enough".
// A marker comment immediately above the fenced block records which file:
//
//	<!-- config-source: cmd/ch-oauth-ldap/testdata/operator-guide.yaml -->
//	```yaml
//	oauth:
//	  ...
//	```
//
// docsContractSourceFiles is the fixed set of files a config-source marker
// is allowed to name, resolved once relative to the module root so every
// test below reads the same real bytes docs are claimed to be copied from:
//   - cmd/ch-oauth-ldap/testdata/operator-guide.yaml — the exact file
//     TestOperatorGuideYAML_LoadsThroughProductionLoadConfig
//     (cmd/ch-oauth-ldap/config_test.go) loads through the real production
//     LoadConfig, and TestOperatorGuideYAML_StrictKnownFields additionally
//     strict-decodes with yaml.NewDecoder(...).KnownFields(true) against the
//     production Config struct (coordinator amendment A3). That strict test
//     — asserted still present by TestDocsContract_YAMLProofTestStillExists
//     below — is the actual proof that every field these YAML fences show is
//     real and current; this file only proves the fences match that
//     audited YAML, not that the YAML itself is valid (config_test.go
//     already owns that).
//   - integration/clickhouse/clickhouse/common/config.d/ldap.xml — the real
//     ClickHouse LDAP fixture the manual integration suite runs against.
//
// TestDocsContract_MarkedFencesAreExactContiguousExcerpts is the general
// proof (every marked fence names an allowlisted source — see
// isAllowedDocsContractSource below — and is a verbatim contiguous
// substring of it); TestDocsContract_ClickHouseXMLFencesMatchFixtureElement
// is the stronger, element-scoped proof §21.4 specifically calls for on top
// of that (EVERY docsContractMarkdownFiles entry's <clickhouse>...</clickhouse>
// fence must equal exactly the fixture's own <clickhouse>...</clickhouse>
// element — not merely be found somewhere inside the whole fixture file,
// which also carries a long XML comment header this element-level
// comparison deliberately excludes — so README.md and
// docs/ch-oauth-ldap-operator-guide.md get the identical guarantee, not
// just one of them).

// docsContractMarkdownFiles is every markdown file this contract enforces
// config-source fences and the required/forbidden HA-and-trust-boundary
// wording guards across — the complete operator-facing configuration
// narrative. docs/clickhouse-ldap-wire-profile.md is intentionally absent:
// it is engineering evidence, not operator-facing configuration narrative,
// and its own doc-boundary rules (exactly one decision marker, no XML/YAML
// fences) live in wire_profile_contract_test.go instead — see this file's
// package comment above.
var docsContractMarkdownFiles = []string{
	"docs/ch-oauth-ldap-operator-guide.md",
	"README.md",
}

// docsContractSourceFiles is the fixed set of files a config-source marker
// is allowed to name, resolved once relative to the module root so every
// test below reads the same real bytes docs are claimed to be copied from.
// isAllowedDocsContractSource is the actual enforcement of this set: without
// it, a marker naming any readable in-repo path — including one of
// docsContractMarkdownFiles itself — would pass
// TestDocsContract_MarkedFencesAreExactContiguousExcerpts vacuously, since a
// fence's own content trivially substring-matches the very file it was
// pasted into (strings.Contains(src, f.content) with src == f.content's own
// document). Both entries are cited elsewhere in this file by name
// (cmd/ch-oauth-ldap/testdata/operator-guide.yaml and
// clickhouseFixtureRelPath) rather than duplicated as literals.
var docsContractSourceFiles = []string{
	"cmd/ch-oauth-ldap/testdata/operator-guide.yaml",
	clickhouseFixtureRelPath,
}

// isAllowedDocsContractSource reports whether sourcePath is one of the
// fixed docsContractSourceFiles entries — the only files a config-source
// marker may legitimately name.
func isAllowedDocsContractSource(sourcePath string) bool {
	for _, allowed := range docsContractSourceFiles {
		if sourcePath == allowed {
			return true
		}
	}
	return false
}

// configSourceMarkerRE matches a config-source marker line exactly (its own
// line, no trailing content besides the closing "-->").
var configSourceMarkerRE = regexp.MustCompile(`^<!--\s*config-source:\s*(\S+)\s*-->\s*$`)

// fenceOpenRE matches a fenced-code-block opening line and captures its
// language tag (e.g. "yaml", "xml", "bash" — empty capture for a bare
// ``` fence, which this contract never expects to see used for a
// config-source-marked block).
var fenceOpenRE = regexp.MustCompile("^```([a-zA-Z0-9_-]*)\\s*$")

// markedFence is one config-source-marked fenced code block discovered in a
// markdown file.
type markedFence struct {
	mdFile     string // the markdown file this fence was found in, relative to root
	mdLine     int    // 1-based line number of the marker comment
	sourcePath string // the path named by the marker, relative to root
	lang       string // the fence's language tag (yaml/xml)
	content    string // the fence body, lines joined by "\n", no trailing newline
}

// unmarkedConfigFence is a yaml/xml fenced code block found with no
// immediately preceding config-source marker.
type unmarkedConfigFence struct {
	mdFile string
	mdLine int
	lang   string
}

// scanMarkdownFences walks path line by line and returns every
// config-source-marked fence plus every yaml/xml fence found with no
// marker immediately above it (docsContractMarkdownFiles's own existing,
// non-config fences — e.g. README's ```bash / ```sql examples — are simply
// never yaml/xml, so they never appear in either return value).
func scanMarkdownFences(root, relPath string) ([]markedFence, []unmarkedConfigFence, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
	if err != nil {
		return nil, nil, err
	}
	lines := strings.Split(string(data), "\n")

	var marked []markedFence
	var unmarked []unmarkedConfigFence

	for i := 0; i < len(lines); i++ {
		m := fenceOpenRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		lang := m[1]
		// Find the fence's closing ``` line.
		end := -1
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimRight(lines[j], " \t") == "```" {
				end = j
				break
			}
		}
		if end == -1 {
			return nil, nil, &fenceNotClosedError{mdFile: relPath, line: i + 1}
		}
		body := strings.Join(lines[i+1:end], "\n")

		// Is there a config-source marker on the immediately preceding line?
		var markerTarget string
		hasMarker := false
		if i > 0 {
			if mm := configSourceMarkerRE.FindStringSubmatch(lines[i-1]); mm != nil {
				hasMarker = true
				markerTarget = mm[1]
			}
		}

		switch {
		case hasMarker:
			marked = append(marked, markedFence{
				mdFile:     relPath,
				mdLine:     i, // marker's own 1-based line number (i-1 is 0-based, +1)
				sourcePath: markerTarget,
				lang:       lang,
				content:    body,
			})
		case lang == "yaml" || lang == "xml":
			unmarked = append(unmarked, unmarkedConfigFence{mdFile: relPath, mdLine: i + 1, lang: lang})
		}

		i = end
	}
	return marked, unmarked, nil
}

type fenceNotClosedError struct {
	mdFile string
	line   int
}

func (e *fenceNotClosedError) Error() string {
	return "securitytest: " + e.mdFile + ":" + strconv.Itoa(e.line) + ": fenced code block never closed"
}

// allMarkedAndUnmarkedFences scans every file in docsContractMarkdownFiles.
func allMarkedAndUnmarkedFences(t *testing.T) ([]markedFence, []unmarkedConfigFence) {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	var allMarked []markedFence
	var allUnmarked []unmarkedConfigFence
	for _, mdFile := range docsContractMarkdownFiles {
		marked, unmarked, err := scanMarkdownFences(root, mdFile)
		if err != nil {
			t.Fatalf("securitytest: scan %s: %v", mdFile, err)
		}
		allMarked = append(allMarked, marked...)
		allUnmarked = append(allUnmarked, unmarked...)
	}
	return allMarked, allUnmarked
}

// TestDocsContract_EveryConfigFenceIsMarked fails when docs/README carry a
// yaml/xml fenced code block with no config-source marker immediately above
// it — the T13b requirement that "every new YAML/XML fence carries a
// config-source marker".
func TestDocsContract_EveryConfigFenceIsMarked(t *testing.T) {
	_, unmarked := allMarkedAndUnmarkedFences(t)
	if len(unmarked) == 0 {
		return
	}
	var msgs []string
	for _, u := range unmarked {
		msgs = append(msgs, u.mdFile+":"+strconv.Itoa(u.mdLine)+" (```"+u.lang+")")
	}
	sort.Strings(msgs)
	t.Fatalf("%d yaml/xml fenced code block(s) with no config-source marker immediately above them:\n%s",
		len(msgs), strings.Join(msgs, "\n"))
}

// TestDocsContract_MarkedFencesAreExactContiguousExcerpts fails when a
// config-source-marked fence's content is not found, byte-for-byte, as a
// contiguous substring of the file its marker names. This is the general
// "docs snippets come from executable evidence" invariant (plan §25):
// editing a fence's text without also matching the real source (or letting
// the real source drift away from a stale fence) breaks this test.
func TestDocsContract_MarkedFencesAreExactContiguousExcerpts(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	marked, _ := allMarkedAndUnmarkedFences(t)
	if len(marked) == 0 {
		t.Fatalf("no config-source-marked fences discovered in %v — expected at least the ClickHouse XML and the operator-guide YAML fences", docsContractMarkdownFiles)
	}

	sourceCache := make(map[string]string)
	var bad []string
	for _, f := range marked {
		if !isAllowedDocsContractSource(f.sourcePath) {
			bad = append(bad, f.mdFile+":"+strconv.Itoa(f.mdLine)+": config-source names "+f.sourcePath+
				", which is not in the fixed allowlist ("+strings.Join(docsContractSourceFiles, ", ")+")")
			continue
		}
		src, ok := sourceCache[f.sourcePath]
		if !ok {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.sourcePath)))
			if err != nil {
				bad = append(bad, f.mdFile+":"+strconv.Itoa(f.mdLine)+": config-source names unreadable file "+f.sourcePath+": "+err.Error())
				continue
			}
			src = string(data)
			sourceCache[f.sourcePath] = src
		}
		if !strings.Contains(src, f.content) {
			bad = append(bad, f.mdFile+":"+strconv.Itoa(f.mdLine)+": fence content is not a contiguous excerpt of "+f.sourcePath)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("%d marked fence(s) failed the exact-contiguous-excerpt check:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// clickhouseFixtureRelPath is the real ClickHouse LDAP fixture the root
// README's XML fence claims to be copied verbatim from.
const clickhouseFixtureRelPath = "integration/clickhouse/clickhouse/common/config.d/ldap.xml"

// extractElement returns the contiguous substring of src from the first
// "<"+tag+">" through the first "</"+tag+">" that follows it (inclusive),
// or ("", false) if either delimiter is absent or out of order. This is
// deliberately simple (no general XML parsing) because it only ever needs
// to isolate exactly one, non-nested-in-itself element
// (<clickhouse>...</clickhouse>) from a fixture file that also carries a
// long comment header before it — see §21.4's "do not compare against the
// entire fixture file" requirement.
func extractElement(src, tag string) (string, bool) {
	open := "<" + tag + ">"
	close_ := "</" + tag + ">"
	startIdx := strings.Index(src, open)
	if startIdx == -1 {
		return "", false
	}
	endIdx := strings.Index(src[startIdx:], close_)
	if endIdx == -1 {
		return "", false
	}
	endIdx += startIdx + len(close_)
	return src[startIdx:endIdx], true
}

// TestDocsContract_ClickHouseXMLFencesMatchFixtureElement is the
// element-scoped strengthening of the general contiguous-excerpt check,
// applied to EVERY docsContractMarkdownFiles entry's <clickhouse> fence
// (plan §21.4) — originally README-only, now also covering
// docs/ch-oauth-ldap-operator-guide.md's own §1 fence so both of this
// repo's operator-facing documents get the same strict guarantee, not just
// one of them: each fence must equal EXACTLY the fixture's own
// <clickhouse>...</clickhouse> element, not merely be found somewhere
// inside the whole fixture file (which also has a long comment header
// preceding that element — comparing against the whole file would let a
// fence drift from the actual <clickhouse> content as long as it stayed a
// substring of the header too).
func TestDocsContract_ClickHouseXMLFencesMatchFixtureElement(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}

	fixtureData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(clickhouseFixtureRelPath)))
	if err != nil {
		t.Fatalf("securitytest: read fixture %s: %v", clickhouseFixtureRelPath, err)
	}
	fixtureElement, ok := extractElement(string(fixtureData), "clickhouse")
	if !ok {
		t.Fatalf("securitytest: could not locate a <clickhouse>...</clickhouse> element in %s", clickhouseFixtureRelPath)
	}
	fixtureElement = strings.TrimSpace(fixtureElement)

	for _, mdFile := range docsContractMarkdownFiles {
		marked, _, err := scanMarkdownFences(root, mdFile)
		if err != nil {
			t.Fatalf("securitytest: scan %s: %v", mdFile, err)
		}

		var clickhouseFence *markedFence
		for i := range marked {
			f := &marked[i]
			if f.sourcePath == clickhouseFixtureRelPath && strings.HasPrefix(strings.TrimSpace(f.content), "<clickhouse>") {
				clickhouseFence = f
				break
			}
		}
		if clickhouseFence == nil {
			t.Fatalf("%s has no config-source-marked <clickhouse> fence pointing at %s", mdFile, clickhouseFixtureRelPath)
		}

		fenceContent := strings.TrimSpace(clickhouseFence.content)
		if fenceContent != fixtureElement {
			t.Fatalf("%s's <clickhouse> fence does not equal the fixture's contiguous <clickhouse>...</clickhouse> element.\n--- %s fence ---\n%s\n--- fixture element ---\n%s",
				mdFile, mdFile, fenceContent, fixtureElement)
		}
	}
}

// requiredDocPhrases must each appear (as a literal, single-line substring
// — no markdown line-wrap through the middle of the phrase) at least once
// in docs/ch-oauth-ldap-operator-guide.md. Mirrors T13b's "false-claim
// guards" (plan §21.14): these are the honest claims this phase can
// actually make, and their absence would mean the guide silently dropped
// one of them.
var requiredDocPhrases = []string{
	"not verified in this environment",
	"NetworkPolicy is not transport confidentiality",
	"existing connection to a killed replica may fail",
	"requires ClickHouse ≥ 25.8",
}

// TestDocsContract_RequiredPhrasesPresent fails when
// docs/ch-oauth-ldap-operator-guide.md is missing any requiredDocPhrases
// entry.
func TestDocsContract_RequiredPhrasesPresent(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "docs", "ch-oauth-ldap-operator-guide.md"))
	if err != nil {
		t.Fatalf("securitytest: read operator guide: %v", err)
	}
	content := string(data)

	var missing []string
	for _, phrase := range requiredDocPhrases {
		if !strings.Contains(content, phrase) {
			missing = append(missing, phrase)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/ch-oauth-ldap-operator-guide.md is missing %d required phrase(s):\n%s", len(missing), strings.Join(missing, "\n"))
	}
}

// forbiddenDocPhrases must NEVER appear in any docsContractMarkdownFiles
// entry — each names a claim this phase explicitly did not (and, for
// LDAPS/StartTLS, does not at all) verify or implement. Matches the exact
// strings the T13b doneWhen grep checks for.
var forbiddenDocPhrases = []string{
	"Kubernetes HA verified",
	"supports LDAPS",
	"StartTLS support",
}

// TestDocsContract_ForbiddenPhrasesAbsent fails when any
// docsContractMarkdownFiles entry contains a forbiddenDocPhrases entry.
func TestDocsContract_ForbiddenPhrasesAbsent(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	var bad []string
	for _, mdFile := range docsContractMarkdownFiles {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(mdFile)))
		if err != nil {
			t.Fatalf("securitytest: read %s: %v", mdFile, err)
		}
		content := string(data)
		for _, phrase := range forbiddenDocPhrases {
			if strings.Contains(content, phrase) {
				bad = append(bad, mdFile+": contains forbidden phrase \""+phrase+"\"")
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("%d forbidden-phrase violation(s):\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// TestDocsContract_ServerGoCapCommentDoesNotClaimOneMebibyte formerly
// guarded internal/ldap/server.go (the legacy LDAP server's own comment
// about its message body cap) against reverting to a stale "1 MiB" figure
// after a fix reduced the real cap to 64 KiB. The issue #33 phase 4 cutover
// deleted internal/ldap/server.go along with the rest of the legacy
// implementation, so there is no longer a file this guard could protect —
// the permanent successor, internal/ldap/profile, was never described with
// the stale "1 MiB" figure in the first place, and its own body-cap
// invariant (64 KiB) is covered by its own frame/adversarial/fuzz tests, not
// a docs-contract wording guard. This test is deliberately not replaced with
// an internal/ldap/profile analog: there is no stale-comment history to
// protect against there.

// TestDocsContract_ReleaseGateWordingStaysGeneric fails if
// release_gate_test.go's blocked_external release-gate doc comment or
// failure message ever again hardcode the (now-resolved) SDK kid-rotation
// row by name. That row was the only blocked_external row for a while, but
// the gate fails for ANY blocked_external row, present or future, for any
// dependency — wording that still says "currently exactly the SDK
// kid-rotation row" or steers every reader toward "bump+re-audit the SDK"
// specifically would misdiagnose a future, unrelated blocked_external row.
// The gate's prose and remediation text must stay generic to whichever
// row(s) are actually blocked (and their named gate) at the time it fails.
func TestDocsContract_ReleaseGateWordingStaysGeneric(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "internal", "securitytest", "release_gate_test.go"))
	if err != nil {
		t.Fatalf("securitytest: read internal/securitytest/release_gate_test.go: %v", err)
	}
	// Normalize away Go comment markers and line-wrap whitespace so a
	// phrase that happens to wrap across "// "-prefixed comment lines (as
	// the stale wording did) is still matched as one contiguous phrase.
	normalized := strings.Join(strings.Fields(strings.ReplaceAll(string(data), "//", " ")), " ")
	staleReleaseGateWordingPhrases := []string{
		"currently exactly the SDK kid-rotation row",
		"bump+re-audit the SDK, or record kid as allowed non-credential metadata",
	}
	var bad []string
	for _, phrase := range staleReleaseGateWordingPhrases {
		normalizedPhrase := strings.Join(strings.Fields(phrase), " ")
		if strings.Contains(normalized, normalizedPhrase) {
			bad = append(bad, "release_gate_test.go: contains stale kid-specific release-gate wording \""+phrase+"\"")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("%d stale release-gate wording violation(s):\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// operatorGuideYAMLProofTest is the exact T13a test function name §21.4/A3
// cites as the proof that every YAML fence's field set is real: it strict-
// decodes cmd/ch-oauth-ldap/testdata/operator-guide.yaml (the file every
// YAML fence in docs/ch-oauth-ldap-operator-guide.md is copied from) against
// the production Config struct with yaml.NewDecoder(...).KnownFields(true).
const operatorGuideYAMLProofTest = "TestOperatorGuideYAML_StrictKnownFields"

// TestDocsContract_YAMLProofTestStillExists fails if
// cmd/ch-oauth-ldap/config_test.go no longer defines
// operatorGuideYAMLProofTest — without it, this package's YAML-fence
// contiguous-excerpt checks above would only prove the fences match
// operator-guide.yaml, with nothing left proving operator-guide.yaml itself
// still parses correctly against the real production Config shape.
func TestDocsContract_YAMLProofTestStillExists(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "cmd", "ch-oauth-ldap", "config_test.go"))
	if err != nil {
		t.Fatalf("securitytest: read cmd/ch-oauth-ldap/config_test.go: %v", err)
	}
	if !strings.Contains(string(data), "func "+operatorGuideYAMLProofTest+"(") {
		t.Fatalf("cmd/ch-oauth-ldap/config_test.go no longer defines %s — this is the strict-decode proof docs/ch-oauth-ldap-operator-guide.md's YAML fences depend on; do not delete it without replacing this citation", operatorGuideYAMLProofTest)
	}
}

// TestDocsContract_OperatorGuideCitesEachExpectedSource is a sanity guard
// against a gutted or misfiled guide: it requires at least one
// config-source marker per expected source file, so removing all fences
// derived from one of them (rather than genuinely updating the guide)
// fails loudly instead of silently shrinking documentation coverage. The
// expected set is docsContractSourceFiles itself — the same fixed allowlist
// isAllowedDocsContractSource enforces — so this stays a floor on top of
// that ceiling rather than a second, independently-maintained list that
// could quietly drift from it.
func TestDocsContract_OperatorGuideCitesEachExpectedSource(t *testing.T) {
	marked, _ := allMarkedAndUnmarkedFences(t)
	cited := make(map[string]bool, len(marked))
	for _, f := range marked {
		cited[f.sourcePath] = true
	}

	var missing []string
	for _, src := range docsContractSourceFiles {
		if !cited[src] {
			missing = append(missing, src)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("no config-source-marked fence cites the following expected source file(s): %s", strings.Join(missing, ", "))
	}
}

// TestIsAllowedDocsContractSource_RejectsArbitraryAndSelfReferentialPaths is
// the sabotage case for the docs-contract allowlist itself. Before this
// test (and isAllowedDocsContractSource) existed,
// TestDocsContract_MarkedFencesAreExactContiguousExcerpts validated a
// marker-supplied sourcePath against nothing but "is it readable" — so a
// marker naming one of docsContractMarkdownFiles itself (e.g.
// "<!-- config-source: README.md -->" above a fence pasted from README.md
// verbatim) would pass every check in this file, because
// strings.Contains(src, f.content) is trivially true when src and f.content
// come from the same document. This test proves the allowlist actually
// constrains what a marker may name, in both directions: every real source
// this contract relies on stays allowed, and every path that would make the
// contract vacuous — the two docs files themselves, an arbitrary in-repo
// file, and the empty string — is rejected.
func TestIsAllowedDocsContractSource_RejectsArbitraryAndSelfReferentialPaths(t *testing.T) {
	for _, allowed := range docsContractSourceFiles {
		if !isAllowedDocsContractSource(allowed) {
			t.Errorf("isAllowedDocsContractSource(%q) = false, want true (listed in docsContractSourceFiles)", allowed)
		}
	}

	var rejected []string
	rejected = append(rejected, docsContractMarkdownFiles...) // the self-referential case
	rejected = append(rejected,
		"go.mod",
		"cmd/ch-oauth-ldap/main.go",
		"cmd/ch-oauth-ldap/testdata/operator-guide.yaml/../../../go.mod",
		"",
	)
	for _, path := range rejected {
		if isAllowedDocsContractSource(path) {
			t.Errorf("isAllowedDocsContractSource(%q) = true, want false (not a member of the fixed docsContractSourceFiles allowlist)", path)
		}
	}
}

// TestDocsContract_MarkedFencesRejectSelfReferentialSource is the
// end-to-end version of the sabotage case above: it drives an actual
// self-referential config-source marker through scanMarkdownFences (the
// same parser TestDocsContract_MarkedFencesAreExactContiguousExcerpts uses)
// against a synthetic markdown file, then confirms the allowlist check that
// test performs would reject the resulting sourcePath — i.e. the fix is
// wired into the real fence-scanning path, not just proven against the
// allowlist function in isolation.
func TestDocsContract_MarkedFencesRejectSelfReferentialSource(t *testing.T) {
	dir := t.TempDir()
	const body = "oauth:\n  clientID: example\n"
	doc := "# Self-referential fence\n\n" +
		"<!-- config-source: self.md -->\n" +
		"```yaml\n" + body + "```\n"
	if err := os.WriteFile(filepath.Join(dir, "self.md"), []byte(doc), 0o644); err != nil {
		t.Fatalf("write synthetic doc: %v", err)
	}

	marked, _, err := scanMarkdownFences(dir, "self.md")
	if err != nil {
		t.Fatalf("scanMarkdownFences: %v", err)
	}
	if len(marked) != 1 {
		t.Fatalf("got %d marked fence(s), want 1", len(marked))
	}
	f := marked[0]
	if f.sourcePath != "self.md" {
		t.Fatalf("sourcePath = %q, want %q", f.sourcePath, "self.md")
	}
	// The fence body is, by construction, a contiguous substring of the very
	// document it was pasted into — the vacuous case the allowlist exists to
	// catch, since the general contiguous-excerpt check alone would pass it.
	if !strings.Contains(doc, f.content) {
		t.Fatalf("test setup invariant broken: fence content is not a substring of its own document")
	}
	if isAllowedDocsContractSource(f.sourcePath) {
		t.Fatalf("isAllowedDocsContractSource(%q) = true, want false — a self-referential config-source marker must be rejected, not silently accepted as a vacuous match", f.sourcePath)
	}
}
