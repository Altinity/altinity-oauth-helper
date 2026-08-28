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
// proof (every marked fence is a verbatim contiguous substring of its named
// source); TestDocsContract_ClickHouseXMLFencesMatchFixtureElement is the
// stronger, element-scoped proof §21.4 specifically calls for on top of
// that (EVERY docsContractMarkdownFiles entry's <clickhouse>...</clickhouse>
// fence must equal exactly the fixture's own <clickhouse>...</clickhouse>
// element — not merely be found somewhere inside the whole fixture file,
// which also carries a long XML comment header this element-level
// comparison deliberately excludes — so README.md and
// docs/ch-oauth-ldap-operator-guide.md get the identical guarantee, not
// just one of them).

// docsContractMarkdownFiles is every markdown file this contract enforces
// config-source fences and the required/forbidden HA-and-trust-boundary
// wording guards across.
var docsContractMarkdownFiles = []string{
	"docs/ch-oauth-ldap-operator-guide.md",
	"README.md",
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

// TestDocsContract_ServerGoCapCommentDoesNotClaimOneMebibyte fails if
// internal/ldap/server.go ever again describes the current LDAP message
// body cap as 1 MiB (plan §21.13/§21.14's capacity-wording-stays-current
// guard) — the real, current cap is 64 KiB
// (third_party/ldapserver/packet.go's maxMessageBodyLength); 1 MiB was only
// ever the FIRST fix's value, before later hardening reduced it.
func TestDocsContract_ServerGoCapCommentDoesNotClaimOneMebibyte(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "internal", "ldap", "server.go"))
	if err != nil {
		t.Fatalf("securitytest: read internal/ldap/server.go: %v", err)
	}
	if strings.Contains(string(data), "1 MiB") {
		t.Fatalf("internal/ldap/server.go mentions \"1 MiB\" — the current LDAP message body cap is 64 KiB; restore/update the comment rather than reintroducing the stale figure")
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
// fails loudly instead of silently shrinking documentation coverage.
func TestDocsContract_OperatorGuideCitesEachExpectedSource(t *testing.T) {
	marked, _ := allMarkedAndUnmarkedFences(t)
	cited := make(map[string]bool, len(marked))
	for _, f := range marked {
		cited[f.sourcePath] = true
	}

	expected := []string{
		"cmd/ch-oauth-ldap/testdata/operator-guide.yaml",
		clickhouseFixtureRelPath,
	}
	var missing []string
	for _, src := range expected {
		if !cited[src] {
			missing = append(missing, src)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("no config-source-marked fence cites the following expected source file(s): %s", strings.Join(missing, ", "))
	}
}
