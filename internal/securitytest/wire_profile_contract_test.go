package securitytest

// This file implements issue #33 phase 1's Docker-free wire-profile
// contract (plan §30), plus the three closely related mechanical proofs
// the plan groups alongside it: §9's WirecaptureUsesSharedFixtureSchema
// (single serialization ownership), §11's .gitattributes assertion (also
// §30.5), and §29's ConstructedMessageIDFixturesReproduce
// (regenerate-and-byte-compare boundary proof). It never re-derives the
// cryptobyte-vs-local-ber-cursor verdict itself (plan §33: "Only
// TestClickHouseWireCryptobyteDecision computes the cryptobyte verdict" —
// internal/ldap/clickhouse_wire_cryptobyte_test.go, a separate sub-task,
// owns that) — this file verifies only the decision MARKER's syntax and
// uniqueness in the wire doc (§30.8), never a second copy of the decision
// algorithm.
//
// Per coordinator amendment 7, this file keeps using this package's own
// moduleRoot() (doc.go) for locating the repository root, exactly like
// every other contract test in this package — internal/wirefixture's
// separate ModuleRoot() helper exists for internal/ldap's decision test
// and the wirecapture tool, not for internal/securitytest. wirefixture is
// still imported here, for its Read*/Stable*/ClickHouseConfigElementSHA256
// schema APIs and its exported BlobKey*/Operation*/Provenance* constants —
// this file is a READER of the shared schema, never a second writer.
//
// Static-matrix rationale (plan §51, "The source matrix duplicates
// external provenance into a test"): auditedProvenanceMatrix below is a
// second, independently typed-in copy of the exact source provenance the
// wire doc and every profile.json also carry. That duplication is
// deliberate: a doc and a profile.json compared only to each other could
// drift together and this test would still pass. Changing a tracked
// line's provenance requires updating this matrix, the doc, and every
// profile.json together, in the same reviewed change — never one
// unilaterally.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	goldapmessage "github.com/vjeantet/goldap/message"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// ---------------------------------------------------------------------
// 30.1 — static audited source-provenance matrix
// ---------------------------------------------------------------------

// auditedLineProvenance is one tracked line's independently audited
// source-provenance record (plan §2.2/§2.3), typed in here rather than
// read from any file this test also checks against it.
type auditedLineProvenance struct {
	Line                 string
	Image                string
	ClickHouseRepository string
	ClickHouseTag        string
	ClickHouseCommit     string
	// Blobs is keyed by the wirefixture.BlobKey* constants.
	Blobs              map[string]string
	OpenLDAPRepository string
	OpenLDAPPin        string
	OpenLDAPVersion    string
}

// auditedProvenanceMatrix is the plan §2.2/§2.3 audited matrix, typed in
// once here and required to agree with run-all-builds.sh's BUILDS array,
// the wire doc's tables, and every committed profile.json (plan §30.1).
var auditedProvenanceMatrix = []auditedLineProvenance{
	{
		Line:                 "24.8",
		Image:                "altinity/clickhouse-server:24.8.11.51285.altinitystable",
		ClickHouseRepository: "Altinity/ClickHouse",
		ClickHouseTag:        "v24.8.11.51285.altinitystable",
		ClickHouseCommit:     "351edb1a2ec26940aee4c2d1d332fd280c232964",
		Blobs: map[string]string{
			wirefixture.BlobKeyLDAPClientCPP:             "3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0",
			wirefixture.BlobKeyLDAPClientH:               "0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6",
			wirefixture.BlobKeyLDAPAccessStorageCPP:      "917ad7cbb922083ab82f85ab25c120a17fd009c7",
			wirefixture.BlobKeyExternalAuthenticatorsCPP: "77812ac5eb5d0027f081ac43dccc6b89110aeb73",
		},
		OpenLDAPRepository: "ClickHouse/openldap",
		OpenLDAPPin:        "5671b80e369df2caf5f34e02924316205a43c895",
		OpenLDAPVersion:    "2.5.16",
	},
	{
		Line:                 "25.8",
		Image:                "altinity/clickhouse-server:25.8.28.10001.altinitystable",
		ClickHouseRepository: "Altinity/ClickHouse",
		ClickHouseTag:        "v25.8.28.10001.altinitystable",
		ClickHouseCommit:     "568824f4327b379e86bce93f12b9cebe0cfd9ff5",
		Blobs: map[string]string{
			wirefixture.BlobKeyLDAPClientCPP:             "3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0",
			wirefixture.BlobKeyLDAPClientH:               "0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6",
			wirefixture.BlobKeyLDAPAccessStorageCPP:      "fc55c6b081b38ecccbf4894a9a5fa223d3cd2bd8",
			wirefixture.BlobKeyExternalAuthenticatorsCPP: "ca61b55dc5dc200353971ff53580b2ee04439334",
		},
		OpenLDAPRepository: "openldap/openldap",
		OpenLDAPPin:        "22fe35c6b4098e3ad166469f9574c79832c42952",
		OpenLDAPVersion:    "2.6.10",
	},
}

// auditedLDAPOptions is the plan §3.3/§5 sentinel set of non-TLS
// ldap_set_option names the tracked openConnection() source is audited to
// set, required to appear, exactly, in the wire doc's own sentinel
// section (see TestWireProfileContract_LDAPOptionSentinelMatchesAuditedSet).
var auditedLDAPOptions = []string{
	"LDAP_OPT_PROTOCOL_VERSION",
	"LDAP_OPT_RESTART",
	"LDAP_OPT_KEEPCONN",
	"LDAP_OPT_TIMEOUT",
	"LDAP_OPT_NETWORK_TIMEOUT",
	"LDAP_OPT_TIMELIMIT",
	"LDAP_OPT_SIZELIMIT",
}

func wireProfileAuditedLines() []string {
	out := make([]string, 0, len(auditedProvenanceMatrix))
	for _, p := range auditedProvenanceMatrix {
		out = append(out, p.Line)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------
// Shared path/read helpers
// ---------------------------------------------------------------------

const runAllBuildsRelPath = "integration/clickhouse/run-all-builds.sh"
const wireProfileDocRelPath = "docs/clickhouse-ldap-wire-profile.md"
const gitAttributesRelPath = ".gitattributes"
const clickhouseLDAPXMLRelPath = "integration/clickhouse/clickhouse/common/config.d/ldap.xml"

func wireProfileFixtureRoot(root string) string {
	return wirefixture.ClickHouseWireFixtureRoot(root)
}

func wireProfileReadFile(t *testing.T, root, relPath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
	if err != nil {
		t.Fatalf("wire_profile_contract: read %s: %v", relPath, err)
	}
	return data
}

// ---------------------------------------------------------------------
// run-all-builds.sh BUILDS parsing
// ---------------------------------------------------------------------

// wireProfileParseBuildsImages extracts the literal image strings from
// run-all-builds.sh's BUILDS=(...) bash array, in the order they appear —
// the four-way and static-matrix contracts derive their expected tracked
// set from this parse rather than maintaining an independent list (plan
// §2.1/§30.1: "The contract test derives this set from the runner instead
// of maintaining an independent list").
func wireProfileParseBuildsImages(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(runAllBuildsRelPath)))
	if err != nil {
		return nil, fmt.Errorf("wire_profile_contract: read %s: %w", runAllBuildsRelPath, err)
	}
	text := string(data)
	const marker = "BUILDS=("
	start := strings.Index(text, marker)
	if start < 0 {
		return nil, fmt.Errorf("wire_profile_contract: %s: no %q found", runAllBuildsRelPath, marker)
	}
	rest := text[start+len(marker):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return nil, fmt.Errorf("wire_profile_contract: %s: %q never closed with ')'", runAllBuildsRelPath, marker)
	}
	block := rest[:end]
	quoted := regexp.MustCompile(`"([^"]+)"`)
	matches := quoted.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("wire_profile_contract: %s: BUILDS array parsed with zero image entries", runAllBuildsRelPath)
	}
	images := make([]string, 0, len(matches))
	for _, m := range matches {
		images = append(images, m[1])
	}
	return images, nil
}

// wireProfileImageLineRE derives a tracked-line key (e.g. "24.8") from a
// clickhouse-server image tag, matching this document's and every
// profile.json's own line-key convention.
var wireProfileImageLineRE = regexp.MustCompile(`clickhouse-server:(\d+\.\d+)\.`)

func wireProfileLineFromImage(image string) (string, error) {
	m := wireProfileImageLineRE.FindStringSubmatch(image)
	if m == nil {
		return "", fmt.Errorf("wire_profile_contract: image %q does not match the expected clickhouse-server:<major>.<minor>. shape", image)
	}
	return m[1], nil
}

// ---------------------------------------------------------------------
// Markdown table parsing (wire doc)
// ---------------------------------------------------------------------

func wireProfileSplitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

func wireProfileIsTableSeparator(line string) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") {
		return false
	}
	for _, r := range line {
		if r != '|' && r != '-' && r != ':' && r != ' ' {
			return false
		}
	}
	return true
}

func wireProfileStripCell(s string) string {
	return strings.Trim(strings.TrimSpace(s), "`")
}

// wireProfileExtractTable locates the first line containing every needle
// in needles (a crude but sufficient locator for this single, hand-authored
// doc's small fixed set of tables), requires the following line to be a
// markdown table separator, and returns the header row plus every data row
// until a line that no longer starts with "|".
func wireProfileExtractTable(doc string, needles ...string) (header []string, rows [][]string, err error) {
	lines := strings.Split(doc, "\n")
	headerIdx := -1
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "|") {
			continue
		}
		allPresent := true
		for _, n := range needles {
			if !strings.Contains(l, n) {
				allPresent = false
				break
			}
		}
		if allPresent {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil, nil, fmt.Errorf("wire_profile_contract: %s: no table header line contains all of %q", wireProfileDocRelPath, needles)
	}
	if headerIdx+1 >= len(lines) || !wireProfileIsTableSeparator(lines[headerIdx+1]) {
		return nil, nil, fmt.Errorf("wire_profile_contract: %s: line %d matched %q but the next line is not a table separator", wireProfileDocRelPath, headerIdx+1, needles)
	}
	header = wireProfileSplitTableRow(lines[headerIdx])
	i := headerIdx + 2
	for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
		rows = append(rows, wireProfileSplitTableRow(lines[i]))
		i++
	}
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("wire_profile_contract: %s: table matched by %q has a header and separator but zero data rows", wireProfileDocRelPath, needles)
	}
	return header, rows, nil
}

// wireProfileParseTrackedLineTable parses §1's "Tracked-line authority"
// table into an ordered line->image slice.
func wireProfileParseTrackedLineTable(doc string) ([]string, map[string]string, error) {
	_, rows, err := wireProfileExtractTable(doc, "Tracked image (verbatim from")
	if err != nil {
		return nil, nil, err
	}
	lineToImage := make(map[string]string, len(rows))
	var order []string
	for _, row := range rows {
		if len(row) != 2 {
			return nil, nil, fmt.Errorf("wire_profile_contract: tracked-line table row %v has %d cells, want 2", row, len(row))
		}
		line := wireProfileStripCell(row[0])
		image := wireProfileStripCell(row[1])
		lineToImage[line] = image
		order = append(order, line)
	}
	return order, lineToImage, nil
}

type docProvenanceRow struct {
	ClickHouseRepository string
	ClickHouseTag        string
	ClickHouseCommit     string
	OpenLDAPRepository   string
	OpenLDAPPin          string
	OpenLDAPVersion      string
}

// wireProfileParseProvenanceTable parses §2.1's repository/tag/commit/
// OpenLDAP table into a line-keyed map.
func wireProfileParseProvenanceTable(doc string) (map[string]docProvenanceRow, error) {
	header, rows, err := wireProfileExtractTable(doc, "ClickHouse repository", "OpenLDAP repository")
	if err != nil {
		return nil, err
	}
	if len(header) != 7 {
		return nil, fmt.Errorf("wire_profile_contract: provenance table header %v has %d columns, want 7", header, len(header))
	}
	out := make(map[string]docProvenanceRow, len(rows))
	for _, row := range rows {
		if len(row) != 7 {
			return nil, fmt.Errorf("wire_profile_contract: provenance table row %v has %d cells, want 7", row, len(row))
		}
		line := wireProfileStripCell(row[0])
		out[line] = docProvenanceRow{
			ClickHouseRepository: wireProfileStripCell(row[1]),
			ClickHouseTag:        wireProfileStripCell(row[2]),
			ClickHouseCommit:     wireProfileStripCell(row[3]),
			OpenLDAPRepository:   wireProfileStripCell(row[4]),
			OpenLDAPPin:          wireProfileStripCell(row[5]),
			OpenLDAPVersion:      wireProfileStripCell(row[6]),
		}
	}
	return out, nil
}

// wireProfileBlobColumnRE recognizes a blob-table column header naming the
// tracked line that column's SHAs belong to, e.g. "24.8 blob".
var wireProfileBlobColumnRE = regexp.MustCompile(`^(\d+\.\d+)\s+blob$`)

// wireProfileParseBlobTable parses §2.2's per-file, per-line blob-SHA
// table into file-basename -> line -> sha256.
func wireProfileParseBlobTable(doc string) (map[string]map[string]string, error) {
	header, rows, err := wireProfileExtractTable(doc, "blob")
	if err != nil {
		return nil, err
	}
	lineByColumn := make(map[int]string)
	for i, h := range header {
		if i == 0 {
			continue
		}
		m := wireProfileBlobColumnRE.FindStringSubmatch(h)
		if m == nil {
			return nil, fmt.Errorf("wire_profile_contract: blob table column %d header %q does not match %q", i, h, wireProfileBlobColumnRE.String())
		}
		lineByColumn[i] = m[1]
	}
	if len(lineByColumn) == 0 {
		return nil, fmt.Errorf("wire_profile_contract: blob table header %v named no tracked-line columns", header)
	}
	out := make(map[string]map[string]string)
	for _, row := range rows {
		if len(row) != len(header) {
			return nil, fmt.Errorf("wire_profile_contract: blob table row %v has %d cells, want %d", row, len(row), len(header))
		}
		file := filepath.Base(wireProfileStripCell(row[0]))
		for col, line := range lineByColumn {
			if out[file] == nil {
				out[file] = make(map[string]string)
			}
			out[file][line] = wireProfileStripCell(row[col])
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------
// 30.1 — the static matrix itself
// ---------------------------------------------------------------------

func TestWireProfileContract_StaticSourceProvenanceMatrix(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}

	buildImages, err := wireProfileParseBuildsImages(root)
	if err != nil {
		t.Fatal(err)
	}
	buildsByLine := make(map[string]string, len(buildImages))
	for _, image := range buildImages {
		line, err := wireProfileLineFromImage(image)
		if err != nil {
			t.Fatal(err)
		}
		buildsByLine[line] = image
	}

	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))

	_, docLineToImage, err := wireProfileParseTrackedLineTable(doc)
	if err != nil {
		t.Fatal(err)
	}
	docProvenance, err := wireProfileParseProvenanceTable(doc)
	if err != nil {
		t.Fatal(err)
	}
	docBlobs, err := wireProfileParseBlobTable(doc)
	if err != nil {
		t.Fatal(err)
	}

	fixtureRoot := wireProfileFixtureRoot(root)

	for _, audited := range auditedProvenanceMatrix {
		line := audited.Line

		// vs run-all-builds.sh
		if got, ok := buildsByLine[line]; !ok {
			t.Errorf("wire_profile_contract: %s: BUILDS has no entry for tracked line %s", runAllBuildsRelPath, line)
		} else if got != audited.Image {
			t.Errorf("wire_profile_contract: %s: line %s image %q, want audited %q", runAllBuildsRelPath, line, got, audited.Image)
		}

		// vs the wire doc's §1 tracked-line table
		if got, ok := docLineToImage[line]; !ok {
			t.Errorf("wire_profile_contract: %s: §1 table has no row for line %s", wireProfileDocRelPath, line)
		} else if got != audited.Image {
			t.Errorf("wire_profile_contract: %s: §1 table line %s image %q, want audited %q", wireProfileDocRelPath, line, got, audited.Image)
		}

		// vs the wire doc's §2.1 provenance table
		if got, ok := docProvenance[line]; !ok {
			t.Errorf("wire_profile_contract: %s: §2.1 table has no row for line %s", wireProfileDocRelPath, line)
		} else {
			want := docProvenanceRow{
				ClickHouseRepository: audited.ClickHouseRepository,
				ClickHouseTag:        audited.ClickHouseTag,
				ClickHouseCommit:     audited.ClickHouseCommit,
				OpenLDAPRepository:   audited.OpenLDAPRepository,
				OpenLDAPPin:          audited.OpenLDAPPin,
				OpenLDAPVersion:      audited.OpenLDAPVersion,
			}
			if got != want {
				t.Errorf("wire_profile_contract: %s: §2.1 table line %s = %+v, want audited %+v", wireProfileDocRelPath, line, got, want)
			}
		}

		// vs the wire doc's §2.2 blob table
		for file, wantSHA := range audited.Blobs {
			gotByLine, ok := docBlobs[file]
			if !ok {
				t.Errorf("wire_profile_contract: %s: §2.2 table has no row for file %s", wireProfileDocRelPath, file)
				continue
			}
			if got, ok := gotByLine[line]; !ok {
				t.Errorf("wire_profile_contract: %s: §2.2 table file %s has no column for line %s", wireProfileDocRelPath, file, line)
			} else if got != wantSHA {
				t.Errorf("wire_profile_contract: %s: §2.2 table file %s line %s blob %s, want audited %s", wireProfileDocRelPath, file, line, got, wantSHA)
			}
		}

		// vs the committed profile.json
		profilePath := wirefixture.ProfilePath(wirefixture.LineDir(fixtureRoot, line))
		profile, err := wirefixture.ReadProfile(profilePath)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", profilePath, err)
			continue
		}
		if profile.Line != line {
			t.Errorf("wire_profile_contract: %s: line field %q, want %q", profilePath, profile.Line, line)
		}
		if profile.TrackedImage != audited.Image {
			t.Errorf("wire_profile_contract: %s: tracked_image %q, want audited %q", profilePath, profile.TrackedImage, audited.Image)
		}
		if profile.ClickHouseRepository != audited.ClickHouseRepository {
			t.Errorf("wire_profile_contract: %s: clickhouse_repository %q, want %q", profilePath, profile.ClickHouseRepository, audited.ClickHouseRepository)
		}
		if profile.ClickHouseTag != audited.ClickHouseTag {
			t.Errorf("wire_profile_contract: %s: clickhouse_tag %q, want %q", profilePath, profile.ClickHouseTag, audited.ClickHouseTag)
		}
		if profile.ClickHouseCommit != audited.ClickHouseCommit {
			t.Errorf("wire_profile_contract: %s: clickhouse_commit %q, want %q", profilePath, profile.ClickHouseCommit, audited.ClickHouseCommit)
		}
		if profile.OpenLDAPRepository != audited.OpenLDAPRepository {
			t.Errorf("wire_profile_contract: %s: openldap_repository %q, want %q", profilePath, profile.OpenLDAPRepository, audited.OpenLDAPRepository)
		}
		if profile.OpenLDAPPin != audited.OpenLDAPPin {
			t.Errorf("wire_profile_contract: %s: openldap_pin %q, want %q", profilePath, profile.OpenLDAPPin, audited.OpenLDAPPin)
		}
		if profile.OpenLDAPVersion != audited.OpenLDAPVersion {
			t.Errorf("wire_profile_contract: %s: openldap_version %q, want %q", profilePath, profile.OpenLDAPVersion, audited.OpenLDAPVersion)
		}
		for blobKey, wantSHA := range audited.Blobs {
			if got := profile.ClickHouseSourceBlobs[blobKey]; got != wantSHA {
				t.Errorf("wire_profile_contract: %s: clickhouse_source_blobs[%s] = %q, want audited %q", profilePath, blobKey, got, wantSHA)
			}
		}
		if len(profile.ClickHouseSourceBlobs) != len(audited.Blobs) {
			t.Errorf("wire_profile_contract: %s: clickhouse_source_blobs has %d entries, want exactly %d", profilePath, len(profile.ClickHouseSourceBlobs), len(audited.Blobs))
		}
	}
}

// ---------------------------------------------------------------------
// 30.2 — four-way tracked-line equality
// ---------------------------------------------------------------------

func TestWireProfileContract_TrackedLineFourWayEquality(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}

	buildImages, err := wireProfileParseBuildsImages(root)
	if err != nil {
		t.Fatal(err)
	}
	buildsLines := make([]string, 0, len(buildImages))
	for _, image := range buildImages {
		line, err := wireProfileLineFromImage(image)
		if err != nil {
			t.Fatal(err)
		}
		buildsLines = append(buildsLines, line)
	}
	sort.Strings(buildsLines)

	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	docLines, _, err := wireProfileParseTrackedLineTable(doc)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(docLines)

	fixtureRoot := wireProfileFixtureRoot(root)
	fixtureLines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("wire_profile_contract: validate fixture root %s: %v", fixtureRoot, err)
	}

	profileLines := make([]string, 0, len(fixtureLines))
	for _, line := range fixtureLines {
		profilePath := wirefixture.ProfilePath(wirefixture.LineDir(fixtureRoot, line))
		profile, err := wirefixture.ReadProfile(profilePath)
		if err != nil {
			t.Fatalf("wire_profile_contract: read %s: %v", profilePath, err)
		}
		profileLines = append(profileLines, profile.Line)
	}
	sort.Strings(profileLines)

	sources := map[string][]string{
		"run-all-builds.sh BUILDS":            buildsLines,
		"wire doc §1 tracked-line table":      docLines,
		"clickhouse-wire fixture directories": fixtureLines,
		"profile.json line fields":            profileLines,
	}
	auditedLines := wireProfileAuditedLines()
	for name, got := range sources {
		if !stringSlicesEqual(got, auditedLines) {
			t.Errorf("wire_profile_contract: tracked-line set from %s = %v, want %v (agreement required across BUILDS, doc, fixture directories, and profile metadata)", name, got, auditedLines)
		}
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------
// 30.3 — config contract
// ---------------------------------------------------------------------

func wireProfileExtractXMLElement(xmlText, tag string) (string, error) {
	open := "<" + tag + ">"
	close_ := "</" + tag + ">"
	openCount := strings.Count(xmlText, open)
	closeCount := strings.Count(xmlText, close_)
	if openCount != 1 || closeCount != 1 {
		return "", fmt.Errorf("wire_profile_contract: %s: expected exactly one <%s>...</%s> element, found open=%d close=%d", clickhouseLDAPXMLRelPath, tag, tag, openCount, closeCount)
	}
	start := strings.Index(xmlText, open) + len(open)
	end := strings.Index(xmlText, close_)
	if end < start {
		return "", fmt.Errorf("wire_profile_contract: %s: <%s> closing tag precedes opening tag", clickhouseLDAPXMLRelPath, tag)
	}
	return strings.TrimSpace(xmlText[start:end]), nil
}

// wireProfileExtractClickHouseElement returns just the executable
// <clickhouse>...</clickhouse> element of xmlText, excluding the file's
// leading explanatory XML comment (which itself prose-mentions several of
// these same tag names, e.g. "<search_limit>") — the same scoping
// wirefixture.ClickHouseConfigElementSHA256 applies for drift hashing
// (plan §3.1), so semantic element lookups below must use this same scope
// or a tag mentioned only in the comment would be miscounted as
// duplicated.
func wireProfileExtractClickHouseElement(xmlText string) (string, error) {
	const open, close_ = "<clickhouse>", "</clickhouse>"
	start := strings.Index(xmlText, open)
	end := strings.Index(xmlText, close_)
	if start < 0 || end < 0 || end < start {
		return "", fmt.Errorf("wire_profile_contract: %s: no well-formed <clickhouse>...</clickhouse> element found", clickhouseLDAPXMLRelPath)
	}
	return xmlText[start : end+len(close_)], nil
}

func TestWireProfileContract_ConfigContract(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}

	xmlBytes := wireProfileReadFile(t, root, clickhouseLDAPXMLRelPath)
	fullText := string(xmlBytes)
	xmlText, err := wireProfileExtractClickHouseElement(fullText)
	if err != nil {
		t.Fatalf("wire_profile_contract: %v", err)
	}

	wantHash, err := wirefixture.ClickHouseConfigElementSHA256(xmlBytes)
	if err != nil {
		t.Fatalf("wire_profile_contract: compute %s config element hash: %v", clickhouseLDAPXMLRelPath, err)
	}

	fixtureRoot := wireProfileFixtureRoot(root)
	for _, audited := range auditedProvenanceMatrix {
		profilePath := wirefixture.ProfilePath(wirefixture.LineDir(fixtureRoot, audited.Line))
		profile, err := wirefixture.ReadProfile(profilePath)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", profilePath, err)
			continue
		}
		if profile.ClickHouseConfigElementSHA256 != wantHash {
			t.Errorf("wire_profile_contract: %s: clickhouse_config_element_sha256 %q, want freshly computed %q from %s", profilePath, profile.ClickHouseConfigElementSHA256, wantHash, clickhouseLDAPXMLRelPath)
		}
		if profile.CanonicalConfigPath != clickhouseLDAPXMLRelPath {
			t.Errorf("wire_profile_contract: %s: canonical_config_path %q, want %q", profilePath, profile.CanonicalConfigPath, clickhouseLDAPXMLRelPath)
		}
	}

	type semanticCheck struct {
		tag  string
		want string
	}
	checks := []semanticCheck{
		{"bind_dn", "uid={user_name},ou=users,dc=altinity,dc=internal"},
		{"search_limit", "256"},
		{"base_dn", "ou=groups,dc=altinity,dc=internal"},
		{"scope", "subtree"},
		{"attribute", "cn"},
	}
	for _, c := range checks {
		got, err := wireProfileExtractXMLElement(xmlText, c.tag)
		if err != nil {
			t.Errorf("wire_profile_contract: %v", err)
			continue
		}
		if got != c.want {
			t.Errorf("wire_profile_contract: %s: <%s> = %q, want %q", clickhouseLDAPXMLRelPath, c.tag, got, c.want)
		}
	}

	filterRaw, err := wireProfileExtractXMLElement(xmlText, "search_filter")
	if err != nil {
		t.Errorf("wire_profile_contract: %v", err)
	} else {
		filter := strings.ReplaceAll(filterRaw, "&amp;", "&")
		const wantFilter = "(&(objectClass=groupOfNames)(member={bind_dn}))"
		if filter != wantFilter {
			t.Errorf("wire_profile_contract: %s: <search_filter> (unescaped) = %q, want %q", clickhouseLDAPXMLRelPath, filter, wantFilter)
		}
	}
}

// ---------------------------------------------------------------------
// 30.4 — fixture inventory
// ---------------------------------------------------------------------

// wireProfileExpectedOperations names, in order, the exact PDU.Operation
// sequence a session of the given Mode must contain (plan §8.1/§8.5/§8.6's
// success/timeout-abandon shapes, and §29's constructed boundary bundle).
var wireProfileExpectedOperations = map[string][]string{
	"success":         {wirefixture.OperationBindRequest, wirefixture.OperationSearchRequest, wirefixture.OperationUnbindRequest},
	"timeout-abandon": {wirefixture.OperationBindRequest, wirefixture.OperationSearchRequest, wirefixture.OperationAbandonRequest, wirefixture.OperationUnbindRequest},
	wirefixture.ConstructedMessageIDBoundaryMode: {wirefixture.OperationBindRequest, wirefixture.OperationBindRequest},
}

type wireProfileSessionLocation struct {
	Category string // tracked line, or "constructed"
	Name     string // session directory name
	Dir      string // absolute path
}

func wireProfileDiscoverSessions(fixtureRoot string, lines []string) ([]wireProfileSessionLocation, error) {
	var out []wireProfileSessionLocation
	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		entries, err := os.ReadDir(lineDir)
		if err != nil {
			return nil, fmt.Errorf("wire_profile_contract: read %s: %w", lineDir, err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			out = append(out, wireProfileSessionLocation{Category: line, Name: e.Name(), Dir: filepath.Join(lineDir, e.Name())})
		}
	}
	constructedDir := wirefixture.ConstructedDir(fixtureRoot)
	if info, statErr := os.Stat(constructedDir); statErr == nil && info.IsDir() {
		entries, err := os.ReadDir(constructedDir)
		if err != nil {
			return nil, fmt.Errorf("wire_profile_contract: read %s: %w", constructedDir, err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			out = append(out, wireProfileSessionLocation{Category: "constructed", Name: e.Name(), Dir: filepath.Join(constructedDir, e.Name())})
		}
	}
	return out, nil
}

func TestWireProfileContract_FixtureInventory(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	fixtureRoot := wireProfileFixtureRoot(root)
	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("wire_profile_contract: validate fixture root %s: %v", fixtureRoot, err)
	}

	// profile.json's session_paths must equal the real session directories.
	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		profilePath := wirefixture.ProfilePath(lineDir)
		profile, err := wirefixture.ReadProfile(profilePath)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", profilePath, err)
			continue
		}
		entries, err := os.ReadDir(lineDir)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", lineDir, err)
			continue
		}
		var realDirs []string
		for _, e := range entries {
			if e.IsDir() {
				realDirs = append(realDirs, e.Name())
			}
		}
		sort.Strings(realDirs)
		wantSessionPaths := append([]string(nil), profile.SessionPaths...)
		sort.Strings(wantSessionPaths)
		if !stringSlicesEqual(realDirs, wantSessionPaths) {
			t.Errorf("wire_profile_contract: %s: session_paths %v does not match real session directories %v", profilePath, profile.SessionPaths, realDirs)
		}
	}

	sessions, err := wireProfileDiscoverSessions(fixtureRoot, lines)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) == 0 {
		t.Fatal("wire_profile_contract: discovered zero session directories under the fixture root")
	}

	for _, loc := range sessions {
		sessionPath := wirefixture.SessionMetadataPath(loc.Dir)
		session, err := wirefixture.ReadSession(sessionPath)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", sessionPath, err)
			continue
		}

		entries, err := os.ReadDir(loc.Dir)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", loc.Dir, err)
			continue
		}
		berOnDisk := make(map[string]bool)
		for _, e := range entries {
			if e.IsDir() {
				t.Errorf("wire_profile_contract: %s: unexpected subdirectory %q inside a session directory", loc.Dir, e.Name())
				continue
			}
			name := e.Name()
			switch {
			case name == wirefixture.SessionFileName:
				// expected
			case strings.HasSuffix(name, ".ber"):
				berOnDisk[name] = true
			default:
				t.Errorf("wire_profile_contract: %s: unexpected file %q (want only %s and *.ber)", loc.Dir, name, wirefixture.SessionFileName)
			}
		}

		// Sequence numbers: unique, contiguous, 1..len(PDUs).
		seen := make(map[int]bool, len(session.PDUs))
		referenced := make(map[string]bool, len(session.PDUs))
		for _, pdu := range session.PDUs {
			if seen[pdu.Sequence] {
				t.Errorf("wire_profile_contract: %s: duplicate PDU sequence %d", sessionPath, pdu.Sequence)
			}
			seen[pdu.Sequence] = true
			referenced[pdu.Filename] = true

			wantPrefix := fmt.Sprintf("%03d-", pdu.Sequence)
			if !strings.HasPrefix(pdu.Filename, wantPrefix) {
				t.Errorf("wire_profile_contract: %s: PDU sequence %d filename %q does not start with %q", sessionPath, pdu.Sequence, pdu.Filename, wantPrefix)
			}

			berPath := filepath.Join(loc.Dir, pdu.Filename)
			data, err := os.ReadFile(berPath)
			if err != nil {
				t.Errorf("wire_profile_contract: %s: PDU %q metadata references missing file: %v", sessionPath, pdu.Filename, err)
				continue
			}
			sum := sha256.Sum256(data)
			gotSHA := hex.EncodeToString(sum[:])
			if gotSHA != pdu.SanitizedSHA256 {
				t.Errorf("wire_profile_contract: %s: PDU %q sanitized_sha256 %q does not match file content SHA-256 %q", sessionPath, pdu.Filename, pdu.SanitizedSHA256, gotSHA)
			}
		}
		for i := 1; i <= len(session.PDUs); i++ {
			if !seen[i] {
				t.Errorf("wire_profile_contract: %s: PDU sequence numbers are not contiguous from 1 — missing %d", sessionPath, i)
			}
		}

		// No orphan .ber files: every file on disk must be referenced.
		for name := range berOnDisk {
			if !referenced[name] {
				t.Errorf("wire_profile_contract: %s: orphan .ber file %q not referenced by any PDU in %s", loc.Dir, name, wirefixture.SessionFileName)
			}
		}
		// Every referenced filename must exist on disk (redundant with the
		// per-PDU os.ReadFile above, kept as an explicit, separately-named
		// invariant per plan §30.4's "every metadata BER path exists").
		for name := range referenced {
			if !berOnDisk[name] {
				t.Errorf("wire_profile_contract: %s: %s references %q, which does not exist on disk", sessionPath, wirefixture.SessionFileName, name)
			}
		}

		// Provenance-class / connection-count consistency.
		if loc.Category == wirefixture.ConstructedDirName {
			if session.ProvenanceClass != wirefixture.ProvenanceConstructed {
				t.Errorf("wire_profile_contract: %s: provenance_class %q, want %q under constructed/", sessionPath, session.ProvenanceClass, wirefixture.ProvenanceConstructed)
			}
			if session.ConnectionCount != 0 {
				t.Errorf("wire_profile_contract: %s: connection_count %d, want 0 for a constructed session", sessionPath, session.ConnectionCount)
			}
		} else {
			if session.ProvenanceClass != wirefixture.ProvenanceCapturedRedacted {
				t.Errorf("wire_profile_contract: %s: provenance_class %q, want %q under a tracked-line directory", sessionPath, session.ProvenanceClass, wirefixture.ProvenanceCapturedRedacted)
			}
			if session.Line != loc.Category {
				t.Errorf("wire_profile_contract: %s: line %q, want %q (its own directory)", sessionPath, session.Line, loc.Category)
			}
			if !stringSlicesEqual(session.Applicability, []string{loc.Category}) {
				t.Errorf("wire_profile_contract: %s: applicability %v, want [%q]", sessionPath, session.Applicability, loc.Category)
			}
			if session.ConnectionCount != 1 {
				t.Errorf("wire_profile_contract: %s: connection_count %d, want exactly 1 for a captured session (plan §21)", sessionPath, session.ConnectionCount)
			}
			// A captured-redacted session's token claim recipe must be the
			// one fixed, non-secret recipe every capture-ldap-wire.sh run
			// passes to `sanitize --token-claim-recipe` (plan §27/§28) —
			// never empty, and never a different ad hoc string.
			if session.TokenClaimRecipe != wirefixture.FixedTokenClaimRecipe {
				t.Errorf("wire_profile_contract: %s: token_claim_recipe %q, want %q", sessionPath, session.TokenClaimRecipe, wirefixture.FixedTokenClaimRecipe)
			}
		}

		// Expected operation coverage per mode.
		wantOps, ok := wireProfileExpectedOperations[session.Mode]
		if !ok {
			t.Errorf("wire_profile_contract: %s: mode %q has no registered expected-operation sequence in this contract test", sessionPath, session.Mode)
			continue
		}
		gotOps := make([]string, len(session.PDUs))
		for i, pdu := range session.PDUs {
			gotOps[i] = pdu.Operation
		}
		if !stringSlicesEqual(gotOps, wantOps) {
			t.Errorf("wire_profile_contract: %s: operation sequence %v, want %v for mode %q", sessionPath, gotOps, wantOps, session.Mode)
		}
		if session.Mode == "timeout-abandon" {
			for _, pdu := range session.PDUs {
				if pdu.Operation != wirefixture.OperationAbandonRequest {
					continue
				}
				if pdu.AbandonTarget == nil {
					t.Errorf("wire_profile_contract: %s: abandonRequest PDU has nil abandon_target", sessionPath)
				} else if *pdu.AbandonTarget != 2 {
					t.Errorf("wire_profile_contract: %s: abandon_target %d, want 2 (the Search's MessageID)", sessionPath, *pdu.AbandonTarget)
				}
			}
		}

		// expected_semantics (plan §27/§28's "expected operation semantics
		// needed by Phase 2") must never be "" for any committed PDU.
		// Captured-redacted sessions must match wirefixture's fixed
		// per-operation table exactly (the same table the sanitizer writes
		// from); constructed fixtures author their own, more specific text
		// describing the exact BER boundary they exist to prove, so they
		// are only checked for non-emptiness here.
		for _, pdu := range session.PDUs {
			if pdu.ExpectedSemantics == "" {
				t.Errorf("wire_profile_contract: %s: PDU %s (%s) has empty expected_semantics", sessionPath, pdu.Filename, pdu.Operation)
				continue
			}
			if loc.Category == wirefixture.ConstructedDirName {
				continue
			}
			want, ok := wirefixture.ExpectedSemanticsForOperation(pdu.Operation)
			if !ok {
				t.Errorf("wire_profile_contract: %s: PDU %s: operation %q has no registered expected-semantics table entry", sessionPath, pdu.Filename, pdu.Operation)
				continue
			}
			if pdu.ExpectedSemantics != want {
				t.Errorf("wire_profile_contract: %s: PDU %s (%s) expected_semantics %q, want %q", sessionPath, pdu.Filename, pdu.Operation, pdu.ExpectedSemantics, want)
			}
		}
	}
}

// wireProfileRoleClaimVarRE finds the synthetic IdP's local variable that
// holds the repeated-`role=`-query-parameter role list (cmd/synthetic-idp
// main.go's `roles := q["role"]`) — whatever that variable is actually
// named, so a rename doesn't silently defeat the claim-key check below.
var wireProfileRoleClaimVarRE = regexp.MustCompile(`(\w+)\s*:=\s*q\["role"\]`)

// wireProfileClaimAssignRE, built per-role-variable-name below, finds the
// map-index assignment that stamps that role list into the minted JWT's
// claim set (`claims["roles"] = roles`) and captures the literal claim key
// used — whatever it actually is.
func wireProfileClaimAssignRE(roleVar string) *regexp.Regexp {
	return regexp.MustCompile(`claims\["(\w+)"\]\s*=\s*` + regexp.QuoteMeta(roleVar) + `\b`)
}

// TestWireProfileContract_TokenClaimRecipeMatchesSyntheticIdP independently
// verifies wirefixture.FixedTokenClaimRecipe names the actual JWT claim key
// the synthetic IdP mints its role list under, by reading and pattern-
// matching cmd/synthetic-idp/main.go's own source — not by comparing the
// constant against itself. TestWireProfileContract_FixtureInventory above
// only checks that every committed session.json equals
// wirefixture.FixedTokenClaimRecipe verbatim; that alone can never catch
// the constant itself naming the wrong claim (e.g. "groups" when the IdP
// actually emits "roles"), because both sides of that comparison trace
// back to the same Go literal. This test instead derives the expected
// claim key from the synthetic IdP's implementation directly, so a future
// rename of that claim key (without updating FixedTokenClaimRecipe to
// match) fails here even though FixtureInventory's self-comparison would
// stay green.
func TestWireProfileContract_TokenClaimRecipeMatchesSyntheticIdP(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: moduleRoot: %v", err)
	}
	path := filepath.Join(root, "cmd", "synthetic-idp", "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("wire_profile_contract: reading %s: %v", path, err)
	}

	roleVarMatch := wireProfileRoleClaimVarRE.FindSubmatch(src)
	if roleVarMatch == nil {
		t.Fatalf("wire_profile_contract: %s: could not find `<var> := q[\"role\"]` — the synthetic IdP's role-claim wiring changed shape; update this test's pattern alongside it", path)
	}
	roleVar := string(roleVarMatch[1])

	claimMatch := wireProfileClaimAssignRE(roleVar).FindSubmatch(src)
	if claimMatch == nil {
		t.Fatalf(`wire_profile_contract: %s: could not find claims["..."] = %s — the synthetic IdP's role-claim key assignment changed shape; update this test's pattern alongside it`, path, roleVar)
	}
	actualClaimKey := string(claimMatch[1])

	wantSubstr := actualClaimKey + "="
	if !strings.Contains(wirefixture.FixedTokenClaimRecipe, wantSubstr) {
		t.Errorf("wire_profile_contract: synthetic IdP (%s) mints its role list under JWT claim %q, but wirefixture.FixedTokenClaimRecipe = %q does not contain %q — fixture provenance names the wrong claim", path, actualClaimKey, wirefixture.FixedTokenClaimRecipe, wantSubstr)
	}
}

// ---------------------------------------------------------------------
// 30.5 / §11 — .gitattributes binary rule
// ---------------------------------------------------------------------

func TestWireProfileContract_GitAttributesDeclaresBerBinary(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	data := wireProfileReadFile(t, root, gitAttributesRelPath)
	const want = "*.ber binary"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == want {
			return
		}
	}
	t.Fatalf("wire_profile_contract: %s does not contain a line %q (plan §11/§30.5 — .ber files must survive checkout as binary)", gitAttributesRelPath, want)
}

// ---------------------------------------------------------------------
// 30.6 / 30.7 — JWT-shape scanner
// ---------------------------------------------------------------------

// wireProfileJWTRunRE matches a maximal run of base64url-alphabet
// characters and '.' separators; individual dot-separated segments are
// then validated by findJWTShapedCandidates.
var wireProfileJWTRunRE = regexp.MustCompile(`[A-Za-z0-9_.-]+`)

// wireProfileLooksLikeJWTHeader reports whether seg is a base64url string
// starting with "eyJ" that decodes to a JSON object (plan §30.6's exact
// candidate rule for the first of three segments).
func wireProfileLooksLikeJWTHeader(seg string) bool {
	if !strings.HasPrefix(seg, "eyJ") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		padded := seg
		if m := len(padded) % 4; m != 0 {
			padded += strings.Repeat("=", 4-m)
		}
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return false
		}
	}
	var obj map[string]any
	return json.Unmarshal(decoded, &obj) == nil
}

// wireProfileFindJWTShapedCandidates scans data for substrings shaped like
// a compact JWT: exactly three non-empty base64url-like segments, the
// first starting "eyJ" and Base64URL-decoding to a JSON object (plan
// §30.6). It operates on raw bytes so it is safe to run over arbitrary
// (including non-UTF-8) .ber content.
func wireProfileFindJWTShapedCandidates(data []byte) []string {
	var found []string
	for _, run := range wireProfileJWTRunRE.FindAll(data, -1) {
		parts := strings.Split(string(run), ".")
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			continue
		}
		if !wireProfileLooksLikeJWTHeader(parts[0]) {
			continue
		}
		found = append(found, string(run))
	}
	return found
}

func TestWireProfileContract_NoJWTShapedTokensInCorpusOrDoc(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}

	var scanTargets []string
	fixtureRoot := wireProfileFixtureRoot(root)
	walkErr := filepath.WalkDir(fixtureRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		scanTargets = append(scanTargets, path)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("wire_profile_contract: walk %s: %v", fixtureRoot, walkErr)
	}
	scanTargets = append(scanTargets, filepath.Join(root, filepath.FromSlash(wireProfileDocRelPath)))

	if len(scanTargets) == 0 {
		t.Fatal("wire_profile_contract: zero files discovered to JWT-scan — fixture root walk is broken")
	}

	for _, path := range scanTargets {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("wire_profile_contract: read %s: %v", path, err)
			continue
		}
		if candidates := wireProfileFindJWTShapedCandidates(data); len(candidates) > 0 {
			rel, _ := filepath.Rel(root, path)
			offset := bytes.Index(data, []byte(candidates[0]))
			t.Errorf("wire_profile_contract: %s contains %d JWT-shaped candidate substring(s), first at byte offset %d (length %d bytes) (no committed evidence file may carry a real or JWT-shaped credential; candidate bytes withheld from this public log — inspect the file at that offset to act)", rel, len(candidates), offset, len(candidates[0]))
		}
	}
}

func TestWireProfileContract_JWTScannerDetectsBoundaryBearerToken(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	const redactionBoundaryTestRelPath = "internal/ldap/redaction_boundary_test.go"
	value, err := wireProfileExtractStringConst(filepath.Join(root, filepath.FromSlash(redactionBoundaryTestRelPath)), "ldapBoundaryBearer")
	if err != nil {
		t.Fatalf("wire_profile_contract: %v", err)
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(value, bearerPrefix) {
		t.Fatalf("wire_profile_contract: %s's ldapBoundaryBearer (%d bytes) no longer starts with %q — update this test's expectations alongside that fixture", redactionBoundaryTestRelPath, len(value), bearerPrefix)
	}
	wantToken := strings.TrimPrefix(value, bearerPrefix)

	candidates := wireProfileFindJWTShapedCandidates([]byte(value))
	if len(candidates) != 1 {
		t.Fatalf("wire_profile_contract: scanning ldapBoundaryBearer (%d bytes) found %d JWT-shaped candidate(s), want exactly 1 (candidate bytes withheld from this public log)", len(value), len(candidates))
	}
	if candidates[0] != wantToken {
		t.Fatalf("wire_profile_contract: scanner detected a candidate of length %d, want it to detect exactly the token portion (length %d) (candidate bytes withheld from this public log)", len(candidates[0]), len(wantToken))
	}
}

// wireProfileExtractStringConst AST-parses the Go source file at path and
// returns the string value of the named untyped string constant declared
// in a top-level const block.
func wireProfileExtractStringConst(path, name string) (string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name {
					continue
				}
				if i >= len(vs.Values) {
					return "", fmt.Errorf("%s: const %s has no value expression", path, name)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", fmt.Errorf("%s: const %s is not a plain string literal", path, name)
				}
				return strconv.Unquote(lit.Value)
			}
		}
	}
	return "", fmt.Errorf("%s: no top-level const named %s found", path, name)
}

// ---------------------------------------------------------------------
// 30.8 — engineering-doc boundary
// ---------------------------------------------------------------------

var wireProfileDecisionMarkerRE = regexp.MustCompile(`<!--\s*ldap-primitive-decision:\s*(cryptobyte|local-ber-cursor)\s*-->`)

// wireProfileForbiddenConfigFenceRE matches a fenced-code-block opening
// line tagged xml/yaml/yml (case-insensitive) — the wire doc is
// engineering evidence, not a second configuration authority (plan §33/
// §34: "does not restate configuration"), so it must never carry one.
var wireProfileForbiddenConfigFenceRE = regexp.MustCompile("(?m)^\\s*```(?i:xml|yaml|yml)\\b")

func TestWireProfileContract_EngineeringDocBoundary(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))

	rawCount := strings.Count(doc, "ldap-primitive-decision")
	matches := wireProfileDecisionMarkerRE.FindAllStringSubmatch(doc, -1)
	if rawCount != 1 || len(matches) != 1 {
		t.Fatalf("wire_profile_contract: %s: found %d occurrence(s) of \"ldap-primitive-decision\" and %d well-formed marker(s), want exactly one well-formed <!-- ldap-primitive-decision: cryptobyte|local-ber-cursor --> marker and no other occurrence of that text", wireProfileDocRelPath, rawCount, len(matches))
	}

	if fenceMatches := wireProfileForbiddenConfigFenceRE.FindAllString(doc, -1); len(fenceMatches) != 0 {
		t.Fatalf("wire_profile_contract: %s: contains %d xml/yaml/yml fenced code block(s) — this doc must cite configuration by path, never duplicate it as a fence (plan §33/§34)", wireProfileDocRelPath, len(fenceMatches))
	}
}

// ---------------------------------------------------------------------
// LDAP option sentinel
// ---------------------------------------------------------------------

func TestWireProfileContract_LDAPOptionSentinelMatchesAuditedSet(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))

	const startNeedle = "are exactly:"
	const endNeedle = "Nothing else appears"
	start := strings.Index(doc, startNeedle)
	if start < 0 {
		t.Fatalf("wire_profile_contract: %s: sentinel start marker %q not found", wireProfileDocRelPath, startNeedle)
	}
	rest := doc[start+len(startNeedle):]
	end := strings.Index(rest, endNeedle)
	if end < 0 {
		t.Fatalf("wire_profile_contract: %s: sentinel end marker %q not found after %q", wireProfileDocRelPath, endNeedle, startNeedle)
	}
	section := rest[:end]

	optionRE := regexp.MustCompile("`(LDAP_OPT_[A-Z_]+)`")
	found := optionRE.FindAllStringSubmatch(section, -1)
	if len(found) == 0 {
		t.Fatalf("wire_profile_contract: %s: sentinel section between %q and %q named zero LDAP_OPT_* options", wireProfileDocRelPath, startNeedle, endNeedle)
	}
	got := make([]string, 0, len(found))
	for _, m := range found {
		got = append(got, m[1])
	}
	sort.Strings(got)

	want := append([]string(nil), auditedLDAPOptions...)
	sort.Strings(want)

	if !stringSlicesEqual(got, want) {
		t.Fatalf("wire_profile_contract: %s: sentinel section names options %v, want exactly the audited set %v", wireProfileDocRelPath, got, want)
	}
}

// ---------------------------------------------------------------------
// Search-profile fixed-field sentinel (derefAliases / Controls)
// ---------------------------------------------------------------------
//
// TestWireProfileContract_LDAPOptionSentinelMatchesAuditedSet's pattern —
// scan a doc section against an independently-authored Go set — only ever
// mechanically compares two things a human wrote; it cannot notice the
// doc's prose drifting away from what the committed wire bytes actually
// contain. That gap is exactly what a review found for two Search-profile
// facts §6/§8.2 assert but nothing here previously checked against a raw
// fixture byte: derefAliases==neverDerefAliases(0), and that no Controls
// sequence follows any LDAPMessage's protocolOp. Deleting those doc
// statements alone previously left this whole package's suite green.
//
// This sentinel closes that gap with two independent legs, both required:
//
//  1. Doc side: the specific claims must still be present, in the same
//     table/prose locations §6/§8.2 use today.
//  2. Fixture side: every committed searchRequest PDU (and every PDU's
//     LDAPMessage generally, for Controls) is independently decoded with
//     the vendored goldap BER decoder — a second, structurally distinct
//     implementation from internal/ldap's cryptobyte characterizer, which
//     stays the SOLE owner of the primitive-layer cryptobyte-vs-
//     local-ber-cursor decision (plan §33) — and the actual decoded field
//     values are asserted directly, not merely compared to the doc's own
//     text.
//
// Removing either leg's claim (the doc prose, or the byte-level truth it
// describes) now fails this test, instead of both drifting together
// silently.

// searchProfileDocDerefAliasesLabel is the §6 source-of-value table's row
// label for derefAliases, stripped of surrounding backticks the same way
// wireProfileStripCell strips table cells.
const searchProfileDocDerefAliasesLabel = "derefAliases"

// searchProfileControlsAbsentNeedle is §8.2's prose claim that Controls is
// absent (not merely empty) from every captured PDU.
const searchProfileControlsAbsentNeedle = "`controls` is absent (not merely empty)"

func TestWireProfileContract_SearchProfileFixedFieldsSentinel(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))

	// --- doc side: leg 1 ---

	_, rows, err := wireProfileExtractTable(doc, "Value in this fixture")
	if err != nil {
		t.Fatalf("wire_profile_contract: %s: %v", wireProfileDocRelPath, err)
	}
	var derefAliasesRow []string
	for _, row := range rows {
		if len(row) > 0 && wireProfileStripCell(row[0]) == searchProfileDocDerefAliasesLabel {
			derefAliasesRow = row
			break
		}
	}
	if derefAliasesRow == nil {
		t.Errorf("wire_profile_contract: %s: source-of-value table has no %q row", wireProfileDocRelPath, searchProfileDocDerefAliasesLabel)
	} else {
		value := derefAliasesRow[1]
		if !strings.Contains(value, "neverDerefAliases") || !strings.Contains(value, "(0)") {
			t.Errorf("wire_profile_contract: %s: %q row's value column is %q, want it to state neverDerefAliases and (0)", wireProfileDocRelPath, searchProfileDocDerefAliasesLabel, value)
		}
	}

	if !strings.Contains(doc, searchProfileControlsAbsentNeedle) {
		t.Errorf("wire_profile_contract: %s: missing required Controls-absent claim (expected substring %q)", wireProfileDocRelPath, searchProfileControlsAbsentNeedle)
	}

	// --- fixture side: leg 2 ---

	fixtureRoot := wireProfileFixtureRoot(root)
	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("wire_profile_contract: validate fixture root %s: %v", fixtureRoot, err)
	}
	if len(lines) == 0 {
		t.Fatalf("wire_profile_contract: fixture root %s: no tracked-line directories found", fixtureRoot)
	}

	sawSearchRequest := false
	checkSession := func(label, sessDir string) {
		sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
		if err != nil {
			t.Fatalf("wire_profile_contract: read session.json for %s: %v", label, err)
		}
		for _, pdu := range sess.PDUs {
			path := filepath.Join(sessDir, pdu.Filename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("wire_profile_contract: read %s: %v", path, err)
			}
			assertSearchProfileFixedFields(t, path, pdu.Operation, raw, &sawSearchRequest)
		}
	}

	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		profile, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
		if err != nil {
			t.Fatalf("wire_profile_contract: read profile.json for line %s: %v", line, err)
		}
		for _, sp := range profile.SessionPaths {
			checkSession(fmt.Sprintf("%s/%s", line, sp), wirefixture.SessionDir(lineDir, sp))
		}
	}
	constructedDir := wirefixture.ConstructedDir(fixtureRoot)
	entries, err := os.ReadDir(constructedDir)
	if err != nil {
		t.Fatalf("wire_profile_contract: read constructed fixture dir %s: %v", constructedDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		checkSession("constructed/"+e.Name(), filepath.Join(constructedDir, e.Name()))
	}

	if !sawSearchRequest {
		t.Fatalf("wire_profile_contract: no committed searchRequest fixture found under %s — this sentinel's derefAliases leg has nothing to check", fixtureRoot)
	}
}

// assertSearchProfileFixedFields independently decodes raw as a complete
// LDAPMessage using the vendored goldap BER decoder (third_party/goldap,
// already this repo's production LDAP decoder, consumed by internal/ldap's
// non-test files — not a decoder invented for this test) and asserts:
//
//   - every PDU's LDAPMessage carries no Controls sequence (plan §8.2:
//     absent, not merely empty), regardless of operation type;
//   - a searchRequest's derefAliases field is exactly neverDerefAliases(0)
//     (plan §6/§8.2), and *sawSearchRequest is set so the caller can
//     require at least one such PDU was actually checked.
//
// This never recomputes internal/ldap's cryptobyte-vs-local-ber-cursor
// verdict (plan §33 reserves that to TestClickHouseWireCryptobyteDecision
// alone) — goldap is used here purely to read two specific decoded field
// values, an orthogonal concern from which BER primitive parser ClickHouse
// wire traffic should use.
func assertSearchProfileFixedFields(t *testing.T, path, operation string, raw []byte, sawSearchRequest *bool) {
	t.Helper()

	msg, err := goldapmessage.ReadLDAPMessage(goldapmessage.NewBytes(0, raw))
	if err != nil {
		t.Errorf("wire_profile_contract: %s: independent goldap BER decode failed: %v", path, err)
		return
	}
	if msg.Controls() != nil {
		t.Errorf("wire_profile_contract: %s: decoded LDAPMessage carries a Controls sequence, want absent (plan §8.2)", path)
	}

	if operation != wirefixture.OperationSearchRequest {
		return
	}
	search, ok := msg.ProtocolOp().(goldapmessage.SearchRequest)
	if !ok {
		t.Errorf("wire_profile_contract: %s: committed metadata says operation %q but decoded protocolOp is %T", path, operation, msg.ProtocolOp())
		return
	}
	*sawSearchRequest = true
	if got := int(search.DerefAliases()); got != 0 {
		t.Errorf("wire_profile_contract: %s: decoded derefAliases=%d, want neverDerefAliases(0)", path, got)
	}
}

// ---------------------------------------------------------------------
// §29 — constructed MessageID 127/128 boundary fixtures reproduce
// ---------------------------------------------------------------------

func TestWireProfileContract_ConstructedMessageIDFixturesReproduce(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	fixtureRoot := wireProfileFixtureRoot(root)
	constructedSessionDir := wirefixture.SessionDir(wirefixture.ConstructedDir(fixtureRoot), "message-id-boundary")

	committedSession, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(constructedSessionDir))
	if err != nil {
		t.Fatalf("wire_profile_contract: read committed constructed session.json: %v", err)
	}

	regenSession, regenFiles, err := wirefixture.BuildConstructedMessageIDBoundarySession(committedSession.Applicability)
	if err != nil {
		t.Fatalf("wire_profile_contract: BuildConstructedMessageIDBoundarySession: %v", err)
	}
	if len(regenFiles) != 2 {
		t.Fatalf("wire_profile_contract: BuildConstructedMessageIDBoundarySession returned %d files, want 2", len(regenFiles))
	}
	if len(regenSession.PDUs) != 2 {
		t.Fatalf("wire_profile_contract: regenerated session has %d PDUs, want 2", len(regenSession.PDUs))
	}

	const file127 = "001-bind-messageid-127.ber"
	const file128 = "002-bind-messageid-128.ber"

	committed127, err := os.ReadFile(filepath.Join(constructedSessionDir, file127))
	if err != nil {
		t.Fatalf("wire_profile_contract: read committed %s: %v", file127, err)
	}
	committed128, err := os.ReadFile(filepath.Join(constructedSessionDir, file128))
	if err != nil {
		t.Fatalf("wire_profile_contract: read committed %s: %v", file128, err)
	}

	regen127, regen128 := regenFiles[0], regenFiles[1]

	if !bytes.Equal(regen127, committed127) {
		t.Errorf("wire_profile_contract: regenerated MessageID-127 bytes do not byte-compare equal to committed %s", file127)
	}
	if !bytes.Equal(regen128, committed128) {
		t.Errorf("wire_profile_contract: regenerated MessageID-128 bytes do not byte-compare equal to committed %s", file128)
	}

	// Explicit 127/128 DER-minimal-INTEGER boundary assertions (plan §29),
	// against the freshly regenerated bytes (independent of whether the
	// byte-compare above already passed, so a genuine encoding regression
	// is diagnosed precisely rather than only as "bytes differ").
	assertMessageIDIntegerContent(t, regen127, 127, []byte{0x7f})
	assertMessageIDIntegerContent(t, regen128, 128, []byte{0x00, 0x80})

	if len(regen128) <= len(regen127) {
		t.Errorf("wire_profile_contract: regenerated MessageID-128 payload (%d bytes) is not longer than MessageID-127's (%d bytes) — the DER-minimal length must grow at this boundary", len(regen128), len(regen127))
	}
}

// assertMessageIDIntegerContent parses just enough of a
// BuildConstructedSimpleBind LDAPMessage — SEQUENCE tag, one short-form
// outer length byte, then the leading MessageID INTEGER TLV — to check its
// content bytes directly, independent of the higher-level byte-equality
// check above.
func assertMessageIDIntegerContent(t *testing.T, data []byte, messageID int, wantContent []byte) {
	t.Helper()
	if len(data) < 5 {
		t.Errorf("wire_profile_contract: MessageID %d payload too short (%d bytes) to contain SEQUENCE+INTEGER headers", messageID, len(data))
		return
	}
	if data[0] != 0x30 {
		t.Errorf("wire_profile_contract: MessageID %d: outer tag 0x%02x, want SEQUENCE 0x30", messageID, data[0])
		return
	}
	if data[1]&0x80 != 0 {
		t.Errorf("wire_profile_contract: MessageID %d: outer length byte 0x%02x uses long form; this builder's fixed payload size is expected to stay under 128 bytes (short form)", messageID, data[1])
		return
	}
	if data[2] != 0x02 {
		t.Errorf("wire_profile_contract: MessageID %d: first inner tag 0x%02x, want INTEGER 0x02 (the MessageID)", messageID, data[2])
		return
	}
	contentLen := int(data[3])
	if len(data) < 4+contentLen {
		t.Errorf("wire_profile_contract: MessageID %d: INTEGER length byte %d exceeds remaining payload", messageID, contentLen)
		return
	}
	got := data[4 : 4+contentLen]
	if !bytes.Equal(got, wantContent) {
		t.Errorf("wire_profile_contract: MessageID %d: INTEGER content bytes % x, want % x", messageID, got, wantContent)
	}
}

// ---------------------------------------------------------------------
// §9 — WirecaptureUsesSharedFixtureSchema
// ---------------------------------------------------------------------

const wirecaptureDirRelPath = "integration/clickhouse/wirecapture"
const wirefixtureImportPath = "github.com/altinity/altinity-oauth-helper/internal/wirefixture"

// wireProfileForbiddenLocalTypeNames are the canonical on-disk-serialization
// type names internal/wirefixture owns exclusively (plan §9): no other
// package — in particular not the wirecapture writer — may declare its own
// type of the same name for that purpose.
var wireProfileForbiddenLocalTypeNames = map[string]bool{
	"Profile": true,
	"Session": true,
	"PDU":     true,
}

func TestWireProfileContract_WirecaptureUsesSharedFixtureSchema(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	dir := filepath.Join(root, filepath.FromSlash(wirecaptureDirRelPath))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("wire_profile_contract: read %s: %v", dir, err)
	}

	sawWirefixtureImport := false
	sawWriteProfileCall := false
	sawWriteSessionCall := false

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("wire_profile_contract: parse %s: %v", path, err)
		}

		aliases := importAliases(file)
		wirefixtureLocalName := ""
		for local, importPath := range aliases {
			if importPath == wirefixtureImportPath {
				wirefixtureLocalName = local
				sawWirefixtureImport = true
			}
		}

		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if wireProfileForbiddenLocalTypeNames[ts.Name.Name] {
					pos := fset.Position(ts.Pos())
					t.Errorf("wire_profile_contract: %s:%d declares a local type %q — on-disk metadata serialization types are owned exclusively by internal/wirefixture (plan §9)", e.Name(), pos.Line, ts.Name.Name)
				}
			}
		}

		if wirefixtureLocalName == "" {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != wirefixtureLocalName {
				return true
			}
			switch sel.Sel.Name {
			case "WriteProfile":
				sawWriteProfileCall = true
			case "WriteSession":
				sawWriteSessionCall = true
			}
			return true
		})
	}

	if !sawWirefixtureImport {
		t.Errorf("wire_profile_contract: no non-test file directly in %s imports %s (plan §9)", wirecaptureDirRelPath, wirefixtureImportPath)
	}
	if !sawWriteProfileCall {
		t.Errorf("wire_profile_contract: no non-test file directly in %s calls wirefixture.WriteProfile (plan §9)", wirecaptureDirRelPath)
	}
	if !sawWriteSessionCall {
		t.Errorf("wire_profile_contract: no non-test file directly in %s calls wirefixture.WriteSession (plan §9)", wirecaptureDirRelPath)
	}

	// go list -deps must also show the real dependency, not merely an
	// AST-visible import statement (plan §9's second, independent proof).
	// Reuses this package's own deterministic go-invocation pattern
	// (resolveGoBin/deterministicGoListEnv, dependency_contract_test.go)
	// rather than inventing a second one.
	goBin := resolveGoBin(t)
	cmd := exec.Command(goBin, //nolint:gosec // fixed, deterministically-resolved go tool binary; fixed argv below
		"list", "-mod=readonly", "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}",
		"./"+wirecaptureDirRelPath)
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("wire_profile_contract: %s list -deps ./%s failed: %v\nstderr:\n%s", filepath.Base(goBin), wirecaptureDirRelPath, err, stderr.String())
	}
	deps := normalizeDepsOutput(stdout.String())
	foundDep := false
	for _, d := range deps {
		if d == wirefixtureImportPath {
			foundDep = true
			break
		}
	}
	if !foundDep {
		t.Errorf("wire_profile_contract: go list -deps ./%s does not include %s", wirecaptureDirRelPath, wirefixtureImportPath)
	}
}
