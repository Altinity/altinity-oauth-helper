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
	// The issue #33 phase 4 cutover deleted internal/ldap/redaction_boundary_
	// test.go (this test's original source of a real, committed, JWT-shaped
	// fixture constant, ldapBoundaryBearer) along with the rest of the
	// legacy internal/ldap implementation and its tests. Its permanent
	// successor, internal/ldap/profile/redaction_boundary_test.go, proves
	// the same redaction boundary but never needed its own "Bearer "-
	// prefixed constant; internal/ldap/profile/fakes_test.go's
	// markerJWTPassword is the still-real, still-committed, JWT-shaped
	// (three dot-separated segments) fixture this test now reads instead —
	// only the "Bearer " prefix below is test-local, added here because no
	// remaining committed constant carries it verbatim.
	const fakesTestRelPath = "internal/ldap/profile/fakes_test.go"
	jwtShapedValue, err := wireProfileExtractStringConst(filepath.Join(root, filepath.FromSlash(fakesTestRelPath)), "markerJWTPassword")
	if err != nil {
		t.Fatalf("wire_profile_contract: %v", err)
	}

	const bearerPrefix = "Bearer "
	wantToken := jwtShapedValue
	value := bearerPrefix + jwtShapedValue

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
//     Oracle B (wire_oracle_b_test.go) — a second, structurally distinct,
//     hand-written bounded BER cursor from internal/ldap's cryptobyte
//     characterizer, which stays the SOLE owner of the primitive-layer
//     cryptobyte-vs-local-ber-cursor decision (plan §33) — and the actual
//     decoded field values are asserted directly, not merely compared to
//     the doc's own text. Issue #33 phase 4 replaced this leg's prior
//     vendored-goldap decoder with Oracle B as part of deleting the
//     general vendored LDAP/BER stack from the repository entirely.
//
// Removing either leg's claim (the doc prose, or the byte-level truth it
// describes) now fails this test, instead of both drifting together
// silently.
//
// # Search filter structure/values leg (review pass 3)
//
// A review found that this sentinel's fixture-side leg still stopped short
// of the single most security-relevant field in the whole request: the §6
// table's "Search filter" row claims every captured/constructed searchRequest
// carries exactly `(&(objectClass=groupOfNames)(member={bind_dn}))` — an AND
// of two equalityMatch terms — sourced from the ClickHouse config XML
// (checked, as a wholly separate artifact, by TestWireProfileContract_
// ConfigContract). Nothing previously tied that claim to the actual decoded
// Filter structure/values inside the committed .ber wire bytes: a fixture's
// Search filter tag could be changed from AND (0xa0) to OR (0xa1) — a
// same-shape edit, since Filter::and and Filter::or are both `SET OF Filter`
// with byte-identical children/lengths — with sanitized_sha256 updated to
// match, and this whole package's suite (including cryptobyte's own,
// deliberately narrow "and"/"equalityMatch"-only characterization) would stay
// green: cryptobyte would reject the mutated fixture outright (an unsupported
// filter tag), but a corrupted-fixture rejection is not what any check here
// treats as evidence of the mutation — nothing decoded the *valid* AND/OR
// shape and compared it against the canonical profile.
//
// assertSearchProfileFixedFields below closes this: for every committed
// searchRequest PDU it independently decodes the Filter (still via Oracle
// B, never recomputing internal/ldap's cryptobyte verdict) and requires it
// to be exactly AND(equalityMatch(objectClass, groupOfNames),
// equalityMatch(member, <this session's own Bind DN>)) — not a hardcoded
// literal Bind DN (which would itself be an unverified
// second copy of "alice@example.com" that could silently drift from what a
// future recapture actually uses), but the exact Bind DN bytes this
// sentinel independently decodes from the *same session's own* bindRequest
// PDU. That is the only ground truth {bind_dn} can mean on a real
// connection (§6.3/§8.4: Search always follows a successful Bind on the same
// libldap handle, using that handle's own bind DN), so cross-checking against
// it — rather than a literal this test would otherwise have to keep in sync
// by hand — proves the Search filter's member value is genuinely the bound
// identity, not merely well-formed BER.

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

		// Ground truth for {bind_dn}: independently decode this session's
		// own bindRequest PDU first (a second, structurally distinct
		// decoder from internal/ldap's cryptobyte characterizer, exactly
		// like every other decode in this sentinel), so the Search filter's
		// "member" value below is checked against what this connection
		// actually bound as — not a hardcoded literal duplicating that
		// value from elsewhere.
		var bindDN string
		var sawBindRequest bool
		for _, pdu := range sess.PDUs {
			if pdu.Operation != wirefixture.OperationBindRequest {
				continue
			}
			path := filepath.Join(sessDir, pdu.Filename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("wire_profile_contract: read %s: %v", path, err)
			}
			msg, err := oracleBDecodeLDAPMessage(raw)
			if err != nil {
				t.Fatalf("wire_profile_contract: %s: independent Oracle B decode of bindRequest failed: %v", path, err)
			}
			if msg.Bind == nil {
				t.Fatalf("wire_profile_contract: %s: committed metadata says operation %q but decoded protocolOp tag is 0x%02x, not bindRequest", path, pdu.Operation, msg.OpTag)
			}
			bindDN = msg.Bind.Name
			sawBindRequest = true
			break
		}
		if !sawBindRequest {
			t.Fatalf("wire_profile_contract: session %s has no bindRequest PDU — the Search filter leg has no Bind DN ground truth to check against", label)
		}

		for _, pdu := range sess.PDUs {
			path := filepath.Join(sessDir, pdu.Filename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("wire_profile_contract: read %s: %v", path, err)
			}
			assertSearchProfileFixedFields(t, path, pdu.Operation, raw, bindDN, &sawSearchRequest)
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
// LDAPMessage using Oracle B (wire_oracle_b_test.go — a hand-written
// bounded BER cursor implemented separately from Oracle A, from
// internal/ldap/profile's own production decoder, and from
// integration/clickhouse/wirecapture's producer parsing) and asserts:
//
//   - every PDU's LDAPMessage carries no Controls sequence (plan §8.2:
//     absent, not merely empty), regardless of operation type;
//   - a searchRequest's derefAliases field is exactly neverDerefAliases(0)
//     (plan §6/§8.2), and *sawSearchRequest is set so the caller can
//     require at least one such PDU was actually checked.
//
// This never recomputes internal/ldap/profile's cryptobyte-vs-local-ber-
// cursor verdict (plan §33 reserves that to Oracle A alone) — Oracle B is
// used here purely to read specific decoded field values, an orthogonal
// concern from which BER primitive parser ClickHouse wire traffic should
// use.
//
// wantBindDN is the exact Bind DN this same session's own bindRequest PDU
// decoded to (see the caller, checkSession) — the ground truth the Search
// filter's "member" equalityMatch value is checked against.
func assertSearchProfileFixedFields(t *testing.T, path, operation string, raw []byte, wantBindDN string, sawSearchRequest *bool) {
	t.Helper()

	msg, err := oracleBDecodeLDAPMessage(raw)
	if err != nil {
		t.Errorf("wire_profile_contract: %s: independent Oracle B decode failed: %v", path, err)
		return
	}
	if msg.ControlsPresent {
		t.Errorf("wire_profile_contract: %s: decoded LDAPMessage carries a Controls sequence, want absent (plan §8.2)", path)
	}

	if operation != wirefixture.OperationSearchRequest {
		return
	}
	if msg.Search == nil {
		t.Errorf("wire_profile_contract: %s: committed metadata says operation %q but decoded protocolOp tag is 0x%02x, not searchRequest", path, operation, msg.OpTag)
		return
	}
	*sawSearchRequest = true
	if msg.Search.DerefAliases != 0 {
		t.Errorf("wire_profile_contract: %s: decoded derefAliases=%d, want neverDerefAliases(0)", path, msg.Search.DerefAliases)
	}
	for _, defect := range oracleBCanonicalFilterDefects(msg.Search.Filter, wantBindDN) {
		t.Errorf("wire_profile_contract: %s: %s", path, defect)
	}
}

// TestWireProfileContract_SearchFilterStructureIsDiscriminating is the
// sabotage check for oracleBCanonicalFilterDefects itself (review pass 3,
// carried forward into Oracle B): it proves the Search-filter structural/
// value check TestWireProfileContract_SearchProfileFixedFieldsSentinel
// relies on is a real, discriminating check — not a rubber stamp — by
// reproducing the exact scenario the review named: a committed
// searchRequest fixture's outer filter tag mutated from AND (0xa0) to OR
// (0xa1), same shape and length, which independent Oracle B decoding still
// accepts as well-formed BER (both are `SET OF Filter`) but which must now
// be rejected as not matching the canonical AND-of-two-equalityMatch
// profile. The mutation happens only on an in-memory copy of the fixture
// bytes read for this test — the committed .ber file on disk is never
// written to.
func TestWireProfileContract_SearchFilterStructureIsDiscriminating(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	fixtureRoot := wireProfileFixtureRoot(root)
	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("wire_profile_contract: validate fixture root %s: %v", fixtureRoot, err)
	}

	var searchTemplate []byte
	findSearchTemplate := func(sessDir string) {
		if searchTemplate != nil {
			return
		}
		sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
		if err != nil {
			t.Fatalf("wire_profile_contract: read session.json for %s: %v", sessDir, err)
		}
		for _, pdu := range sess.PDUs {
			if pdu.Operation != wirefixture.OperationSearchRequest {
				continue
			}
			path := filepath.Join(sessDir, pdu.Filename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("wire_profile_contract: read %s: %v", path, err)
			}
			searchTemplate = raw
			return
		}
	}
	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		profile, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
		if err != nil {
			t.Fatalf("wire_profile_contract: read profile.json for line %s: %v", line, err)
		}
		for _, sp := range profile.SessionPaths {
			findSearchTemplate(wirefixture.SessionDir(lineDir, sp))
		}
	}
	if searchTemplate == nil {
		t.Fatalf("wire_profile_contract: no committed searchRequest fixture found under %s", fixtureRoot)
	}

	// Sanity check: the un-mutated template must itself pass, against its
	// own actual decoded Bind DN (whatever the fixture's real value is —
	// this sabotage check does not depend on a hardcoded Bind DN literal).
	sanityMsg, err := oracleBDecodeLDAPMessage(searchTemplate)
	if err != nil {
		t.Fatalf("search template sanity check: independent Oracle B decode failed: %v", err)
	}
	if sanityMsg.Search == nil {
		t.Fatalf("search template sanity check: decoded protocolOp tag is 0x%02x, want searchRequest", sanityMsg.OpTag)
	}
	var realBindDN string
	for _, term := range sanityMsg.Search.Filter.Terms {
		if term.IsEquality && term.Attribute == "member" {
			realBindDN = term.Value
		}
	}
	if realBindDN == "" {
		t.Fatalf("search template sanity check: no member equalityMatch term found in the decoded filter")
	}
	if defects := oracleBCanonicalFilterDefects(sanityMsg.Search.Filter, realBindDN); len(defects) != 0 {
		t.Fatalf("search template sanity check: expected the un-mutated template to pass against its own decoded Bind DN, got defects: %v", defects)
	}

	// The outer "and" filter wrapper (a0 5f) immediately followed by the
	// first equalityMatch element's tag+length (a3 1b) — same anchor
	// clickhouse_wire_cryptobyte_test.go's "wrong-tag-filter" mutation uses,
	// but mutating the AND wrapper's own tag byte (offset 0) instead of the
	// nested equalityMatch tag (offset 2).
	pattern := []byte{0xa0, 0x5f, 0xa3, 0x1b}
	idx := bytes.Index(searchTemplate, pattern)
	if idx < 0 {
		t.Fatalf("mutation template: pattern %x not found in search template", pattern)
	}
	if searchTemplate[idx] != 0xa0 {
		t.Fatalf("mutation template: byte at offset %d is 0x%02x, want 0xa0 (template shape may have changed)", idx, searchTemplate[idx])
	}
	mutated := append([]byte(nil), searchTemplate...)
	mutated[idx] = 0xa1 // AND [0] -> OR [1]: same SET OF Filter shape, same length

	mutatedMsg, err := oracleBDecodeLDAPMessage(mutated)
	if err != nil {
		t.Fatalf("independent Oracle B decoder rejected the AND->OR mutation as malformed BER, expected it to still decode (same shape/length): %v", err)
	}
	if mutatedMsg.Search == nil {
		t.Fatalf("mutated fixture: decoded protocolOp tag is 0x%02x, want searchRequest", mutatedMsg.OpTag)
	}
	if defects := oracleBCanonicalFilterDefects(mutatedMsg.Search.Filter, realBindDN); len(defects) == 0 {
		t.Fatalf("oracleBCanonicalFilterDefects accepted an AND(0xa0)->OR(0xa1) filter-tag mutation as the canonical shape — the discriminating check is a rubber stamp")
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

// ---------------------------------------------------------------------
// Issue #33 Phase 3 — §11.5 replacement release-gate evidence contracts
// ---------------------------------------------------------------------
//
// docs/clickhouse-ldap-wire-profile.md §11.5 is Stage C's populated
// evidence record for Phase 3's Stage B manual certification (plan
// "Evidence landing order"). The checks below prove that section's SHAPE
// and INTERNAL/CROSS-FILE CONSISTENCY — exactly one marker pair, no
// placeholder values, the recorded selector/Dockerfile/image-set/
// fuzz-target facts match this repository's own other ground truth
// (phase3_selector_contract_test.go's constants, auditedProvenanceMatrix
// above), the recorded final LOC equals a *fresh* recount of the current
// tree (never compared against §11.1's historical 2,682 baseline as
// though that pinned figure were meant to track today's tree — plan "LOC
// guardrail and documentation repair"), the eleven §11.3/§11.5 narrowing
// dispositions use only the exact tokens ACCEPT/REJECT, and the recorded
// certified-surface digest is independently reproduced by this test's own
// Go implementation of the plan's "Certified-surface anti-drift digest"
// algorithm.
//
// None of this is proof that a human actually ran the Docker ClickHouse
// matrix, the HA harness, wire-capture verify, or any 20-second fuzz
// smoke — that stays human-attested (plan "Machine-checked versus
// human-attested evidence"): a parser accepting the literal word PASS is
// never treated here as evidence Docker ran.
//
// If TestWireProfileContract_Phase3EvidenceCertifiedSurfaceDigestMatches
// ever fails because the two sides genuinely disagree (as opposed to a
// bug in this test's own algorithm), that means the certified surface
// changed after Stage B's manual certification: per the plan, the
// certification is INVALID. The fix is a new Stage B certification against
// a new tested_behavior_head, never editing the recorded digest (or this
// test's algorithm) to force agreement.

// phase3EvidenceMarkerStart and phase3EvidenceMarkerEnd bound exactly one
// occurrence of §11.5's evidence section, the same marker-pair pattern
// TestWireProfileContract_EngineeringDocBoundary already uses for the
// ldap-primitive-decision marker.
const phase3EvidenceMarkerStart = "<!-- phase3-release-gate-evidence:start -->"
const phase3EvidenceMarkerEnd = "<!-- phase3-release-gate-evidence:end -->"

// phase3NarrowingIDs is the plan's exact, ordered eleven-row narrowing-ID
// sequence ("§11.3 narrowing dispositions": "Record exactly eleven decision
// rows: 1, 1a, then 2 through 10").
var phase3NarrowingIDs = []string{"1", "1a", "2", "3", "4", "5", "6", "7", "8", "9", "10"}

// phase3HardeningNarrowingIDs are the three rows the plan requires an
// explicit lifecycle/resource/config hardening label for, rather than a
// wire-evidence reference (items 6, 9, 10 — "For 6, 9, and 10, explicitly
// label the decision as lifecycle/resource/config hardening rather than
// pretending a wire fixture proves it").
var phase3HardeningNarrowingIDs = map[string]bool{"6": true, "9": true, "10": true}

// phase3EvidenceSection returns the exact text strictly between one
// well-formed §11.5 marker pair, failing the test if the pair is missing,
// duplicated, or out of order.
func phase3EvidenceSection(t *testing.T, doc string) string {
	t.Helper()
	startCount := strings.Count(doc, phase3EvidenceMarkerStart)
	endCount := strings.Count(doc, phase3EvidenceMarkerEnd)
	if startCount != 1 || endCount != 1 {
		t.Fatalf("wire_profile_contract: %s: found %d %q and %d %q, want exactly one §11.5 marker pair", wireProfileDocRelPath, startCount, phase3EvidenceMarkerStart, endCount, phase3EvidenceMarkerEnd)
	}
	start := strings.Index(doc, phase3EvidenceMarkerStart)
	end := strings.Index(doc, phase3EvidenceMarkerEnd)
	if end < start {
		t.Fatalf("wire_profile_contract: %s: §11.5 end marker appears before its start marker", wireProfileDocRelPath)
	}
	return doc[start+len(phase3EvidenceMarkerStart) : end]
}

// phase3EvidenceField extracts the value of a "- **Label:** `value`"
// recorded field from an already-isolated §11.5 section, failing the test
// if that exact label is not present in that exact form.
func phase3EvidenceField(t *testing.T, section, label string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta("**"+label+":**") + "\\s*`([^`]+)`")
	m := re.FindStringSubmatch(section)
	if m == nil {
		t.Fatalf("wire_profile_contract: %s: §11.5 has no %q field in the required `- **%s:** `value`` form", wireProfileDocRelPath, label, label)
	}
	return m[1]
}

// phase3EvidencePlaceholderRE matches the plan's named placeholder tokens
// ("no placeholder values such as PENDING or TBD").
var phase3EvidencePlaceholderRE = regexp.MustCompile(`\b(PENDING|TBD)\b`)

// phase3WhitespaceRunRE collapses any run of whitespace (including the
// doc's own hard-wrapped line breaks, which are cosmetic prose formatting,
// not semantic content) to a single space, so a literal multi-word needle
// search is insensitive to exactly where a paragraph happens to wrap.
// Table extraction (wireProfileExtractTable) must never see flattened
// text — only the freeform-prose substring checks below use this.
var phase3WhitespaceRunRE = regexp.MustCompile(`\s+`)

func phase3CollapseWhitespace(s string) string {
	return phase3WhitespaceRunRE.ReplaceAllString(strings.TrimSpace(s), " ")
}

func TestWireProfileContract_Phase3EvidenceMarkerAndPlaceholders(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	if !strings.Contains(section, "11.5 Phase 3 replacement release-gate evidence") {
		t.Fatalf("wire_profile_contract: %s: §11.5 marker pair does not bound the §11.5 heading text", wireProfileDocRelPath)
	}
	if matches := phase3EvidencePlaceholderRE.FindAllString(section, -1); len(matches) != 0 {
		t.Fatalf("wire_profile_contract: %s: §11.5 contains placeholder value(s) %v — every recorded field must carry a real Stage B result", wireProfileDocRelPath, matches)
	}
}

// phase3HistoricalSelector and phase3HistoricalIntegrationDockerfileRelPath
// are locally owned copies of the exact Phase 3 historical facts §11.5
// recorded — never references to phase3_selector_contract_test.go's
// selector-contract constants (that file, and the temporary phase3profile
// selector mechanism it polices, is deleted at cutover), and never a live
// read of any current Dockerfile. Per issue #33 phase 4's plan, §11.5 is a
// historical record: once recorded, this test must keep proving it still
// reads back as the exact certification Phase 3 produced — regardless of
// what a later cutover does to selectors, tags, or Dockerfiles.
const phase3HistoricalSelector = "phase3profile"
const phase3HistoricalIntegrationDockerfileRelPath = "integration/clickhouse/Dockerfile"

// TestWireProfileContract_Phase3EvidenceIdentityAndSelector requires
// §11.5's tested_behavior_head/selector/Dockerfile/production-remains-
// legacy fields to still read back exactly as Phase 3 recorded them. It no
// longer reads any current Dockerfile or depends on any selector-contract
// constant (both would make this a claim about today's tree, which is
// exactly what a historical record must not be) — only a real 40-hex
// commit-ish string shape and the frozen selector/path literals above.
func TestWireProfileContract_Phase3EvidenceIdentityAndSelector(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	head := phase3EvidenceField(t, section, "tested_behavior_head")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(head) {
		t.Fatalf("wire_profile_contract: %s: §11.5 tested_behavior_head %q is not exactly 40 lowercase hex characters", wireProfileDocRelPath, head)
	}

	selector := phase3EvidenceField(t, section, "Selector")
	if selector != phase3HistoricalSelector {
		t.Fatalf("wire_profile_contract: %s: §11.5 Selector is %q, want exactly the historically recorded %q", wireProfileDocRelPath, selector, phase3HistoricalSelector)
	}

	dockerfilePath := phase3EvidenceField(t, section, "Integration Dockerfile")
	if dockerfilePath != phase3HistoricalIntegrationDockerfileRelPath {
		t.Fatalf("wire_profile_contract: %s: §11.5 Integration Dockerfile is %q, want exactly the historically recorded %q", wireProfileDocRelPath, dockerfilePath, phase3HistoricalIntegrationDockerfileRelPath)
	}

	const productionRemainsLegacyNeedle = "select the legacy `internal/ldap` server"
	if !strings.Contains(phase3CollapseWhitespace(section), productionRemainsLegacyNeedle) {
		t.Fatalf("wire_profile_contract: %s: §11.5 must still record that normal production remained on the legacy server at the time of Phase 3 certification", wireProfileDocRelPath)
	}
}

// phase3EvidenceHAMarker is the exact heading text that opens §11.5's "HA"
// subsection, used to split the section into a matrix-only prefix and an
// HA-only suffix so each "| Image | Result |" table can be located and
// asserted independently. Without this split, wireProfileExtractTable's
// documented "first line containing every needle" semantics make a single
// call against the whole section find only the FIRST such table (the
// Supported ClickHouse matrix) and never reach the second (HA) — see
// TestWireProfileContract_Phase3EvidenceSupportedMatrixAndHA's doc comment.
const phase3EvidenceHAMarker = "**HA**"

// phase3SplitOnHAHeading splits section into everything before
// phase3EvidenceHAMarker (the Supported ClickHouse matrix subsection) and
// everything from the marker onward (the HA subsection), failing the test
// if the marker is missing or not unique — both tables must exist exactly
// once each, in that order, for the two halves to be well-defined.
func phase3SplitOnHAHeading(t *testing.T, section string) (matrixPart, haPart string) {
	t.Helper()
	idx := strings.Index(section, phase3EvidenceHAMarker)
	if idx < 0 {
		t.Fatalf("wire_profile_contract: %s: §11.5 has no %q heading to split the Supported ClickHouse matrix from the HA subsection", wireProfileDocRelPath, phase3EvidenceHAMarker)
	}
	if strings.Count(section, phase3EvidenceHAMarker) != 1 {
		t.Fatalf("wire_profile_contract: %s: §11.5 must contain exactly one %q heading, found %d", wireProfileDocRelPath, phase3EvidenceHAMarker, strings.Count(section, phase3EvidenceHAMarker))
	}
	return section[:idx], section[idx:]
}

// phase3HistoricalImages is the locally owned, frozen Phase 3 §11.5
// tracked-image set — the exact two images actually certified at
// tested_behavior_head. It is intentionally NOT derived from
// auditedProvenanceMatrix (used elsewhere in this file for the CURRENT,
// mutable tracked-line set): a future tracked-line addition or removal
// must never silently change what this historical record is checked
// against (plan: "not a future mutable live matrix").
var phase3HistoricalImages = []string{
	"altinity/clickhouse-server:24.8.11.51285.altinitystable",
	"altinity/clickhouse-server:25.8.28.10001.altinitystable",
}

// TestWireProfileContract_Phase3EvidenceSupportedMatrixAndHA requires §11.5's
// "Supported ClickHouse matrix" and "HA" tables to name exactly the
// historically certified image set (phase3HistoricalImages above) each
// with a PASS result, and requires a recorded session-probe result.
//
// The matrix and HA subsections each contain their own "| Image | Result |"
// table. wireProfileExtractTable documents (and implements) "locate the
// FIRST line containing every needle" — calling it once against the whole
// section with the single needle "Image" therefore only ever reaches the
// matrix table; the HA table's images and results were never independently
// parsed or asserted. This test scopes the extraction to each subsection
// separately (via phase3SplitOnHAHeading) so a wrong image set or a
// non-PASS result in the HA table fails this test, not just a wrong value
// in the matrix table.
func TestWireProfileContract_Phase3EvidenceSupportedMatrixAndHA(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)
	matrixPart, haPart := phase3SplitOnHAHeading(t, section)

	wantImages := append([]string(nil), phase3HistoricalImages...)
	sort.Strings(wantImages)

	assertImageResultTable := func(tableName, scopeLabel, scope string) {
		_, rows, err := wireProfileExtractTable(scope, tableName)
		if err != nil {
			t.Fatalf("wire_profile_contract: %s: §11.5 %s %s table: %v", wireProfileDocRelPath, scopeLabel, tableName, err)
		}
		var gotImages []string
		for _, row := range rows {
			if len(row) != 2 {
				t.Fatalf("wire_profile_contract: %s: §11.5 %s %s table row %v has %d cells, want 2", wireProfileDocRelPath, scopeLabel, tableName, row, len(row))
			}
			image := wireProfileStripCell(row[0])
			result := wireProfileStripCell(row[1])
			if result != "PASS" {
				t.Fatalf("wire_profile_contract: %s: §11.5 %s %s table: image %s has result %q, want exactly PASS", wireProfileDocRelPath, scopeLabel, tableName, image, result)
			}
			gotImages = append(gotImages, image)
		}
		sort.Strings(gotImages)
		if !stringSlicesEqual(gotImages, wantImages) {
			t.Fatalf("wire_profile_contract: %s: §11.5 %s %s table names images %v, want exactly the historically certified set %v", wireProfileDocRelPath, scopeLabel, tableName, gotImages, wantImages)
		}
	}

	assertImageResultTable("Image", "Supported ClickHouse matrix", matrixPart)
	assertImageResultTable("Image", "HA", haPart)

	const sessionProbeNeedle = "**Session-probe result:** `PASS`"
	if !strings.Contains(phase3CollapseWhitespace(haPart), sessionProbeNeedle) {
		t.Fatalf("wire_profile_contract: %s: §11.5 must record a session-probe result", wireProfileDocRelPath)
	}
}

// TestWireProfileContract_Phase3EvidenceWireVerify requires §11.5 to record
// the wire-capture Phase 3 policy ("generation: frozen", never new
// provenance), a verify command, and an explicit PASS result, per the
// plan's "Wire-capture fixture disposition" and "Recorded fields" sections.
// A prior version of this test stopped short of the PASS check: it
// confirmed the command and "generation: frozen" were recorded but never
// looked for "**Result:** `PASS`" under "Wire-capture verification", so a
// recorded FAIL (or a missing Result line entirely) would have passed this
// test just as cleanly as the doc's actual, correct PASS.
func TestWireProfileContract_Phase3EvidenceWireVerify(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	flat := phase3CollapseWhitespace(section)
	if !strings.Contains(flat, "generation: frozen") {
		t.Fatalf("wire_profile_contract: %s: §11.5 must explicitly record `generation: frozen`", wireProfileDocRelPath)
	}
	if !strings.Contains(flat, "capture-ldap-wire.sh") || !strings.Contains(flat, "--mode verify") {
		t.Fatalf("wire_profile_contract: %s: §11.5 must record the --mode verify capture-ldap-wire.sh command", wireProfileDocRelPath)
	}

	const wireVerifyHeading = "**Wire-capture verification**"
	verifyIdx := strings.Index(section, wireVerifyHeading)
	if verifyIdx < 0 {
		t.Fatalf("wire_profile_contract: %s: §11.5 has no %q subsection", wireProfileDocRelPath, wireVerifyHeading)
	}
	const wireVerifyResultNeedle = "**Result:** `PASS`"
	if !strings.Contains(phase3CollapseWhitespace(section[verifyIdx:]), wireVerifyResultNeedle) {
		t.Fatalf("wire_profile_contract: %s: §11.5 %q subsection must explicitly record %q", wireProfileDocRelPath, wireVerifyHeading, wireVerifyResultNeedle)
	}
}

// phase3FuzzTargetNames is the locally owned, frozen Phase 3 §11.5 fuzz
// table's exact five target names. Historical use only — the live
// existence check this variable used to also drive (confirming each name
// is a real declared Fuzz func) now lives independently in
// TestWireProfileContract_CurrentFuzzTargetsExist below (plan: "Move live
// target-existence checking into a permanent current-profile contract").
var phase3FuzzTargetNames = []string{
	"FuzzLDAPFrame",
	"FuzzBindRequest",
	"FuzzSearchRequest",
	"FuzzRestrictedDN",
	"FuzzMemberAssertionDN",
}

// TestWireProfileContract_Phase3EvidenceFuzzTable validates §11.5's fuzz
// table against the frozen historical five-target/20s/PASS record only. It
// no longer reaches into internal/ldap/profile's current test files —
// that live check is TestWireProfileContract_CurrentFuzzTargetsExist's job
// now, so this historical test cannot fail merely because a later phase
// renamed or moved a fuzz target.
func TestWireProfileContract_Phase3EvidenceFuzzTable(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	_, rows, err := wireProfileExtractTable(section, "Fuzz target", "Duration")
	if err != nil {
		t.Fatalf("wire_profile_contract: %s: §11.5 fuzz table: %v", wireProfileDocRelPath, err)
	}
	if len(rows) != len(phase3FuzzTargetNames) {
		t.Fatalf("wire_profile_contract: %s: §11.5 fuzz table has %d rows, want exactly %d", wireProfileDocRelPath, len(rows), len(phase3FuzzTargetNames))
	}
	var gotTargets []string
	for _, row := range rows {
		if len(row) != 3 {
			t.Fatalf("wire_profile_contract: %s: §11.5 fuzz table row %v has %d cells, want 3", wireProfileDocRelPath, row, len(row))
		}
		target := wireProfileStripCell(row[0])
		duration := wireProfileStripCell(row[1])
		result := wireProfileStripCell(row[2])
		if duration != "20s" {
			t.Fatalf("wire_profile_contract: %s: §11.5 fuzz table: target %s has duration %q, want exactly \"20s\"", wireProfileDocRelPath, target, duration)
		}
		if result != "PASS" {
			t.Fatalf("wire_profile_contract: %s: §11.5 fuzz table: target %s has result %q, want exactly PASS", wireProfileDocRelPath, target, result)
		}
		gotTargets = append(gotTargets, target)
	}
	sort.Strings(gotTargets)
	wantTargets := append([]string(nil), phase3FuzzTargetNames...)
	sort.Strings(wantTargets)
	if !stringSlicesEqual(gotTargets, wantTargets) {
		t.Fatalf("wire_profile_contract: %s: §11.5 fuzz table names targets %v, want exactly the historically recorded %v", wireProfileDocRelPath, gotTargets, wantTargets)
	}
}

// TestWireProfileContract_CurrentFuzzTargetsExist is the permanent,
// current-profile contract that §11.5's historical fuzz-target check used
// to also perform inline: each of the five named fuzz targets is a real
// exported Fuzz func declared somewhere in internal/ldap/profile's test
// files today (never proof any target was actually run for 20s — only
// that the name is not a typo or a stale reference). Unlike
// TestWireProfileContract_Phase3EvidenceFuzzTable, this test has no
// dependency on §11.5's frozen text and keeps checking the actual current
// tree even after §11.5 itself stops changing.
func TestWireProfileContract_CurrentFuzzTargetsExist(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	profileDir := filepath.Join(root, filepath.FromSlash("internal/ldap/profile"))
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		t.Fatalf("wire_profile_contract: read %s: %v", profileDir, err)
	}
	declared := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(profileDir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("wire_profile_contract: parse %s: %v", e.Name(), err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			declared[fd.Name.Name] = true
		}
	}
	for _, name := range phase3FuzzTargetNames {
		if !declared[name] {
			t.Errorf("wire_profile_contract: current-profile contract names fuzz target %s, but no such func is declared anywhere in internal/ldap/profile's test files", name)
		}
	}
}

// phase3AssertDispositionRows validates that rows contains exactly
// phase3NarrowingIDs, in that exact order, at idCol, and that every value
// at dispCol is the exact string ACCEPT or REJECT — never a variant such as
// "ACCEPT AS DOCUMENTED" (plan "§11.3 narrowing dispositions": "Use exact
// string equality. No prefix grammar and no variants"). Returns the
// ID->disposition map for cross-table comparison.
func phase3AssertDispositionRows(t *testing.T, tableName string, rows [][]string, idCol, dispCol int) map[string]string {
	t.Helper()
	if len(rows) != len(phase3NarrowingIDs) {
		t.Fatalf("wire_profile_contract: %s: %s table has %d rows, want exactly %d (IDs %v)", wireProfileDocRelPath, tableName, len(rows), len(phase3NarrowingIDs), phase3NarrowingIDs)
	}
	out := make(map[string]string, len(rows))
	for i, row := range rows {
		wantID := phase3NarrowingIDs[i]
		id := wireProfileStripCell(row[idCol])
		if id != wantID {
			t.Fatalf("wire_profile_contract: %s: %s table row %d has ID %q, want exactly %q in that position", wireProfileDocRelPath, tableName, i, id, wantID)
		}
		disp := wireProfileStripCell(row[dispCol])
		if disp != "ACCEPT" && disp != "REJECT" {
			t.Fatalf("wire_profile_contract: %s: %s table row ID %s has disposition %q, want exactly the string ACCEPT or REJECT (no prefix grammar, no variants)", wireProfileDocRelPath, tableName, id, disp)
		}
		out[id] = disp
	}
	return out
}

// TestWireProfileContract_Section113NarrowingDispositions validates §11.3's
// full disposition table: exactly the eleven IDs in order, exact-token
// dispositions, and — per the plan — a wire-evidence reference for items
// 1-5/7/8 versus an explicit hardening label for items 6/9/10 in a
// dedicated column separate from the rationale.
func TestWireProfileContract_Section113NarrowingDispositions(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))

	_, rows, err := wireProfileExtractTable(doc, "Evidence / hardening label")
	if err != nil {
		t.Fatalf("wire_profile_contract: %s: §11.3 disposition table: %v", wireProfileDocRelPath, err)
	}
	for _, row := range rows {
		if len(row) != 4 {
			t.Fatalf("wire_profile_contract: %s: §11.3 disposition table row %v has %d cells, want 4 (ID, Disposition, Evidence/hardening label, Rationale)", wireProfileDocRelPath, row, len(row))
		}
	}
	phase3AssertDispositionRows(t, "§11.3", rows, 0, 1)

	for _, row := range rows {
		id := wireProfileStripCell(row[0])
		label := wireProfileStripCell(row[2])
		rationale := wireProfileStripCell(row[3])
		if rationale == "" {
			t.Fatalf("wire_profile_contract: %s: §11.3 disposition row %s has an empty rationale cell", wireProfileDocRelPath, id)
		}
		if phase3HardeningNarrowingIDs[id] {
			if !strings.HasPrefix(label, "hardening:") {
				t.Fatalf("wire_profile_contract: %s: §11.3 disposition row %s must carry an explicit hardening: label (lifecycle/resource/config), got %q", wireProfileDocRelPath, id, label)
			}
		} else {
			if !strings.HasPrefix(label, "wire-evidence:") {
				t.Fatalf("wire_profile_contract: %s: §11.3 disposition row %s must reference wire-evidence:, got %q", wireProfileDocRelPath, id, label)
			}
		}
	}
}

// phase3HistoricalNarrowingDispositions is the locally owned, frozen
// Phase 3 §11.5 record of all eleven narrowing dispositions (every one
// certified ACCEPT). This test no longer cross-checks §11.5 against §11.3:
// §11.3 is current engineering prose outside the frozen marker pair and is
// free to keep evolving after Phase 3 (its own structural shape stays
// separately enforced by TestWireProfileContract_Section113NarrowingDispositions
// below) — a historical record must be checked against a frozen fact, not
// against another document section that can legitimately change later.
var phase3HistoricalNarrowingDispositions = map[string]string{
	"1": "ACCEPT", "1a": "ACCEPT", "2": "ACCEPT", "3": "ACCEPT", "4": "ACCEPT",
	"5": "ACCEPT", "6": "ACCEPT", "7": "ACCEPT", "8": "ACCEPT", "9": "ACCEPT", "10": "ACCEPT",
}

// TestWireProfileContract_Phase3EvidenceDispositionsMatchSection113 requires
// §11.5's compact ID/Disposition table to still read back exactly the
// eleven dispositions Phase 3 certified (phase3HistoricalNarrowingDispositions
// above) — a frozen historical fact, never a live comparison against
// §11.3's current table.
func TestWireProfileContract_Phase3EvidenceDispositionsMatchSection113(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	_, section115Rows, err := wireProfileExtractTable(section, "ID", "Disposition")
	if err != nil {
		t.Fatalf("wire_profile_contract: %s: §11.5 disposition table: %v", wireProfileDocRelPath, err)
	}
	for _, row := range section115Rows {
		if len(row) != 2 {
			t.Fatalf("wire_profile_contract: %s: §11.5 disposition table row %v has %d cells, want 2 (ID, Disposition)", wireProfileDocRelPath, row, len(row))
		}
	}
	section115 := phase3AssertDispositionRows(t, "§11.5", section115Rows, 0, 1)

	for _, id := range phase3NarrowingIDs {
		want, ok := phase3HistoricalNarrowingDispositions[id]
		if !ok {
			t.Fatalf("wire_profile_contract: internal test error: no historical disposition recorded for narrowing %s", id)
		}
		if got := section115[id]; got != want {
			t.Fatalf("wire_profile_contract: %s: §11.5 narrowing %s is %q, want the historically certified %q", wireProfileDocRelPath, id, got, want)
		}
	}
}

// TestWireProfileContract_Phase3EvidenceLOC requires §11.5's LOC guardrail
// fields to still read back exactly the historical Phase 3 record: the
// Merged Phase 2 baseline "2682" pinned to commit "e26e30f", Final Phase 3
// LOC "2702", and Phase 3 delta "+20". Issue #33 phase 4 removed this
// test's prior fresh-current-tree recount (which compared the recorded
// Final Phase 3 LOC against a live git-ls-files count of
// internal/ldap/profile's non-test .go files): that comparison made a
// historical §11.5 fact depend on the CURRENT tree, which stops being true
// the moment phase 4's own LOC accounting changes profile.go's contents or
// adds cmd/ch-oauth-ldap/ldap_backend.go to what counts as production LDAP
// LOC. phase3FreshProfileLOC below is kept, unused by this historical
// test, for Phase 4's own current-tree LOC accounting to reuse.
func TestWireProfileContract_Phase3EvidenceLOC(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	baseline := phase3EvidenceField(t, section, "Merged Phase 2 baseline")
	if baseline != "2682" {
		t.Fatalf("wire_profile_contract: %s: §11.5 Merged Phase 2 baseline is %q, want exactly the historically recorded \"2682\"", wireProfileDocRelPath, baseline)
	}
	if !strings.Contains(section, "pinned to `e26e30f`") {
		t.Fatalf("wire_profile_contract: %s: §11.5 must pin the merged Phase 2 baseline to commit `e26e30f`", wireProfileDocRelPath)
	}

	finalLOCStr := phase3EvidenceField(t, section, "Final Phase 3 LOC")
	if finalLOCStr != "2702" {
		t.Fatalf("wire_profile_contract: %s: §11.5 Final Phase 3 LOC is %q, want exactly the historically recorded \"2702\" — this is a frozen fact about tested_behavior_head, never recomputed against the current tree", wireProfileDocRelPath, finalLOCStr)
	}

	deltaStr := phase3EvidenceField(t, section, "Phase 3 delta")
	if deltaStr != "+20" {
		t.Fatalf("wire_profile_contract: %s: §11.5 Phase 3 delta is %q, want exactly the historically recorded \"+20\"", wireProfileDocRelPath, deltaStr)
	}
}

// phase3FreshProfileLOC independently recomputes internal/ldap/profile's
// current non-test physical LOC using exactly the plan's own definition:
// `git ls-files 'internal/ldap/profile/*.go' | grep -v '_test.go$' | xargs
// wc -l`, summed. It reads working-tree bytes (not git blobs) and counts
// newline bytes, matching `wc -l` for gofmt'd Go source (which always ends
// in a trailing newline). Kept intact, though no longer called by any
// historical §11.5 test above, so a later Phase 4 task in this same
// package can reuse it for the current-tree LOC accounting §11.6 records
// (see docs/clickhouse-ldap-wire-profile.md's Phase 4 plan, "Final LOC
// accounting": "Do not reuse Phase 3's profile-only helper as the final
// Phase 4 total" — reuse for the profile-only component is still expected).
func phase3FreshProfileLOC(t *testing.T, root string) int {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "--", "internal/ldap/profile/*.go") //nolint:gosec // fixed argv, no user input
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("wire_profile_contract: fresh LOC recount: git ls-files: %v\nstderr:\n%s", err, stderr.String())
	}
	total := 0
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(line)))
		if err != nil {
			t.Fatalf("wire_profile_contract: fresh LOC recount: read %s: %v", line, err)
		}
		total += bytes.Count(data, []byte("\n"))
	}
	return total
}

// TestWireProfileContract_Phase3EvidenceTLSRow requires §11.5's TLS
// applicability field to reference issue #31 and read exactly the plan's
// literal N/A/out-of-scope sentence, never a bare "N/A" or "PASS".
func TestWireProfileContract_Phase3EvidenceTLSRow(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	const want = "N/A — issue #31 is a separate open unit and is out of scope for #33 Phase 3"
	if !strings.Contains(phase3CollapseWhitespace(section), want) {
		t.Fatalf("wire_profile_contract: %s: §11.5 TLS applicability must read exactly %q", wireProfileDocRelPath, want)
	}
}

// TestWireProfileContract_Phase3EvidenceRedactionAndReleaseGate requires
// §11.5 to record both the phase5release vet and test results as PASS.
func TestWireProfileContract_Phase3EvidenceRedactionAndReleaseGate(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	flat := phase3CollapseWhitespace(section)
	for _, needle := range []string{
		"**`phase5release` vet:** `PASS`",
		"**`phase5release` test:** `PASS`",
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("wire_profile_contract: %s: §11.5 must record %q", wireProfileDocRelPath, needle)
		}
	}
}

// certifiedSurfacePatterns is a literal transcription of the plan's
// "Certified-surface anti-drift digest" file-selection list (git pathspec
// patterns, non-recursive per named directory except where ** is used).
// Changing this list is changing what the digest certifies — do so only in
// lockstep with the plan section it implements. This is the same pathset
// issue #33 phase 4's plan directs be reused, unchanged, for the Phase 4
// live digest contract (§11.6) — including keeping "third_party/**" even
// after that directory is deleted at cutover, so an eventual reintroduction
// would again alter the digest.
var certifiedSurfacePatterns = []string{
	"go.mod",
	"go.sum",
	"cmd/ch-oauth-ldap/*.go",
	"cmd/synthetic-idp/*.go",
	"internal/identity/*.go",
	"internal/roles/*.go",
	"internal/verification/*.go",
	"internal/ldap/profile/*.go",
	"internal/wirefixture/*.go",
	"integration/clickhouse/wirecapture/*.go",
	"integration/clickhouse/ha/session-probe/*.go",
	"third_party/**",
	"internal/ldap/testdata/clickhouse-wire/**",
	"integration/clickhouse/Dockerfile",
	"integration/clickhouse/compose.yml",
	"integration/clickhouse/compose-ha.yml",
	"integration/clickhouse/compose-wirecapture.yml",
	"integration/clickhouse/run.sh",
	"integration/clickhouse/run-all-builds.sh",
	"integration/clickhouse/run-ha.sh",
	"integration/clickhouse/capture-ldap-wire.sh",
	"integration/clickhouse/lib/**",
	"integration/clickhouse/scenarios/**",
	"integration/clickhouse/bootstrap/**",
	"integration/clickhouse/helper/**",
	"integration/clickhouse/clickhouse/**",
	"integration/clickhouse/ha/haproxy.cfg",
}

// computeCertifiedSurfaceDigest independently reproduces the plan's
// "Certified-surface anti-drift digest" algorithm in Go: for every tracked
// path matching certifiedSurfacePatterns (deduplicated, non-test .go files
// excluded), sorted byte-wise, stream "<path> NUL <file-bytes> NUL" into one
// SHA-256. This must never itself compute the verdict a Docker/fuzz command
// ran — it only proves the source it is pointed at hashes to a given
// value. No historical §11.5 test above calls this any longer (§11.5 is
// now checked as a frozen record, never recomputed against a later tree —
// see TestWireProfileContract_Phase3EvidenceCertifiedSurfaceDigestMatches);
// it is kept intact for a later Phase 4 task in this package to reuse for
// §11.6's own current-tree live digest contract.
func computeCertifiedSurfaceDigest(t *testing.T, root string) (digestHex string, fileCount int) {
	t.Helper()
	seen := map[string]bool{}
	var all []string
	for _, pat := range certifiedSurfacePatterns {
		cmd := exec.Command("git", "ls-files", "--", pat) //nolint:gosec // fixed argv, no user input
		cmd.Dir = root
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("wire_profile_contract: certified-surface digest: git ls-files -- %q: %v\nstderr:\n%s", pat, err, stderr.String())
		}
		for _, line := range strings.Split(stdout.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !seen[line] {
				seen[line] = true
				all = append(all, line)
			}
		}
	}

	var filtered []string
	for _, p := range all {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		filtered = append(filtered, p)
	}
	sort.Strings(filtered)

	h := sha256.New()
	for _, p := range filtered {
		h.Write([]byte(p))
		h.Write([]byte{0})
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatalf("wire_profile_contract: certified-surface digest: read tracked file %s: %v", p, err)
		}
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), len(filtered)
}

// phase3HistoricalCertifiedSurfaceDigest and
// phase3HistoricalCertifiedSurfaceFileCount are the locally owned, frozen
// Phase 3 §11.5 certified-surface digest facts, recorded once at Stage B
// manual certification and never recomputed thereafter.
const phase3HistoricalCertifiedSurfaceDigest = "90619015fcb4965888a0e090474f8ed11d7991a7bc24b67e71b7251147b52c48"
const phase3HistoricalCertifiedSurfaceFileCount = 173

// TestWireProfileContract_Phase3EvidenceCertifiedSurfaceDigestMatches
// requires §11.5 to still read back exactly the certified-surface digest
// and tracked-file count Phase 3's Stage B manual certification recorded.
// Issue #33 phase 4 replaced this test's prior live recomputation
// (independently reproducing the digest algorithm over the CURRENT tree
// and requiring equality) with this frozen-record check: the certified
// surface's own file set (certifiedSurfacePatterns) is expected to change
// at cutover — that is the whole point of Phase 4 — so a §11.5 test that
// recomputed against today's tree would necessarily start failing the
// moment cutover touched any certified-surface path, even though §11.5's
// recorded bytes describe Phase 3's tested_behavior_head correctly and
// truthfully. computeCertifiedSurfaceDigest and certifiedSurfacePatterns
// are kept intact, unused by this historical test, for Phase 4's own
// current-tree digest contract (§11.6) to reuse.
func TestWireProfileContract_Phase3EvidenceCertifiedSurfaceDigestMatches(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("wire_profile_contract: locate module root: %v", err)
	}
	doc := string(wireProfileReadFile(t, root, wireProfileDocRelPath))
	section := phase3EvidenceSection(t, doc)

	recorded := phase3EvidenceField(t, section, "Certified-surface digest (SHA-256)")
	if recorded != phase3HistoricalCertifiedSurfaceDigest {
		t.Fatalf("wire_profile_contract: %s: §11.5 records certified-surface digest %s, want exactly the historically certified %s — this is a frozen fact about tested_behavior_head and must never be edited to match a later tree; a mismatch means §11.5's recorded bytes were altered, which §11.5 forbids", wireProfileDocRelPath, recorded, phase3HistoricalCertifiedSurfaceDigest)
	}

	flat := phase3CollapseWhitespace(section)
	wantFileCountNeedle := fmt.Sprintf("reproduced 3× identically over %d tracked files", phase3HistoricalCertifiedSurfaceFileCount)
	if !strings.Contains(flat, wantFileCountNeedle) {
		t.Fatalf("wire_profile_contract: %s: §11.5 must record %q", wireProfileDocRelPath, wantFileCountNeedle)
	}
}
