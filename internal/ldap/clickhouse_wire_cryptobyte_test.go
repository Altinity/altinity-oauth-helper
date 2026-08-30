package ldap

// This file implements issue #33 phase 1's cryptobyte characterization and
// primitive-layer decision (plan §32, §33, §31's closure-must-stay-unchanged
// invariant): it loads every committed ClickHouse/libldap wire-evidence
// fixture (internal/ldap/testdata/clickhouse-wire — captured-redacted and
// constructed alike) through internal/wirefixture, characterizes each one
// with golang.org/x/crypto/cryptobyte plus a handful of fixed first-party
// checks cryptobyte's tag-fixed high-level readers cannot express on their
// own, runs a bounded set of invalid-form mutations to prove they are
// rejected, and computes the plan §32 primitive-layer verdict:
//
//   - "cryptobyte" iff every valid fixture is safely consumable by
//     cryptobyte plus those fixed checks;
//   - "local-ber-cursor" iff some valid fixture needs a BER form cryptobyte
//     cannot safely consume.
//
// Malformed-input rejection (the negative-mutation half of this file) never
// justifies "local-ber-cursor" — only a genuine valid-fixture parse failure
// does (plan §32 "Decision"). "Genuine" is not taken on cryptobyte's own
// say-so: a cryptobyte characterization failure is corroborated by
// independentlyWellFormedBER, a second, structurally distinct BER decoder
// (the vendored, patched github.com/vjeantet/goldap message package — the
// same decoder internal/ldap's production Bind/Search/Unbind/Abandon
// handlers already run) before it may flip the verdict. A fixture that
// BOTH decoders reject is fixture corruption, not evidence for
// local-ber-cursor, and fails the test outright (see the per-case loop in
// TestClickHouseWireCryptobyteDecision) — this closes the sabotage path
// where corrupting a single non-template fixture and updating only its own
// session.json hash would otherwise flip the computed verdict unnoticed.
//
// This test is the SOLE owner of the cryptobyte verdict (plan §33):
// internal/securitytest's wire-profile contract (a separate sub-task) only
// checks the decision-doc marker's syntax/uniqueness, never recomputes this
// algorithm.
//
// golang.org/x/crypto/cryptobyte is deliberately imported only from this
// _test.go file. internal/securitytest/dependency_contract_test.go's
// TestDependencyContract_NoNonStandardCryptobyte proves that import never
// reaches ./cmd/ch-oauth-ldap's production closure — `go list -deps`
// against a production package target never follows a dependency's own
// _test.go imports, so this file's cryptobyte usage cannot leak there
// regardless of what internal/ldap's non-test files import.
//
// # Scope of the BER forms characterized
//
// The fixtures committed for phase 1 (plan §8.3/§22's recorder scope) cover
// exactly: a version-3 simple Bind, a Search with an AND(equalityMatch,
// equalityMatch) filter and no controls, an Abandon targeting the Search's
// MessageID, and an Unbind — plus the constructed MessageID 127/128
// boundary Binds (plan §29). The characterizers below are intentionally
// narrow to that shape (e.g. only the "and"/"equalityMatch" filter context
// tags, no SASL choice, no controls): anything outside that shape is
// rejected by the same default-case/trailing-data checks the negative
// mutations exercise, which is the correct behavior for a characterization
// of what ClickHouse's libldap client actually sends, not a general LDAP
// BER decoder.
//
// # Error hygiene
//
// Every error returned by the characterizers below reports only structural
// information — a field name, a tag byte, a length, a fixture path — never
// raw fixture bytes (there is no credential in any committed fixture, but
// the discipline is kept consistent with the rest of this package).

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	goldapmessage "github.com/vjeantet/goldap/message"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// BER application/context tags this characterization supports. Named
// individually, matching wirefixture/constructed.go's own convention,
// because this is a characterization of one fixed, narrow protocol profile
// rather than a general BER/LDAP tag table.
const (
	tagBindRequest    = asn1.Tag(0x60) // [APPLICATION 0], constructed — BindRequest
	tagUnbindRequest  = asn1.Tag(0x42) // [APPLICATION 2], primitive — UnbindRequest (NULL)
	tagSearchRequest  = asn1.Tag(0x63) // [APPLICATION 3], constructed — SearchRequest
	tagAbandonRequest = asn1.Tag(0x50) // [APPLICATION 16], primitive — AbandonRequest (implicit MessageID)

	tagFilterAnd           = asn1.Tag(0xa0) // [0] SET OF Filter, constructed
	tagFilterEqualityMatch = asn1.Tag(0xa3) // [3] AttributeValueAssertion, constructed
)

// tagSimpleAuth is AuthenticationChoice::simple, [0] context-specific
// primitive.
var tagSimpleAuth = asn1.Tag(0).ContextSpecific()

// filterMaxDepth bounds characterizeFilter's recursion. The captured
// fixtures nest one level (AND of two equalityMatch terms); this bound only
// guards against a pathological mutation, not any real captured shape.
const filterMaxDepth = 8

// ldapMessageSummary is what characterizeLDAPMessage extracts from a valid
// LDAPMessage, for cross-checking against the fixture's own committed PDU
// metadata (wirefixture.PDU).
type ldapMessageSummary struct {
	MessageID     uint32
	Operation     string
	AbandonTarget *int
}

// characterizeLDAPMessage decodes raw as a complete, single LDAPMessage
// using cryptobyte, enforcing every "accepted safely" property from plan
// §32: the outer SEQUENCE is consumed completely with no trailing input at
// either level, MessageID is canonical (definite-length, non-negative,
// minimally encoded — which cryptobyte's checkASN1Integer/asn1Unsigned
// already enforce for any universal INTEGER read through
// ReadASN1Integer), the protocolOp carries a supported application tag, and
// controls (never present in any phase-1 fixture) are treated as
// unsupported trailing content rather than silently skipped.
func characterizeLDAPMessage(raw []byte) (ldapMessageSummary, error) {
	var summary ldapMessageSummary

	s := cryptobyte.String(raw)
	var outer cryptobyte.String
	if !s.ReadASN1(&outer, asn1.SEQUENCE) {
		return summary, fmt.Errorf("outer LDAPMessage: not a complete, definite-length SEQUENCE")
	}
	if !s.Empty() {
		return summary, fmt.Errorf("trailing bytes after the outer LDAPMessage")
	}

	var messageID uint32
	if !outer.ReadASN1Integer(&messageID) {
		return summary, fmt.Errorf("MessageID: not a canonical (definite-length, minimally encoded, non-negative) INTEGER")
	}
	summary.MessageID = messageID

	var opContent cryptobyte.String
	var opTag asn1.Tag
	if !outer.ReadAnyASN1(&opContent, &opTag) {
		return summary, fmt.Errorf("protocolOp: malformed element")
	}

	switch opTag {
	case tagBindRequest:
		summary.Operation = wirefixture.OperationBindRequest
		if err := characterizeBindRequest(opContent); err != nil {
			return summary, fmt.Errorf("bindRequest: %w", err)
		}
	case tagSearchRequest:
		summary.Operation = wirefixture.OperationSearchRequest
		if err := characterizeSearchRequest(opContent); err != nil {
			return summary, fmt.Errorf("searchRequest: %w", err)
		}
	case tagUnbindRequest:
		summary.Operation = wirefixture.OperationUnbindRequest
		if len(opContent) != 0 {
			return summary, fmt.Errorf("unbindRequest: expected empty (NULL) content, got %d byte(s)", len(opContent))
		}
	case tagAbandonRequest:
		summary.Operation = wirefixture.OperationAbandonRequest
		target, err := validateImplicitPositiveInteger([]byte(opContent))
		if err != nil {
			return summary, fmt.Errorf("abandonRequest: target MessageID: %w", err)
		}
		t := int(target)
		summary.AbandonTarget = &t
	default:
		return summary, fmt.Errorf("protocolOp: unsupported application tag 0x%02x", byte(opTag))
	}

	if !outer.Empty() {
		return summary, fmt.Errorf("trailing bytes after protocolOp (e.g. an unsupported control — this profile's fixtures never carry one)")
	}
	return summary, nil
}

// independentlyWellFormedBER reports whether raw is a complete, well-formed
// BER LDAPMessage according to a *second, structurally independent* decoder
// — the vendored, patched github.com/vjeantet/goldap message package
// (third_party/goldap/message), which internal/ldap's production
// Bind/Search/Unbind/Abandon handlers already consume via
// third_party/ldapserver — rather than trusting characterizeLDAPMessage's
// own verdict about validity. It is the independent-validity gate plan §32
// requires before a cryptobyte characterization failure may be treated as
// "a valid form cryptobyte cannot safely consume" (the local-ber-cursor
// justification) instead of "this fixture is malformed" (which must stay
// fatal regardless of what cryptobyte made of it).
//
// goldap/message's reader is derived from Go's stdlib encoding/asn1 tag/
// length parser (see third_party/goldap/message/asn1.go's "BEGIN
// encoding/asn1/asn1.go" block), so it independently enforces DER-style
// minimal-length and definite-length encoding the same way cryptobyte does,
// via a completely separate implementation with its own bug surface —
// exactly the second-implementation property an anti-drift check on a
// single self-referential hash (internal/securitytest's fixture-corpus
// check) cannot provide on its own.
//
// message.ReadLDAPMessage only checks that its own SEQUENCE content is
// fully consumed, not that nothing follows that SEQUENCE in raw, so this
// helper additionally requires the outer *Bytes cursor to have no
// remaining data afterward — mirroring characterizeLDAPMessage's own
// "trailing bytes after the outer LDAPMessage" check.
func independentlyWellFormedBER(raw []byte) error {
	cursor := goldapmessage.NewBytes(0, raw)
	if _, err := goldapmessage.ReadLDAPMessage(cursor); err != nil {
		return fmt.Errorf("goldap BER decoder: %w", err)
	}
	if cursor.HasMoreData() {
		return fmt.Errorf("goldap BER decoder: trailing bytes after the outer LDAPMessage")
	}
	return nil
}

// characterizeBindRequest checks the "Bind version/simple-auth context"
// property: version is the canonical INTEGER 3, name is a non-empty
// OCTET STRING (the Bind DN), authentication is exactly the supported [0]
// simple context tag, and nothing follows (no SASL choice, no other
// trailing field).
func characterizeBindRequest(content cryptobyte.String) error {
	var version uint8
	if !content.ReadASN1Integer(&version) {
		return fmt.Errorf("version: not a canonical non-negative INTEGER")
	}
	if version != 3 {
		return fmt.Errorf("version: unsupported Bind version %d (only version 3 is in this profile's scope)", version)
	}

	var name []byte
	if !content.ReadASN1Bytes(&name, asn1.OCTET_STRING) {
		return fmt.Errorf("name: not a canonical OCTET STRING")
	}
	if len(name) == 0 {
		return fmt.Errorf("name: empty Bind DN")
	}

	var simple []byte
	if !content.ReadASN1Bytes(&simple, tagSimpleAuth) {
		return fmt.Errorf("authentication: not the supported [0] simple context tag")
	}

	if !content.Empty() {
		return fmt.Errorf("unexpected trailing field after simple authentication (e.g. an unsupported SASL choice)")
	}
	return nil
}

// characterizeSearchRequest checks the "Search ENUMERATED/INTEGER/BOOLEAN
// forms", "supported filter context tags", and "attributes" properties.
func characterizeSearchRequest(content cryptobyte.String) error {
	var base []byte
	if !content.ReadASN1Bytes(&base, asn1.OCTET_STRING) {
		return fmt.Errorf("baseObject: not a canonical OCTET STRING")
	}

	var scope int
	if !content.ReadASN1Enum(&scope) {
		return fmt.Errorf("scope: not a canonical ENUMERATED")
	}
	if scope < 0 || scope > 2 {
		return fmt.Errorf("scope: value %d outside the defined baseObject(0)/singleLevel(1)/wholeSubtree(2) range", scope)
	}

	var derefAliases int
	if !content.ReadASN1Enum(&derefAliases) {
		return fmt.Errorf("derefAliases: not a canonical ENUMERATED")
	}
	if derefAliases < 0 || derefAliases > 3 {
		return fmt.Errorf("derefAliases: value %d outside the defined 0..3 range", derefAliases)
	}

	var sizeLimit, timeLimit uint32
	if !content.ReadASN1Integer(&sizeLimit) {
		return fmt.Errorf("sizeLimit: not a canonical non-negative INTEGER")
	}
	if !content.ReadASN1Integer(&timeLimit) {
		return fmt.Errorf("timeLimit: not a canonical non-negative INTEGER")
	}

	var typesOnly bool
	if !content.ReadASN1Boolean(&typesOnly) {
		return fmt.Errorf("typesOnly: not a canonical BOOLEAN")
	}

	if err := characterizeFilter(&content, 0); err != nil {
		return fmt.Errorf("filter: %w", err)
	}

	var attrs cryptobyte.String
	if !content.ReadASN1(&attrs, asn1.SEQUENCE) {
		return fmt.Errorf("attributes: not a canonical SEQUENCE")
	}
	for !attrs.Empty() {
		var attr []byte
		if !attrs.ReadASN1Bytes(&attr, asn1.OCTET_STRING) {
			return fmt.Errorf("attributes: element is not a canonical OCTET STRING")
		}
		if len(attr) == 0 {
			return fmt.Errorf("attributes: empty attribute description")
		}
	}

	if !content.Empty() {
		return fmt.Errorf("unexpected trailing field after attributes")
	}
	return nil
}

// characterizeFilter recursively characterizes a Filter CHOICE element,
// supporting exactly the context tags the phase-1 fixtures use: "and" and
// "equalityMatch". Any other context tag is rejected by the default case,
// which is what the "wrong tags"/negative-mutation coverage for filters
// exercises.
func characterizeFilter(content *cryptobyte.String, depth int) error {
	if depth > filterMaxDepth {
		return fmt.Errorf("nesting exceeds bound %d", filterMaxDepth)
	}

	var body cryptobyte.String
	var tag asn1.Tag
	if !content.ReadAnyASN1(&body, &tag) {
		return fmt.Errorf("malformed filter element")
	}

	switch tag {
	case tagFilterAnd:
		if len(body) == 0 {
			return fmt.Errorf("and: empty SET OF Filter")
		}
		for !body.Empty() {
			if err := characterizeFilter(&body, depth+1); err != nil {
				return fmt.Errorf("and: %w", err)
			}
		}
	case tagFilterEqualityMatch:
		var attrDesc, attrValue []byte
		if !body.ReadASN1Bytes(&attrDesc, asn1.OCTET_STRING) {
			return fmt.Errorf("equalityMatch: attribute description is not a canonical OCTET STRING")
		}
		if len(attrDesc) == 0 {
			return fmt.Errorf("equalityMatch: empty attribute description")
		}
		if !body.ReadASN1Bytes(&attrValue, asn1.OCTET_STRING) {
			return fmt.Errorf("equalityMatch: assertion value is not a canonical OCTET STRING")
		}
		if !body.Empty() {
			return fmt.Errorf("equalityMatch: unexpected trailing field")
		}
	default:
		return fmt.Errorf("unsupported filter context tag 0x%02x (only 'and'/'equalityMatch' are in this profile's captured scope)", byte(tag))
	}
	return nil
}

// validateImplicitPositiveInteger is a fixed first-party profile check
// (plan §32): LDAP's AbandonRequest ::= [APPLICATION 16] MessageID is an
// INTEGER value carried under a non-universal *implicit* tag, so
// cryptobyte's high-level integer readers — which hard-code the universal
// INTEGER tag internally — cannot be used on it directly. This mirrors
// cryptobyte's own unexported DER minimality/sign checks
// (checkASN1Integer/asn1Unsigned in golang.org/x/crypto/cryptobyte/asn1.go)
// by hand, bounded to uint32 since no tracked MessageID exceeds it.
func validateImplicitPositiveInteger(content []byte) (uint32, error) {
	if len(content) == 0 {
		return 0, fmt.Errorf("empty INTEGER content")
	}
	if len(content) > 1 {
		if content[0] == 0x00 && content[1]&0x80 == 0 {
			return 0, fmt.Errorf("non-minimal encoding (redundant leading 0x00)")
		}
		if content[0] == 0xff && content[1]&0x80 != 0 {
			return 0, fmt.Errorf("non-minimal encoding (redundant leading 0xff)")
		}
	}
	if content[0]&0x80 != 0 {
		return 0, fmt.Errorf("negative INTEGER not supported by this profile")
	}
	if len(content) > 5 || (len(content) == 5 && content[0] != 0x00) {
		return 0, fmt.Errorf("INTEGER too large for uint32")
	}
	var v uint64
	for _, b := range content {
		v = v<<8 | uint64(b)
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("INTEGER too large for uint32")
	}
	return uint32(v), nil
}

// fixtureCase is one loaded, committed PDU (.ber file plus its wirefixture
// metadata) to characterize.
type fixtureCase struct {
	Label string
	Path  string
	Raw   []byte
	PDU   wirefixture.PDU
}

// loadFixtureCases loads every captured (per tracked line, per session) and
// constructed PDU under fixtureRoot via wirefixture's reader API, in the
// order plan §32 step 1 requires ("loads every valid captured/constructed
// supported request").
func loadFixtureCases(t *testing.T, fixtureRoot string, lines []string) []fixtureCase {
	t.Helper()
	var cases []fixtureCase

	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		profile, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
		if err != nil {
			t.Fatalf("read profile.json for line %s: %v", line, err)
		}
		if len(profile.SessionPaths) == 0 {
			t.Fatalf("line %s: profile.json lists no session_paths", line)
		}
		for _, sp := range profile.SessionPaths {
			sessDir := wirefixture.SessionDir(lineDir, sp)
			cases = append(cases, loadSessionCases(t, fmt.Sprintf("%s/%s", line, sp), sessDir)...)
		}
	}

	constructedDir := wirefixture.ConstructedDir(fixtureRoot)
	entries, err := os.ReadDir(constructedDir)
	if err != nil {
		t.Fatalf("read constructed fixture dir %s: %v", constructedDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			t.Fatalf("constructed fixture dir %s: unexpected non-directory entry %q", constructedDir, e.Name())
		}
		sessDir := filepath.Join(constructedDir, e.Name())
		cases = append(cases, loadSessionCases(t, fmt.Sprintf("constructed/%s", e.Name()), sessDir)...)
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].Label < cases[j].Label })
	return cases
}

func loadSessionCases(t *testing.T, label, sessDir string) []fixtureCase {
	t.Helper()
	sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
	if err != nil {
		t.Fatalf("read session.json for %s: %v", label, err)
	}
	if len(sess.PDUs) == 0 {
		t.Fatalf("session %s: no PDUs recorded", label)
	}
	cases := make([]fixtureCase, 0, len(sess.PDUs))
	for _, pdu := range sess.PDUs {
		path := filepath.Join(sessDir, pdu.Filename)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read PDU file %s: %v", path, err)
		}
		cases = append(cases, fixtureCase{
			Label: fmt.Sprintf("%s/%s", label, pdu.Filename),
			Path:  path,
			Raw:   raw,
			PDU:   pdu,
		})
	}
	return cases
}

// decisionMarkerPattern matches the plan §33 decision marker exactly.
var decisionMarkerPattern = regexp.MustCompile(`<!--\s*ldap-primitive-decision:\s*(cryptobyte|local-ber-cursor)\s*-->`)

// TestClickHouseWireCryptobyteDecision is the named decision test (plan
// §32): it loads every committed fixture, characterizes each with
// cryptobyte plus this file's fixed first-party checks, runs the bounded
// negative-mutation set, computes the primitive-layer verdict, and requires
// the wire-profile doc's decision marker to agree with it exactly (plan
// §33).
func TestClickHouseWireCryptobyteDecision(t *testing.T) {
	moduleRoot, err := wirefixture.ModuleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	fixtureRoot := wirefixture.ClickHouseWireFixtureRoot(moduleRoot)
	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("validate fixture root %s: %v", fixtureRoot, err)
	}
	if len(lines) == 0 {
		t.Fatalf("fixture root %s: no tracked-line directories found", fixtureRoot)
	}

	cases := loadFixtureCases(t, fixtureRoot, lines)
	if len(cases) == 0 {
		t.Fatalf("no PDU fixtures found under %s", fixtureRoot)
	}

	cryptobyteSafe := true
	for _, c := range cases {
		c := c
		t.Run("characterize/"+c.Label, func(t *testing.T) {
			summary, err := characterizeLDAPMessage(c.Raw)
			if err != nil {
				// A committed fixture is *supposed* to be, by
				// construction, a valid, real-ClickHouse-captured wire
				// form — but that assumption is exactly what a
				// corrupted-fixture sabotage would violate, and nothing
				// upstream (the fixture-corpus anti-drift check compares
				// bytes only to a hash stored in the same session.json)
				// enforces it independently. So a cryptobyte failure is
				// never, on its own, treated as "cryptobyte cannot
				// consume this valid form": independentlyWellFormedBER
				// must first corroborate, with a second, structurally
				// independent BER decoder, that these bytes really are a
				// complete, well-formed LDAPMessage before that failure
				// counts as local-ber-cursor evidence. If the independent
				// decoder rejects it too, this is fixture corruption (or
				// a genuinely malformed committed fixture), not a
				// primitive-layer decision, and must fail loudly rather
				// than silently flip the verdict.
				if wfErr := independentlyWellFormedBER(c.Raw); wfErr != nil {
					t.Fatalf(
						"%s: cryptobyte characterization failed (%v), AND the independent goldap BER decoder also rejected it (%v) — "+
							"this fixture is not valid, well-formed BER, so its cryptobyte failure cannot be used as local-ber-cursor "+
							"evidence; treat this as fixture corruption (or a genuinely malformed committed fixture), not a primitive-layer decision",
						c.Path, err, wfErr,
					)
					return
				}
				// The independent decoder confirms this is genuinely
				// valid, well-formed BER that cryptobyte nonetheless
				// cannot safely consume — exactly the local-ber-cursor
				// decision this test exists to compute, not a test
				// failure in itself: t.Logf (not t.Errorf/t.Fatalf)
				// records why, cryptobyteSafe flips to false, and
				// decision-marker-agreement below is what actually
				// enforces the resulting verdict against the doc's
				// committed marker. Fatal-ing this subtest would make the
				// local-ber-cursor branch of that verdict mechanically
				// unable to ever produce a passing run, even when
				// correctly computed and in full agreement with the doc.
				cryptobyteSafe = false
				t.Logf("cryptobyte could not safely characterize %s (independently confirmed valid BER; selecting local-ber-cursor primitive): %v", c.Path, err)
				return
			}
			if summary.Operation != c.PDU.Operation {
				t.Errorf("%s: parsed operation %q does not match committed metadata operation %q", c.Path, summary.Operation, c.PDU.Operation)
			}
			if int(summary.MessageID) != c.PDU.MessageID {
				t.Errorf("%s: parsed MessageID %d does not match committed metadata MessageID %d", c.Path, summary.MessageID, c.PDU.MessageID)
			}
			switch {
			case (summary.AbandonTarget == nil) != (c.PDU.AbandonTarget == nil):
				t.Errorf("%s: abandon-target presence does not match committed metadata", c.Path)
			case summary.AbandonTarget != nil && *summary.AbandonTarget != *c.PDU.AbandonTarget:
				t.Errorf("%s: parsed abandon target %d does not match committed metadata %d", c.Path, *summary.AbandonTarget, *c.PDU.AbandonTarget)
			}
		})
	}

	t.Run("negative-mutations", func(t *testing.T) {
		testNegativeMutations(t, cases)
	})

	// Every currently-committed fixture must independently confirm as
	// well-formed BER on its own, regardless of what cryptobyte made of
	// it — this is the direction of the independent-validity check that
	// runs unconditionally (not gated behind a cryptobyte failure), so a
	// fixture that is malformed in a way cryptobyte's narrower profile
	// characterizers happen not to notice still gets caught here.
	for _, c := range cases {
		c := c
		t.Run("independently-well-formed/"+c.Label, func(t *testing.T) {
			if err := independentlyWellFormedBER(c.Raw); err != nil {
				t.Errorf("%s: independent goldap BER decoder rejects this committed fixture as malformed: %v", c.Path, err)
			}
		})
	}

	verdict := "cryptobyte"
	if !cryptobyteSafe {
		verdict = "local-ber-cursor"
	}

	// docs/clickhouse-ldap-wire-profile.md (plan §33/§34) carries the
	// matching marker; checkDecisionMarkerAgreement's diagnostic explains
	// what to do if a future fixture change ever flips this test's
	// computed verdict out of agreement with it.
	t.Run("decision-marker-agreement", func(t *testing.T) {
		checkDecisionMarkerAgreement(t, moduleRoot, verdict)
	})
}

// checkDecisionMarkerAgreement reads docs/clickhouse-ldap-wire-profile.md
// and requires exactly one plan §33 decision marker whose verdict exactly
// equals verdict (this test's own computed decision — plan §33: "Only
// TestClickHouseWireCryptobyteDecision computes the cryptobyte verdict").
func checkDecisionMarkerAgreement(t *testing.T, moduleRoot, verdict string) {
	t.Helper()

	docPath := filepath.Join(moduleRoot, "docs", "clickhouse-ldap-wire-profile.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf(
			"docs/clickhouse-ldap-wire-profile.md is missing (%v).\n"+
				"This test computed primitive-layer verdict %q. The doc author must "+
				"create docs/clickhouse-ldap-wire-profile.md containing exactly one "+
				"marker:\n\n  <!-- ldap-primitive-decision: %s -->\n",
			err, verdict, verdict,
		)
		return
	}

	matches := decisionMarkerPattern.FindAllSubmatch(data, -1)
	if len(matches) != 1 {
		t.Fatalf(
			"docs/clickhouse-ldap-wire-profile.md must contain exactly one "+
				"<!-- ldap-primitive-decision: cryptobyte|local-ber-cursor --> marker, "+
				"found %d (this test computed verdict %q)",
			len(matches), verdict,
		)
		return
	}

	docVerdict := string(matches[0][1])
	if docVerdict != verdict {
		t.Fatalf(
			"docs/clickhouse-ldap-wire-profile.md's decision marker says %q but "+
				"this test computed verdict %q — the doc's marker must exactly agree "+
				"with TestClickHouseWireCryptobyteDecision's computed verdict",
			docVerdict, verdict,
		)
	}
}

// testNegativeMutations runs the plan §32 bounded invalid-form mutation set
// and asserts every one is rejected. Most mutations are built by mutating a
// byte within a real fixture-derived template (bindTemplate/searchTemplate/
// unbindTemplate, taken verbatim from the committed corpus); the
// "redundant-integer-padding" case is the one exception — it is a fully
// hand-built byte sequence (a minimal SEQUENCE{INTEGER,UnbindRequest} with a
// padded MessageID), not derived from any committed fixture, because no
// committed template happens to exercise that exact encoding shape.
// Malformed-input rejection here never affects the cryptobyte/
// local-ber-cursor verdict computed in the caller (plan §32's "Decision") —
// only a *valid* fixture's characterization failure does.
func testNegativeMutations(t *testing.T, cases []fixtureCase) {
	var bindTemplate, searchTemplate, unbindTemplate []byte
	for _, c := range cases {
		switch c.PDU.Operation {
		case wirefixture.OperationBindRequest:
			if bindTemplate == nil {
				bindTemplate = append([]byte(nil), c.Raw...)
			}
		case wirefixture.OperationSearchRequest:
			if searchTemplate == nil {
				searchTemplate = append([]byte(nil), c.Raw...)
			}
		case wirefixture.OperationUnbindRequest:
			if unbindTemplate == nil {
				unbindTemplate = append([]byte(nil), c.Raw...)
			}
		}
	}
	if bindTemplate == nil || searchTemplate == nil || unbindTemplate == nil {
		t.Fatalf("negative mutations: need at least one bindRequest, one searchRequest, and one unbindRequest fixture as templates")
	}
	if len(unbindTemplate) < 2 || unbindTemplate[1]&0x80 != 0 {
		t.Fatalf("negative mutations: unbindRequest template does not start with a short-form outer length as expected")
	}

	assertAccepted(t, bindTemplate, "bind template sanity check")
	assertAccepted(t, searchTemplate, "search template sanity check")
	assertAccepted(t, unbindTemplate, "unbind template sanity check")

	t.Run("indefinite-length", func(t *testing.T) {
		mutated := append([]byte(nil), bindTemplate...)
		mutated[1] = 0x80 // indefinite-length marker in place of the real length byte
		assertRejected(t, mutated, "indefinite-length outer SEQUENCE")
	})

	t.Run("non-minimal-long-length", func(t *testing.T) {
		// Re-encode the (short) unbind template's outer length using a
		// needlessly long form: one explicit length octet for a value that
		// fits short form (< 0x80).
		contentLen := unbindTemplate[1]
		mutated := append([]byte{unbindTemplate[0], 0x81, contentLen}, unbindTemplate[2:]...)
		assertRejected(t, mutated, "non-minimal long-form outer length")
	})

	t.Run("truncation", func(t *testing.T) {
		mutated := bindTemplate[:len(bindTemplate)-10]
		assertRejected(t, mutated, "truncated BindRequest")
	})

	t.Run("negative-integer-messageid", func(t *testing.T) {
		mutated := mutateAt(t, unbindTemplate, []byte{0x02, 0x01, 0x03, 0x42, 0x00}, 2, 0x03, 0xff)
		assertRejected(t, mutated, "MessageID content with the sign bit set")
	})

	t.Run("redundant-integer-padding", func(t *testing.T) {
		// A hand-crafted Unbind (MessageID=3) whose MessageID INTEGER
		// carries a redundant leading 0x00 content byte: SEQUENCE{
		//   INTEGER len2 [0x00,0x03], UnbindRequest (APPLICATION 2, empty)
		// }.
		mutated := []byte{0x30, 0x06, 0x02, 0x02, 0x00, 0x03, 0x42, 0x00}
		assertRejected(t, mutated, "MessageID with a redundant leading 0x00 padding byte")
	})

	t.Run("malformed-enumerated-value", func(t *testing.T) {
		// scope=2 immediately followed by derefAliases=0, right after the
		// literal Search base DN suffix "dc=internal" — mutate the scope
		// *value* byte to 9, outside the defined 0..2 range, while keeping
		// its ENUMERATED tag intact.
		pattern := append([]byte("dc=internal"), 0x0a, 0x01, 0x02, 0x0a, 0x01, 0x00)
		mutated := mutateAt(t, searchTemplate, pattern, len("dc=internal")+2, 0x02, 0x09)
		assertRejected(t, mutated, "out-of-range scope ENUMERATED value")
	})

	t.Run("malformed-boolean-value", func(t *testing.T) {
		// timeLimit=20 (02 01 14) immediately followed by typesOnly (01 01
		// ..) immediately followed by the filter's "and" tag (a0) — mutate
		// typesOnly's content byte to 0x01, which is neither the canonical
		// 0x00 (false) nor 0xff (true).
		pattern := []byte{0x02, 0x01, 0x14, 0x01, 0x01, 0x00, 0xa0}
		mutated := mutateAt(t, searchTemplate, pattern, 5, 0x00, 0x01)
		assertRejected(t, mutated, "BOOLEAN content byte that is neither 0x00 nor 0xff")
	})

	t.Run("wrong-tag-protocolop", func(t *testing.T) {
		// MessageID=1 (02 01 01) immediately followed by the BindRequest
		// application tag (0x60) — replace it with an unsupported
		// application tag.
		pattern := []byte{0x02, 0x01, 0x01, 0x60}
		mutated := mutateAt(t, bindTemplate, pattern, 3, 0x60, 0x6a)
		assertRejected(t, mutated, "unsupported protocolOp application tag")
	})

	t.Run("wrong-tag-scope-enumerated", func(t *testing.T) {
		// Same anchor as malformed-enumerated-value, but mutate the tag
		// byte itself (ENUMERATED 0x0a -> INTEGER 0x02) instead of the
		// value.
		pattern := append([]byte("dc=internal"), 0x0a, 0x01, 0x02)
		mutated := mutateAt(t, searchTemplate, pattern, len("dc=internal"), 0x0a, 0x02)
		assertRejected(t, mutated, "scope ENUMERATED replaced by an INTEGER tag")
	})

	t.Run("wrong-tag-filter", func(t *testing.T) {
		// The "and" filter wrapper (a0 5f) immediately followed by the
		// first equalityMatch element's tag+length (a3 1b) — replace the
		// equalityMatch tag with an unsupported filter context tag
		// (greaterOrEqual, 0xa5).
		pattern := []byte{0xa0, 0x5f, 0xa3, 0x1b}
		mutated := mutateAt(t, searchTemplate, pattern, 2, 0xa3, 0xa5)
		assertRejected(t, mutated, "unsupported filter context tag")
	})

	t.Run("trailing-data-after-message", func(t *testing.T) {
		mutated := append(append([]byte(nil), unbindTemplate...), 0xde, 0xad, 0xbe, 0xef)
		assertRejected(t, mutated, "trailing bytes after a complete, otherwise-valid LDAPMessage")
	})

	t.Run("trailing-control-inside-message", func(t *testing.T) {
		// Grow the outer length to absorb 4 extra trailing bytes inside the
		// declared LDAPMessage content, simulating an unsupported control
		// appended after protocolOp rather than garbage after the message.
		contentLen := unbindTemplate[1]
		mutated := append([]byte{unbindTemplate[0], contentLen + 4}, unbindTemplate[2:]...)
		mutated = append(mutated, 0xde, 0xad, 0xbe, 0xef)
		assertRejected(t, mutated, "unsupported control-shaped trailing content inside the LDAPMessage")
	})
}

// mutateAt locates the first occurrence of pattern in base, asserts the
// byte at pattern-relative offset offsetIntoPattern equals expectedByte
// (protecting against the pattern silently matching the wrong spot after a
// future fixture regeneration), and returns a copy of base with that byte
// replaced by newByte.
func mutateAt(t *testing.T, base, pattern []byte, offsetIntoPattern int, expectedByte, newByte byte) []byte {
	t.Helper()
	idx := bytes.Index(base, pattern)
	if idx < 0 {
		t.Fatalf("mutation template: pattern %x not found in template", pattern)
	}
	pos := idx + offsetIntoPattern
	out := append([]byte(nil), base...)
	if out[pos] != expectedByte {
		t.Fatalf("mutation template: byte at offset %d is 0x%02x, want 0x%02x (template shape may have changed)", pos, out[pos], expectedByte)
	}
	out[pos] = newByte
	return out
}

// assertAccepted fails the test if raw is not safely characterized — used
// to prove a mutation's un-mutated template is itself a valid base case
// before asserting the mutation is rejected.
func assertAccepted(t *testing.T, raw []byte, why string) {
	t.Helper()
	if _, err := characterizeLDAPMessage(raw); err != nil {
		t.Fatalf("%s: expected the un-mutated template to be accepted, got: %v", why, err)
	}
}

// assertRejected fails the test if raw is accepted by characterizeLDAPMessage
// (it must not be, for every case this is called with).
func assertRejected(t *testing.T, raw []byte, why string) {
	t.Helper()
	if _, err := characterizeLDAPMessage(raw); err == nil {
		t.Fatalf("expected rejection (%s), but cryptobyte characterization accepted the mutated message", why)
	}
}

// TestIndependentBERDecoderIsDiscriminating is the sabotage check for
// independentlyWellFormedBER itself: it proves the independent-validity
// gate added to TestClickHouseWireCryptobyteDecision's per-fixture loop is
// a real, discriminating second opinion — not a rubber stamp that always
// returns nil regardless of input, which would silently reopen exactly the
// sabotage path this gate exists to close (corrupting a committed fixture
// and updating only its own session.json hash must not be able to pass
// through this check unnoticed).
//
// The malformed cases below are deliberately restricted to violations of
// definite-length BER itself — the encoding rule every LDAPMessage on the
// wire is required to use (RFC 4511 §5.1) — rather than this file's own
// narrow-profile choices (e.g. "only 'and'/'equalityMatch' filter tags"):
// third_party/goldap/message is a general LDAP BER decoder, not a
// characterizer of this narrow ClickHouse/libldap profile, so it is only
// guaranteed to reject encodings that are malformed BER outright, not every
// mutation characterizeLDAPMessage's narrower profile checks reject (e.g.
// a syntactically-valid-but-differently-tagged Filter alternative is not
// something a general LDAP decoder has any reason to refuse).
func TestIndependentBERDecoderIsDiscriminating(t *testing.T) {
	moduleRoot, err := wirefixture.ModuleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	fixtureRoot := wirefixture.ClickHouseWireFixtureRoot(moduleRoot)
	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("validate fixture root %s: %v", fixtureRoot, err)
	}
	cases := loadFixtureCases(t, fixtureRoot, lines)

	var bindTemplate, unbindTemplate []byte
	for _, c := range cases {
		switch c.PDU.Operation {
		case wirefixture.OperationBindRequest:
			if bindTemplate == nil {
				bindTemplate = append([]byte(nil), c.Raw...)
			}
		case wirefixture.OperationUnbindRequest:
			if unbindTemplate == nil {
				unbindTemplate = append([]byte(nil), c.Raw...)
			}
		}
	}
	if bindTemplate == nil || unbindTemplate == nil {
		t.Fatalf("need at least one bindRequest and one unbindRequest fixture as templates")
	}
	if len(bindTemplate) < 12 || len(unbindTemplate) < 2 {
		t.Fatalf("template too short to safely mutate byte offset 1")
	}

	// Sanity check: the independent decoder must accept the real,
	// un-mutated templates before we trust its verdict on mutated copies.
	if err := independentlyWellFormedBER(bindTemplate); err != nil {
		t.Fatalf("bind template sanity check: expected the independent decoder to accept the un-mutated template, got: %v", err)
	}
	if err := independentlyWellFormedBER(unbindTemplate); err != nil {
		t.Fatalf("unbind template sanity check: expected the independent decoder to accept the un-mutated template, got: %v", err)
	}

	t.Run("indefinite-length", func(t *testing.T) {
		// RFC 4511 requires definite-length BER; indefinite length (the
		// 0x80 length-octet marker) is a malformation independent of any
		// narrow profile.
		mutated := append([]byte(nil), bindTemplate...)
		mutated[1] = 0x80
		if err := independentlyWellFormedBER(mutated); err == nil {
			t.Fatalf("independent decoder accepted an indefinite-length outer SEQUENCE as well-formed")
		}
	})

	t.Run("truncation", func(t *testing.T) {
		mutated := bindTemplate[:len(bindTemplate)-10]
		if err := independentlyWellFormedBER(mutated); err == nil {
			t.Fatalf("independent decoder accepted a truncated BindRequest as well-formed")
		}
	})

	t.Run("trailing-data-after-message", func(t *testing.T) {
		// This fixture-corpus convention is "one complete PDU per file,
		// nothing more" — the same convention characterizeLDAPMessage
		// enforces via its own outer-SEQUENCE "trailing bytes" check,
		// which independentlyWellFormedBER mirrors via cursor.HasMoreData
		// (message.ReadLDAPMessage alone does not check this on its own).
		mutated := append(append([]byte(nil), unbindTemplate...), 0xde, 0xad, 0xbe, 0xef)
		if err := independentlyWellFormedBER(mutated); err == nil {
			t.Fatalf("independent decoder accepted trailing bytes after a complete LDAPMessage as well-formed")
		}
	})
}
