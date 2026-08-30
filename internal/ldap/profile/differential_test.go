package profile

// This file implements the Phase 2 plan's "Differential oracle" section
// (sub-task p2-13-differential): TestProfile_DifferentialDecoder compares
// this package's own wire decoders against the vendored, independent
// third_party/goldap decoder on profile-valid inputs, proving the two
// agree on normalized semantics rather than merely "both didn't panic".
//
// It uses package `profile` (not profile_test) specifically so it can
// reach unexported decode primitives -- decodeEnvelope, minimalPositiveInt32,
// authChoiceSimple/authChoiceSASL, filterTagAnd/filterTagEquality,
// decodeEquality, the tag* constants -- and reuses them directly wherever
// possible, rather than re-deriving a second copy of this package's own
// wire-shape knowledge. Only the goldap side is genuinely independent.
//
// github.com/vjeantet/goldap/message is imported ONLY from this file:
// `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOWORK=off go list -mod=readonly
// -deps ./internal/ldap/profile | grep -c vjeantet` must print 0, since
// `go list -deps` never walks a package's _test.go imports -- this file's
// import cannot reach the production dependency closure by construction,
// and internal/securitytest/profile_dependency_contract_test.go proves
// that mechanically for the package as a whole.
//
// # Phase 4: delete this file
//
// Per the plan's "Phase 1 independent decoder" section (coordinator
// amendment on top of the Phase 1 ship log): Phase 1's wire-profile
// contracts currently use vendored goldap as an independent decoder to
// prove committed fixture bytes are well-formed. This plan deliberately
// selects, for Phase 4, a bounded test-only definite-length structural
// cursor as goldap's replacement there -- NOT this package's own
// production decoder, which would be self-referential (using the
// production decoder to prove fixture well-formedness for itself proves
// nothing). Phase 4 must therefore delete this exact file
// (internal/ldap/profile/differential_test.go) at the same time it
// retires goldap as Phase 1's independent oracle; it must not repurpose
// this file's comparison logic as that replacement oracle.
//
// # Amendment 2 / Amendment 6 coverage
//
// Amendment 2's parity case -- legacy's vendored goldap decoder
// recognizes only AuthenticationChoice tags [0] (simple) and [3] (sasl),
// turning any other tag into a decode error -- is covered by
// TestProfile_DifferentialDecoder/bind_sasl_choice_result7_parity: both
// decoders recognize a well-formed [3] SaslCredentials Bind as a
// legitimate (if unsupported-by-policy) Bind, not malformed input.
//
// Amendment 6's shared-rule claim -- AbandonRequest's [APPLICATION 16]
// IMPLICIT MessageID content is validated by the exact same
// minimalPositiveInt32 rule the envelope MessageID uses -- is exercised
// by TestProfile_DifferentialDecoder/abandon_envelope_decode's 127/128
// targets, the same boundary values covered elsewhere for the envelope
// MessageID itself.
//
// # Explicitly excluded (per the plan's "Differential oracle" section)
//
// This file deliberately does NOT compare:
//
//   - v2 Bind (goldap accepts any version in 1..127; this package's own
//     Bind decoder only reads the version as a minimally-encoded
//     positive INTEGER at decode time -- version *policy* narrowing to
//     v3-only is bind.go's own concern, exercised in bind_test.go, not a
//     decoder-level difference this oracle would ever catch);
//   - derefAliases/typesOnly/attribute-selection values outside this
//     profile's supported shape (deref=0, typesOnly=false, exactly one
//     "cn" attribute) -- both decoders decode any in-range value
//     identically; only this package's Search *authorization* narrows
//     them further (search_test.go covers that table already);
//   - ordinary (non-Abandon-envelope) Cancel/Abandon *scheduling*
//     semantics -- this file only compares the Abandon target integer's
//     decode, never any cancellation behavior (server.go documents that
//     Abandon's target is never looked up or acted on at all);
//   - arbitrary malformed BER, beyond the one named parity case below
//     (the non-canonical `01 01 01` Controls BOOLEAN, which both this
//     package's cryptobyte-based scanner and goldap's own DER-strict
//     boolean parser reject -- Finding 4 in this plan's review responses
//     rejected the claim of a compatibility gap here, precisely because
//     both decoders already agree);
//   - generic filters/routes/projection outside the one fixed
//     `(&(objectClass=groupOfNames)(member=<dn>))` membership shape this
//     profile's Search ever recognizes.

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
	goldap "github.com/vjeantet/goldap/message"
)

// --- normalized semantic struct ------------------------------------------

// filterPair is the fixed membership filter's two equalityMatch children,
// decoded structurally (raw description/value bytes, in wire order) and
// then classified into (objectClass value, member DN bytes) the same way
// on both decoder sides, via the single shared classifyMembershipPair
// below -- so a description-case-variant input exercises real decoder
// agreement (both sides must extract byte-identical raw description/value
// pairs) rather than two independently-invented classifiers that could
// quietly agree by coincidence.
type filterPair struct {
	child1Desc, child1Value string
	child2Desc, child2Value string
	objectClass, memberDN   string
	classified              bool
}

// diffMessage is TestProfile_DifferentialDecoder's normalized comparison
// target: everything the plan's "Differential oracle" section lists
// (messageID, op kind, Bind version/name/password bytes/auth choice,
// Search base/scope/deref/sizeLimit/timeLimit/typesOnly/attribute list/
// filter pair, Abandon target, Controls present/critical), populated
// identically by decodeProfileMessage and decodeGoldapMessage for a
// profile-valid input.
type diffMessage struct {
	messageID int32
	kind      string // "bind" | "search" | "abandon" | "unbind"

	bindVersion  int32
	bindName     string
	bindPassword string
	bindAuth     string // "simple" | "sasl"

	searchBase      string
	searchScope     int32
	searchDeref     int32
	searchSizeLimit int32
	searchTimeLimit int32
	searchTypesOnly bool
	searchAttrs     []string
	searchFilter    filterPair

	abandonTarget int32

	controlsPresent  bool
	controlsCritical bool
}

// classifyMembershipPair implements the same objectClass/member
// classification search.go's own decodeMembershipFilter uses (case-
// insensitive attribute-description match, exactly one of each,
// order-independent), applied identically to whichever decoder produced
// (desc1, val1, desc2, val2) -- so a genuine decode divergence in the raw
// description/value bytes (not just a classification quirk local to one
// side) is what would make the two decoders disagree here.
func classifyMembershipPair(desc1, val1, desc2, val2 string) (objectClass, memberDN string, ok bool) {
	isObjClass1, isMember1 := strings.EqualFold(desc1, "objectClass"), strings.EqualFold(desc1, "member")
	isObjClass2, isMember2 := strings.EqualFold(desc2, "objectClass"), strings.EqualFold(desc2, "member")
	switch {
	case isObjClass1 && isMember2 && !isObjClass2 && !isMember1:
		return val1, val2, true
	case isObjClass2 && isMember1 && !isObjClass1 && !isMember2:
		return val2, val1, true
	default:
		return "", "", false
	}
}

// --- profile-side decode (reuses this package's own unexported decoders) --

// profileControlsPresent reports whether body -- readFrame's already
// bounds-checked SEQUENCE content, the same bytes decodeEnvelope itself
// consumes -- carries a Controls [0] element at all, independent of
// decodeEnvelope's own HasCritical (which reports only whether some
// control was critical, not whether any control is present at all). It
// walks exactly the same two leading fields (messageID, protocolOp)
// decodeEnvelope consumes before scanControls runs, using the same
// cryptobyte primitives, and never re-validates or duplicates
// scanControls' own structural/criticality rules -- it only checks
// whether anything is left over for scanControls to have looked at.
func profileControlsPresent(body []byte) (bool, error) {
	s := cryptobyte.String(body)
	var messageIDContent cryptobyte.String
	if !s.ReadASN1(&messageIDContent, asn1.INTEGER) {
		return false, errMalformed
	}
	var protocolOpContent cryptobyte.String
	var protocolOpTag asn1.Tag
	if !s.ReadAnyASN1(&protocolOpContent, &protocolOpTag) {
		return false, errMalformed
	}
	return !s.Empty(), nil
}

// decodeProfileBindFields mirrors bind.go's handleBind decode sequence
// exactly (version INTEGER, name OCTET STRING, authentication CHOICE via
// ReadAnyASN1, then requires op empty) -- but stops at decode: it never
// clears/replaces auth state, never calls Verifier.Verify or
// RoleResolver.Roles, and never writes a response. It reuses bind.go's
// own authChoiceSimple/authChoiceSASL tag constants and
// minimalPositiveInt32 directly, so a change to either there is
// automatically reflected here too.
func decodeProfileBindFields(msg *diffMessage, op cryptobyte.String) error {
	var versionContent cryptobyte.String
	if !op.ReadASN1(&versionContent, asn1.INTEGER) {
		return errMalformed
	}
	version, err := minimalPositiveInt32(versionContent)
	if err != nil {
		return err
	}

	var nameBytes []byte
	if !op.ReadASN1Bytes(&nameBytes, asn1.OCTET_STRING) {
		return errMalformed
	}

	var authContent cryptobyte.String
	var authTag asn1.Tag
	if !op.ReadAnyASN1(&authContent, &authTag) {
		return errMalformed
	}
	if !op.Empty() {
		return errMalformed
	}

	switch authTag {
	case authChoiceSimple:
		msg.bindAuth = "simple"
		msg.bindPassword = string(authContent)
	case authChoiceSASL:
		msg.bindAuth = "sasl"
	default:
		return errMalformed
	}

	msg.bindVersion = version
	msg.bindName = string(nameBytes)
	return nil
}

// decodeProfileMembershipPair decodes the fixed two-predicate membership
// filter's raw (description, value) pairs using search.go's own
// filterTagAnd/filterTagEquality tag constants and decodeEquality
// function directly (the exact same production primitives
// decodeMembershipFilter itself builds on), then classifies them with the
// shared classifyMembershipPair above. Unlike decodeMembershipFilter, it
// never compares the member value against a bound DN -- that is Search
// authorization, not decode, and out of this oracle's scope.
func decodeProfileMembershipPair(filterTag asn1.Tag, filterContent cryptobyte.String) (filterPair, bool) {
	if filterTag != filterTagAnd {
		return filterPair{}, false
	}
	var c1Content, c2Content cryptobyte.String
	var c1Tag, c2Tag asn1.Tag
	if !filterContent.ReadAnyASN1(&c1Content, &c1Tag) {
		return filterPair{}, false
	}
	if !filterContent.ReadAnyASN1(&c2Content, &c2Tag) {
		return filterPair{}, false
	}
	if !filterContent.Empty() {
		return filterPair{}, false
	}

	desc1, val1, ok1 := decodeEquality(c1Tag, c1Content)
	desc2, val2, ok2 := decodeEquality(c2Tag, c2Content)
	if !ok1 || !ok2 {
		return filterPair{}, false
	}

	objClass, member, classified := classifyMembershipPair(desc1, string(val1), desc2, string(val2))
	return filterPair{
		child1Desc: desc1, child1Value: string(val1),
		child2Desc: desc2, child2Value: string(val2),
		objectClass: objClass, memberDN: member,
		classified: classified,
	}, true
}

// decodeProfileSearchFields mirrors search.go's handleSearch decode
// sequence exactly (baseObject, scope, derefAliases, sizeLimit,
// timeLimit, typesOnly, filter, attributes, then requires op empty), but
// stops at decode: no authorization table, no c.auth/c.cfg access, no
// response write. The scope/derefAliases in-range checks (Amendment 2:
// out of the ENUMERATED type's own legal range is malformed, not merely
// out of profile) are reproduced here identically to search.go's own,
// since that boundary is exactly what this oracle must agree with goldap
// on for in-range values.
func decodeProfileSearchFields(msg *diffMessage, op cryptobyte.String) error {
	var baseBytes []byte
	if !op.ReadASN1Bytes(&baseBytes, asn1.OCTET_STRING) {
		return errMalformed
	}

	var scopeVal int
	if !op.ReadASN1Enum(&scopeVal) {
		return errMalformed
	}
	if scopeVal < 0 || scopeVal > maxScopeValue {
		return errMalformed
	}

	var derefVal int
	if !op.ReadASN1Enum(&derefVal) {
		return errMalformed
	}
	if derefVal < 0 || derefVal > maxDerefValue {
		return errMalformed
	}

	var sizeLimit int32
	if !op.ReadASN1Integer(&sizeLimit) {
		return errMalformed
	}
	if sizeLimit < 0 {
		return errMalformed
	}

	var timeLimit int32
	if !op.ReadASN1Integer(&timeLimit) {
		return errMalformed
	}
	if timeLimit < 0 {
		return errMalformed
	}

	var typesOnly bool
	if !op.ReadASN1Boolean(&typesOnly) {
		return errMalformed
	}

	var filterTag asn1.Tag
	var filterContent cryptobyte.String
	if !op.ReadAnyASN1(&filterContent, &filterTag) {
		return errMalformed
	}

	var attrsSeq cryptobyte.String
	if !op.ReadASN1(&attrsSeq, asn1.SEQUENCE) {
		return errMalformed
	}
	var attributes []string
	for !attrsSeq.Empty() {
		var a []byte
		if !attrsSeq.ReadASN1Bytes(&a, asn1.OCTET_STRING) {
			return errMalformed
		}
		attributes = append(attributes, string(a))
	}

	if !op.Empty() {
		return errMalformed
	}

	fp, ok := decodeProfileMembershipPair(filterTag, filterContent)
	if !ok {
		return errors.New("differential_test: unsupported filter shape")
	}

	msg.searchBase = string(baseBytes)
	msg.searchScope = int32(scopeVal)
	msg.searchDeref = int32(derefVal)
	msg.searchSizeLimit = sizeLimit
	msg.searchTimeLimit = timeLimit
	msg.searchTypesOnly = typesOnly
	msg.searchAttrs = attributes
	msg.searchFilter = fp
	return nil
}

// decodeProfileMessage decodes raw -- one complete, wire-identical
// LDAPMessage -- using this package's own readFrame + decodeEnvelope,
// then one of the field-decode helpers above by protocolOp application
// tag. A non-nil error means "this package's decoder rejects this input
// as malformed" (readFrame/decodeEnvelope's own errMalformed, or one of
// the field-decode helpers' own errors above) -- never a panic.
func decodeProfileMessage(raw []byte) (diffMessage, error) {
	body, err := readFrame(bytes.NewReader(raw))
	if err != nil {
		return diffMessage{}, err
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		return diffMessage{}, err
	}
	present, err := profileControlsPresent(body)
	if err != nil {
		return diffMessage{}, err
	}

	msg := diffMessage{
		messageID:        env.MessageID,
		controlsPresent:  present,
		controlsCritical: env.HasCritical,
	}

	switch env.ProtocolOp {
	case tagBindRequest:
		msg.kind = "bind"
		if err := decodeProfileBindFields(&msg, env.Content); err != nil {
			return diffMessage{}, err
		}
	case tagSearchRequest:
		msg.kind = "search"
		if err := decodeProfileSearchFields(&msg, env.Content); err != nil {
			return diffMessage{}, err
		}
	case tagAbandonRequest:
		msg.kind = "abandon"
		target, err := minimalPositiveInt32(env.Content)
		if err != nil {
			return diffMessage{}, err
		}
		msg.abandonTarget = target
	case tagUnbindRequest:
		if len(env.Content) != 0 {
			return diffMessage{}, errMalformed
		}
		msg.kind = "unbind"
	default:
		return diffMessage{}, errMalformed
	}
	return msg, nil
}

// --- goldap-side decode (the genuinely independent oracle) ---------------

// bindRequestVersion reads goldap's unexported BindRequest.version field
// via reflection's Kind-based primitive accessors (Value.Int()), which --
// unlike Value.Interface() -- do not require the field to be exported.
// This is necessary only because upstream goldap's BindRequest exposes
// Name()/Authentication()/AuthenticationChoice() but no Version()
// accessor; adding one would mean editing third_party/goldap/message, a
// production file outside this sub-task's file scope
// (internal/ldap/profile/differential_test.go only). Confined to this one
// helper, read-only, test-only.
func bindRequestVersion(req goldap.BindRequest) int32 {
	return int32(reflect.ValueOf(req).FieldByName("version").Int())
}

// decodeGoldapMembershipPair mirrors decodeProfileMembershipPair's shape
// exactly, but built entirely from goldap's own public Filter/
// FilterAnd/FilterEqualityMatch API -- the independent side of this
// comparison.
func decodeGoldapMembershipPair(filter goldap.Filter) (filterPair, bool) {
	fa, ok := filter.(goldap.FilterAnd)
	if !ok || len(fa) != 2 {
		return filterPair{}, false
	}
	eq1, ok1 := fa[0].(goldap.FilterEqualityMatch)
	eq2, ok2 := fa[1].(goldap.FilterEqualityMatch)
	if !ok1 || !ok2 {
		return filterPair{}, false
	}
	desc1, val1 := string(eq1.AttributeDesc()), string(eq1.AssertionValue())
	desc2, val2 := string(eq2.AttributeDesc()), string(eq2.AssertionValue())

	objClass, member, classified := classifyMembershipPair(desc1, val1, desc2, val2)
	return filterPair{
		child1Desc: desc1, child1Value: val1,
		child2Desc: desc2, child2Value: val2,
		objectClass: objClass, memberDN: member,
		classified: classified,
	}, true
}

// decodeGoldapMessage decodes raw with the vendored, independent goldap
// decoder (github.com/vjeantet/goldap/message, imported only from this
// file) and normalizes its result into the same diffMessage shape
// decodeProfileMessage produces.
func decodeGoldapMessage(raw []byte) (diffMessage, error) {
	b := goldap.NewBytes(0, raw)
	lm, err := goldap.ReadLDAPMessage(b)
	if err != nil {
		return diffMessage{}, err
	}
	if b.HasMoreData() {
		return diffMessage{}, errors.New("differential_test: trailing bytes after LDAPMessage")
	}

	msg := diffMessage{messageID: int32(lm.MessageID())}

	if controls := lm.Controls(); controls != nil {
		msg.controlsPresent = true
		for _, c := range *controls {
			cc := c
			if bool(cc.Criticality()) {
				msg.controlsCritical = true
			}
		}
	}

	switch v := lm.ProtocolOp().(type) {
	case goldap.BindRequest:
		msg.kind = "bind"
		msg.bindVersion = bindRequestVersion(v)
		msg.bindName = string(v.Name())
		switch v.AuthenticationChoice() {
		case "simple":
			msg.bindAuth = "simple"
			msg.bindPassword = string(v.AuthenticationSimple())
		case "sasl":
			msg.bindAuth = "sasl"
		default:
			return diffMessage{}, fmt.Errorf("differential_test: unrecognized AuthenticationChoice %q", v.AuthenticationChoice())
		}
	case goldap.SearchRequest:
		msg.kind = "search"
		msg.searchBase = string(v.BaseObject())
		msg.searchScope = int32(v.Scope())
		msg.searchDeref = int32(v.DerefAliases())
		msg.searchSizeLimit = int32(v.SizeLimit())
		msg.searchTimeLimit = int32(v.TimeLimit())
		msg.searchTypesOnly = bool(v.TypesOnly())
		for _, a := range v.Attributes() {
			msg.searchAttrs = append(msg.searchAttrs, string(a))
		}
		fp, ok := decodeGoldapMembershipPair(v.Filter())
		if !ok {
			return diffMessage{}, errors.New("differential_test: unsupported filter shape")
		}
		msg.searchFilter = fp
	case goldap.AbandonRequest:
		msg.kind = "abandon"
		msg.abandonTarget = int32(v)
	case goldap.UnbindRequest:
		msg.kind = "unbind"
	default:
		return diffMessage{}, fmt.Errorf("differential_test: unrecognized protocolOp %T", v)
	}
	return msg, nil
}

// --- comparison helpers ---------------------------------------------------

// requireDifferentialParity asserts both decoders accept raw and produce
// byte-identical normalized semantics.
func requireDifferentialParity(t *testing.T, raw []byte) {
	t.Helper()
	pm, perr := decodeProfileMessage(raw)
	if perr != nil {
		t.Fatalf("profile decoder rejected a profile-valid input: %v\n% x", perr, raw)
	}
	gm, gerr := decodeGoldapMessage(raw)
	if gerr != nil {
		t.Fatalf("goldap decoder rejected a profile-valid input: %v\n% x", gerr, raw)
	}
	if !reflect.DeepEqual(pm, gm) {
		t.Fatalf("decoders disagree on normalized semantics:\nprofile: %+v\ngoldap:  %+v", pm, gm)
	}
}

// requireMalformedParity asserts both decoders reject raw.
func requireMalformedParity(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := decodeProfileMessage(raw); err == nil {
		t.Fatalf("profile decoder accepted input expected to be malformed:\n% x", raw)
	}
	if _, err := decodeGoldapMessage(raw); err == nil {
		t.Fatalf("goldap decoder accepted input expected to be malformed:\n% x", raw)
	}
}

// --- fixture corpus (via internal/wirefixture, test-only) -----------------

// fixturePDU is one committed client-to-server Bind or Search PDU
// discovered under internal/ldap/testdata/clickhouse-wire.
type fixturePDU struct {
	name string
	raw  []byte
}

// loadFixtureBindAndSearchPDUs walks the whole committed wire-evidence
// corpus (every tracked ClickHouse line's every committed session, plus
// every constructed session) through internal/wirefixture only --
// ModuleRoot/ClickHouseWireFixtureRoot/ValidateFixtureRoot/LineDir/
// ReadProfile/SessionDir/ReadSession/ConstructedDir/SessionMetadataPath,
// the same helpers replay_test.go and the *_fuzz_test.go seed loaders
// already use -- and returns every client-to-server bindRequest/
// searchRequest PDU's exact, unmodified file bytes.
func loadFixtureBindAndSearchPDUs(t *testing.T) []fixturePDU {
	t.Helper()

	moduleRoot, err := wirefixture.ModuleRoot()
	if err != nil {
		t.Fatalf("wirefixture.ModuleRoot: %v", err)
	}
	fixtureRoot := wirefixture.ClickHouseWireFixtureRoot(moduleRoot)

	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("wirefixture.ValidateFixtureRoot(%s): %v", fixtureRoot, err)
	}

	var out []fixturePDU
	collect := func(sessDir, label string) {
		sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
		if err != nil {
			t.Fatalf("read session.json for %s: %v", sessDir, err)
		}
		for _, pdu := range sess.PDUs {
			if pdu.Direction != wirefixture.DirectionClientToServer {
				continue
			}
			if pdu.Operation != wirefixture.OperationBindRequest && pdu.Operation != wirefixture.OperationSearchRequest {
				continue
			}
			path := filepath.Join(sessDir, pdu.Filename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read PDU file %s: %v", path, err)
			}
			out = append(out, fixturePDU{name: label + "/" + pdu.Filename, raw: raw})
		}
	}

	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		p, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
		if err != nil {
			t.Fatalf("read profile.json for line %s: %v", line, err)
		}
		if len(p.SessionPaths) == 0 {
			t.Fatalf("line %s: profile.json lists no session_paths", line)
		}
		for _, sp := range p.SessionPaths {
			collect(wirefixture.SessionDir(lineDir, sp), line+"/"+sp)
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
		collect(filepath.Join(constructedDir, e.Name()), "constructed/"+e.Name())
	}

	if len(out) == 0 {
		t.Fatal("loadFixtureBindAndSearchPDUs: loaded zero Bind/Search PDUs from the wire fixture corpus")
	}
	return out
}

// --- TestProfile_DifferentialDecoder --------------------------------------

func TestProfile_DifferentialDecoder(t *testing.T) {
	t.Run("captured_fixture_binds_and_searches", func(t *testing.T) {
		for _, pdu := range loadFixtureBindAndSearchPDUs(t) {
			t.Run(pdu.name, func(t *testing.T) {
				requireDifferentialParity(t, pdu.raw)
			})
		}
	})

	t.Run("bind_ldapv3_simple", func(t *testing.T) {
		requireDifferentialParity(t, bindRequestBytes(1, testAliceDN, "alice-pw", false))
	})

	t.Run("bind_sasl_choice_result7_parity", func(t *testing.T) {
		// Amendment 2: legacy's vendored goldap decoder recognizes only
		// [0] (simple) and [3] (sasl) -- a well-formed [3] SaslCredentials
		// Bind must be accepted (as an unsupported-by-policy choice, not
		// malformed input) by both decoders. The mechanism content itself
		// (SaslCredentials ::= SEQUENCE { mechanism LDAPString,
		// credentials OCTET STRING OPTIONAL }) must be a genuinely valid
		// SEQUENCE for goldap's stricter readSaslCredentials to accept it
		// -- this package's own Bind decoder never looks inside [3] at
		// all, so an opaque/invalid payload there would pass on this
		// side but not goldap's, which would be a false differential
		// failure, not a real one.
		mechanism := tlv(0x04, []byte("GSSAPI"))
		raw := buildMessage(berInteger(1), tlv(byte(tagBindRequest), bindOp(3, testAliceDN, authTagSASL, mechanism)), nil)
		requireDifferentialParity(t, raw)
	})

	t.Run("bind_messageid_boundaries", func(t *testing.T) {
		for _, msgID := range []int64{1, 127, 128, math.MaxInt32} {
			t.Run(fmt.Sprintf("messageID=%d", msgID), func(t *testing.T) {
				raw := buildMessage(berInteger(msgID), tlv(byte(tagBindRequest), bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw"))), nil)
				requireDifferentialParity(t, raw)
			})
		}
	})

	t.Run("bind_controls_supported", func(t *testing.T) {
		op := bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw"))
		t.Run("no_controls", func(t *testing.T) {
			requireDifferentialParity(t, buildMessage(berInteger(1), tlv(byte(tagBindRequest), op), nil))
		})
		t.Run("unknown_non_critical", func(t *testing.T) {
			controls := buildControls(buildControl("1.2.840.113556.1.4.319", nil, nil))
			requireDifferentialParity(t, buildMessage(berInteger(1), tlv(byte(tagBindRequest), op), controls))
		})
		t.Run("critical", func(t *testing.T) {
			controls := buildControls(buildControl("1.2.3.4.5", trueVal(), nil))
			requireDifferentialParity(t, buildMessage(berInteger(1), tlv(byte(tagBindRequest), op), controls))
		})
	})

	const searchBase = "ou=roles,dc=profile,dc=test"

	t.Run("search_profile_valid", func(t *testing.T) {
		op := searchOp(searchBase, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
		requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), nil))
	})

	t.Run("search_attribute_description_case_variants", func(t *testing.T) {
		for _, attr := range []string{"cn", "CN", "Cn", "cN"} {
			t.Run("attr="+attr, func(t *testing.T) {
				op := searchOp(searchBase, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(testBoundDN), attr)
				requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), nil))
			})
		}

		descCases := []struct{ objectClassDesc, memberDesc string }{
			{"objectClass", "member"},
			{"OBJECTCLASS", "MEMBER"},
			{"ObjectClass", "Member"},
			{"objectclass", "MeMbEr"},
		}
		for _, dc := range descCases {
			t.Run("filterDesc="+dc.objectClassDesc+"/"+dc.memberDesc, func(t *testing.T) {
				filter := filterAnd(filterEquality(dc.objectClassDesc, "groupOfNames"), filterEquality(dc.memberDesc, testBoundDN))
				op := searchOp(searchBase, scopeWholeSubtree, derefNever, 0, 0, false, filter, "cn")
				requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), nil))
			})
		}
	})

	t.Run("search_filter_child_order_swapped", func(t *testing.T) {
		filter := filterAnd(filterEquality("member", testBoundDN), filterEquality("objectClass", "groupOfNames"))
		op := searchOp(searchBase, scopeWholeSubtree, derefNever, 0, 0, false, filter, "cn")
		requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), nil))
	})

	t.Run("search_size_limit_boundaries", func(t *testing.T) {
		for _, n := range []int64{0, 1, 255, 256, 257, math.MaxInt32} {
			t.Run(fmt.Sprintf("sizeLimit=%d", n), func(t *testing.T) {
				op := searchOp(searchBase, scopeWholeSubtree, derefNever, n, 0, false, validMembershipFilter(testBoundDN), "cn")
				requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), nil))
			})
		}
	})

	t.Run("search_time_limit_boundaries", func(t *testing.T) {
		for _, n := range []int64{0, 1, 20, math.MaxInt32} {
			t.Run(fmt.Sprintf("timeLimit=%d", n), func(t *testing.T) {
				op := searchOp(searchBase, scopeWholeSubtree, derefNever, 0, n, false, validMembershipFilter(testBoundDN), "cn")
				requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), nil))
			})
		}
	})

	t.Run("search_controls_supported", func(t *testing.T) {
		op := searchOp(searchBase, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
		t.Run("unknown_non_critical", func(t *testing.T) {
			controls := buildControls(buildControl("1.2.840.113556.1.4.319", nil, nil))
			requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), controls))
		})
		t.Run("critical", func(t *testing.T) {
			controls := buildControls(buildControl("1.2.3.4.5", trueVal(), nil))
			requireDifferentialParity(t, buildMessage(berInteger(2), tlv(byte(tagSearchRequest), op), controls))
		})
	})

	t.Run("abandon_envelope_decode", func(t *testing.T) {
		for _, target := range []int64{1, 127, 128} {
			t.Run(fmt.Sprintf("target=%d", target), func(t *testing.T) {
				raw := abandonRequestBytes(3, minimalIntegerContent(target), false)
				requireDifferentialParity(t, raw)
			})
		}
	})

	t.Run("unbind", func(t *testing.T) {
		requireDifferentialParity(t, unbindRequestBytes(4))
	})

	t.Run("malformed_boolean_control_parity", func(t *testing.T) {
		// The one named malformed-input parity case (plan's "Native
		// fuzzing" / "Framing seeds" section, and this sub-task's
		// description): a non-canonical `01 01 01` BOOLEAN criticality
		// octet. Both this package's cryptobyte-based Controls scanner
		// (frame.go's scanControls, ReadASN1Boolean) and goldap's own
		// parseBool (asn1.go) accept only 0x00/0xFF -- Finding 4 in this
		// plan's review responses rejected the claim of a compatibility
		// gap here precisely because both already agree.
		badControl := tlv(0x30, append(tlv(0x04, []byte("1.2.3")), tlv(0x01, []byte{0x01})...))
		badControls := tlv(0xa0, badControl)
		op := bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw"))
		raw := buildMessage(berInteger(1), tlv(byte(tagBindRequest), op), badControls)
		requireMalformedParity(t, raw)
	})
}
