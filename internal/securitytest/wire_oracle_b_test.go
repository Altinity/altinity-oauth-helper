package securitytest

// Oracle B — the wire-profile semantic decoder (issue #33 phase 4).
//
// This file implements a second, independently written, test-only bounded
// BER cursor for exactly the fields the wire-profile evidence tests in
// wire_profile_contract_test.go need: a bindRequest's Bind DN, a
// searchRequest's derefAliases, the top-level Controls sequence's
// presence/criticality, the outer Search filter's operator (AND/OR/other),
// and, for an AND, its two equalityMatch children's attribute description
// and assertion value.
//
// It deliberately shares nothing with:
//
//   - Oracle A (the primitive-selection/fixture-well-formedness cursor
//     living under internal/ldap/profile, whose own job is the
//     cryptobyte-vs-local-ber-cursor primitive decision — a wholly
//     different, purely structural/tag-based question this file never
//     re-derives);
//   - the production internal/ldap/profile decoder (frame.go/protocol.go),
//     which this file must never call as its own oracle — that would make
//     the "independent" decoder merely re-run the code under test;
//   - integration/clickhouse/wirecapture's producer-side parsing, which
//     writes the fixtures this file only ever reads.
//
// Oracle B replaces the vendored github.com/vjeantet/goldap decode legs
// that wire_profile_contract_test.go previously used for this same
// purpose (issue #33 phases 1-3): this repository is being cut over off
// the general vendored LDAP/BER stack entirely (see the Phase 4 plan's
// "Independent BER oracle replacement"), so a permanent independent-decoder
// proof can no longer depend on that vendored package even from a _test.go
// file.
//
// This is a bounded cursor, not a general BER/ASN.1 library: it reads
// exactly one TLV at a time, never trusts a declared length past the bytes
// actually present, rejects BER indefinite-length encoding outright (this
// wire profile never uses it), and requires every byte inside a decoded
// container to be accounted for by its children (no silently-ignored
// trailing bytes at any nesting level). It does not attempt to decode
// fields the wire-profile tests never need (Search's baseObject/attributes
// contents, Bind's authentication choice, Abandon's target, ...) — those
// are read only far enough to skip past them, via their own TLV framing.

import (
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------
// BER tag constants this cursor recognizes.
// ---------------------------------------------------------------------

const (
	oracleBSequenceTag = 0x30 // universal, constructed SEQUENCE
	oracleBIntegerTag  = 0x02 // universal, primitive INTEGER

	oracleBBindRequestTag   = 0x60 // [APPLICATION 0], constructed
	oracleBSearchRequestTag = 0x63 // [APPLICATION 3], constructed

	// oracleBControlsTag is LDAPMessage's optional trailing
	// `controls [0] Controls` — numerically identical to
	// oracleBFilterAndTag below (both are context tag 0, constructed) but
	// never ambiguous in this decoder because each is only ever inspected
	// at its own fixed nesting level (LDAPMessage's tail vs. a Search
	// filter).
	oracleBControlsTag = 0xa0
	oracleBControlTag  = 0x30 // each Control is itself a SEQUENCE

	oracleBFilterAndTag     = 0xa0 // Filter CHOICE "and" [0], constructed SET OF Filter
	oracleBFilterOrTag      = 0xa1 // Filter CHOICE "or" [1], constructed SET OF Filter
	oracleBEqualityMatchTag = 0xa3 // Filter CHOICE "equalityMatch" [3]
)

// ---------------------------------------------------------------------
// Bounded TLV cursor.
// ---------------------------------------------------------------------

// oracleBTLV is one decoded tag-length-value unit: Value is exactly the
// Length bytes the header declared (never more, never fewer — oracleBReadTLV
// fails rather than returning a short slice), and Next is the offset of the
// first byte after this TLV within the slice it was read from.
type oracleBTLV struct {
	Tag   byte
	Value []byte
	Next  int
}

// oracleBReadTLV reads exactly one BER tag-length-value unit starting at
// pos in data. It supports only single-byte tags (tag number <= 30, which
// covers every tag this wire profile ever uses) and definite-form lengths
// (short form, or long form up to 4 length-of-length bytes); it rejects
// indefinite length outright and never returns a Value slice extending
// past len(data).
func oracleBReadTLV(data []byte, pos int) (oracleBTLV, error) {
	if pos >= len(data) {
		return oracleBTLV{}, fmt.Errorf("oracle-b: unexpected end of data at offset %d reading a tag byte", pos)
	}
	tag := data[pos]
	pos++
	if tag&0x1f == 0x1f {
		return oracleBTLV{}, fmt.Errorf("oracle-b: multi-byte (high-tag-number) tag at offset %d is outside this bounded cursor's supported shapes", pos-1)
	}
	if pos >= len(data) {
		return oracleBTLV{}, fmt.Errorf("oracle-b: unexpected end of data at offset %d reading a length byte", pos)
	}
	lengthByte := data[pos]
	pos++
	var length int
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		n := int(lengthByte &^ 0x80)
		if n == 0 {
			return oracleBTLV{}, fmt.Errorf("oracle-b: BER indefinite length at offset %d is not a supported shape", pos-1)
		}
		if n > 4 {
			return oracleBTLV{}, fmt.Errorf("oracle-b: length-of-length %d at offset %d exceeds this cursor's bound", n, pos-1)
		}
		if pos+n > len(data) {
			return oracleBTLV{}, fmt.Errorf("oracle-b: truncated long-form length at offset %d (need %d more byte(s))", pos, n)
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(data[pos+i])
		}
		pos += n
	}
	if length < 0 {
		return oracleBTLV{}, fmt.Errorf("oracle-b: decoded a negative length at offset %d", pos)
	}
	if pos+length > len(data) {
		return oracleBTLV{}, fmt.Errorf("oracle-b: declared length %d at offset %d exceeds the %d remaining byte(s) — truncated body", length, pos, len(data)-pos)
	}
	return oracleBTLV{Tag: tag, Value: data[pos : pos+length], Next: pos + length}, nil
}

// oracleBDecodeInt decodes a minimal, non-negative BER INTEGER/ENUMERATED
// content (this profile's MessageID/scope/derefAliases fields never carry
// negative values).
func oracleBDecodeInt(content []byte) (int, error) {
	if len(content) == 0 {
		return 0, fmt.Errorf("oracle-b: empty INTEGER content")
	}
	if len(content) > 8 {
		return 0, fmt.Errorf("oracle-b: INTEGER content %d bytes exceeds this cursor's bound", len(content))
	}
	if content[0]&0x80 != 0 {
		return 0, fmt.Errorf("oracle-b: negative INTEGER content is not a supported shape for this field")
	}
	v := 0
	for _, b := range content {
		v = v<<8 | int(b)
	}
	return v, nil
}

// ---------------------------------------------------------------------
// Decoded message shape.
// ---------------------------------------------------------------------

// oracleBEqualityTerm is one child of a Search filter's outer AND/OR. For a
// non-equalityMatch child, IsEquality is false and RawTag records the tag
// actually seen, so a canonical-shape check can report exactly what was
// wrong instead of decoding it as if it were attribute/value pair.
type oracleBEqualityTerm struct {
	IsEquality bool
	RawTag     byte
	Attribute  string
	Value      string
}

// oracleBFilter is a Search request's decoded outer filter: Operator is
// "and", "or", "equalityMatch", or "unsupported(0x%02x)" for any other
// Filter CHOICE tag; Terms is populated only for "and"/"or" (each child,
// including a non-equalityMatch one — see oracleBEqualityTerm above).
type oracleBFilter struct {
	Operator string
	Terms    []oracleBEqualityTerm
}

// oracleBBind is a decoded bindRequest: only Name (the Bind DN) and Version
// are read; the authentication choice is skipped, never decoded.
type oracleBBind struct {
	Version int
	Name    string
}

// oracleBSearch is a decoded searchRequest, limited to the two fields this
// wire profile's evidence tests need.
type oracleBSearch struct {
	DerefAliases int
	Filter       oracleBFilter
}

// oracleBControl is one decoded LDAP Control. CriticalityPresent
// distinguishes an explicitly-encoded criticality BOOLEAN from the RFC 4511
// DEFAULT FALSE case (Criticality is meaningless when CriticalityPresent is
// false).
type oracleBControl struct {
	Type               string
	CriticalityPresent bool
	Criticality        bool
}

// oracleBMessage is one decoded LDAPMessage: MessageID and OpTag are always
// populated; Bind is non-nil only when OpTag is a bindRequest, Search only
// when OpTag is a searchRequest (any other protocolOp is framed but its
// content left undecoded — Oracle B has no need for it); ControlsPresent
// records whether a trailing controls sequence was present at all (plan
// §8.2: it must be absent, not merely empty, for every committed PDU).
type oracleBMessage struct {
	MessageID       int
	OpTag           byte
	ControlsPresent bool
	Controls        []oracleBControl
	Bind            *oracleBBind
	Search          *oracleBSearch
}

// ---------------------------------------------------------------------
// Decoders.
// ---------------------------------------------------------------------

// oracleBDecodeLDAPMessage decodes raw as one complete LDAPMessage:
// SEQUENCE { messageID INTEGER, protocolOp <application-tagged>,
// controls [0] Controls OPTIONAL }, requiring every byte of raw to be
// consumed by exactly these fields (no trailing unconsumed bytes at any
// level) and no BER indefinite length or truncated body anywhere along the
// way.
func oracleBDecodeLDAPMessage(raw []byte) (*oracleBMessage, error) {
	outer, err := oracleBReadTLV(raw, 0)
	if err != nil {
		return nil, fmt.Errorf("outer LDAPMessage: %w", err)
	}
	if outer.Tag != oracleBSequenceTag {
		return nil, fmt.Errorf("oracle-b: outer tag 0x%02x, want SEQUENCE 0x%02x", outer.Tag, oracleBSequenceTag)
	}
	if outer.Next != len(raw) {
		return nil, fmt.Errorf("oracle-b: %d trailing byte(s) after the outer LDAPMessage", len(raw)-outer.Next)
	}

	body := outer.Value
	pos := 0

	idTLV, err := oracleBReadTLV(body, pos)
	if err != nil {
		return nil, fmt.Errorf("oracle-b: messageID: %w", err)
	}
	if idTLV.Tag != oracleBIntegerTag {
		return nil, fmt.Errorf("oracle-b: messageID tag 0x%02x, want INTEGER 0x%02x", idTLV.Tag, oracleBIntegerTag)
	}
	messageID, err := oracleBDecodeInt(idTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("oracle-b: messageID: %w", err)
	}
	pos = idTLV.Next

	opTLV, err := oracleBReadTLV(body, pos)
	if err != nil {
		return nil, fmt.Errorf("oracle-b: protocolOp: %w", err)
	}
	pos = opTLV.Next

	msg := &oracleBMessage{MessageID: messageID, OpTag: opTLV.Tag}
	switch opTLV.Tag {
	case oracleBBindRequestTag:
		bind, err := oracleBDecodeBindRequest(opTLV.Value)
		if err != nil {
			return nil, fmt.Errorf("oracle-b: bindRequest: %w", err)
		}
		msg.Bind = bind
	case oracleBSearchRequestTag:
		search, err := oracleBDecodeSearchRequest(opTLV.Value)
		if err != nil {
			return nil, fmt.Errorf("oracle-b: searchRequest: %w", err)
		}
		msg.Search = search
	default:
		// Any other protocolOp (unbindRequest, abandonRequest, ...) frames
		// correctly above via opTLV's own bounded length, but its content
		// is not decoded further — Oracle B has no need for it.
	}

	if pos < len(body) {
		ctlTLV, err := oracleBReadTLV(body, pos)
		if err != nil {
			return nil, fmt.Errorf("oracle-b: controls: %w", err)
		}
		if ctlTLV.Tag != oracleBControlsTag {
			return nil, fmt.Errorf("oracle-b: unexpected trailing tag 0x%02x after protocolOp, want controls 0x%02x", ctlTLV.Tag, oracleBControlsTag)
		}
		msg.ControlsPresent = true
		controls, err := oracleBDecodeControls(ctlTLV.Value)
		if err != nil {
			return nil, fmt.Errorf("oracle-b: controls: %w", err)
		}
		msg.Controls = controls
		pos = ctlTLV.Next
	}
	if pos != len(body) {
		return nil, fmt.Errorf("oracle-b: %d trailing byte(s) inside LDAPMessage after controls", len(body)-pos)
	}
	return msg, nil
}

// oracleBDecodeBindRequest decodes a bindRequest's SEQUENCE content:
// version INTEGER, name LDAPDN (OCTET STRING), authentication
// AuthenticationChoice. Only version/name are read; authentication is
// framed (via its own TLV) but never decoded.
func oracleBDecodeBindRequest(content []byte) (*oracleBBind, error) {
	pos := 0
	versionTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if versionTLV.Tag != oracleBIntegerTag {
		return nil, fmt.Errorf("version tag 0x%02x, want INTEGER 0x%02x", versionTLV.Tag, oracleBIntegerTag)
	}
	version, err := oracleBDecodeInt(versionTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	pos = versionTLV.Next

	const ldapDNTag = 0x04 // universal, primitive OCTET STRING
	nameTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}
	if nameTLV.Tag != ldapDNTag {
		return nil, fmt.Errorf("name tag 0x%02x, want OCTET STRING 0x%02x", nameTLV.Tag, ldapDNTag)
	}
	pos = nameTLV.Next

	// authentication AuthenticationChoice: framed and skipped, not decoded.
	authTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("authentication: %w", err)
	}
	pos = authTLV.Next

	if pos != len(content) {
		return nil, fmt.Errorf("%d trailing byte(s) inside bindRequest", len(content)-pos)
	}
	return &oracleBBind{Version: version, Name: string(nameTLV.Value)}, nil
}

// oracleBDecodeSearchRequest decodes a searchRequest's SEQUENCE content in
// its fixed field order (baseObject, scope, derefAliases, sizeLimit,
// timeLimit, typesOnly, filter, attributes), reading every field's own TLV
// to advance the cursor correctly even though only derefAliases and filter
// are actually inspected.
func oracleBDecodeSearchRequest(content []byte) (*oracleBSearch, error) {
	pos := 0

	baseObjectTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("baseObject: %w", err)
	}
	pos = baseObjectTLV.Next

	const enumeratedTag = 0x0a // universal, primitive ENUMERATED
	scopeTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if scopeTLV.Tag != enumeratedTag {
		return nil, fmt.Errorf("scope tag 0x%02x, want ENUMERATED 0x%02x", scopeTLV.Tag, enumeratedTag)
	}
	pos = scopeTLV.Next

	derefTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("derefAliases: %w", err)
	}
	if derefTLV.Tag != enumeratedTag {
		return nil, fmt.Errorf("derefAliases tag 0x%02x, want ENUMERATED 0x%02x", derefTLV.Tag, enumeratedTag)
	}
	derefAliases, err := oracleBDecodeInt(derefTLV.Value)
	if err != nil {
		return nil, fmt.Errorf("derefAliases: %w", err)
	}
	pos = derefTLV.Next

	sizeLimitTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("sizeLimit: %w", err)
	}
	pos = sizeLimitTLV.Next

	timeLimitTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("timeLimit: %w", err)
	}
	pos = timeLimitTLV.Next

	typesOnlyTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("typesOnly: %w", err)
	}
	pos = typesOnlyTLV.Next

	filterTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	pos = filterTLV.Next
	filter, err := oracleBDecodeFilter(filterTLV)
	if err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}

	if pos < len(content) {
		attributesTLV, err := oracleBReadTLV(content, pos)
		if err != nil {
			return nil, fmt.Errorf("attributes: %w", err)
		}
		pos = attributesTLV.Next
	}
	if pos != len(content) {
		return nil, fmt.Errorf("%d trailing byte(s) inside searchRequest", len(content)-pos)
	}

	return &oracleBSearch{DerefAliases: derefAliases, Filter: filter}, nil
}

// oracleBDecodeFilter decodes a Filter CHOICE TLV. For "and"/"or" it
// decodes every child filter in the outer TLV's content (a flat sequence of
// child TLVs, since AND/OR's "SET OF Filter" uses IMPLICIT tagging — no
// extra SET wrapper byte); a non-equalityMatch child is recorded (not
// silently dropped) so a canonical-shape check downstream can reject it
// explicitly instead of miscounting the term list.
func oracleBDecodeFilter(tlv oracleBTLV) (oracleBFilter, error) {
	switch tlv.Tag {
	case oracleBFilterAndTag, oracleBFilterOrTag:
		op := "and"
		if tlv.Tag == oracleBFilterOrTag {
			op = "or"
		}
		var terms []oracleBEqualityTerm
		pos := 0
		for pos < len(tlv.Value) {
			childTLV, err := oracleBReadTLV(tlv.Value, pos)
			if err != nil {
				return oracleBFilter{}, fmt.Errorf("child filter: %w", err)
			}
			pos = childTLV.Next
			if childTLV.Tag != oracleBEqualityMatchTag {
				terms = append(terms, oracleBEqualityTerm{IsEquality: false, RawTag: childTLV.Tag})
				continue
			}
			term, err := oracleBDecodeEqualityMatch(childTLV.Value)
			if err != nil {
				return oracleBFilter{}, fmt.Errorf("equalityMatch: %w", err)
			}
			terms = append(terms, term)
		}
		return oracleBFilter{Operator: op, Terms: terms}, nil
	case oracleBEqualityMatchTag:
		term, err := oracleBDecodeEqualityMatch(tlv.Value)
		if err != nil {
			return oracleBFilter{}, err
		}
		return oracleBFilter{Operator: "equalityMatch", Terms: []oracleBEqualityTerm{term}}, nil
	default:
		return oracleBFilter{Operator: fmt.Sprintf("unsupported(0x%02x)", tlv.Tag)}, nil
	}
}

// oracleBDecodeEqualityMatch decodes an AttributeValueAssertion's content
// (attributeDesc, assertionValue — both OCTET STRING), requiring both
// fields to fully account for the content bytes.
func oracleBDecodeEqualityMatch(content []byte) (oracleBEqualityTerm, error) {
	const octetStringTag = 0x04
	pos := 0
	attrTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return oracleBEqualityTerm{}, fmt.Errorf("attributeDesc: %w", err)
	}
	if attrTLV.Tag != octetStringTag {
		return oracleBEqualityTerm{}, fmt.Errorf("attributeDesc tag 0x%02x, want OCTET STRING 0x%02x", attrTLV.Tag, octetStringTag)
	}
	pos = attrTLV.Next

	valueTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return oracleBEqualityTerm{}, fmt.Errorf("assertionValue: %w", err)
	}
	if valueTLV.Tag != octetStringTag {
		return oracleBEqualityTerm{}, fmt.Errorf("assertionValue tag 0x%02x, want OCTET STRING 0x%02x", valueTLV.Tag, octetStringTag)
	}
	pos = valueTLV.Next

	if pos != len(content) {
		return oracleBEqualityTerm{}, fmt.Errorf("%d trailing byte(s) inside equalityMatch", len(content)-pos)
	}
	return oracleBEqualityTerm{IsEquality: true, RawTag: oracleBEqualityMatchTag, Attribute: string(attrTLV.Value), Value: string(valueTLV.Value)}, nil
}

// oracleBDecodeControls decodes LDAPMessage's optional trailing controls
// sequence content as zero or more Control SEQUENCEs.
func oracleBDecodeControls(content []byte) ([]oracleBControl, error) {
	var out []oracleBControl
	pos := 0
	for pos < len(content) {
		ctlTLV, err := oracleBReadTLV(content, pos)
		if err != nil {
			return nil, fmt.Errorf("control: %w", err)
		}
		pos = ctlTLV.Next
		if ctlTLV.Tag != oracleBControlTag {
			return nil, fmt.Errorf("control tag 0x%02x, want SEQUENCE 0x%02x", ctlTLV.Tag, oracleBControlTag)
		}
		c, err := oracleBDecodeOneControl(ctlTLV.Value)
		if err != nil {
			return nil, fmt.Errorf("control: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// oracleBDecodeOneControl decodes one Control's SEQUENCE content:
// controlType LDAPOID (OCTET STRING), criticality BOOLEAN DEFAULT FALSE
// OPTIONAL, controlValue OCTET STRING OPTIONAL. controlValue, if present,
// is framed but never decoded — Oracle B has no need for it.
func oracleBDecodeOneControl(content []byte) (oracleBControl, error) {
	const octetStringTag = 0x04
	const booleanTag = 0x01
	pos := 0

	typeTLV, err := oracleBReadTLV(content, pos)
	if err != nil {
		return oracleBControl{}, fmt.Errorf("controlType: %w", err)
	}
	if typeTLV.Tag != octetStringTag {
		return oracleBControl{}, fmt.Errorf("controlType tag 0x%02x, want OCTET STRING 0x%02x", typeTLV.Tag, octetStringTag)
	}
	pos = typeTLV.Next

	c := oracleBControl{Type: string(typeTLV.Value)}
	if pos < len(content) {
		nextTLV, err := oracleBReadTLV(content, pos)
		if err != nil {
			return oracleBControl{}, fmt.Errorf("criticality: %w", err)
		}
		if nextTLV.Tag == booleanTag {
			if len(nextTLV.Value) != 1 {
				return oracleBControl{}, fmt.Errorf("criticality BOOLEAN content length %d, want 1", len(nextTLV.Value))
			}
			c.CriticalityPresent = true
			c.Criticality = nextTLV.Value[0] != 0
			pos = nextTLV.Next
		}
	}
	if pos < len(content) {
		valueTLV, err := oracleBReadTLV(content, pos)
		if err != nil {
			return oracleBControl{}, fmt.Errorf("controlValue: %w", err)
		}
		pos = valueTLV.Next
	}
	if pos != len(content) {
		return oracleBControl{}, fmt.Errorf("%d trailing byte(s) inside Control", len(content)-pos)
	}
	return c, nil
}

// ---------------------------------------------------------------------
// Semantic canonical-shape check.
// ---------------------------------------------------------------------

// oracleBCanonicalFilterDefects requires filter to be exactly the canonical
// ClickHouse membership-search shape — AND(equalityMatch(objectClass,
// groupOfNames), equalityMatch(member, wantBindDN)) — decoded structurally
// (Filter CHOICE tag, then each child's AttributeValueAssertion field
// values), never by re-encoding and byte-comparing. Either equality-child
// order is accepted (plan: "Either equality-child order remains acceptable
// if that is the certified profile"). It returns one human-readable defect
// string per violated property; nil/empty means filter fully matches.
//
// A same-shape tag swap (AND 0xa0 -> OR 0xa1, or any other Filter CHOICE
// alternative) is rejected by the very first check below, because this
// decoder already classified it under a different Operator — this is what
// keeps the check discriminating rather than a rubber stamp (see
// TestWireProfileContract_SearchFilterStructureIsDiscriminating).
func oracleBCanonicalFilterDefects(filter oracleBFilter, wantBindDN string) []string {
	var defects []string

	if filter.Operator != "and" {
		return append(defects, fmt.Sprintf("oracle-b: decoded Search filter operator is %q, want \"and\"", filter.Operator))
	}
	if len(filter.Terms) != 2 {
		return append(defects, fmt.Sprintf("oracle-b: decoded Search filter AND has %d child term(s), want exactly 2", len(filter.Terms)))
	}
	for i, term := range filter.Terms {
		if !term.IsEquality {
			defects = append(defects, fmt.Sprintf("oracle-b: AND child %d is not an equalityMatch (tag 0x%02x)", i, term.RawTag))
		}
	}
	if len(defects) != 0 {
		return defects
	}

	haveObjectClass, haveMember := false, false
	for _, term := range filter.Terms {
		switch term.Attribute {
		case "objectClass":
			haveObjectClass = true
			if term.Value != "groupOfNames" {
				defects = append(defects, fmt.Sprintf("oracle-b: objectClass equalityMatch value is %q, want %q", term.Value, "groupOfNames"))
			}
		case "member":
			haveMember = true
			if term.Value != wantBindDN {
				defects = append(defects, fmt.Sprintf("oracle-b: member equalityMatch value is %q, want this session's own decoded Bind DN %q ({bind_dn})", term.Value, wantBindDN))
			}
		default:
			defects = append(defects, fmt.Sprintf("oracle-b: unexpected equalityMatch attribute %q, want objectClass or member", term.Attribute))
		}
	}
	if !haveObjectClass {
		defects = append(defects, "oracle-b: no objectClass equalityMatch term found among the AND's children")
	}
	if !haveMember {
		defects = append(defects, "oracle-b: no member equalityMatch term found among the AND's children")
	}
	return defects
}

// ---------------------------------------------------------------------
// Oracle B self-check.
// ---------------------------------------------------------------------

// TestOracleB_RejectsTruncatedFrame is a minimal proof that Oracle B is
// itself a discriminating bounded cursor, not one that silently agrees with
// whatever bytes it is given: a SEQUENCE header declaring more content
// than is actually present must be rejected, never read out of bounds or
// silently truncated.
func TestOracleB_RejectsTruncatedFrame(t *testing.T) {
	// SEQUENCE, declared length 0x10 (16), but only 3 content bytes follow.
	truncated := []byte{0x30, 0x10, 0x02, 0x01, 0x01}
	if _, err := oracleBDecodeLDAPMessage(truncated); err == nil {
		t.Fatal("oracle-b: decoded a truncated LDAPMessage without error")
	}
}
