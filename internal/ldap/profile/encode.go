package profile

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// This file implements the plan's "Response encoding" and "Diagnostics"
// sections: the closed diagnostic enum and its one text-mapping function,
// the one addLDAPResultFields helper every response ends with, the
// per-response-shape encoders (BindResponse, the fixed cn-only
// SearchResultEntry, SearchResultDone, and the minimal common
// unsupported-operation responses), the one shared minimal-positive-
// INTEGER MessageID encoder, and the "Response memory bound" preflight
// arithmetic (entryPDUSize) plus a final, defensive post-build size guard.
// Every encoder uses cryptobyte.Builder only — no other BER/ASN.1 library.

// diagnostic is the closed, unexported enum of every diagnosticMessage
// text this package ever writes to the wire. It is deliberately not a
// string: every response function that needs a diagnostic accepts this
// type, never a computed or ad hoc string, so the only way wire bytes for
// a diagnosticMessage are produced is through diagnostic.text() below —
// mechanically enforced by profile_architecture_contract_test.go, which
// also sabotage-checks that a dynamic conversion such as
// diagnostic(err.Error()) is rejected.
type diagnostic uint8

const (
	diagEmpty diagnostic = iota
	diagInvalidCredentials
	diagSimpleOnly
	diagLDAPv3Required
	diagInsufficientAccess
	diagCriticalControl
	diagOperationUnsupported
)

// text returns the literal diagnosticMessage text for d — one of exactly
// the seven strings the plan names, and nothing else. This is the only
// function in the package that produces diagnostic wire text.
func (d diagnostic) text() string {
	switch d {
	case diagEmpty:
		return ""
	case diagInvalidCredentials:
		return "invalid credentials"
	case diagSimpleOnly:
		return "only simple authentication is supported"
	case diagLDAPv3Required:
		return "LDAPv3 required"
	case diagInsufficientAccess:
		return "insufficient access"
	case diagCriticalControl:
		return "critical control unavailable"
	case diagOperationUnsupported:
		return "operation not supported"
	default:
		// Unreachable for any value produced by this package's own
		// closed enum; kept only so the switch is a total function
		// without relying on exhaustiveness analysis. Still one of the
		// seven literals (the empty string) if it were ever hit.
		return ""
	}
}

// addLDAPResultFields appends the three LDAPResult fields every response
// this package builds ends with (RFC 4511 §4.1.9): resultCode
// ENUMERATED, an always-empty matchedDN OCTET STRING (this profile never
// has a partial-match DN to report), and diagnosticMessage OCTET STRING
// carrying d's text. resultCode is the caller's chosen result code (see
// protocol.go's named constants); d is always a package-level diagnostic
// constant, never a computed value — see the diagnostic type's own
// comment above.
func addLDAPResultFields(b *cryptobyte.Builder, resultCode int, d diagnostic) {
	b.AddASN1Enum(int64(resultCode))
	b.AddASN1OctetString(nil)
	b.AddASN1OctetString([]byte(d.text()))
}

// addMessageID appends msgID as a minimal positive INTEGER — the one
// encoder every response function below shares. It is the exact inverse
// of minimalPositiveInt32's decode rule (protocol.go): 127 encodes as
// `02 01 7f`, 128 as `02 02 00 80` (cryptobyte.Builder.AddASN1Int64
// already implements minimal two's-complement DER, including the
// disambiguating leading 0x00 whenever the top content byte's high bit
// would otherwise be set).
func addMessageID(b *cryptobyte.Builder, msgID int32) {
	b.AddASN1Int64(int64(msgID))
}

// errResponseBodyTooLarge is the defensive sentinel encodeMessage returns
// if, despite a caller checking entryPDUSize (or any other preflight)
// first, the actually built LDAPMessage body still exceeds maxBodyBytes.
// This should never fire in practice: entryPDUSize's overflow-checked
// arithmetic, run before any buffer is built, is the real gate for
// Search entries, and every other response shape here has a small,
// bounded size regardless of input. encodeMessage's check exists purely
// so no coding mistake in this file can ever hand back an oversized PDU.
var errResponseBodyTooLarge = errors.New("ldap/profile: encoded response body exceeds cap")

// encodeMessage assembles one complete LDAPMessage: messageID, then
// exactly one protocolOp under protocolOpTag, whose content is built by
// addOp. It is the one shared assembly point for every encoder in this
// file (BindResponse, SearchResultEntry, SearchResultDone, and the
// unsupported-operation responses) — one output PDU at a time, matching
// the plan's "Response encoding" section.
func encodeMessage(msgID int32, protocolOpTag asn1.Tag, addOp cryptobyte.BuilderContinuation) ([]byte, error) {
	var body cryptobyte.Builder
	addMessageID(&body, msgID)
	body.AddASN1(protocolOpTag, addOp)
	bodyBytes, err := body.Bytes()
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) > maxBodyBytes {
		return nil, errResponseBodyTooLarge
	}

	var msg cryptobyte.Builder
	msg.AddASN1(asn1.SEQUENCE, func(m *cryptobyte.Builder) {
		m.AddBytes(bodyBytes)
	})
	return msg.Bytes()
}

// encodeBindResponse builds a BindResponse [APPLICATION 1] LDAPMessage:
// LDAPResult fields only — this profile's Bind exchange is simple-only
// (RFC 4511 §4.1.9 note b), so serverSaslCreds is never present.
func encodeBindResponse(msgID int32, result int, d diagnostic) ([]byte, error) {
	return encodeMessage(msgID, tagBindResponse, func(b *cryptobyte.Builder) {
		addLDAPResultFields(b, result, d)
	})
}

// encodeSearchResultDone builds a SearchResultDone [APPLICATION 5]
// LDAPMessage: LDAPResult fields only.
func encodeSearchResultDone(msgID int32, result int, d diagnostic) ([]byte, error) {
	return encodeMessage(msgID, tagSearchResultDone, func(b *cryptobyte.Builder) {
		addLDAPResultFields(b, result, d)
	})
}

// encodeUnsupportedResponse builds the minimal common mapped response for
// one of the six recognizable-but-unsupported request shapes the plan's
// dispatch table names — AddResponse, ModifyResponse, DeleteResponse
// (DelResponse), CompareResponse, ModifyDNResponse, and ExtendedResponse
// (caller passes the matching tagAddResponse/tagModifyResponse/
// tagDelResponse/tagCompareResponse/tagModifyDNResponse/
// tagExtendedResponse constant from protocol.go, converted to byte).
// Every one of these shapes carries LDAPResult fields only: for Extended
// in particular this means no responseName/response fields are ever
// written, even though RFC 4511 §4.12.2 permits them.
func encodeUnsupportedResponse(msgID int32, appTag byte, result int, d diagnostic) ([]byte, error) {
	return encodeMessage(msgID, asn1.Tag(appTag), func(b *cryptobyte.Builder) {
		addLDAPResultFields(b, result, d)
	})
}

// cnAttributeType is the one PartialAttribute "type" this package ever
// emits in a SearchResultEntry — always this exact lowercase spelling,
// regardless of how the inbound SearchRequest spelled its requested
// attribute description (see profile/search.go's case-insensitive
// description matching).
const cnAttributeType = "cn"

// encodeSearchResultEntry builds a SearchResultEntry [APPLICATION 4]
// LDAPMessage carrying exactly one PartialAttribute — type "cn", one
// value (cnValue) — and nothing else: never objectClass, never member,
// never any other attribute. objectName is the entry's already-rendered,
// already-escaped DN (see profile/dn.go's RenderGroupDN); it is written
// verbatim as the LDAPDN OCTET STRING.
//
// Callers on the Search response path (profile/search.go, a later
// sub-task) must call entryPDUSize first and never call this function
// for an entry it rejects — this function's own final size guard
// (encodeMessage's, via errResponseBodyTooLarge) is defensive-only, not
// the mechanism relied on to stay under the response-PDU cap.
func encodeSearchResultEntry(msgID int32, objectName string, cnValue string) ([]byte, error) {
	return encodeMessage(msgID, tagSearchResultEntry, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString([]byte(objectName))
		b.AddASN1(asn1.SEQUENCE, func(attrs *cryptobyte.Builder) {
			attrs.AddASN1(asn1.SEQUENCE, func(attr *cryptobyte.Builder) {
				attr.AddASN1OctetString([]byte(cnAttributeType))
				attr.AddASN1(asn1.SET, func(vals *cryptobyte.Builder) {
					vals.AddASN1OctetString([]byte(cnValue))
				})
			})
		})
	})
}

// --- Response memory bound: overflow-checked preflight arithmetic ------
//
// The plan requires every outbound LDAPMessage body capped at
// maxBodyBytes, preflighted with overflow-checked TLV arithmetic BEFORE
// any buffer is built. entryPDUSize below is that preflight for
// SearchResultEntry, the only response shape whose size depends on
// attacker/operator-influenced input (a role name folded into cnValue
// and the synthetic group DN). Every other encoder above produces a
// small, fixed-shape PDU with no comparable size risk.

// maxMessageIDContentLen is the largest INTEGER content-octet length any
// message ID in this profile's valid range (1..math.MaxInt32, enforced
// by minimalPositiveInt32) can ever take. MaxInt32 (0x7fffffff) already
// fits in 4 content octets with its leading byte's high bit clear, so no
// value in range ever needs a disambiguating 5th octet. entryPDUSize
// uses this fixed constant, rather than a real msgID, precisely so its
// signature (matching the plan's exact declaration) does not need one:
// the resulting size is always at least as large as the real encoding of
// any valid msgID, so this preflight never underestimates.
const maxMessageIDContentLen = 4

// addSize adds two non-negative sizes, reporting whether the sum
// overflowed (wrapped negative) — the "overflow-checked" arithmetic the
// plan requires for the response memory bound, using a plain twos-
// complement wraparound check rather than a bignum type: since a and b
// are both non-negative, a wrapped sum is always < either operand.
func addSize(a, b int) (int, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	sum := a + b
	if sum < a || sum < b {
		return 0, false
	}
	return sum, true
}

// tlvSize returns the total encoded size (tag + minimal DER length
// octets + content) of one TLV whose content is contentSize bytes long,
// or ok=false if contentSize is negative or the arithmetic overflows.
func tlvSize(contentSize int) (int, bool) {
	if contentSize < 0 {
		return 0, false
	}

	var lenOctets int
	switch {
	case contentSize <= 0x7f:
		lenOctets = 1
	case contentSize <= 0xff:
		lenOctets = 2
	case contentSize <= 0xffff:
		lenOctets = 3
	case contentSize <= 0xffffff:
		lenOctets = 4
	default:
		lenOctets = 5
	}

	overhead, ok := addSize(1, lenOctets) // tag octet + length octet(s)
	if !ok {
		return 0, false
	}
	return addSize(overhead, contentSize)
}

// entryPDUSize computes, with overflow-checked arithmetic and entirely
// before any buffer is built, the LDAPMessage body size (messageID +
// protocolOp — the same "body" readFrame/maxBodyBytes bound on the way
// in) that encodeSearchResultEntry(msgID, objectName, cnValue) would
// produce for any valid msgID. ok reports whether that size fits within
// maxBodyBytes; size is meaningful even when ok is false (for
// diagnostics), except that arithmetic overflow itself always reports
// (0, false) rather than a wrapped/misleading size.
func entryPDUSize(objectName, cnValue string) (int, bool) {
	valueTLV, ok := tlvSize(len(cnValue))
	if !ok {
		return 0, false
	}
	valsTLV, ok := tlvSize(valueTLV) // SET OF AttributeValue, exactly one
	if !ok {
		return 0, false
	}
	typeTLV, ok := tlvSize(len(cnAttributeType))
	if !ok {
		return 0, false
	}
	attrContent, ok := addSize(typeTLV, valsTLV)
	if !ok {
		return 0, false
	}
	attrTLV, ok := tlvSize(attrContent) // one PartialAttribute SEQUENCE
	if !ok {
		return 0, false
	}
	attributesTLV, ok := tlvSize(attrTLV) // PartialAttributeList, exactly one
	if !ok {
		return 0, false
	}
	nameTLV, ok := tlvSize(len(objectName))
	if !ok {
		return 0, false
	}
	entryContent, ok := addSize(nameTLV, attributesTLV)
	if !ok {
		return 0, false
	}
	entryTLV, ok := tlvSize(entryContent) // SearchResultEntry [APPLICATION 4]
	if !ok {
		return 0, false
	}
	msgIDTLV, ok := tlvSize(maxMessageIDContentLen)
	if !ok {
		return 0, false
	}
	body, ok := addSize(msgIDTLV, entryTLV)
	if !ok {
		return 0, false
	}
	return body, body <= maxBodyBytes
}
