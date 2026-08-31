package profile

import (
	"io"
	"math"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// This file implements the "Framing before allocation" and "LDAPMessage
// envelope"/"Controls" sections of the Phase 2 plan: readFrame reads and
// bounds-checks exactly one LDAPMessage's outer SEQUENCE tag/length
// straight off the wire, entirely before allocating a buffer sized to its
// declared body — the historical approximately-2-GiB length declaration
// this profile must reject is rejected without ever reading its own length
// octets, let alone allocating anything sized by them. decodeEnvelope and
// scanControls then decode that bounded buffer's MessageID/protocolOp/
// Controls structure using cryptobyte.
//
// # Allocation accounting
//
// allocBody is the package's one production-shaped body allocator
// (make([]byte, n)) exposed as a reassignable package-level variable so
// tests can wrap it to record every call's size without exporting
// anything — proving both "no allocation happens before the cap check"
// (boundary/sabotage tests) and "no allocation ever exceeds maxBodyBytes"
// (FuzzLDAPFrame). Production code must never call make([]byte, ...) for
// a declared body length anywhere but through this hook.
var allocBody = func(n int) []byte { return make([]byte, n) }

// tagSequence is the universal, constructed SEQUENCE tag (0x30) every
// LDAPMessage's outer envelope must start with.
const tagSequence = 0x30

// readFrame reads exactly one bounded LDAPMessage off r and returns the
// outer SEQUENCE's raw content bytes — the still-BER-encoded
// messageID/protocolOp/controls — never the tag/length octets that
// preceded it, and never more than maxBodyBytes.
//
// r must already have its read deadline set by the caller before this is
// called; readFrame does not touch deadlines itself. Every check below
// runs, in this exact order, before allocating anything sized by the
// declared length ("Framing before allocation"):
//
//  1. the outer tag must be universal constructed SEQUENCE (0x30);
//  2. a definite length is required — the indefinite form (the single
//     length byte 0x80) is rejected;
//  3. a long-form length using more than three length octets is rejected
//     (this alone rejects the historical ~2 GiB declaration,
//     `30 84 7f ff ff ff`, without ever reading its four length octets);
//  4. a long-form length octet sequence starting with 0x00 is rejected
//     (non-minimal: a shorter encoding exists);
//  5. a long-form length whose value is < 128 is rejected (non-minimal:
//     short form would have sufficed);
//  6. a declared length > maxBodyBytes is rejected.
//
// Only once every check above has passed does readFrame call allocBody
// for exactly the declared length and fill it with io.ReadFull.
//
// A rejection at any of steps 1-6 returns errMalformed and never calls
// allocBody. An I/O error reading the tag, length, or body octets
// themselves (deadline expiry, EOF, connection reset, a body shorter than
// declared) is returned unwrapped from the underlying io.ReadFull call —
// that is stream/connection trouble, not a decision this profile made
// about the bytes it did see, and callers should not treat it the same
// as errMalformed's "definitely malformed input" signal.
func readFrame(r io.Reader) ([]byte, error) {
	var tagByte [1]byte
	if _, err := io.ReadFull(r, tagByte[:]); err != nil {
		return nil, err
	}
	if tagByte[0] != tagSequence {
		return nil, errMalformed
	}

	var firstLenByte [1]byte
	if _, err := io.ReadFull(r, firstLenByte[:]); err != nil {
		return nil, err
	}

	var length int
	if firstLenByte[0]&0x80 == 0 {
		// Short form (ITU-T X.690 §8.1.3.4): the length is the low 7
		// bits of this one octet, 0..127.
		length = int(firstLenByte[0])
	} else {
		lenLen := int(firstLenByte[0] &^ 0x80)
		switch {
		case lenLen == 0:
			// 0x80 exactly: the indefinite form. Not permitted here.
			return nil, errMalformed
		case lenLen > 3:
			// More than three length octets — also where the ~2 GiB
			// historical declaration (lenLen=4) is rejected, before
			// reading any of its length octets.
			return nil, errMalformed
		}

		var lenOctetsArr [3]byte
		lenOctets := lenOctetsArr[:lenLen]
		if _, err := io.ReadFull(r, lenOctets); err != nil {
			return nil, err
		}
		if lenOctets[0] == 0x00 {
			// Non-minimal: a shorter long-form encoding (or short form)
			// exists for this value.
			return nil, errMalformed
		}

		var v uint32
		for _, b := range lenOctets {
			v = v<<8 | uint32(b)
		}
		if v < 128 {
			// Non-minimal: this value should have used short form.
			return nil, errMalformed
		}
		// lenLen <= 3 keeps v within 24 bits, so this branch can never
		// actually overflow int on any platform this runs on; the check
		// is kept anyway as the named, defensive proof against integer
		// overflow the plan requires, in case the three-octet cap above
		// is ever loosened without this line being revisited.
		if v > math.MaxInt32 {
			return nil, errMalformed
		}
		length = int(v)
	}

	if length > maxBodyBytes {
		return nil, errMalformed
	}

	body := allocBody(length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// Envelope is one decoded LDAPMessage: its MessageID, the raw
// application-tagged protocolOp content, and whether any Controls element
// carried a critical control.
//
// Content is the protocolOp's tag/length-stripped body, still
// BER-encoded — decoding it further (BindRequest, SearchRequest, ...) is
// each operation's own decoder's job (bind.go, search.go), kept outside
// this file's framing/envelope/Controls scope.
type Envelope struct {
	MessageID   int32
	ProtocolOp  asn1.Tag
	Content     cryptobyte.String
	HasCritical bool
}

// decodeEnvelope decodes body — readFrame's returned SEQUENCE content —
// as one LDAPMessage: a minimally encoded positive MessageID (1..MaxInt32,
// via minimalPositiveInt32), exactly one protocolOp, an optional
// Controls [0], and no trailing bytes. Any structural failure returns
// errMalformed; the caller (server.go) treats that as "close the
// connection without resynchronizing the stream", never as a case to
// recover from mid-stream.
func decodeEnvelope(body []byte) (Envelope, error) {
	s := cryptobyte.String(body)

	var messageIDContent cryptobyte.String
	if !s.ReadASN1(&messageIDContent, asn1.INTEGER) {
		return Envelope{}, errMalformed
	}
	messageID, err := minimalPositiveInt32(messageIDContent)
	if err != nil {
		return Envelope{}, errMalformed
	}

	var protocolOpTag asn1.Tag
	var protocolOpContent cryptobyte.String
	if !s.ReadAnyASN1(&protocolOpContent, &protocolOpTag) {
		return Envelope{}, errMalformed
	}

	hasCritical, err := scanControls(&s)
	if err != nil {
		return Envelope{}, errMalformed
	}

	if !s.Empty() {
		// Trailing bytes after controls (or after protocolOp, if no
		// controls element was present).
		return Envelope{}, errMalformed
	}

	return Envelope{
		MessageID:   messageID,
		ProtocolOp:  protocolOpTag,
		Content:     protocolOpContent,
		HasCritical: hasCritical,
	}, nil
}

// scanControls consumes an optional Controls [0] element from the tail of
// one LDAPMessage (s, positioned immediately after protocolOp) and reports
// only whether any control's criticality was TRUE. Per the plan's
// "Minimal scanner": controlType and controlValue are read only far enough
// to walk past them structurally and are never retained, logged, or
// interpreted beyond that — no OID or value from any control survives
// this function's return.
//
// criticality is decoded with cryptobyte.ReadASN1Boolean's strict
// 0x00/0xff-only BOOLEAN rule (matching the formerly vendored goldap
// parser, deleted at the #33 phase 4 cutover, and the pinned cryptobyte
// release): a non-canonical TRUE encoding such as content byte 0x01 is
// malformed, not a compatibility narrowing.
//
// A malformed Controls element returns errMalformed.
func scanControls(s *cryptobyte.String) (bool, error) {
	var present bool
	var controls cryptobyte.String
	if !s.ReadOptionalASN1(&controls, &present, tagControls) {
		return false, errMalformed
	}
	if !present {
		return false, nil
	}

	hasCritical := false
	for !controls.Empty() {
		var control cryptobyte.String
		if !controls.ReadASN1(&control, asn1.SEQUENCE) {
			return false, errMalformed
		}

		var controlType cryptobyte.String
		if !control.ReadASN1(&controlType, asn1.OCTET_STRING) {
			return false, errMalformed
		}

		criticality := false
		if control.PeekASN1Tag(asn1.BOOLEAN) {
			if !control.ReadASN1Boolean(&criticality) {
				return false, errMalformed
			}
		}

		if control.PeekASN1Tag(asn1.OCTET_STRING) {
			var value []byte
			if !control.ReadASN1Bytes(&value, asn1.OCTET_STRING) {
				return false, errMalformed
			}
		}

		if !control.Empty() {
			// Trailing bytes inside one Control SEQUENCE.
			return false, errMalformed
		}

		if criticality {
			hasCritical = true
		}
	}

	return hasCritical, nil
}

// readMessage reads and decodes exactly one bounded LDAPMessage off r,
// composing readFrame and decodeEnvelope. r must already have its read
// deadline set by the caller.
func readMessage(r io.Reader) (Envelope, error) {
	body, err := readFrame(r)
	if err != nil {
		return Envelope{}, err
	}
	return decodeEnvelope(body)
}
