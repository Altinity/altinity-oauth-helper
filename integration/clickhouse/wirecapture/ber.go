package main

import (
	"bufio"
	"fmt"
	"io"
)

// This file implements ONLY the bounded, fixed-envelope LDAPMessage framing
// the recorder is scoped to (plan §22): enough BER to (a) read one complete
// LDAPMessage's raw bytes so they can be forwarded byte-for-byte, and (b)
// pull the MessageID and the protocolOp's application tag (for Bind/
// Search/Abandon/Unbind labeling and the Abandon target). It never parses
// filters, attributes, controls, or any nested structure beyond that, and
// it never accepts indefinite-length BER — both by design, not oversight.

// maxPDUBytes bounds every single LDAPMessage this recorder will read, on
// either direction of the proxy. A legitimate Bind/Search/Abandon/Unbind
// PDU in this fixture's scope is at most a few hundred bytes; this is a
// generous but still bounded ceiling against a malformed or hostile length
// field driving an unbounded allocation/read.
const maxPDUBytes = 1 << 20 // 1 MiB

// application tags this recorder labels. Values are the raw BER identifier
// octet for each LDAP protocolOp CHOICE alternative (APPLICATION class,
// constructed except Unbind/Abandon which are primitive with no content or
// an IMPLICIT INTEGER content respectively).
const (
	tagBindRequest     = 0x60
	tagBindResponse    = 0x61
	tagUnbindRequest   = 0x42
	tagSearchRequest   = 0x63
	tagSearchResultEnt = 0x64
	tagSearchResDone   = 0x65
	tagAbandonRequest  = 0x50
)

// operationLabel returns the recorder's fixed vocabulary label for a
// protocolOp application tag. Anything outside the small set this recorder
// is scoped to inspect is reported, not silently coerced, so a caller can
// treat "unrecognized" framing as the stop/reassess condition plan §22
// requires rather than mislabeling it.
func operationLabel(tag byte) string {
	switch tag {
	case tagBindRequest:
		return "bind"
	case tagBindResponse:
		return "bind-response"
	case tagUnbindRequest:
		return "unbind"
	case tagSearchRequest:
		return "search"
	case tagSearchResultEnt:
		return "search-result-entry"
	case tagSearchResDone:
		return "search-result-done"
	case tagAbandonRequest:
		return "abandon"
	default:
		return "unrecognized"
	}
}

// pdu is the recorder's own in-memory, non-persisted view of one decoded
// LDAPMessage. It is NOT the committed wire-fixture schema (that is
// internal/wirefixture.PDU, owned exclusively by that package) — this type
// exists only to carry framing results between readLDAPMessage and its
// callers within this package and is never serialized to profile.json or
// session.json.
type pdu struct {
	raw           []byte // the exact bytes read, forwarded byte-for-byte
	messageID     int
	opTag         byte
	abandonTarget int
	hasAbandon    bool
}

// readLDAPMessage reads exactly one complete, bounded, definite-length
// LDAPMessage SEQUENCE from r: outer tag/length/content, then within the
// content a MessageID INTEGER TLV followed by a protocolOp TLV whose tag
// alone is inspected. It does not descend into the protocolOp's own content
// except for AbandonRequest, whose IMPLICIT-INTEGER content directly is the
// target MessageID.
func readLDAPMessage(r *bufio.Reader) (pdu, error) {
	var out pdu

	outerTag, err := r.ReadByte()
	if err != nil {
		return out, err // includes io.EOF: caller decides how to treat a clean close
	}
	if outerTag != 0x30 {
		return out, fmt.Errorf("wirecapture: unexpected outer LDAPMessage tag 0x%02x", outerTag)
	}
	outerLen, lenBytes, err := readDefiniteLength(r)
	if err != nil {
		return out, fmt.Errorf("wirecapture: LDAPMessage length: %w", err)
	}
	if outerLen > maxPDUBytes {
		return out, fmt.Errorf("wirecapture: LDAPMessage length %d exceeds bound %d", outerLen, maxPDUBytes)
	}
	content := make([]byte, outerLen)
	if _, err := io.ReadFull(r, content); err != nil {
		return out, fmt.Errorf("wirecapture: LDAPMessage content: %w", err)
	}

	out.raw = make([]byte, 0, 1+len(lenBytes)+len(content))
	out.raw = append(out.raw, outerTag)
	out.raw = append(out.raw, lenBytes...)
	out.raw = append(out.raw, content...)

	// messageID: INTEGER TLV at content[0:].
	if len(content) < 2 || content[0] != 0x02 {
		return out, fmt.Errorf("wirecapture: LDAPMessage missing leading MessageID INTEGER")
	}
	midLen, _, rest, err := readDefiniteLengthFromSlice(content[1:])
	if err != nil {
		return out, fmt.Errorf("wirecapture: MessageID length: %w", err)
	}
	if midLen == 0 || midLen > 4 || midLen > len(rest) {
		return out, fmt.Errorf("wirecapture: MessageID content length %d out of bounds", midLen)
	}
	midBytes := rest[:midLen]
	out.messageID = decodeUnsignedMinimalInt(midBytes)
	after := rest[midLen:]

	// protocolOp: only the leading tag is inspected.
	if len(after) < 1 {
		return out, fmt.Errorf("wirecapture: LDAPMessage missing protocolOp")
	}
	out.opTag = after[0]
	opLen, opLenBytes, opRest, err := readDefiniteLengthFromSlice(after[1:])
	if err != nil {
		return out, fmt.Errorf("wirecapture: protocolOp length: %w", err)
	}
	if opLen > len(opRest) {
		return out, fmt.Errorf("wirecapture: protocolOp content length %d exceeds remaining bytes", opLen)
	}
	opContent := opRest[:opLen]
	_ = opLenBytes

	if out.opTag == tagAbandonRequest {
		// AbandonRequest ::= [APPLICATION 16] MessageID — an IMPLICIT tag on
		// INTEGER, so opContent itself directly holds the target's integer
		// bytes (no nested TLV).
		if len(opContent) == 0 || len(opContent) > 4 {
			return out, fmt.Errorf("wirecapture: AbandonRequest target length %d out of bounds", len(opContent))
		}
		out.abandonTarget = decodeUnsignedMinimalInt(opContent)
		out.hasAbandon = true
	}

	return out, nil
}

// readDefiniteLength reads a DER definite-form length from r, returning the
// decoded value and the exact bytes consumed (so callers can reconstruct
// raw framing without re-encoding). It rejects indefinite length (0x80
// alone) and non-minimal / oversized long-form encodings, matching this
// recorder's "bounded ... definite lengths" scope (plan §22/§32).
func readDefiniteLength(r *bufio.Reader) (int, []byte, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, nil, fmt.Errorf("read length: %w", err)
	}
	if first == 0x80 {
		return 0, nil, fmt.Errorf("indefinite length not supported")
	}
	if first < 0x80 {
		return int(first), []byte{first}, nil
	}
	n := int(first & 0x7f)
	if n == 0 || n > 4 {
		return 0, nil, fmt.Errorf("unsupported long-form length octet count %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, fmt.Errorf("read long-form length: %w", err)
	}
	if buf[0] == 0x00 {
		return 0, nil, fmt.Errorf("non-minimal long-form length")
	}
	val := 0
	for _, b := range buf {
		val = val<<8 | int(b)
	}
	all := append([]byte{first}, buf...)
	return val, all, nil
}

// readDefiniteLengthFromSlice mirrors readDefiniteLength but operates over
// an in-memory slice (used once the outer LDAPMessage content has already
// been buffered), returning the decoded length, the length-octet count
// consumed, and the remaining slice after those octets.
func readDefiniteLengthFromSlice(b []byte) (int, int, []byte, error) {
	if len(b) < 1 {
		return 0, 0, nil, fmt.Errorf("read length: empty")
	}
	first := b[0]
	if first == 0x80 {
		return 0, 0, nil, fmt.Errorf("indefinite length not supported")
	}
	if first < 0x80 {
		return int(first), 1, b[1:], nil
	}
	n := int(first & 0x7f)
	if n == 0 || n > 4 || len(b) < 1+n {
		return 0, 0, nil, fmt.Errorf("unsupported/truncated long-form length")
	}
	lenBytes := b[1 : 1+n]
	if lenBytes[0] == 0x00 {
		return 0, 0, nil, fmt.Errorf("non-minimal long-form length")
	}
	val := 0
	for _, x := range lenBytes {
		val = val<<8 | int(x)
	}
	return val, 1 + n, b[1+n:], nil
}

// decodeUnsignedMinimalInt decodes an INTEGER's content bytes as a plain
// non-negative value. MessageID and AbandonRequest targets are always
// positive per RFC 4511, so a two's-complement negative encoding here is
// out of this recorder's supported scope; callers bound the byte count
// (<=4) before calling this, keeping the result well within int range.
func decodeUnsignedMinimalInt(b []byte) int {
	v := 0
	for _, x := range b {
		v = v<<8 | int(x)
	}
	return v
}
