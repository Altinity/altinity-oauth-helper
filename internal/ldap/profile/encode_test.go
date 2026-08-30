package profile

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// --- shared expected-bytes builders --------------------------------
//
// These reuse frame_test.go's already-independent BER construction
// helpers (tlv, encodeLength, minimalIntegerContent, berInteger,
// buildMessage) — never encode.go's own production code — so a bug
// shared between the encoder and its test can't cancel out.

// ldapResultContent returns the three LDAPResult fields' encoded content
// (resultCode ENUMERATED, always-empty matchedDN, diagnosticMessage
// carrying text) — the tail every response encoder in this file produces.
func ldapResultContent(result int64, text string) []byte {
	out := tlv(0x0a, minimalIntegerContent(result)) // ENUMERATED
	out = append(out, tlv(0x04, nil)...)            // matchedDN, always empty
	out = append(out, tlv(0x04, []byte(text))...)   // diagnosticMessage
	return out
}

// cnEntryContent returns a SearchResultEntry's content: objectName plus
// exactly one PartialAttribute (type "cn", one value).
func cnEntryContent(objectName, cnValue string) []byte {
	valSet := tlv(0x31, tlv(0x04, []byte(cnValue)))
	partialAttr := tlv(0x30, append(tlv(0x04, []byte("cn")), valSet...))
	attributes := tlv(0x30, partialAttr)
	return append(tlv(0x04, []byte(objectName)), attributes...)
}

// expectedResponse assembles a complete expected LDAPMessage: msgID as a
// minimal INTEGER, protocolOp under tag wrapping content, no Controls.
func expectedResponse(msgID int32, tag byte, content []byte) []byte {
	return buildMessage(berInteger(int64(msgID)), tlv(tag, content), nil)
}

// --- BindResponse / SearchResultDone: exact LDAPResult-shaped bytes -----

func TestEncodeBindResponse_ExactBytes(t *testing.T) {
	cases := []struct {
		result int
		diag   diagnostic
		text   string
	}{
		{0, diagEmpty, ""},
		{49, diagInvalidCredentials, "invalid credentials"},
		{7, diagSimpleOnly, "only simple authentication is supported"},
		{2, diagLDAPv3Required, "LDAPv3 required"},
		{12, diagCriticalControl, "critical control unavailable"},
	}
	const msgID = int32(1)
	for _, c := range cases {
		got, err := encodeBindResponse(msgID, c.result, c.diag)
		if err != nil {
			t.Fatalf("encodeBindResponse(result=%d) error = %v", c.result, err)
		}
		want := expectedResponse(msgID, byte(tagBindResponse), ldapResultContent(int64(c.result), c.text))
		if !bytes.Equal(got, want) {
			t.Errorf("encodeBindResponse(result=%d):\n got  % x\nwant % x", c.result, got, want)
		}
	}
}

func TestEncodeSearchResultDone_ExactBytes(t *testing.T) {
	cases := []struct {
		result int
		diag   diagnostic
		text   string
	}{
		{0, diagEmpty, ""},
		{3, diagEmpty, ""},
		{4, diagEmpty, ""},
		{11, diagEmpty, ""},
		{12, diagCriticalControl, "critical control unavailable"},
		{50, diagInsufficientAccess, "insufficient access"},
	}
	const msgID = int32(1)
	for _, c := range cases {
		got, err := encodeSearchResultDone(msgID, c.result, c.diag)
		if err != nil {
			t.Fatalf("encodeSearchResultDone(result=%d) error = %v", c.result, err)
		}
		want := expectedResponse(msgID, byte(tagSearchResultDone), ldapResultContent(int64(c.result), c.text))
		if !bytes.Equal(got, want) {
			t.Errorf("encodeSearchResultDone(result=%d):\n got  % x\nwant % x", c.result, got, want)
		}
	}
}

func TestEncodeUnsupportedResponse_ExactBytes(t *testing.T) {
	const msgID = int32(1)
	cases := []struct {
		name   string
		tag    byte
		result int
		diag   diagnostic
		text   string
	}{
		{"Add", byte(tagAddResponse), 53, diagEmpty, ""},
		{"Modify", byte(tagModifyResponse), 53, diagEmpty, ""},
		{"Delete", byte(tagDelResponse), 53, diagEmpty, ""},
		{"Compare", byte(tagCompareResponse), 53, diagEmpty, ""},
		{"ModifyDN", byte(tagModifyDNResponse), 53, diagEmpty, ""},
		{"Extended", byte(tagExtendedResponse), 53, diagOperationUnsupported, "operation not supported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := encodeUnsupportedResponse(msgID, c.tag, c.result, c.diag)
			if err != nil {
				t.Fatalf("encodeUnsupportedResponse(%s) error = %v", c.name, err)
			}
			want := expectedResponse(msgID, c.tag, ldapResultContent(int64(c.result), c.text))
			if !bytes.Equal(got, want) {
				t.Errorf("%s:\n got  % x\nwant % x", c.name, got, want)
			}
		})
	}
}

// --- SearchResultEntry: exact cn-only wire shape ------------------------

func TestEncodeSearchResultEntry_ExactBytes(t *testing.T) {
	const msgID = int32(1)
	const objectName = "cn=viewer,ou=groups,dc=example,dc=com"
	const cnValue = "viewer"

	got, err := encodeSearchResultEntry(msgID, objectName, cnValue)
	if err != nil {
		t.Fatalf("encodeSearchResultEntry error = %v", err)
	}
	want := expectedResponse(msgID, byte(tagSearchResultEntry), cnEntryContent(objectName, cnValue))
	if !bytes.Equal(got, want) {
		t.Fatalf("cn entry:\n got  % x\nwant % x", got, want)
	}

	for _, forbidden := range []string{"objectClass", "member"} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Errorf("encoded entry contains forbidden substring %q: % x", forbidden, got)
		}
	}
}

// TestEncodeSearchResultEntry_TypeAlwaysLowercaseCN documents that this
// encoder's PartialAttribute type is unconditionally the compile-time
// constant "cn": nothing here ever varies by how an inbound SearchRequest
// spelled the requested attribute description (that case-insensitive
// matching is search.go's job, a later sub-task) — encodeSearchResultEntry
// takes no such input and so can only ever emit lowercase "cn".
func TestEncodeSearchResultEntry_TypeAlwaysLowercaseCN(t *testing.T) {
	got, err := encodeSearchResultEntry(5, "cn=x,dc=example,dc=com", "x")
	if err != nil {
		t.Fatalf("encodeSearchResultEntry error = %v", err)
	}
	if !bytes.Contains(got, tlv(0x04, []byte("cn"))) {
		t.Fatalf("expected lowercase %q attribute-type TLV in encoded entry: % x", "cn", got)
	}
	if bytes.Contains(got, tlv(0x04, []byte("CN"))) {
		t.Fatalf("unexpected uppercase %q attribute-type TLV in encoded entry: % x", "CN", got)
	}
}

// --- MessageID: minimal positive INTEGER, shared encoder ---------------

func TestAddMessageID_ExactBytes(t *testing.T) {
	cases := []struct {
		msgID int32
		want  []byte
	}{
		{1, []byte{0x02, 0x01, 0x01}},
		{127, []byte{0x02, 0x01, 0x7f}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}},
		{math.MaxInt32, tlv(0x02, minimalIntegerContent(math.MaxInt32))},
	}
	for _, c := range cases {
		var b cryptobyte.Builder
		addMessageID(&b, c.msgID)
		got, err := b.Bytes()
		if err != nil {
			t.Fatalf("addMessageID(%d) builder error = %v", c.msgID, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("addMessageID(%d) = % x, want % x", c.msgID, got, c.want)
		}
	}
}

// TestEncodeBindResponse_MessageIDBoundary asserts the literal byte
// sequences 02 01 7f (127) and 02 02 00 80 (128) appear at the MessageID
// position of a complete, otherwise-ordinary encoded LDAPMessage — not
// just in isolation (TestAddMessageID_ExactBytes above) but as actually
// assembled by encodeBindResponse. Both responses here have a body under
// 128 bytes, so the outer SEQUENCE's own length is single-octet (short
// form): the two bytes right after it are exactly the outer tag+length,
// and the MessageID TLV begins immediately after that.
func TestEncodeBindResponse_MessageIDBoundary(t *testing.T) {
	got127, err := encodeBindResponse(127, 0, diagEmpty)
	if err != nil {
		t.Fatalf("encodeBindResponse(127) error = %v", err)
	}
	if len(got127) < 2 || !bytes.HasPrefix(got127[2:], []byte{0x02, 0x01, 0x7f}) {
		t.Fatalf("msgID=127: expected `02 01 7f` at the MessageID position, got % x", got127)
	}

	got128, err := encodeBindResponse(128, 0, diagEmpty)
	if err != nil {
		t.Fatalf("encodeBindResponse(128) error = %v", err)
	}
	if len(got128) < 2 || !bytes.HasPrefix(got128[2:], []byte{0x02, 0x02, 0x00, 0x80}) {
		t.Fatalf("msgID=128: expected `02 02 00 80` at the MessageID position, got % x", got128)
	}
}

// --- Diagnostics: closed enum, exhaustive text mapping ------------------

func TestDiagnostic_TextIsOneOfSevenLiterals(t *testing.T) {
	allowed := map[string]bool{
		"":                    true,
		"invalid credentials": true,
		"only simple authentication is supported": true,
		"LDAPv3 required":                         true,
		"insufficient access":                     true,
		"critical control unavailable":            true,
		"operation not supported":                 true,
	}
	all := []diagnostic{
		diagEmpty,
		diagInvalidCredentials,
		diagSimpleOnly,
		diagLDAPv3Required,
		diagInsufficientAccess,
		diagCriticalControl,
		diagOperationUnsupported,
	}
	seen := map[string]bool{}
	for _, d := range all {
		text := d.text()
		if !allowed[text] {
			t.Errorf("diagnostic %d produced text %q, not one of the seven mandated literals", d, text)
		}
		seen[text] = true
	}
	if len(seen) != 7 {
		t.Errorf("expected exactly 7 distinct diagnostic texts across the 7 constants, got %d: %v", len(seen), seen)
	}
}

// --- Response memory bound: overflow-checked preflight ------------------

func TestEntryPDUSize_ExactFitBoundary(t *testing.T) {
	// Hand-derived (not by calling tlvSize/addSize) so this is an
	// independent check of entryPDUSize's boundary: with objectName empty,
	// a 65504-byte cnValue produces a body of exactly maxBodyBytes
	// (65536); one byte more overflows the cap by exactly one byte. See
	// the accompanying derivation in this sub-task's implementation notes
	// — every intermediate TLV length stays within the 3-length-octet
	// (<=65535 content) band, so no length-class boundary is crossed
	// between the two cases.
	const exactFitLen = 65504

	fit, ok := entryPDUSize("", strings.Repeat("a", exactFitLen))
	if !ok || fit != maxBodyBytes {
		t.Fatalf("entryPDUSize exact-fit: got (%d, %v), want (%d, true)", fit, ok, maxBodyBytes)
	}

	over, ok := entryPDUSize("", strings.Repeat("a", exactFitLen+1))
	if ok || over != maxBodyBytes+1 {
		t.Fatalf("entryPDUSize one-over: got (%d, %v), want (%d, false)", over, ok, maxBodyBytes+1)
	}
}

func TestAddSize_Overflow(t *testing.T) {
	if v, ok := addSize(5, 7); !ok || v != 12 {
		t.Errorf("addSize(5, 7) = (%d, %v), want (12, true)", v, ok)
	}
	if _, ok := addSize(math.MaxInt, 1); ok {
		t.Error("addSize(MaxInt, 1) should overflow")
	}
	if _, ok := addSize(-1, 5); ok {
		t.Error("addSize(-1, 5) should be rejected (negative input)")
	}
}

func TestTlvSize_Overflow(t *testing.T) {
	if _, ok := tlvSize(-1); ok {
		t.Error("tlvSize(-1) should be rejected (negative content size)")
	}
	if _, ok := tlvSize(math.MaxInt); ok {
		t.Error("tlvSize(MaxInt) should overflow (tag+length overhead pushes past MaxInt)")
	}
	if v, ok := tlvSize(4); !ok || v != 6 {
		t.Errorf("tlvSize(4) = (%d, %v), want (6, true)", v, ok)
	}
}

// TestEntryPDUSize_OverflowSafe exercises entryPDUSize with a cnValue far
// larger than any real Search response could ever legitimately carry
// (five cap's worth of bytes) — a size real allocated-string arithmetic
// can still represent, unlike a true int-overflow-inducing length, but
// large enough to prove entryPDUSize never panics and always reports the
// cap correctly rather than wrapping into a false accept.
func TestEntryPDUSize_OverflowSafe(t *testing.T) {
	huge := strings.Repeat("x", 5*maxBodyBytes)
	size, ok := entryPDUSize("", huge)
	if ok {
		t.Fatalf("entryPDUSize(huge cnValue) unexpectedly accepted: size=%d", size)
	}
}
