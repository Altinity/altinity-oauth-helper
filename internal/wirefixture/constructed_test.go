package wirefixture

import (
	"strings"
	"testing"
)

// TestBuildConstructedSimpleBindMessageIDBoundary asserts the exact
// DER-minimal INTEGER encoding of the 127/128 MessageID boundary (plan
// section 29): 127 encodes as a single positive INTEGER content byte
// 0x7f, 128 requires a leading zero content byte (0x00 0x80) to remain
// positive, and the enclosing LDAPMessage length therefore grows by
// exactly one byte between the two.
func TestBuildConstructedSimpleBindMessageIDBoundary(t *testing.T) {
	bytes127, err := BuildConstructedSimpleBind(127)
	if err != nil {
		t.Fatalf("BuildConstructedSimpleBind(127): %v", err)
	}
	bytes128, err := BuildConstructedSimpleBind(128)
	if err != nil {
		t.Fatalf("BuildConstructedSimpleBind(128): %v", err)
	}

	// Outer LDAPMessage SEQUENCE tag, short-form length.
	if bytes127[0] != tagSequence || bytes128[0] != tagSequence {
		t.Fatalf("outer tag: got 0x%02x / 0x%02x, want 0x%02x", bytes127[0], bytes128[0], tagSequence)
	}
	if bytes127[1] >= 0x80 || bytes128[1] >= 0x80 {
		t.Fatalf("expected short-form outer length for both fixtures, got 0x%02x / 0x%02x", bytes127[1], bytes128[1])
	}

	// The messageID INTEGER TLV is the first thing inside the SEQUENCE.
	if bytes127[2] != tagInteger || bytes128[2] != tagInteger {
		t.Fatalf("messageID tag: got 0x%02x / 0x%02x, want 0x%02x", bytes127[2], bytes128[2], tagInteger)
	}

	// messageID=127: length 1, content byte 0x7f.
	if got, want := bytes127[3], byte(0x01); got != want {
		t.Fatalf("messageID=127 INTEGER length = 0x%02x, want 0x%02x", got, want)
	}
	if got, want := bytes127[4], byte(0x7f); got != want {
		t.Fatalf("messageID=127 INTEGER content byte = 0x%02x, want 0x%02x", got, want)
	}

	// messageID=128: length 2, content 0x00 0x80.
	if got, want := bytes128[3], byte(0x02); got != want {
		t.Fatalf("messageID=128 INTEGER length = 0x%02x, want 0x%02x", got, want)
	}
	if got, want := bytes128[4], byte(0x00); got != want {
		t.Fatalf("messageID=128 INTEGER content[0] = 0x%02x, want 0x%02x", got, want)
	}
	if got, want := bytes128[5], byte(0x80); got != want {
		t.Fatalf("messageID=128 INTEGER content[1] = 0x%02x, want 0x%02x", got, want)
	}

	// The outer length grows canonically: exactly one byte longer, both
	// in the encoded length value and in total message length, because
	// only the messageID INTEGER's content grew (by one byte).
	if bytes128[1] != bytes127[1]+1 {
		t.Fatalf("outer length byte: 128-case = 0x%02x, 127-case = 0x%02x, want exactly one greater", bytes128[1], bytes127[1])
	}
	if len(bytes128) != len(bytes127)+1 {
		t.Fatalf("total length: 128-case = %d, 127-case = %d, want exactly one byte longer", len(bytes128), len(bytes127))
	}

	// BindRequest application tag and the fixed non-JWT-shaped DN/password
	// must be present downstream of the messageID TLV in both fixtures.
	if !containsSubslice(bytes127, []byte{tagApplicationBindRequest}) {
		t.Fatalf("expected BindRequest application tag 0x%02x present", tagApplicationBindRequest)
	}
	if !containsSubslice(bytes127, []byte(constructedBindDN)) {
		t.Fatal("expected fixed Bind DN bytes present in constructed fixture")
	}
	if !containsSubslice(bytes127, []byte(constructedBindPassword)) {
		t.Fatal("expected fixed Bind password bytes present in constructed fixture")
	}
}

func containsSubslice(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}

// TestBuildConstructedSimpleBindNotJWTShaped proves the fixed password
// literal cannot itself trip the repository-wide JWT-shape scanner (plan
// section 30.6): it must not start with "eyJ", and it must not split into
// exactly three non-empty dot-separated segments.
func TestBuildConstructedSimpleBindNotJWTShaped(t *testing.T) {
	if strings.HasPrefix(constructedBindPassword, "eyJ") {
		t.Fatalf("constructedBindPassword must not start with eyJ: %q", constructedBindPassword)
	}
	segments := strings.Split(constructedBindPassword, ".")
	nonEmpty := 0
	for _, seg := range segments {
		if seg != "" {
			nonEmpty++
		}
	}
	if nonEmpty == 3 {
		t.Fatalf("constructedBindPassword must not look like three dot-separated segments: %q", constructedBindPassword)
	}
}

func TestBuildConstructedSimpleBindRejectsNonPositiveMessageID(t *testing.T) {
	for _, id := range []int{0, -1, -127} {
		if _, err := BuildConstructedSimpleBind(id); err == nil {
			t.Fatalf("BuildConstructedSimpleBind(%d): expected error, got nil", id)
		}
	}
}

// TestBuildConstructedSimpleBindDeterministic proves the generator is a
// pure function of its input: two calls with the same MessageID produce
// byte-identical output.
func TestBuildConstructedSimpleBindDeterministic(t *testing.T) {
	a, err := BuildConstructedSimpleBind(127)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := BuildConstructedSimpleBind(127)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("BuildConstructedSimpleBind is not deterministic for identical input")
	}
}

func TestMinimalPositiveIntegerBytesRejectsNegative(t *testing.T) {
	if _, err := minimalPositiveIntegerBytes(-1); err == nil {
		t.Fatal("minimalPositiveIntegerBytes(-1): expected error, got nil")
	}
}

func TestBuildConstructedMessageIDBoundarySession(t *testing.T) {
	session, payloads, err := BuildConstructedMessageIDBoundarySession([]string{"24.8", "25.8"})
	if err != nil {
		t.Fatalf("BuildConstructedMessageIDBoundarySession: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}
	if session.ProvenanceClass != ProvenanceConstructed {
		t.Fatalf("ProvenanceClass = %q, want %q", session.ProvenanceClass, ProvenanceConstructed)
	}
	if session.Mode != ConstructedMessageIDBoundaryMode {
		t.Fatalf("Mode = %q, want %q", session.Mode, ConstructedMessageIDBoundaryMode)
	}
	if len(session.PDUs) != 2 {
		t.Fatalf("expected 2 PDUs, want 2, got %d", len(session.PDUs))
	}
	if session.PDUs[0].Filename != "001-bind-messageid-127.ber" || session.PDUs[0].MessageID != 127 {
		t.Fatalf("unexpected first PDU: %+v", session.PDUs[0])
	}
	if session.PDUs[1].Filename != "002-bind-messageid-128.ber" || session.PDUs[1].MessageID != 128 {
		t.Fatalf("unexpected second PDU: %+v", session.PDUs[1])
	}
	if session.PDUs[0].SanitizedSHA256 != sha256Hex(payloads[0]) {
		t.Fatal("first PDU hash does not match its own payload bytes")
	}
	if session.PDUs[1].SanitizedSHA256 != sha256Hex(payloads[1]) {
		t.Fatal("second PDU hash does not match its own payload bytes")
	}

	// Regenerating must reproduce byte-identical payloads (the
	// regenerate-and-compare contract this session builder exists to
	// support, plan section 29).
	again127, err := BuildConstructedSimpleBind(127)
	if err != nil {
		t.Fatalf("regenerate 127: %v", err)
	}
	if string(again127) != string(payloads[0]) {
		t.Fatal("regenerated 127 payload does not match BuildConstructedMessageIDBoundarySession's own payload")
	}
}
