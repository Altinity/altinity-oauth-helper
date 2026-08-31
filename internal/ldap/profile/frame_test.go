package profile

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// --- shared BER test-construction helpers -----------------------------
//
// These build well-formed test fixtures only. Malformed vectors (the
// whole point of this file) are written as literal byte slices instead,
// so a bug in a "helper that builds malformed BER" can never quietly
// launder a bad test into a passing one.

// encodeLength returns the minimal DER length encoding of n: short form
// for n < 128, long form (with no leading zero, and no more octets than
// needed) otherwise.
func encodeLength(n int) []byte {
	if n < 0 {
		panic("encodeLength: negative length")
	}
	if n < 128 {
		return []byte{byte(n)}
	}
	var octets []byte
	for v := n; v > 0; v >>= 8 {
		octets = append([]byte{byte(v)}, octets...)
	}
	return append([]byte{0x80 | byte(len(octets))}, octets...)
}

// tlv wraps content in tag+minimal-length+content.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLength(len(content))...)
	return append(out, content...)
}

// minimalIntegerContent returns the minimal two's-complement DER content
// octets (no tag/length) for non-negative v.
func minimalIntegerContent(v int64) []byte {
	if v < 0 {
		panic("minimalIntegerContent: only non-negative values supported")
	}
	if v == 0 {
		return []byte{0x00}
	}
	var out []byte
	for u := uint64(v); u > 0; u >>= 8 {
		out = append([]byte{byte(u)}, out...)
	}
	if out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}
	return out
}

// berInteger returns a complete, minimally encoded INTEGER TLV for
// non-negative v.
func berInteger(v int64) []byte {
	return tlv(0x02, minimalIntegerContent(v))
}

// trivialUnbind is a complete, valid, minimal protocolOp
// ([APPLICATION 2] primitive, no content — UnbindRequest) used as filler
// in envelope/Controls-focused fixtures that don't care which protocolOp
// is present.
var trivialUnbind = []byte{0x42, 0x00}

// buildMessage assembles one complete LDAPMessage: the outer SEQUENCE
// wrapping messageID (a complete INTEGER TLV) + protocolOp (a complete
// TLV) + controls (a complete, already [0]-tagged TLV, or nil for none).
func buildMessage(messageID, protocolOp, controls []byte) []byte {
	body := append(append([]byte{}, messageID...), protocolOp...)
	body = append(body, controls...)
	return tlv(tagSequence, body)
}

// buildControl assembles one complete Control SEQUENCE. criticality nil
// omits the field (DEFAULT FALSE applies); value nil omits the optional
// controlValue.
func buildControl(controlType string, criticality *bool, value []byte) []byte {
	content := tlv(0x04, []byte(controlType))
	if criticality != nil {
		b := byte(0x00)
		if *criticality {
			b = 0xff
		}
		content = append(content, tlv(0x01, []byte{b})...)
	}
	if value != nil {
		content = append(content, tlv(0x04, value)...)
	}
	return tlv(0x30, content)
}

// buildControls wraps zero or more complete Control SEQUENCEs (from
// buildControl) in the [0] Controls element.
func buildControls(controls ...[]byte) []byte {
	var seq []byte
	for _, c := range controls {
		seq = append(seq, c...)
	}
	return tlv(0xa0, seq)
}

func trueVal() *bool  { v := true; return &v }
func falseVal() *bool { v := false; return &v }

// --- allocBody instrumentation -----------------------------------------

// withAllocRecorder swaps allocBody for the duration of fn, recording
// every call's requested size, then restores the original hook.
func withAllocRecorder(t *testing.T, fn func()) []int {
	t.Helper()
	prev := allocBody
	var calls []int
	allocBody = func(n int) []byte {
		calls = append(calls, n)
		return prev(n)
	}
	defer func() { allocBody = prev }()
	fn()
	return calls
}

// --- readFrame: boundary tests -------------------------------------------

func TestReadFrame_ExactCapAccepted(t *testing.T) {
	body := bytes.Repeat([]byte{0x01}, maxBodyBytes)
	frame := tlv(tagSequence, body)

	var got []byte
	var err error
	calls := withAllocRecorder(t, func() {
		got, err = readFrame(bytes.NewReader(frame))
	})
	if err != nil {
		t.Fatalf("readFrame(exactly %d bytes): %v", maxBodyBytes, err)
	}
	if len(got) != maxBodyBytes {
		t.Fatalf("got body length %d, want %d", len(got), maxBodyBytes)
	}
	if len(calls) != 1 || calls[0] != maxBodyBytes {
		t.Fatalf("allocBody calls = %v, want exactly one call for %d", calls, maxBodyBytes)
	}
}

func TestReadFrame_OneOverCapRejectedBeforeAllocation(t *testing.T) {
	body := bytes.Repeat([]byte{0x01}, maxBodyBytes+1)
	frame := tlv(tagSequence, body)

	var err error
	calls := withAllocRecorder(t, func() {
		_, err = readFrame(bytes.NewReader(frame))
	})
	if !errors.Is(err, errMalformed) {
		t.Fatalf("readFrame(%d bytes): err = %v, want errMalformed", maxBodyBytes+1, err)
	}
	if len(calls) != 0 {
		t.Fatalf("allocBody called %d times for a rejected over-cap length, want zero", len(calls))
	}
}

func TestReadFrame_HistoricalTwoGiBDeclarationRejectedBeforeAllocation(t *testing.T) {
	// 30 84 7f ff ff ff: outer SEQUENCE, long-form length claiming FOUR
	// length octets (lenLen=4, rejected by the "more than three length
	// octets" rule alone) encoding a ~2 GiB value. No body bytes follow —
	// proving rejection never even reads the claimed length octets, let
	// alone allocates anything sized by them.
	frame := []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}

	var err error
	calls := withAllocRecorder(t, func() {
		_, err = readFrame(bytes.NewReader(frame))
	})
	if !errors.Is(err, errMalformed) {
		t.Fatalf("readFrame(historical ~2GiB declaration): err = %v, want errMalformed", err)
	}
	if len(calls) != 0 {
		t.Fatalf("allocBody called %d times for the ~2GiB declaration, want zero", len(calls))
	}
}

func TestReadFrame_LengthBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{"short-form max 127", 127},
		{"long-form min 128", 128},
		{"long-form 255 (one octet)", 255},
		{"long-form 256 (two octets)", 256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := bytes.Repeat([]byte{0xAA}, c.length)
			frame := tlv(tagSequence, body)
			got, err := readFrame(bytes.NewReader(frame))
			if err != nil {
				t.Fatalf("readFrame(length %d): %v", c.length, err)
			}
			if len(got) != c.length {
				t.Fatalf("got body length %d, want %d", len(got), c.length)
			}
		})
	}
}

func TestReadFrame_RejectedForms(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"wrong outer tag", []byte{0x31, 0x00}},
		{"indefinite length (30 80)", []byte{0x30, 0x80, 0x00, 0x00}},
		{"non-minimal long form (30 81 05)", append([]byte{0x30, 0x81, 0x05}, make([]byte, 5)...)},
		{"leading-zero long form (30 82 00 05)", append([]byte{0x30, 0x82, 0x00, 0x05}, make([]byte, 5)...)},
		{"four-octet length", []byte{0x30, 0x84, 0x00, 0x00, 0x01, 0x00}},
		{"non-minimal long form just below the short-form boundary (30 81 7f)", append([]byte{0x30, 0x81, 0x7f}, make([]byte, 127)...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			calls := withAllocRecorder(t, func() {
				_, err = readFrame(bytes.NewReader(c.frame))
			})
			if !errors.Is(err, errMalformed) {
				t.Fatalf("readFrame(%s): err = %v, want errMalformed", c.name, err)
			}
			if len(calls) != 0 {
				t.Fatalf("readFrame(%s): allocBody called %d times, want zero", c.name, len(calls))
			}
		})
	}
}

func TestReadFrame_TruncatedBodyIsIOError(t *testing.T) {
	// A declared length of 10 with only 3 body bytes actually available.
	frame := []byte{0x30, 0x0a, 0x01, 0x02, 0x03}
	_, err := readFrame(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("readFrame(truncated body): got nil error, want an I/O error")
	}
	if errors.Is(err, errMalformed) {
		t.Fatalf("readFrame(truncated body): err = %v, want an io error distinct from errMalformed", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("readFrame(truncated body): err = %v, want io.ErrUnexpectedEOF or io.EOF", err)
	}
}

func TestReadFrame_TruncatedHeaderIsIOError(t *testing.T) {
	for _, frame := range [][]byte{{}, {0x30}} {
		_, err := readFrame(bytes.NewReader(frame))
		if err == nil {
			t.Fatalf("readFrame(%x): got nil error, want an I/O error", frame)
		}
		if errors.Is(err, errMalformed) {
			t.Fatalf("readFrame(%x): err = %v, want an io error distinct from errMalformed", frame, err)
		}
	}
}

// --- decodeEnvelope: MessageID tests -------------------------------------

func TestDecodeEnvelope_MessageIDBoundaries(t *testing.T) {
	accepted := []struct {
		name    string
		content []byte
		want    int32
	}{
		{"127 (02 01 7f)", []byte{0x7f}, 127},
		{"128 (02 02 00 80)", []byte{0x00, 0x80}, 128},
		{"1", []byte{0x01}, 1},
	}
	for _, c := range accepted {
		t.Run("accepted/"+c.name, func(t *testing.T) {
			body := append(tlv(0x02, c.content), trivialUnbind...)
			env, err := decodeEnvelope(body)
			if err != nil {
				t.Fatalf("decodeEnvelope: %v", err)
			}
			if env.MessageID != c.want {
				t.Fatalf("MessageID = %d, want %d", env.MessageID, c.want)
			}
		})
	}

	rejected := []struct {
		name    string
		content []byte
	}{
		{"zero", []byte{0x00}},
		{"negative -1 (02 01 ff)", []byte{0xff}},
		{"non-minimal (02 02 00 7f)", []byte{0x00, 0x7f}},
		{"empty content", []byte{}},
	}
	for _, c := range rejected {
		t.Run("rejected/"+c.name, func(t *testing.T) {
			body := append(tlv(0x02, c.content), trivialUnbind...)
			_, err := decodeEnvelope(body)
			if !errors.Is(err, errMalformed) {
				t.Fatalf("decodeEnvelope(MessageID %s): err = %v, want errMalformed", c.name, err)
			}
		})
	}
}

func TestDecodeEnvelope_ProtocolOpAndTrailingBytes(t *testing.T) {
	t.Run("no protocolOp at all", func(t *testing.T) {
		body := berInteger(1)
		_, err := decodeEnvelope(body)
		if !errors.Is(err, errMalformed) {
			t.Fatalf("err = %v, want errMalformed", err)
		}
	})

	t.Run("trailing bytes after protocolOp", func(t *testing.T) {
		body := append(append(berInteger(1), trivialUnbind...), 0x00)
		_, err := decodeEnvelope(body)
		if !errors.Is(err, errMalformed) {
			t.Fatalf("err = %v, want errMalformed", err)
		}
	})

	t.Run("well-formed carries protocolOp tag and content through", func(t *testing.T) {
		op := tlv(0x63, []byte{0xde, 0xad}) // fake SearchRequest-shaped content
		body := append(berInteger(1), op...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if env.ProtocolOp != tagSearchRequest {
			t.Fatalf("ProtocolOp = %#x, want %#x", env.ProtocolOp, tagSearchRequest)
		}
		if !bytes.Equal(env.Content, []byte{0xde, 0xad}) {
			t.Fatalf("Content = %x, want de ad", []byte(env.Content))
		}
	})
}

// --- Controls tests -------------------------------------------------------

func TestDecodeEnvelope_Controls(t *testing.T) {
	t.Run("no controls present", func(t *testing.T) {
		body := append(berInteger(1), trivialUnbind...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if env.HasCritical {
			t.Fatal("HasCritical = true with no Controls element present")
		}
	})

	t.Run("canonical criticality false", func(t *testing.T) {
		controls := buildControls(buildControl("1.2.3", falseVal(), nil))
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if env.HasCritical {
			t.Fatal("HasCritical = true, want false")
		}
	})

	t.Run("canonical criticality true", func(t *testing.T) {
		controls := buildControls(buildControl("1.2.3", trueVal(), nil))
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if !env.HasCritical {
			t.Fatal("HasCritical = false, want true")
		}
	})

	t.Run("criticality omitted defaults false", func(t *testing.T) {
		controls := buildControls(buildControl("1.2.3", nil, nil))
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if env.HasCritical {
			t.Fatal("HasCritical = true for an omitted (DEFAULT FALSE) criticality")
		}
	})

	t.Run("unknown non-critical control ignored, processing continues", func(t *testing.T) {
		controls := buildControls(buildControl("1.99.99.99", falseVal(), []byte("value")))
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if env.HasCritical {
			t.Fatal("HasCritical = true for an unknown non-critical control")
		}
	})

	t.Run("critical among multiple controls detected", func(t *testing.T) {
		controls := buildControls(
			buildControl("1.1.1", falseVal(), nil),
			buildControl("2.2.2", trueVal(), nil),
		)
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		env, err := decodeEnvelope(body)
		if err != nil {
			t.Fatalf("decodeEnvelope: %v", err)
		}
		if !env.HasCritical {
			t.Fatal("HasCritical = false, want true (second control is critical)")
		}
	})

	t.Run("non-canonical criticality 01 01 01 is malformed", func(t *testing.T) {
		// buildControl only ever emits 0x00/0xff, so this control is
		// assembled by hand to force the non-canonical byte.
		controlContent := append(tlv(0x04, []byte("1.2.3")), 0x01, 0x01, 0x01)
		control := tlv(0x30, controlContent)
		controls := buildControls(control)
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		_, err := decodeEnvelope(body)
		if !errors.Is(err, errMalformed) {
			t.Fatalf("decodeEnvelope(non-canonical criticality byte): err = %v, want errMalformed", err)
		}
	})

	t.Run("trailing bytes inside one Control are malformed", func(t *testing.T) {
		controlContent := append(tlv(0x04, []byte("1.2.3")), 0x00) // stray extra byte
		control := tlv(0x30, controlContent)
		controls := buildControls(control)
		body := append(append(berInteger(1), trivialUnbind...), controls...)
		_, err := decodeEnvelope(body)
		if !errors.Is(err, errMalformed) {
			t.Fatalf("err = %v, want errMalformed", err)
		}
	})

	t.Run("trailing bytes after controls are malformed", func(t *testing.T) {
		controls := buildControls(buildControl("1.2.3", nil, nil))
		body := append(append(append(berInteger(1), trivialUnbind...), controls...), 0x00)
		_, err := decodeEnvelope(body)
		if !errors.Is(err, errMalformed) {
			t.Fatalf("err = %v, want errMalformed", err)
		}
	})
}

// --- End-to-end via buildMessage ------------------------------------------

func TestReadMessage_EndToEnd(t *testing.T) {
	controls := buildControls(buildControl("1.2.3", trueVal(), nil))
	frame := buildMessage(berInteger(128), trivialUnbind, controls)

	env, err := readMessage(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}
	if env.MessageID != 128 {
		t.Fatalf("MessageID = %d, want 128", env.MessageID)
	}
	if env.ProtocolOp != tagUnbindRequest {
		t.Fatalf("ProtocolOp = %#x, want %#x", env.ProtocolOp, tagUnbindRequest)
	}
	if !env.HasCritical {
		t.Fatal("HasCritical = false, want true")
	}
}

func TestReadMessage_MalformedEnvelopeInsideWellFormedFrame(t *testing.T) {
	// The outer frame is perfectly well-formed BER (readFrame succeeds);
	// the content inside it is not a valid LDAPMessage (no protocolOp
	// follows the MessageID) — proving frame-acceptance and
	// envelope-acceptance are genuinely separate checks.
	frame := tlv(tagSequence, berInteger(1))
	_, err := readMessage(bytes.NewReader(frame))
	if !errors.Is(err, errMalformed) {
		t.Fatalf("readMessage: err = %v, want errMalformed", err)
	}
}
