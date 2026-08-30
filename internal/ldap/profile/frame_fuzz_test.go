package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// FuzzLDAPFrame is this sub-task's required native fuzz target ("Native
// fuzzing" / "Framing seeds"). Its seed corpus is every committed
// ClickHouse/libldap client PDU under
// internal/ldap/testdata/clickhouse-wire (loaded through
// internal/wirefixture — a test-only import, permitted by the plan) plus
// every boundary vector this file's own frame_test.go exercises by hand.
//
// The fuzz body asserts three things about arbitrary input bytes, none of
// which depend on the input being well-formed:
//
//  1. no panic, from readFrame or decodeEnvelope;
//  2. allocBody is never asked to allocate more than maxBodyBytes — the
//     same property TestReadFrame_OneOverCapRejectedBeforeAllocation and
//     TestReadFrame_HistoricalTwoGiBDeclarationRejectedBeforeAllocation
//     prove on fixed vectors, here checked continuously against whatever
//     the fuzzer generates;
//  3. acceptance implies a well-formed envelope — reaching the point
//     where both readFrame and decodeEnvelope return no error already IS
//     that proof, since decodeEnvelope enforces the full envelope grammar
//     before returning nil.
func FuzzLDAPFrame(f *testing.F) {
	for _, seed := range ldapFrameSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var maxAlloc int
		prev := allocBody
		allocBody = func(n int) []byte {
			if n > maxAlloc {
				maxAlloc = n
			}
			return prev(n)
		}
		defer func() { allocBody = prev }()

		body, frameErr := readFrame(bytes.NewReader(data))
		if maxAlloc > maxBodyBytes {
			t.Fatalf("allocBody asked for %d bytes, want <= %d (input %x)", maxAlloc, maxBodyBytes, data)
		}
		if frameErr != nil {
			return
		}

		if _, envErr := decodeEnvelope(body); envErr != nil {
			// The outer frame was well-formed BER but its content isn't
			// a well-formed LDAPMessage envelope. That's an expected,
			// distinct rejection (TestReadMessage_MalformedEnvelopeInsideWellFormedFrame
			// covers exactly this split on a fixed vector) — not a
			// fuzz failure.
			return
		}
		// Both layers accepted: by construction (decodeEnvelope's own
		// checks) this input decoded to a well-formed envelope. Nothing
		// further to assert — reaching here without panicking already is
		// the proof this fuzz target exists to run continuously.
	})
}

// ldapFrameSeeds returns FuzzLDAPFrame's full seed corpus: every committed
// client-to-server PDU under internal/ldap/testdata/clickhouse-wire, plus
// every boundary vector named in the plan's "Framing seeds" section and
// exercised individually by frame_test.go.
func ldapFrameSeeds(f *testing.F) [][]byte {
	f.Helper()
	seeds := committedClientPDUSeeds(f)
	seeds = append(seeds, boundarySeeds()...)
	return seeds
}

// committedClientPDUSeeds loads every committed client-to-server PDU
// (.ber file) under internal/ldap/testdata/clickhouse-wire via
// internal/wirefixture — every tracked line's every committed session,
// plus every constructed session (127/128 MessageID boundary evidence).
func committedClientPDUSeeds(f *testing.F) [][]byte {
	f.Helper()

	moduleRoot, err := wirefixture.ModuleRoot()
	if err != nil {
		f.Fatalf("wirefixture.ModuleRoot: %v", err)
	}
	fixtureRoot := wirefixture.ClickHouseWireFixtureRoot(moduleRoot)

	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		f.Fatalf("wirefixture.ValidateFixtureRoot(%s): %v", fixtureRoot, err)
	}

	var seeds [][]byte

	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)
		p, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
		if err != nil {
			f.Fatalf("read profile.json for line %s: %v", line, err)
		}
		if len(p.SessionPaths) == 0 {
			f.Fatalf("line %s: profile.json lists no session_paths", line)
		}
		for _, sp := range p.SessionPaths {
			seeds = append(seeds, sessionPDUSeeds(f, wirefixture.SessionDir(lineDir, sp))...)
		}
	}

	constructedDir := wirefixture.ConstructedDir(fixtureRoot)
	entries, err := os.ReadDir(constructedDir)
	if err != nil {
		f.Fatalf("read constructed fixture dir %s: %v", constructedDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			f.Fatalf("constructed fixture dir %s: unexpected non-directory entry %q", constructedDir, e.Name())
		}
		seeds = append(seeds, sessionPDUSeeds(f, filepath.Join(constructedDir, e.Name()))...)
	}

	if len(seeds) == 0 {
		f.Fatal("committedClientPDUSeeds: loaded zero PDUs from the wire fixture corpus")
	}
	return seeds
}

// sessionPDUSeeds reads sessDir's session.json and returns the raw bytes
// of every client-to-server PDU it lists.
func sessionPDUSeeds(f *testing.F, sessDir string) [][]byte {
	f.Helper()
	sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
	if err != nil {
		f.Fatalf("read session.json for %s: %v", sessDir, err)
	}
	var seeds [][]byte
	for _, pdu := range sess.PDUs {
		if pdu.Direction != wirefixture.DirectionClientToServer {
			continue
		}
		path := filepath.Join(sessDir, pdu.Filename)
		raw, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("read PDU file %s: %v", path, err)
		}
		seeds = append(seeds, raw)
	}
	return seeds
}

// boundarySeeds returns every hand-built boundary vector the plan's
// "Framing seeds" list names, beyond the committed wire corpus: the exact
// body-cap boundary, the historical ~2 GiB length declaration and other
// four-octet-length shapes, short/long-form length boundaries, indefinite/
// non-minimal/leading-zero length forms, a truncated body, MessageID
// boundary values (0/negative/non-minimal/127/128), and the Controls
// boundary shapes (canonical/non-canonical BOOLEAN, unknown non-critical,
// critical-among-multiple).
func boundarySeeds() [][]byte {
	var seeds [][]byte
	add := func(b []byte) { seeds = append(seeds, b) }

	// Body-cap boundary: exactly maxBodyBytes accepted, one more rejected.
	add(tlv(tagSequence, bytes.Repeat([]byte{0x01}, maxBodyBytes)))
	add(tlv(tagSequence, bytes.Repeat([]byte{0x01}, maxBodyBytes+1)))

	// The historical ~2 GiB declaration and another four-octet-length
	// shape, both rejected purely for using more than three length
	// octets, before their length octets are even read.
	add([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff})
	add([]byte{0x30, 0x84, 0x00, 0x00, 0x01, 0x00})

	// Short/long-form length boundaries: 127 is the short-form maximum,
	// 128/255/256 exercise one- and two-octet long form.
	for _, n := range []int{127, 128, 255, 256} {
		add(tlv(tagSequence, bytes.Repeat([]byte{0xaa}, n)))
	}

	// Indefinite length (0x80), non-minimal long form (5 fits in short
	// form), long-form leading zero.
	add([]byte{0x30, 0x80, 0x00, 0x00})
	add(append([]byte{0x30, 0x81, 0x05}, make([]byte, 5)...))
	add(append([]byte{0x30, 0x82, 0x00, 0x05}, make([]byte, 5)...))

	// Truncated body: declared length (10) exceeds the bytes actually
	// present (3).
	add([]byte{0x30, 0x0a, 0x01, 0x02, 0x03})

	// MessageID boundary values, each as a complete message with a
	// trivial (Unbind) protocolOp.
	for _, mid := range [][]byte{
		{0x00},       // zero: rejected
		{0xff},       // -1: rejected
		{0x00, 0x7f}, // non-minimal: rejected
		{0x7f},       // 127: accepted
		{0x00, 0x80}, // 128: accepted
	} {
		add(buildMessage(tlv(0x02, mid), trivialUnbind, nil))
	}

	// Controls boundary shapes.
	add(buildMessage(berInteger(1), trivialUnbind, buildControls(buildControl("1.2.3", falseVal(), nil))))
	add(buildMessage(berInteger(1), trivialUnbind, buildControls(buildControl("1.2.3", trueVal(), nil))))
	add(buildMessage(berInteger(1), trivialUnbind, buildControls(buildControl("1.99.99", falseVal(), []byte("value")))))
	add(buildMessage(berInteger(1), trivialUnbind, buildControls(
		buildControl("1.1.1", falseVal(), nil),
		buildControl("2.2.2", trueVal(), nil),
	)))
	{
		// Non-canonical criticality byte 0x01 (neither 0x00 nor 0xff).
		controlContent := append(tlv(0x04, []byte("1.2.3")), 0x01, 0x01, 0x01)
		control := tlv(0x30, controlContent)
		add(buildMessage(berInteger(1), trivialUnbind, buildControls(control)))
	}

	return seeds
}
