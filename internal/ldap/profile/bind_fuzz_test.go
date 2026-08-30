package profile

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// FuzzBindRequest is this sub-task's required native fuzz target ("Native
// fuzzing" / "Bind seeds"). Its seed corpus is every committed
// ClickHouse/libldap client Bind PDU under
// internal/ldap/testdata/clickhouse-wire (loaded through
// internal/wirefixture, decoded down to exactly the bytes handleBind
// itself receives — msgID, hasCritical, and the BindRequest protocolOp
// content — never the full LDAPMessage frame), plus the plan's named
// Bind-seed boundary vectors: MessageID 127/128 (already present among
// the committed constructed fixtures, since decodeEnvelope extracts each
// PDU's real MessageID), v2/v3, [3] SASL, supported and malformed DN
// escapes, and a truncated request.
//
// The fuzz body asserts, for arbitrary (msgID, hasCritical, data):
//
//  1. no panic, from handleBind itself or anything it calls;
//  2. the fake Verifier is called at most once per call (handleBind's own
//     single call site can run at most once per invocation regardless of
//     which branch is taken);
//  3. any non-close outcome (handleBind returning nil) wrote exactly one
//     well-formed LDAPMessage response — no partial write, no extra
//     trailing bytes, no second PDU.
func FuzzBindRequest(f *testing.F) {
	for _, seed := range bindRequestSeeds(f) {
		f.Add(seed.msgID, seed.hasCritical, seed.data)
	}

	f.Fuzz(func(t *testing.T, msgID int32, hasCritical bool, data []byte) {
		if msgID < 1 {
			// handleBind is only ever called, in production, with a
			// msgID that decodeEnvelope already validated as minimally
			// encoded and in 1..math.MaxInt32 (protocol.go's
			// minimalPositiveInt32) — the same precondition server.go's
			// dispatch relies on. Preserving that precondition here
			// keeps this fuzz target's response-shape assertion below
			// meaningful: an out-of-range msgID would make even a
			// perfectly-encoded response fail decodeEnvelope's own
			// MessageID check, which would be testing this harness's
			// fidelity to an impossible input, not handleBind itself.
			msgID = 1
		}

		verifier := newFakeVerifier()
		resolver := newFakeResolver()
		parsed, err := parseConfig(newTestConfig())
		if err != nil {
			t.Fatalf("parseConfig(newTestConfig()): %v", err)
		}

		clientConn, serverConn := net.Pipe()
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(&buf, clientConn)
			close(done)
		}()

		c := &connection{
			nc:           serverConn,
			ctx:          context.Background(),
			cfg:          &parsed,
			verifier:     verifier,
			roles:        resolver,
			clock:        time.Now,
			writeTimeout: 2 * time.Second,
		}

		bindErr := c.handleBind(msgID, cryptobyte.String(data), hasCritical)
		_ = serverConn.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out draining the response side (msgID=%d hasCritical=%v data=% x)", msgID, hasCritical, data)
		}
		_ = clientConn.Close()

		if calls := verifier.callCount(); calls > 1 {
			t.Fatalf("Verify called %d times, want <= 1 (msgID=%d hasCritical=%v data=% x)", calls, msgID, hasCritical, data)
		}

		if bindErr != nil {
			if buf.Len() != 0 {
				t.Fatalf("close outcome (err=%v) still wrote %d bytes, want 0 (msgID=%d hasCritical=%v data=% x)", bindErr, buf.Len(), msgID, hasCritical, data)
			}
			return
		}

		if buf.Len() == 0 {
			t.Fatalf("non-close outcome wrote no response (msgID=%d hasCritical=%v data=% x)", msgID, hasCritical, data)
		}

		remaining := bytes.NewReader(buf.Bytes())
		frameBody, ferr := readFrame(remaining)
		if ferr != nil {
			t.Fatalf("response is not one well-formed frame: %v (bytes=% x)", ferr, buf.Bytes())
		}
		if _, derr := decodeEnvelope(frameBody); derr != nil {
			t.Fatalf("response frame body is not a well-formed envelope: %v (bytes=% x)", derr, buf.Bytes())
		}
		if remaining.Len() != 0 {
			t.Fatalf("response contained %d trailing bytes after exactly one frame (bytes=% x)", remaining.Len(), buf.Bytes())
		}
	})
}

// bindFuzzSeed is one FuzzBindRequest corpus entry: the three arguments
// f.Fuzz's callback above takes.
type bindFuzzSeed struct {
	msgID       int32
	hasCritical bool
	data        []byte
}

// bindRequestSeeds returns FuzzBindRequest's full seed corpus: every
// committed client-to-server Bind PDU (decoded down to msgID/hasCritical/
// protocolOp content) plus the plan's named hand-built Bind-seed vectors.
func bindRequestSeeds(f *testing.F) []bindFuzzSeed {
	f.Helper()
	seeds := committedBindRequestSeeds(f)
	seeds = append(seeds, handBuiltBindSeeds()...)
	return seeds
}

// committedBindRequestSeeds walks every committed session under
// internal/ldap/testdata/clickhouse-wire (every tracked line's every
// committed session, plus every constructed session — the same traversal
// frame_fuzz_test.go's committedClientPDUSeeds uses) and decodes each
// Bind-operation PDU down to a bindFuzzSeed.
func committedBindRequestSeeds(f *testing.F) []bindFuzzSeed {
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

	var seeds []bindFuzzSeed

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
			seeds = append(seeds, bindSeedsFromSession(f, wirefixture.SessionDir(lineDir, sp))...)
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
		seeds = append(seeds, bindSeedsFromSession(f, filepath.Join(constructedDir, e.Name()))...)
	}

	if len(seeds) == 0 {
		f.Fatal("committedBindRequestSeeds: loaded zero Bind PDUs from the wire fixture corpus")
	}
	return seeds
}

// bindSeedsFromSession reads sessDir's session.json and, for every
// client-to-server Bind-operation PDU it lists, reads the raw captured
// LDAPMessage frame and decodes it (readFrame + decodeEnvelope) down to
// exactly the (msgID, hasCritical, protocolOp content) triple handleBind
// receives. A PDU whose metadata says bindRequest but which fails to
// decode as one is a fixture-corpus bug, not a fuzz input, so it fails
// the test immediately rather than being silently skipped.
func bindSeedsFromSession(f *testing.F, sessDir string) []bindFuzzSeed {
	f.Helper()
	sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
	if err != nil {
		f.Fatalf("read session.json for %s: %v", sessDir, err)
	}
	var seeds []bindFuzzSeed
	for _, pdu := range sess.PDUs {
		if pdu.Direction != wirefixture.DirectionClientToServer || pdu.Operation != wirefixture.OperationBindRequest {
			continue
		}
		path := filepath.Join(sessDir, pdu.Filename)
		raw, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("read PDU file %s: %v", path, err)
		}
		body, err := readFrame(bytes.NewReader(raw))
		if err != nil {
			f.Fatalf("readFrame(%s): %v", path, err)
		}
		env, err := decodeEnvelope(body)
		if err != nil {
			f.Fatalf("decodeEnvelope(%s): %v", path, err)
		}
		if env.ProtocolOp != tagBindRequest {
			f.Fatalf("%s: metadata says bindRequest but protocolOp tag = %#x", path, byte(env.ProtocolOp))
		}
		seeds = append(seeds, bindFuzzSeed{
			msgID:       env.MessageID,
			hasCritical: env.HasCritical,
			data:        append([]byte{}, env.Content...),
		})
	}
	return seeds
}

// handBuiltBindSeeds returns the plan's named Bind-seed vectors beyond
// the committed wire corpus: v2/v3, [3] SASL, supported/malformed DN
// escapes, a truncated request, and an explicit critical-control case.
func handBuiltBindSeeds() []bindFuzzSeed {
	const password = "seed-password"
	simpleV3 := bindOp(3, testAliceDN, authTagSimple, []byte(password))

	seeds := []bindFuzzSeed{
		{msgID: 1, hasCritical: false, data: simpleV3},
		{msgID: 1, hasCritical: false, data: bindOp(2, testAliceDN, authTagSimple, []byte(password))},
		{msgID: 1, hasCritical: false, data: bindOp(1, testAliceDN, authTagSimple, []byte(password))},
		{msgID: 1, hasCritical: false, data: bindOp(3, testAliceDN, authTagSASL, []byte("sasl-credentials"))},
		{msgID: 1, hasCritical: true, data: simpleV3},
		{msgID: 127, hasCritical: false, data: simpleV3},
		{msgID: 128, hasCritical: false, data: simpleV3},
		// Supported DN escape: an escaped comma inside the username RDN
		// value.
		{msgID: 1, hasCritical: false, data: bindOp(3, `uid=ali\,ce,ou=users,dc=profile,dc=test`, authTagSimple, []byte(password))},
		// Malformed DN escape: an invalid (non-hex) two-character escape.
		{msgID: 1, hasCritical: false, data: bindOp(3, `uid=ali\ZZce,ou=users,dc=profile,dc=test`, authTagSimple, []byte(password))},
		// Truncated request: a well-formed simple Bind cut off mid auth
		// content.
		{msgID: 1, hasCritical: false, data: simpleV3[:len(simpleV3)-3]},
	}
	return seeds
}
