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

// FuzzSearchRequest is this sub-task's required native fuzz target
// ("Native fuzzing" / "Search seeds"). Its seed corpus is every committed
// ClickHouse/libldap client Search PDU under
// internal/ldap/testdata/clickhouse-wire (decoded down to exactly the
// bytes handleSearch itself receives — msgID, hasCritical, and the
// SearchRequest protocolOp content) plus the plan's named hand-built
// Search-seed vectors: filter child-order swap, description case
// variants, AND->OR, duplicate/missing/third predicate, deep nested
// filter shapes, scope/deref/typesOnly/attribute-selection mutations, and
// the named sizeLimit/timeLimit boundary values.
//
// The fuzz body asserts, for arbitrary (msgID, hasCritical, data):
//
//  1. no panic, from handleSearch itself or anything it calls;
//  2. neither the fake Verifier nor the fake RoleResolver is ever called
//     (Search's one invariant: it reads only the Bind-time snapshot);
//  3. any non-close outcome (handleSearch returning nil) wrote one or
//     more well-formed LDAPMessage PDUs with no trailing bytes, and every
//     one of those PDUs' body stays at or under the 65536-byte response
//     cap.
func FuzzSearchRequest(f *testing.F) {
	for _, seed := range searchRequestSeeds(f) {
		f.Add(seed.msgID, seed.hasCritical, seed.data)
	}

	f.Fuzz(func(t *testing.T, msgID int32, hasCritical bool, data []byte) {
		if msgID < 1 {
			// handleSearch is only ever called, in production, with a
			// msgID decodeEnvelope already validated as minimally
			// encoded and in 1..math.MaxInt32 — the same precondition
			// preserved by FuzzBindRequest, and for the same reason:
			// an out-of-range msgID would make even a well-formed
			// response fail decodeEnvelope, testing this harness's
			// fidelity to an impossible input rather than handleSearch.
			msgID = 1
		}

		verifier := newFakeVerifier()
		resolver := newFakeResolver()
		parsed, err := parseConfig(newTestConfig())
		if err != nil {
			t.Fatalf("parseConfig(newTestConfig()): %v", err)
		}
		boundDN, err := ParseDN(testBoundDN)
		if err != nil {
			t.Fatalf("ParseDN(testBoundDN): %v", err)
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
		c.replaceAuth(authState{
			Username: "alice",
			BoundDN:  testBoundDN,
			boundDN:  boundDN,
			Roles:    []string{markerLegitimateRole, "another_role"},
		})

		searchErr := c.handleSearch(msgID, cryptobyte.String(data), hasCritical)
		_ = serverConn.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out draining the response side (msgID=%d hasCritical=%v data=% x)", msgID, hasCritical, data)
		}
		_ = clientConn.Close()

		if calls := verifier.callCount(); calls != 0 {
			t.Fatalf("Verify called %d times from Search, want 0 (msgID=%d hasCritical=%v data=% x)", calls, msgID, hasCritical, data)
		}
		if calls := resolver.callCount(); calls != 0 {
			t.Fatalf("Roles called %d times from Search, want 0 (msgID=%d hasCritical=%v data=% x)", calls, msgID, hasCritical, data)
		}

		if searchErr != nil {
			if buf.Len() != 0 {
				t.Fatalf("close outcome (err=%v) still wrote %d bytes, want 0 (msgID=%d hasCritical=%v data=% x)", searchErr, buf.Len(), msgID, hasCritical, data)
			}
			return
		}

		if buf.Len() == 0 {
			t.Fatalf("non-close outcome wrote no response (msgID=%d hasCritical=%v data=% x)", msgID, hasCritical, data)
		}

		remaining := bytes.NewReader(buf.Bytes())
		sawDone := false
		for remaining.Len() > 0 {
			frameBody, ferr := readFrame(remaining)
			if ferr != nil {
				t.Fatalf("response is not a sequence of well-formed frames: %v (bytes=% x)", ferr, buf.Bytes())
			}
			if len(frameBody) > maxBodyBytes {
				t.Fatalf("response frame body is %d bytes, exceeds cap %d (bytes=% x)", len(frameBody), maxBodyBytes, buf.Bytes())
			}
			env, derr := decodeEnvelope(frameBody)
			if derr != nil {
				t.Fatalf("response frame body is not a well-formed envelope: %v (bytes=% x)", derr, buf.Bytes())
			}
			if env.ProtocolOp == tagSearchResultDone {
				sawDone = true
			}
		}
		if !sawDone {
			t.Fatalf("non-close outcome's response never included a terminal SearchResultDone (bytes=% x)", buf.Bytes())
		}
	})
}

// searchFuzzSeed is one FuzzSearchRequest corpus entry.
type searchFuzzSeed struct {
	msgID       int32
	hasCritical bool
	data        []byte
}

// searchRequestSeeds returns FuzzSearchRequest's full seed corpus: every
// committed client-to-server Search PDU plus the plan's named hand-built
// Search-seed vectors.
func searchRequestSeeds(f *testing.F) []searchFuzzSeed {
	f.Helper()
	seeds := committedSearchRequestSeeds(f)
	seeds = append(seeds, handBuiltSearchSeeds()...)
	return seeds
}

// committedSearchRequestSeeds walks every committed session under
// internal/ldap/testdata/clickhouse-wire (the same traversal
// committedBindRequestSeeds uses) and decodes each Search-operation PDU
// down to a searchFuzzSeed.
func committedSearchRequestSeeds(f *testing.F) []searchFuzzSeed {
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

	var seeds []searchFuzzSeed

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
			seeds = append(seeds, searchSeedsFromSession(f, wirefixture.SessionDir(lineDir, sp))...)
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
		seeds = append(seeds, searchSeedsFromSession(f, filepath.Join(constructedDir, e.Name()))...)
	}

	if len(seeds) == 0 {
		f.Fatal("committedSearchRequestSeeds: loaded zero Search PDUs from the wire fixture corpus")
	}
	return seeds
}

// searchSeedsFromSession reads sessDir's session.json and, for every
// client-to-server Search-operation PDU it lists, decodes it down to
// exactly the (msgID, hasCritical, protocolOp content) triple
// handleSearch receives.
func searchSeedsFromSession(f *testing.F, sessDir string) []searchFuzzSeed {
	f.Helper()
	sess, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessDir))
	if err != nil {
		f.Fatalf("read session.json for %s: %v", sessDir, err)
	}
	var seeds []searchFuzzSeed
	for _, pdu := range sess.PDUs {
		if pdu.Direction != wirefixture.DirectionClientToServer || pdu.Operation != wirefixture.OperationSearchRequest {
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
		if env.ProtocolOp != tagSearchRequest {
			f.Fatalf("%s: metadata says searchRequest but protocolOp tag = %#x", path, byte(env.ProtocolOp))
		}
		seeds = append(seeds, searchFuzzSeed{
			msgID:       env.MessageID,
			hasCritical: env.HasCritical,
			data:        append([]byte{}, env.Content...),
		})
	}
	return seeds
}

// handBuiltSearchSeeds returns the plan's named Search-seed vectors
// beyond the committed wire corpus.
func handBuiltSearchSeeds() []searchFuzzSeed {
	const groupBase = "ou=groups,dc=profile,dc=test"
	objClass := filterEquality("objectClass", "groupOfNames")
	member := filterEquality("member", testBoundDN)
	valid := filterAnd(objClass, member)

	build := func(scope, deref, sizeLimit, timeLimit int64, typesOnly bool, filterBytes []byte, attrs ...string) []byte {
		return searchOp(groupBase, scope, deref, sizeLimit, timeLimit, typesOnly, filterBytes, attrs...)
	}

	var seeds []searchFuzzSeed
	add := func(op []byte) {
		seeds = append(seeds, searchFuzzSeed{msgID: 1, hasCritical: false, data: op})
	}

	add(build(2, 0, 0, 0, false, valid, "cn"))                                                                                           // captured/canonical shape
	add(build(2, 0, 0, 0, false, filterAnd(member, objClass), "cn"))                                                                     // child-order swap
	add(build(2, 0, 0, 0, false, filterAnd(filterEquality("OBJECTCLASS", "groupOfNames"), filterEquality("MEMBER", testBoundDN)), "CN")) // description case variants
	add(build(2, 0, 0, 0, false, filterOr(objClass, member), "cn"))                                                                      // AND -> OR
	add(build(2, 0, 0, 0, false, filterAnd(objClass, objClass), "cn"))                                                                   // duplicate predicate
	add(build(2, 0, 0, 0, false, filterAnd(objClass), "cn"))                                                                             // missing predicate
	add(build(2, 0, 0, 0, false, filterAnd(objClass, member, filterEquality("cn", "x")), "cn"))                                          // third predicate
	add(build(2, 0, 0, 0, false, filterAnd(filterAnd(objClass), member), "cn"))                                                          // nested AND
	add(build(2, 0, 0, 0, false, filterAnd(filterNot(objClass), member), "cn"))                                                          // deep/NOT nested shape
	add(build(2, 0, 0, 0, false, filterAnd(filterSubstrings("objectClass"), member), "cn"))                                              // substrings child
	add(build(2, 0, 0, 0, false, filterAnd(filterPresent("objectClass"), member), "cn"))                                                 // presence child
	add(build(0, 0, 0, 0, false, valid, "cn"))                                                                                           // scope mutation: baseObject
	add(build(1, 0, 0, 0, false, valid, "cn"))                                                                                           // scope mutation: singleLevel
	add(build(2, 1, 0, 0, false, valid, "cn"))                                                                                           // deref mutation
	add(build(2, 3, 0, 0, false, valid, "cn"))                                                                                           // deref mutation
	add(build(2, 0, 0, 0, true, valid, "cn"))                                                                                            // typesOnly mutation
	add(build(2, 0, 0, 0, false, valid))                                                                                                 // attribute selection: empty
	add(build(2, 0, 0, 0, false, valid, "*"))                                                                                            // attribute selection: "*"
	add(build(2, 0, 0, 0, false, valid, "1.1"))                                                                                          // attribute selection: "1.1"
	add(build(2, 0, 0, 0, false, valid, "cn", "member"))                                                                                 // attribute selection: multi
	add(build(2, 0, 0, 0, false, valid, "member"))                                                                                       // attribute selection: wrong single

	for _, sl := range []int64{0, 1, 255, 256, 257, 1<<31 - 1} {
		add(build(2, 0, sl, 0, false, valid, "cn"))
	}
	for _, tl := range []int64{0, 1, 20, 1<<31 - 1} {
		add(build(2, 0, 0, tl, false, valid, "cn"))
	}

	// ENUMERATED out-of-range (Amendment 2): malformed, not merely
	// out-of-profile.
	add(build(5, 0, 0, 0, false, valid, "cn"))
	add(build(2, 7, 0, 0, false, valid, "cn"))

	return seeds
}
