package profile

// This file is sub-task p2-10's mid-Search suite: abrupt client close
// while a Search is still emitting entries, a recording net.Conn proving
// no further LDAPMessage is ever appended after a partial/failed entry
// write, and a pipelined Unbind proving it is processed only after the
// Search it followed returns — never interrupting it — matching the
// plan's "Unbind" section ("Pipelined Unbind behind Search is processed
// only after Search returns or transport failure ends the connection")
// and its "No PDU after partial write" invariant-map row.
//
// It reuses server_test.go's real-TCP harness (newRunningServer/dial/
// bindRequestBytes/searchRequestBytes/unbindRequestBytes/readEnvelope/
// readLDAPResultFields/expectNoResponseThenClosed), search_test.go's
// testBoundDN/rolesNamed/readSearchResultEntry, and fakes_test.go's
// fakeVerifier/fakeResolver/newVerificationResult/newTestConfig/
// markerLegitimateRole. No existing file is modified.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// waitForGoroutineCountNear polls runtime.NumGoroutine() until it returns
// to within slack of baseline, or fails the test after timeout — evidence
// that request/writer goroutines attributable to a terminated connection
// actually unwound rather than leaking.
func waitForGoroutineCountNear(t *testing.T, baseline, slack int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		runtime.GC()
		cur := runtime.NumGoroutine()
		if cur <= baseline+slack {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count did not settle within %v: current=%d, baseline=%d, slack=%d — the connection's goroutine may have leaked", timeout, cur, baseline, slack)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForActiveCount polls s.activeCountForTest() until it reaches want,
// or fails the test after timeout.
func waitForActiveCount(t *testing.T, s *Server, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := s.activeCountForTest(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active connection count did not reach %d within %v (last observed %d)", want, timeout, s.activeCountForTest())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------
// Abrupt close mid-Search
// ---------------------------------------------------------------------

// TestMidSearch_AbruptCloseAfterKEntriesUnwindsCleanly binds successfully,
// issues an unbounded Search over a real TCP connection, reads exactly k
// SearchResultEntry frames (deliberately never reading the terminal
// SearchResultDone), then abruptly closes the connection — proving the
// connection's one goroutine exits, the server's active-connection map
// shrinks back to zero, no panic occurs, and the server remains fully
// healthy for a fresh connection afterward.
//
// With this profile's small, individually cn-only, 64 KiB-bounded
// entries, whether the server is still literally blocked writing a later
// entry at the exact instant the client closes (as opposed to having
// already finished the whole response and moved on to its next
// SetReadDeadline/readMessage call, which the close then interrupts
// instead) is host-socket-buffer-dependent, exactly the caveat the
// legacy package's own midsearch_test.go documented and accepted for the
// same reason. Either way this test exercises: the client reads only a
// strict subset of a larger response and then severs the connection, and
// every cleanup/no-panic/no-leak invariant below holds regardless of
// which of those two moments the close actually lands in. The dedicated,
// host-independent, deterministic proof that no further LDAPMessage is
// ever appended after a write failure mid-loop is
// TestMidSearch_PartialEntryWriteFailureAppendsNoFurtherMessage below,
// which drives the failure directly rather than racing socket buffers.
func TestMidSearch_AbruptCloseAfterKEntriesUnwindsCleanly(t *testing.T) {
	const totalRoles = 30
	const k = 5

	roles := rolesNamed(totalRoles, "midsearch_role_")
	small := newVerificationResult("bob", "https://idp.example/", "sub-bob", time.Now().Add(time.Hour).Unix())
	big := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())

	v := newFakeVerifier().withSuccess("alice-pw", big).withSuccess("bob-pw", small)
	r := newFakeResolver().withRoles("sub-alice", roles).withRoles("sub-bob", []string{markerLegitimateRole})

	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)

	bindEnv := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false))
	if result, _, _ := readLDAPResultFields(t, bindEnv.Content); result != int(resultSuccess) {
		t.Fatalf("bind result = %d, want success", result)
	}

	// Baseline is taken with this one connection's goroutine already
	// live, so "settled back to baseline" after closing it is a
	// meaningful (not vacuous) check.
	runtime.GC()
	baseline := runtime.NumGoroutine()

	groupBase := newTestConfig().GroupBaseDN
	if _, err := conn.Write(searchRequestBytes(2, groupBase, testAliceDN, 0, 0)); err != nil {
		t.Fatalf("write search: %v", err)
	}

	for i := 0; i < k; i++ {
		env := readEnvelope(t, conn)
		if env.ProtocolOp != tagSearchResultEntry {
			t.Fatalf("entry #%d: protocolOp = %#x, want SearchResultEntry", i, byte(env.ProtocolOp))
		}
	}
	// Deliberately never read the remaining (totalRoles-k) entries or the
	// terminal SearchResultDone: abruptly sever the connection instead.
	if err := conn.Close(); err != nil {
		t.Fatalf("abrupt close: %v", err)
	}

	waitForActiveCount(t, h.server, 0, 5*time.Second)
	waitForGoroutineCountNear(t, baseline, 5, 5*time.Second)

	// The server remains fully healthy: a fresh connection can still
	// Bind and Search normally, and connection-local state died with the
	// terminated connection (this is a brand-new connection, never
	// authenticated on its own).
	fresh := dial(t, h.addr)
	defer fresh.Close()
	freshBindEnv := sendAndReadEnvelope(t, fresh, bindRequestBytes(1, testBobDN, "bob-pw", false))
	if result, _, _ := readLDAPResultFields(t, freshBindEnv.Content); result != int(resultSuccess) {
		t.Fatalf("fresh connection bind result = %d, want success", result)
	}
	freshSearchEnv := sendAndReadEnvelope(t, fresh, searchRequestBytes(2, groupBase, testBobDN, 0, 0))
	if freshSearchEnv.ProtocolOp != tagSearchResultEntry {
		t.Fatalf("fresh connection search: protocolOp = %#x, want SearchResultEntry", byte(freshSearchEnv.ProtocolOp))
	}
	doneEnv := readEnvelope(t, fresh)
	if doneEnv.ProtocolOp != tagSearchResultDone {
		t.Fatalf("fresh connection search: second protocolOp = %#x, want SearchResultDone", byte(doneEnv.ProtocolOp))
	}
	if result, _, _ := readLDAPResultFields(t, doneEnv.Content); result != int(resultSuccess) {
		t.Fatalf("fresh connection search result = %d, want success", result)
	}
}

// ---------------------------------------------------------------------
// Recording net.Conn: no PDU after a partial/failed entry write
// ---------------------------------------------------------------------

// errSimulatedEntryWriteFailure is recordingConn's fixed, non-timeout
// transport-error stand-in for a peer that vanished mid-PDU — the "any
// bytes already written, or any other transport error: close" branch of
// executeSearch's write-error handling (search.go), distinct from the
// "zero bytes written, deadline timeout" branch search_test.go's
// deadlineRecordingConn/closeAfterNWritesConn already cover.
var errSimulatedEntryWriteFailure = errors.New("recordingConn: simulated entry write failure")

// recordingConn wraps a real net.Conn (one end of a net.Pipe) and records
// a full copy of every byte slice passed to Write. Calls numbered 1..N
// (failOnCall-1, i.e. the first N calls) are forwarded to the real
// underlying connection unchanged; call number failOnCall reports
// partialBytes written and errSimulatedEntryWriteFailure without ever
// touching the underlying connection; every recorded call is retained
// regardless, so a test can assert both "exactly N+1 Write calls
// happened" (proving no further message was ever appended after the
// failure) and decode the first N as well-formed entries.
type recordingConn struct {
	net.Conn
	mu           sync.Mutex
	writes       [][]byte
	failOnCall   int
	partialBytes int
}

func (rc *recordingConn) Write(p []byte) (int, error) {
	rc.mu.Lock()
	call := len(rc.writes) + 1
	cp := append([]byte(nil), p...)
	rc.writes = append(rc.writes, cp)
	rc.mu.Unlock()

	if call == rc.failOnCall {
		n := rc.partialBytes
		if n > len(p) {
			n = len(p)
		}
		return n, errSimulatedEntryWriteFailure
	}
	return rc.Conn.Write(p)
}

func (rc *recordingConn) callCount() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.writes)
}

func (rc *recordingConn) writeAt(i int) []byte {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]byte(nil), rc.writes[i]...)
}

// decodeRecordedFrame parses one recorded Write call's bytes as a
// complete LDAPMessage frame (tag+length+body), then decodes its
// envelope — the same two-step readFrame/decodeEnvelope pipeline the
// real connection loop uses, applied here directly to already-captured
// bytes instead of an io.Reader.
func decodeRecordedFrame(t *testing.T, frame []byte) Envelope {
	t.Helper()
	body, err := readFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readFrame(recorded write): %v (% x)", err, frame)
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		t.Fatalf("decodeEnvelope(recorded write): %v", err)
	}
	return env
}

func TestMidSearch_PartialEntryWriteFailureAppendsNoFurtherMessage(t *testing.T) {
	const goodEntries = 2
	roles := rolesNamed(5, "role")

	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	boundDN, err := ParseDN(testBoundDN)
	if err != nil {
		t.Fatalf("ParseDN(testBoundDN): %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	rc := &recordingConn{Conn: serverConn, failOnCall: goodEntries + 1, partialBytes: 3}

	c := &connection{
		nc:           rc,
		ctx:          context.Background(),
		cfg:          &parsed,
		verifier:     newFakeVerifier(),
		roles:        newFakeResolver(),
		clock:        time.Now,
		writeTimeout: 2 * time.Second,
	}
	c.replaceAuth(authState{Username: "alice", BoundDN: testBoundDN, boundDN: boundDN, Roles: roles})

	// A concurrent reader drains exactly `goodEntries` full frames off the
	// pipe — required because net.Pipe's Write blocks until a matching
	// Read consumes it, and the first `goodEntries` writes are forwarded
	// to the real pipe by recordingConn. The (goodEntries+1)-th write
	// never touches the pipe at all (recordingConn intercepts it), so
	// this reader does not need to (and must not) read a (goodEntries+1)-
	// th frame.
	readerDone := make(chan error, 1)
	go func() {
		for i := 0; i < goodEntries; i++ {
			if _, err := readFrame(clientConn); err != nil {
				readerDone <- err
				return
			}
		}
		readerDone <- nil
	}()

	op := searchOp(newTestConfig().GroupBaseDN, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	searchErr := c.handleSearch(1, cryptobyte.String(op), false)

	select {
	case rerr := <-readerDone:
		if rerr != nil {
			t.Fatalf("reader failed to drain %d good entries: %v", goodEntries, rerr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the good-entry reader to finish")
	}

	if !errors.Is(searchErr, errSimulatedEntryWriteFailure) {
		t.Fatalf("handleSearch error = %v, want errSimulatedEntryWriteFailure", searchErr)
	}
	if got := rc.callCount(); got != goodEntries+1 {
		t.Fatalf("recordingConn recorded %d Write calls, want exactly %d (no further message may ever be appended after the failed write)", got, goodEntries+1)
	}

	for i := 0; i < goodEntries; i++ {
		env := decodeRecordedFrame(t, rc.writeAt(i))
		if env.ProtocolOp != tagSearchResultEntry {
			t.Fatalf("recorded write #%d: protocolOp = %#x, want SearchResultEntry", i, byte(env.ProtocolOp))
		}
	}
	failedEnv := decodeRecordedFrame(t, rc.writeAt(goodEntries))
	if failedEnv.ProtocolOp != tagSearchResultEntry {
		t.Fatalf("recorded failed write: protocolOp = %#x, want SearchResultEntry (the entry the server was attempting when the write failed)", byte(failedEnv.ProtocolOp))
	}
}

// ---------------------------------------------------------------------
// Pipelined Unbind behind Search
// ---------------------------------------------------------------------

// TestMidSearch_PipelinedUnbindProcessedOnlyAfterSearchCompletes writes a
// Search request immediately followed by an Unbind request in one
// pipelined burst — before the server has read either — over a real TCP
// connection against a server wired to a fixed, non-advancing fakeClock
// (a deliberately controlled clock rather than real wall-clock time, so
// this test's deadline math never races real time), and proves every
// expected SearchResultEntry plus the terminal SearchResultDone arrive
// first, and only afterward does the connection close (the pipelined
// Unbind read and acted on only once the connection's single
// read-dispatch-respond loop returns from Search) — never interrupting
// the Search's own emission (plan's "Unbind" section).
func TestMidSearch_PipelinedUnbindProcessedOnlyAfterSearchCompletes(t *testing.T) {
	const numRoles = 25
	roles := rolesNamed(numRoles, "pipeline_role_")
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", roles)

	fc := newFakeClock(time.Now())
	h := newRunningServer(t, v, r, func(s *Server) { s.clock = fc.Now })
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	bindEnv := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
	if result, _, _ := readLDAPResultFields(t, bindEnv.Content); result != int(resultSuccess) {
		t.Fatalf("bind result = %d, want success", result)
	}

	groupBase := newTestConfig().GroupBaseDN
	pipelined := append(
		append([]byte{}, searchRequestBytes(2, groupBase, testAliceDN, 0, 0)...),
		unbindRequestBytes(3)...,
	)
	if _, err := conn.Write(pipelined); err != nil {
		t.Fatalf("write pipelined search+unbind: %v", err)
	}

	for i := 0; i < numRoles; i++ {
		env := readEnvelope(t, conn)
		if env.ProtocolOp != tagSearchResultEntry {
			t.Fatalf("entry #%d: protocolOp = %#x, want SearchResultEntry (Unbind must not have interrupted the Search)", i, byte(env.ProtocolOp))
		}
	}
	doneEnv := readEnvelope(t, conn)
	if doneEnv.ProtocolOp != tagSearchResultDone {
		t.Fatalf("final protocolOp = %#x, want SearchResultDone", byte(doneEnv.ProtocolOp))
	}
	if result, _, _ := readLDAPResultFields(t, doneEnv.Content); result != int(resultSuccess) {
		t.Fatalf("search result = %d, want success (all %d entries)", result, numRoles)
	}

	// Only now — after every entry and the terminal Done — does the
	// pipelined Unbind get read and acted on: no response, connection
	// closes.
	expectNoResponseThenClosed(t, conn)
}
