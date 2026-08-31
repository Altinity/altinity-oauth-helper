package profile

// This file is the test suite for server.go: New's construction guards,
// Serve/Stop's one-shot lifecycle and lock discipline, the 30s-default/
// shortened-deadline connection drops, Accept-error policy (retry on
// timeout, terminal otherwise, no busy loop), and real-TCP dispatch
// (Abandon/Unbind/unsupported ops/critical controls/unknown tags),
// proving the connection loop, dispatch table, and shutdown sequencing
// server.go implements. conncap_test.go covers the 256-connection
// admission cap and slot reuse specifically.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// --- wire builders --------------------------------------------------------
//
// These assemble complete LDAPMessage frames (unlike bind_test.go/
// search_test.go's op-content-only builders) because this file drives the
// server end to end over real TCP, never handleBind/handleSearch directly.

// fullMessage assembles one complete LDAPMessage: messageID, one
// protocolOp under appTag with the given content, and an optional
// critical Controls element.
func fullMessage(msgID int64, appTag byte, opContent []byte, critical bool) []byte {
	var controls []byte
	if critical {
		controls = buildControls(buildControl("1.2.3.4.5", trueVal(), nil))
	}
	return buildMessage(berInteger(msgID), tlv(appTag, opContent), controls)
}

func bindRequestBytes(msgID int64, dn, password string, critical bool) []byte {
	return fullMessage(msgID, byte(tagBindRequest), bindOp(3, dn, authTagSimple, []byte(password)), critical)
}

func searchRequestBytes(msgID int64, base, memberDN string, sizeLimit, timeLimit int64) []byte {
	op := searchOp(base, scopeWholeSubtree, derefNever, sizeLimit, timeLimit, false, validMembershipFilter(memberDN), "cn")
	return fullMessage(msgID, byte(tagSearchRequest), op, false)
}

func abandonRequestBytes(msgID int64, targetContent []byte, critical bool) []byte {
	return fullMessage(msgID, byte(tagAbandonRequest), targetContent, critical)
}

func unbindRequestBytes(msgID int64) []byte {
	return fullMessage(msgID, byte(tagUnbindRequest), nil, false)
}

// opaqueRequestBytes builds a complete LDAPMessage for one of the six
// recognizable-but-unsupported operations (or any other application
// tag): its protocolOp content is arbitrary opaque bytes, because
// dispatchOperation never decodes payload fields for these shapes -- the
// dispatch decision is made on the application tag alone.
func opaqueRequestBytes(msgID int64, appTag byte, critical bool) []byte {
	return fullMessage(msgID, appTag, []byte{0xde, 0xad, 0xbe, 0xef}, critical)
}

// --- real-TCP harness ------------------------------------------------------

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(%q): %v", addr, err)
	}
	return conn
}

// sendAndReadEnvelope writes request, reads exactly one bounded LDAPMessage
// response, and decodes it. It fails the test on any read/decode error --
// callers expecting no response use expectNoResponseThenClosed or
// assertNoBytesWithin instead.
func sendAndReadEnvelope(t *testing.T, conn net.Conn, request []byte) Envelope {
	t.Helper()
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return readEnvelope(t, conn)
}

func readEnvelope(t *testing.T, conn net.Conn) Envelope {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	body, err := readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}
	return env
}

// readLDAPResultFields decodes an LDAPResult-only response body (every
// response this package writes: BindResponse, SearchResultDone, and the
// six unsupported-operation responses all share this shape).
func readLDAPResultFields(t *testing.T, content cryptobyte.String) (result int, matchedDN, diagnosticMessage string) {
	t.Helper()
	var resultEnum int
	if !content.ReadASN1Enum(&resultEnum) {
		t.Fatal("LDAPResult: failed to read resultCode ENUMERATED")
	}
	var matchedDNBytes, diagBytes []byte
	if !content.ReadASN1Bytes(&matchedDNBytes, 0x04) {
		t.Fatal("LDAPResult: failed to read matchedDN")
	}
	if !content.ReadASN1Bytes(&diagBytes, 0x04) {
		t.Fatal("LDAPResult: failed to read diagnosticMessage")
	}
	if !content.Empty() {
		t.Fatal("LDAPResult: trailing bytes")
	}
	return resultEnum, string(matchedDNBytes), string(diagBytes)
}

// expectNoResponseThenClosed asserts conn produces no response bytes and
// is then closed by the peer (Unbind, and every "close without resync"
// outcome).
func expectNoResponseThenClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("expected no response bytes, got %d", n)
	}
	if err == nil {
		t.Fatal("expected the connection to be closed (EOF or reset), got nil error")
	}
	// A read-deadline timeout is NOT proof of closure -- it just as
	// happily fires on a connection the server left admitted and idle
	// (e.g. under a sabotaged cap that admits one more than it should).
	// Only a non-timeout error (EOF, connection reset) counts here.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("expected the connection to be closed within the deadline, got a read-deadline timeout instead: %v", err)
	}
}

// assertNoBytesWithin asserts no bytes arrive on conn within d, then
// clears the deadline so a subsequent real read on the same conn is not
// affected by it (the connection stays open -- Abandon's "no response,
// connection stays usable" case).
func assertNoBytesWithin(t *testing.T, conn net.Conn, d time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("expected no bytes within %v, got %d", d, n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read-deadline timeout, got %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline: %v", err)
	}
}

// testServerHandle is a *Server already Serve-ing a real TCP listener,
// with explicit, test-controlled shutdown (no automatic t.Cleanup Stop):
// several tests below need to control exactly when Stop happens and how
// long it is allowed to take.
type testServerHandle struct {
	server *Server
	addr   string
	done   <-chan error
}

func newRunningServer(t *testing.T, v Verifier, r RoleResolver, configure func(*Server)) *testServerHandle {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s, err := New(context.Background(), newTestConfig(), v, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if configure != nil {
		configure(s)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	return &testServerHandle{server: s, addr: ln.Addr().String(), done: done}
}

// stopAndWait calls Stop and requires it, and the paired Serve call, to
// both complete within timeout.
func (h *testServerHandle) stopAndWait(t *testing.T, timeout time.Duration) {
	t.Helper()
	stopped := make(chan struct{})
	go func() {
		h.server.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(timeout):
		t.Fatalf("Stop did not return within %v", timeout)
	}
	select {
	case <-h.done:
	case <-time.After(timeout):
		t.Fatalf("Serve did not return within %v after Stop", timeout)
	}
}

// activeCountForTest reads the current admitted-connection count under
// the lifecycle mutex, for tests proving slot reuse/cap-holding without
// exporting anything from server.go itself.
func (s *Server) activeCountForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// --- New: construction guards ---------------------------------------------

func TestNew_NilGuards(t *testing.T) {
	cfg := newTestConfig()
	v := newFakeVerifier()
	r := newFakeResolver()

	if _, err := New(nil, cfg, v, r); err == nil || err.Error() != "ldap: rootCtx must not be nil" {
		t.Fatalf("New(nil rootCtx) error = %v, want exact text", err)
	}
	if _, err := New(context.Background(), cfg, nil, r); err == nil || err.Error() != "ldap: verifier must not be nil" {
		t.Fatalf("New(nil verifier) error = %v, want exact text", err)
	}
	if _, err := New(context.Background(), cfg, v, nil); err == nil || err.Error() != "ldap: roleResolver must not be nil" {
		t.Fatalf("New(nil roleResolver) error = %v, want exact text", err)
	}
}

func TestNew_InvalidConfigRejected(t *testing.T) {
	cfg := newTestConfig()
	cfg.UserBaseDN = "   "
	if _, err := New(context.Background(), cfg, newFakeVerifier(), newFakeResolver()); !errors.Is(err, errUserBaseDNInvalid) {
		t.Fatalf("New(invalid config) error = %v, want errUserBaseDNInvalid", err)
	}
}

func TestNew_Defaults(t *testing.T) {
	s, err := New(context.Background(), newTestConfig(), newFakeVerifier(), newFakeResolver())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.readTimeout != 30*time.Second {
		t.Fatalf("default readTimeout = %v, want 30s", s.readTimeout)
	}
	if s.writeTimeout != 30*time.Second {
		t.Fatalf("default writeTimeout = %v, want 30s", s.writeTimeout)
	}
	if s.clock == nil {
		t.Fatal("default clock must not be nil")
	}
	if now := s.clock(); time.Since(now) > 2*time.Second {
		t.Fatalf("default clock() = %v, not close to time.Now()", now)
	}
}

// --- Serve/Stop lifecycle --------------------------------------------------

func TestServe_DuplicateCallReturnsFixedError(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)
	defer h.stopAndWait(t, 5*time.Second)

	time.Sleep(50 * time.Millisecond) // let the first Serve reach "serving"

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln2.Close()

	if err := h.server.Serve(ln2); !errors.Is(err, errServeAlreadyCalled) {
		t.Fatalf("second Serve error = %v, want errServeAlreadyCalled", err)
	}
}

func TestServe_AfterStopReturnsFixedError(t *testing.T) {
	s, err := New(context.Background(), newTestConfig(), newFakeVerifier(), newFakeResolver())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Stop() // Stop-before-Serve

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	if err := s.Serve(ln); !errors.Is(err, errServerStopped) {
		t.Fatalf("Serve after Stop error = %v, want errServerStopped", err)
	}
}

func TestStop_BeforeServeReturnsPromptly(t *testing.T) {
	s, err := New(context.Background(), newTestConfig(), newFakeVerifier(), newFakeResolver())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop-before-Serve did not return promptly")
	}
}

func TestStop_RepeatedAndConcurrentConverge(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.server.Stop()
		}()
	}
	allDone := make(chan struct{})
	go func() { wg.Wait(); close(allDone) }()

	select {
	case <-allDone:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Stop calls did not all converge")
	}
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after concurrent Stop")
	}
}

func TestServe_ExternalListenerCloseReturnsErrClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s, err := New(context.Background(), newTestConfig(), newFakeVerifier(), newFakeResolver())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	time.Sleep(50 * time.Millisecond)

	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	select {
	case serveErr := <-done:
		if !errors.Is(serveErr, net.ErrClosed) {
			t.Fatalf("Serve error after external close = %v, want errors.Is(net.ErrClosed)", serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after external listener close")
	}

	// Tidy up: Stop must still converge even though Serve already exited
	// on its own.
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not converge after an externally-closed listener")
	}
}

// --- Accept error policy ----------------------------------------------------

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

type scriptedAddr struct{}

func (scriptedAddr) Network() string { return "test" }
func (scriptedAddr) String() string  { return "scripted:0" }

// scriptedListener replays a fixed sequence of Accept errors and counts
// how many times Accept was called, proving the accept loop retries only
// on net.Error.Timeout() and never busy-loops on anything else.
type scriptedListener struct {
	mu    sync.Mutex
	errs  []error
	calls int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	idx := l.calls - 1
	if idx < len(l.errs) {
		return nil, l.errs[idx]
	}
	return nil, errors.New("scriptedListener: script exhausted")
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return scriptedAddr{} }

func (l *scriptedListener) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func TestServe_AcceptTimeoutRetriesThenArbitraryErrorReturnsWithoutSpinning(t *testing.T) {
	boom := errors.New("boom: arbitrary accept error")
	ln := &scriptedListener{errs: []error{fakeTimeoutError{}, fakeTimeoutError{}, fakeTimeoutError{}, boom}}

	s, err := New(context.Background(), newTestConfig(), newFakeVerifier(), newFakeResolver())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = s.Serve(ln)
	if !errors.Is(err, boom) {
		t.Fatalf("Serve error = %v, want boom", err)
	}
	if got := ln.callCount(); got != 4 {
		t.Fatalf("Accept called %d times, want exactly 4 (3 timeouts + 1 terminal, no spin)", got)
	}
}

// pipeListener hands Accept callers pre-created net.Pipe server ends
// (queued by dial), giving a deterministic, real-deadline-respecting
// connection for the stalled-write test below without depending on OS
// TCP socket buffer sizes.
type pipeListener struct {
	mu      sync.Mutex
	pending []net.Conn
	closed  bool
	wake    chan struct{}
}

func newPipeListener() *pipeListener { return &pipeListener{wake: make(chan struct{}, 1)} }

func (l *pipeListener) dial() net.Conn {
	client, server := net.Pipe()
	l.mu.Lock()
	l.pending = append(l.pending, server)
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
	return client
}

func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, &net.OpError{Op: "accept", Net: "pipe", Err: net.ErrClosed}
		}
		if len(l.pending) > 0 {
			conn := l.pending[0]
			l.pending = l.pending[1:]
			l.mu.Unlock()
			return conn, nil
		}
		l.mu.Unlock()
		<-l.wake
	}
}

func (l *pipeListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return scriptedAddr{} }

// --- shortened-deadline drop tests ------------------------------------------

func TestServer_StalledReadIsDroppedAndStopBounded(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), func(s *Server) {
		s.readTimeout = 200 * time.Millisecond
		s.writeTimeout = 200 * time.Millisecond
	})

	conn := dial(t, h.addr)
	defer conn.Close()

	// Never send anything: the shortened read deadline must drop this
	// connection well within it, independent of Stop.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1)
	n, rerr := conn.Read(buf)
	if n != 0 || rerr == nil {
		t.Fatalf("expected the stalled-read connection to be dropped by the shortened read deadline, got n=%d err=%v", n, rerr)
	}

	start := time.Now()
	h.stopAndWait(t, 3*time.Second)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Stop took %v with a stalled-read connection present", elapsed)
	}
}

func TestServer_StalledWriteIsDroppedAndStopBounded(t *testing.T) {
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})

	s, err := New(context.Background(), newTestConfig(), v, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.readTimeout = 5 * time.Second
	s.writeTimeout = 200 * time.Millisecond

	ln := newPipeListener()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()

	clientConn := ln.dial()
	defer clientConn.Close()

	// Send a valid Bind but never read the response: the server's write
	// deadline must fire well within its shortened writeTimeout instead
	// of blocking forever on net.Pipe's Write, which only unblocks on a
	// matching Read or an expired deadline.
	if _, err := clientConn.Write(bindRequestBytes(1, testAliceDN, "s3cr3t", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}

	start := time.Now()
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return within 3s with a stalled-write connection present")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return within 3s after Stop")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Stop took %v with a stalled-write connection present", elapsed)
	}
}

func TestServer_StopCancelsInFlightVerify(t *testing.T) {
	block := make(chan struct{}) // deliberately never closed
	v := newFakeVerifier().withBlock(block)
	r := newFakeResolver()

	h := newRunningServer(t, v, r, nil)

	conn := dial(t, h.addr)
	defer conn.Close()

	if _, err := conn.Write(bindRequestBytes(1, testAliceDN, "whatever", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}

	// Give the server a moment to actually be blocked inside Verify.
	time.Sleep(100 * time.Millisecond)
	if got := v.callCount(); got != 1 {
		t.Fatalf("Verify call count = %d before Stop, want 1 (must already be in flight)", got)
	}

	// block is never closed: Stop must return anyway, via lifecycle-ctx
	// cancellation unblocking the pending Verify call, not by waiting for
	// block to close.
	h.stopAndWait(t, 5*time.Second)

	ctx := v.contextSeen()
	if ctx == nil || ctx.Err() == nil {
		t.Fatal("blocked Verify's context was never observed canceled by Stop")
	}
}

func TestServer_RaceStopServeConnectionInterleavings(t *testing.T) {
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})

	h := newRunningServer(t, v, r, nil)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", h.addr, 2*time.Second)
			if err != nil {
				return // server may already be tearing down; that's fine here
			}
			defer conn.Close()
			_, _ = conn.Write(bindRequestBytes(int64(n+1), testAliceDN, "s3cr3t", false))
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
		}(i)
	}

	time.Sleep(20 * time.Millisecond)
	h.server.Stop()

	wg.Wait()

	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Stop during concurrent connection activity")
	}
}

// --- real-TCP dispatch: Abandon/Unbind/unsupported/critical/unknown -------

func TestProfile_AbandonNoResponseAndNoCancellation(t *testing.T) {
	block := make(chan struct{})
	v := newFakeVerifier().withBlock(block).withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})

	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	// Abandon(target=1) is sent and processed FIRST -- dropped silently,
	// producing no bytes -- with a blocking Bind (msgID=2) queued right
	// behind it on the same connection. This is the shape that actually
	// exercises "no target lookup/cancellation": once Abandon completes,
	// the server reads the queued Bind next and calls Verify, which must
	// block normally rather than observing an already-canceled context
	// (the failure mode a broken implementation that cancels on Abandon
	// would produce, since that cancellation would reach every
	// subsequently dispatched operation on the connection, not just some
	// specific earlier "target").
	if _, err := conn.Write(abandonRequestBytes(1, minimalIntegerContent(99), false)); err != nil {
		t.Fatalf("write abandon: %v", err)
	}
	assertNoBytesWithin(t, conn, 200*time.Millisecond)

	if _, err := conn.Write(bindRequestBytes(2, testAliceDN, "s3cr3t", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let the server actually block inside Verify

	if got := v.callCount(); got != 1 {
		t.Fatalf("Verify call count = %d before unblocking, want 1 (must already be in flight, not already returned)", got)
	}
	if ctx := v.contextSeen(); ctx == nil || ctx.Err() != nil {
		t.Fatal("the Bind queued behind Abandon must still be blocked with a live context, not already canceled")
	}

	close(block)

	env := readEnvelope(t, conn)
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response tag = %#x, want BindResponse %#x", byte(env.ProtocolOp), byte(tagBindResponse))
	}
	result, _, _ := readLDAPResultFields(t, env.Content)
	if result != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success (Abandon must not have poisoned it)", result)
	}
	if got := v.callCount(); got != 1 {
		t.Fatalf("Verify called %d times, want exactly 1 (Abandon must never re-invoke it)", got)
	}
}

func TestProfile_UnbindClosesWithoutResponse(t *testing.T) {
	v := newFakeVerifier()
	r := newFakeResolver()
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	if _, err := conn.Write(unbindRequestBytes(1)); err != nil {
		t.Fatalf("write unbind: %v", err)
	}
	expectNoResponseThenClosed(t, conn)

	if got := v.callCount(); got != 0 {
		t.Fatalf("Verify called %d times, want 0", got)
	}
	if got := r.callCount(); got != 0 {
		t.Fatalf("Roles called %d times, want 0", got)
	}
}

func TestProfile_AbandonTargetDecodeBoundary(t *testing.T) {
	cases := []struct {
		name      string
		target    []byte
		wantClose bool
	}{
		{"target127Accepted", minimalIntegerContent(127), false},
		{"target128Accepted", minimalIntegerContent(128), false},
		{"nonMinimalTargetCloses", []byte{0x00, 0x01}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newFakeVerifier()
			r := newFakeResolver()
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			if _, err := conn.Write(abandonRequestBytes(1, tc.target, false)); err != nil {
				t.Fatalf("write abandon: %v", err)
			}

			if tc.wantClose {
				expectNoResponseThenClosed(t, conn)
				return
			}

			// Accepted (silently dropped): prove the connection stays
			// open and usable by sending a following Unbind and
			// observing the close only then.
			assertNoBytesWithin(t, conn, 200*time.Millisecond)
			if _, err := conn.Write(unbindRequestBytes(2)); err != nil {
				t.Fatalf("write unbind: %v", err)
			}
			expectNoResponseThenClosed(t, conn)
		})
	}
}

func TestProfile_UnsupportedOperationTable(t *testing.T) {
	cases := []struct {
		name     string
		reqTag   byte
		respTag  byte
		extended bool
	}{
		{"Add", byte(tagAddRequest), byte(tagAddResponse), false},
		{"Modify", byte(tagModifyRequest), byte(tagModifyResponse), false},
		{"Delete", byte(tagDelRequest), byte(tagDelResponse), false},
		{"Compare", byte(tagCompareRequest), byte(tagCompareResponse), false},
		{"ModifyDN", byte(tagModifyDNRequest), byte(tagModifyDNResponse), false},
		{"Extended", byte(tagExtendedRequest), byte(tagExtendedResponse), true},
	}
	for _, tc := range cases {
		for _, critical := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/critical=%v", tc.name, critical), func(t *testing.T) {
				v := newFakeVerifier()
				r := newFakeResolver()
				h := newRunningServer(t, v, r, nil)
				defer h.stopAndWait(t, 5*time.Second)

				conn := dial(t, h.addr)
				defer conn.Close()

				env := sendAndReadEnvelope(t, conn, opaqueRequestBytes(1, tc.reqTag, critical))
				if byte(env.ProtocolOp) != tc.respTag {
					t.Fatalf("response tag = %#x, want %#x", byte(env.ProtocolOp), tc.respTag)
				}
				result, _, diag := readLDAPResultFields(t, env.Content)

				wantResult := int(resultUnwillingToPerform)
				wantDiag := diagEmpty.text()
				if critical {
					wantResult = int(resultUnavailableCriticalExtension)
					wantDiag = diagEmpty.text()
				}
				if tc.extended {
					if critical {
						wantDiag = diagCriticalControl.text()
					} else {
						wantDiag = diagOperationUnsupported.text()
					}
				}
				if result != wantResult {
					t.Fatalf("result = %d, want %d", result, wantResult)
				}
				if diag != wantDiag {
					t.Fatalf("diagnosticMessage = %q, want %q", diag, wantDiag)
				}

				if got := v.callCount(); got != 0 {
					t.Fatalf("Verify called %d times, want 0", got)
				}
				if got := r.callCount(); got != 0 {
					t.Fatalf("Roles called %d times, want 0", got)
				}
			})
		}
	}
}

func TestProfile_CancelExtendedTreatedAsUnsupportedNoSideEffect(t *testing.T) {
	// Cancel has no dedicated wire shape in this profile's dispatch: it is
	// exactly an ExtendedRequest, so the "deliberate Cancel narrowing"
	// (no target scheduling of any kind) is proven the same way as any
	// other Extended request -- non-critical -> 53, critical -> 12, and
	// zero verifier/resolver calls either way.
	for _, critical := range []bool{false, true} {
		t.Run(fmt.Sprintf("critical=%v", critical), func(t *testing.T) {
			v := newFakeVerifier()
			r := newFakeResolver()
			h := newRunningServer(t, v, r, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			env := sendAndReadEnvelope(t, conn, opaqueRequestBytes(1, byte(tagExtendedRequest), critical))
			if byte(env.ProtocolOp) != byte(tagExtendedResponse) {
				t.Fatalf("response tag = %#x, want ExtendedResponse", byte(env.ProtocolOp))
			}
			result, _, diag := readLDAPResultFields(t, env.Content)
			wantResult := int(resultUnwillingToPerform)
			wantDiag := diagOperationUnsupported.text()
			if critical {
				wantResult = int(resultUnavailableCriticalExtension)
				wantDiag = diagCriticalControl.text()
			}
			if result != wantResult {
				t.Fatalf("Cancel result = %d, want %d", result, wantResult)
			}
			if diag != wantDiag {
				t.Fatalf("Cancel diagnosticMessage = %q, want %q", diag, wantDiag)
			}
			if got := v.callCount(); got != 0 {
				t.Fatalf("Verify called %d times, want 0 (no side effect)", got)
			}
			if got := r.callCount(); got != 0 {
				t.Fatalf("Roles called %d times, want 0 (no side effect)", got)
			}
		})
	}
}

func TestProfile_UnknownApplicationTagCloses(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	// 0x5f is not any recognized application tag this profile dispatches
	// on.
	if _, err := conn.Write(opaqueRequestBytes(1, 0x5f, false)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectNoResponseThenClosed(t, conn)
}

func TestProfile_ClientSentResponseTagCloses(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	// A client sending a *response* tag (e.g. BindResponse) has no safe
	// fixed mapping and must close, not be silently ignored.
	if _, err := conn.Write(opaqueRequestBytes(1, byte(tagBindResponse), false)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectNoResponseThenClosed(t, conn)
}

func TestProfile_NoAuthCallsAcrossUnsupportedAbandonUnbindTraffic(t *testing.T) {
	v := newFakeVerifier()
	r := newFakeResolver()
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	msgID := int64(1)
	for _, appTag := range []byte{
		byte(tagAddRequest), byte(tagModifyRequest), byte(tagDelRequest),
		byte(tagCompareRequest), byte(tagModifyDNRequest), byte(tagExtendedRequest),
	} {
		_ = sendAndReadEnvelope(t, conn, opaqueRequestBytes(msgID, appTag, false))
		msgID++
	}

	if _, err := conn.Write(abandonRequestBytes(msgID, minimalIntegerContent(1), false)); err != nil {
		t.Fatalf("write abandon: %v", err)
	}
	msgID++
	assertNoBytesWithin(t, conn, 200*time.Millisecond)

	if _, err := conn.Write(unbindRequestBytes(msgID)); err != nil {
		t.Fatalf("write unbind: %v", err)
	}
	expectNoResponseThenClosed(t, conn)

	if got := v.callCount(); got != 0 {
		t.Fatalf("Verify called %d times, want 0 across all unsupported/Abandon/Unbind traffic", got)
	}
	if got := r.callCount(); got != 0 {
		t.Fatalf("Roles called %d times, want 0 across all unsupported/Abandon/Unbind traffic", got)
	}
}
