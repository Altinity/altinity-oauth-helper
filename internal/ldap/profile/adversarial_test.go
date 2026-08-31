package profile

// This file is sub-task p2-10's adversarial suite: framing/body-cap
// proofs, deadline stalls, malformed-BER survival, bounded shutdown under
// load, and a credential/marker output scan, all driven over a real TCP
// listener against the real Server (server.go/frame.go/bind.go/search.go),
// reusing server_test.go's harness (newRunningServer/dial/
// sendAndReadEnvelope/readEnvelope/readLDAPResultFields/
// expectNoResponseThenClosed/assertNoBytesWithin/fullMessage/
// bindRequestBytes/searchRequestBytes/abandonRequestBytes/
// unbindRequestBytes/opaqueRequestBytes), frame_test.go's BER builders
// (tlv/berInteger/minimalIntegerContent/buildControl/buildControls), and
// fakes_test.go's fakeVerifier/fakeResolver/marker constants. It also
// characterizes (not "preserves parity for") the three deliberate
// narrowings named in the plan's "Cancellation compatibility" section, as
// TestProfileNarrowing_* — peer-disconnect, ordinary Abandon, and ordinary
// Cancel no longer cancel an in-flight Verify the way legacy's vendored
// RouteMux did.
//
// Every allocation-counting test here uses its own mutex-protected
// recorder (allocRecorder below), never frame_test.go's plain-slice
// withAllocRecorder: that helper is safe only for a single goroutine
// calling readFrame directly (as frame_test.go itself does); these tests
// swap the same package-level allocBody hook while the real server's own
// connection goroutine calls it concurrently with this test's goroutine
// observing the result, which requires synchronized access to stay
// -race-clean.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// --- allocation recorder (concurrency-safe) --------------------------------

// allocRecorder mirrors frame_test.go's withAllocRecorder but is safe to
// use while a server connection goroutine calls the swapped allocBody
// concurrently with this test's own goroutine reading the recorded
// calls — every access is taken under mu.
type allocRecorder struct {
	mu    sync.Mutex
	calls []int
}

func (r *allocRecorder) record(n int) {
	r.mu.Lock()
	r.calls = append(r.calls, n)
	r.mu.Unlock()
}

func (r *allocRecorder) snapshot() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.calls...)
}

// withAllocRecorderTCP swaps allocBody for the duration of fn and returns
// the concurrency-safe recorder that captured every call. fn must not
// return until every allocBody call it cares about has already happened
// (e.g. by reading a full response, or by observing the connection
// close) — the read/write completing over the real transport is what
// makes the recorded calls visible to this goroutine once fn returns.
func withAllocRecorderTCP(t *testing.T, fn func()) *allocRecorder {
	t.Helper()
	prev := allocBody
	rec := &allocRecorder{}
	allocBody = func(n int) []byte {
		rec.record(n)
		return prev(n)
	}
	defer func() { allocBody = prev }()
	fn()
	return rec
}

// ---------------------------------------------------------------------
// Framing/body cap over real TCP
// ---------------------------------------------------------------------

// TestAdversarial_OversizedDeclarationClosesWithoutAllocation proves the
// 65537-byte declaration is rejected before any body allocation, over a
// real TCP connection against the real Server: only the outer tag and
// length octets are ever sent (readFrame never attempts to read a body
// once the length exceeds maxBodyBytes, so a well-behaved client — or
// this test — never needs to send one).
func TestAdversarial_OversizedDeclarationClosesWithoutAllocation(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	header := append([]byte{tagSequence}, encodeLength(maxBodyBytes+1)...)
	rec := withAllocRecorderTCP(t, func() {
		if _, err := conn.Write(header); err != nil {
			t.Fatalf("write oversized-declaration header: %v", err)
		}
		expectNoResponseThenClosed(t, conn)
	})
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("allocBody called %v times for a %d-byte declaration, want zero", calls, maxBodyBytes+1)
	}
}

// TestAdversarial_HistoricalTwoGiBDeclarationClosesWithoutAllocation
// replays the historical ~2 GiB long-form length declaration
// (`30 84 7f ff ff ff`) over real TCP: rejected by the "more than three
// length octets" rule alone, before its own length octets are even read.
func TestAdversarial_HistoricalTwoGiBDeclarationClosesWithoutAllocation(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	rec := withAllocRecorderTCP(t, func() {
		if _, err := conn.Write([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}); err != nil {
			t.Fatalf("write historical ~2GiB declaration: %v", err)
		}
		expectNoResponseThenClosed(t, conn)
	})
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("allocBody called %v times for the ~2GiB declaration, want zero", calls)
	}
}

// TestAdversarial_MalformedLengthFormsCloseWithoutAllocation replays every
// other malformed-length-form vector from frame_test.go's
// TestReadFrame_RejectedForms over real TCP, each on its own fresh
// connection: indefinite length, non-minimal long form, leading-zero long
// form, a four-octet length, and a non-minimal long form just below the
// short-form boundary.
func TestAdversarial_MalformedLengthFormsCloseWithoutAllocation(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"indefinite length (30 80)", []byte{0x30, 0x80, 0x00, 0x00}},
		{"non-minimal long form (30 81 05)", append([]byte{0x30, 0x81, 0x05}, make([]byte, 5)...)},
		{"leading-zero long form (30 82 00 05)", append([]byte{0x30, 0x82, 0x00, 0x05}, make([]byte, 5)...)},
		{"four-octet length", []byte{0x30, 0x84, 0x00, 0x00, 0x01, 0x00}},
		{"non-minimal long form just below the short-form boundary (30 81 7f)", append([]byte{0x30, 0x81, 0x7f}, make([]byte, 127)...)},
	}

	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)
	defer h.stopAndWait(t, 5*time.Second)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := dial(t, h.addr)
			defer conn.Close()
			rec := withAllocRecorderTCP(t, func() {
				if _, err := conn.Write(c.frame); err != nil {
					t.Fatalf("write %s: %v", c.name, err)
				}
				expectNoResponseThenClosed(t, conn)
			})
			if calls := rec.snapshot(); len(calls) != 0 {
				t.Fatalf("%s: allocBody called %v times, want zero", c.name, calls)
			}
		})
	}
}

// paddedEnvelopeBody returns a complete LDAPMessage body (messageID +
// protocolOp + an [0] Controls element carrying one unknown non-critical
// control whose OCTET STRING value is sized so the whole body is exactly
// target bytes). It measures rather than hand-computing BER length
// overhead, converging in at most a couple of iterations since that
// overhead only changes at the short/long-form length breakpoints.
func paddedEnvelopeBody(t *testing.T, target int, msgID int64, protocolOp []byte) []byte {
	t.Helper()
	build := func(padLen int) []byte {
		if padLen < 0 {
			padLen = 0
		}
		ctrl := buildControl("1.2.3.4.5.6", nil, bytes.Repeat([]byte{0x00}, padLen))
		controls := buildControls(ctrl)
		return append(append(berInteger(msgID), protocolOp...), controls...)
	}
	padLen := 0
	for i := 0; i < 6; i++ {
		body := build(padLen)
		diff := target - len(body)
		if diff == 0 {
			return body
		}
		padLen += diff
	}
	t.Fatalf("paddedEnvelopeBody: did not converge to target %d", target)
	return nil
}

// TestAdversarial_ExactCapAcceptedWithPaddedEnvelope proves a well-formed
// LDAPMessage declaring exactly maxBodyBytes (65536) is read fully and
// processed normally over real TCP: one allocBody call for exactly
// 65536, and the wrapped BindRequest still succeeds.
func TestAdversarial_ExactCapAcceptedWithPaddedEnvelope(t *testing.T) {
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	bindContent := bindOp(3, testAliceDN, authTagSimple, []byte("s3cr3t"))
	protocolOp := tlv(byte(tagBindRequest), bindContent)
	body := paddedEnvelopeBody(t, maxBodyBytes, 1, protocolOp)
	if len(body) != maxBodyBytes {
		t.Fatalf("constructed body length = %d, want exactly %d", len(body), maxBodyBytes)
	}
	frame := tlv(tagSequence, body)

	// The recorder must be active only around the server's own read of
	// this request — not around this test's subsequent response read,
	// which reuses the very same readFrame/allocBody machinery (via
	// readEnvelope) to decode the BindResponse and would otherwise be
	// double-counted as a second, unrelated allocBody call for the
	// (small) response frame.
	rec := &allocRecorder{}
	prevAllocBody := allocBody
	allocBody = func(n int) []byte {
		rec.record(n)
		return prevAllocBody(n)
	}
	if _, err := conn.Write(frame); err != nil {
		allocBody = prevAllocBody
		t.Fatalf("write padded-envelope frame: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(rec.snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	allocBody = prevAllocBody

	calls := rec.snapshot()
	if len(calls) != 1 || calls[0] != maxBodyBytes {
		t.Fatalf("allocBody calls = %v, want exactly one call for %d", calls, maxBodyBytes)
	}

	env := readEnvelope(t, conn)
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response tag = %#x, want BindResponse", byte(env.ProtocolOp))
	}
	result, _, _ := readLDAPResultFields(t, env.Content)
	if result != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success", result)
	}
}

// ---------------------------------------------------------------------
// Deadline stalls: partial header, partial body, write deadline
// ---------------------------------------------------------------------

// TestAdversarial_PartialFrameStallsDropAtReadDeadlineWhileOtherConnKeepsWorking
// stalls two connections mid-frame (one after only the outer tag byte,
// one after a valid header declaring a body followed by only part of
// it) against a server with a shortened read deadline, and proves both
// are dropped at that deadline while a third, ordinary connection is
// served normally throughout.
func TestAdversarial_PartialFrameStallsDropAtReadDeadlineWhileOtherConnKeepsWorking(t *testing.T) {
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, func(s *Server) {
		s.readTimeout = 300 * time.Millisecond
		s.writeTimeout = 5 * time.Second
	})
	defer h.stopAndWait(t, 5*time.Second)

	headerOnly := dial(t, h.addr)
	defer headerOnly.Close()
	if _, err := headerOnly.Write([]byte{0x30}); err != nil {
		t.Fatalf("write partial header: %v", err)
	}
	// Never send the length octet(s): the read deadline must drop this
	// connection.

	partialBody := dial(t, h.addr)
	defer partialBody.Close()
	// A valid header declaring a 64-byte body, well under maxBodyBytes,
	// followed by only 3 of those 64 declared bytes.
	if _, err := partialBody.Write([]byte{0x30, 0x40}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := partialBody.Write([]byte{0x02, 0x01, 0x03}); err != nil {
		t.Fatalf("write partial body: %v", err)
	}
	// Never send the remaining 61 declared-but-undelivered bytes.

	expectNoResponseThenClosed(t, headerOnly)
	expectNoResponseThenClosed(t, partialBody)

	// The server must remain fully healthy for ordinary traffic while
	// (and after) both stalled connections were dropped.
	ok := dial(t, h.addr)
	defer ok.Close()
	env := sendAndReadEnvelope(t, ok, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response tag = %#x, want BindResponse", byte(env.ProtocolOp))
	}
	if result, _, _ := readLDAPResultFields(t, env.Content); result != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success", result)
	}
}

// TestAdversarial_NonReadingClientDuringLargeSearchHitsWriteDeadline
// proves a client that stops reading partway through a Search response is
// dropped once the server's write deadline elapses, rather than pinning
// the connection (and, by extension, graceful shutdown) forever. It uses
// net.Pipe (via a pipeListener, matching server_test.go's own
// TestServer_StalledWriteIsDroppedAndStopBounded) because a real socket's
// write blocking is host-buffer-size-dependent, while net.Pipe's Write
// blocks deterministically the instant the peer stops reading.
func TestAdversarial_NonReadingClientDuringLargeSearchHitsWriteDeadline(t *testing.T) {
	roles := rolesNamed(50, "adversarial_role_")
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", roles)

	s, err := New(context.Background(), newTestConfig(), v, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.readTimeout = 5 * time.Second
	s.writeTimeout = 300 * time.Millisecond

	ln := newPipeListener()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()

	clientConn := ln.dial()
	defer clientConn.Close()

	if _, err := clientConn.Write(bindRequestBytes(1, testAliceDN, "s3cr3t", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline (bind): %v", err)
	}
	bindBody, err := readFrame(clientConn)
	if err != nil {
		t.Fatalf("read bind response: %v", err)
	}
	bindEnv, err := decodeEnvelope(bindBody)
	if err != nil || bindEnv.ProtocolOp != tagBindResponse {
		t.Fatalf("decode bind response: env=%+v err=%v", bindEnv, err)
	}

	// Issue the Search, then read NOTHING: the server's very first entry
	// write blocks on this unbuffered pipe the moment it is attempted.
	if _, err := clientConn.Write(searchRequestBytes(2, newTestConfig().GroupBaseDN, testAliceDN, 0, 0)); err != nil {
		t.Fatalf("write search: %v", err)
	}
	time.Sleep(5 * s.writeTimeout)

	buf := make([]byte, 4096)
	n, readErr := clientConn.Read(buf)
	if readErr == nil {
		t.Fatalf("server delivered %d bytes of the stalled Search response after the client read nothing — its write was never bounded by writeTimeout", n)
	}

	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s with a stalled Search-response connection present")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s after Stop")
	}
}

// ---------------------------------------------------------------------
// Malformed BER survival
// ---------------------------------------------------------------------

// TestAdversarial_MalformedBERVariantsCloseOnlyTheirOwnConnection sends a
// table of distinct malformed-envelope/Controls shapes, each on its own
// fresh connection, and proves each closes only that one connection
// without disturbing the server: a truncated envelope (messageID with no
// protocolOp at all), MessageID 0 (rejected by minimalPositiveInt32),
// trailing bytes after a structurally complete envelope, and a malformed
// Controls BOOLEAN (`01 01 01` — tag BOOLEAN, length 1, content byte
// 0x01, which cryptobyte's strict DER ReadASN1Boolean rejects as
// non-canonical). It also proves none of this traffic — nor the
// well-formed Abandon/Unbind/unsupported-operation traffic that follows
// it on a further fresh connection — ever increments the Verify/Roles
// counters, and that the server still serves a final, ordinary Bind
// afterward.
func TestAdversarial_MalformedBERVariantsCloseOnlyTheirOwnConnection(t *testing.T) {
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	unbindOp := tlv(byte(tagUnbindRequest), nil)

	cases := []struct {
		name string
		body []byte
	}{
		{
			name: "truncated_envelope_no_protocolOp",
			body: berInteger(1),
		},
		{
			name: "messageID_zero",
			body: append(berInteger(0), unbindOp...),
		},
		{
			name: "trailing_bytes_after_controls",
			body: append(append(berInteger(1), unbindOp...), 0xde, 0xad, 0xbe, 0xef),
		},
		{
			name: "malformed_controls_boolean_01_01_01",
			body: func() []byte {
				rawCriticality := tlv(0x01, []byte{0x01}) // non-canonical BOOLEAN content byte
				ctrlContent := append(tlv(0x04, []byte("1.2.3.4.5")), rawCriticality...)
				ctrl := tlv(0x30, ctrlContent)
				controls := tlv(0xa0, ctrl)
				return append(append(berInteger(1), unbindOp...), controls...)
			}(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := dial(t, h.addr)
			defer conn.Close()
			if _, err := conn.Write(tlv(tagSequence, c.body)); err != nil {
				t.Fatalf("write %s: %v", c.name, err)
			}
			expectNoResponseThenClosed(t, conn)
		})
	}

	if got := v.callCount(); got != 0 {
		t.Fatalf("Verify called %d times across malformed-BER traffic, want 0", got)
	}
	if got := r.callCount(); got != 0 {
		t.Fatalf("Roles called %d times across malformed-BER traffic, want 0", got)
	}

	// Well-formed but non-authenticating traffic on a further connection
	// must also never touch the counters.
	quiet := dial(t, h.addr)
	defer quiet.Close()
	quietMsgID := int64(1)
	for _, appTag := range []byte{
		byte(tagAddRequest), byte(tagModifyRequest), byte(tagDelRequest),
		byte(tagCompareRequest), byte(tagModifyDNRequest), byte(tagExtendedRequest),
	} {
		_ = sendAndReadEnvelope(t, quiet, opaqueRequestBytes(quietMsgID, appTag, false))
		quietMsgID++
	}
	if _, err := quiet.Write(abandonRequestBytes(quietMsgID, minimalIntegerContent(1), false)); err != nil {
		t.Fatalf("write abandon: %v", err)
	}
	quietMsgID++
	assertNoBytesWithin(t, quiet, 200*time.Millisecond)
	if _, err := quiet.Write(unbindRequestBytes(quietMsgID)); err != nil {
		t.Fatalf("write unbind: %v", err)
	}
	expectNoResponseThenClosed(t, quiet)

	if got := v.callCount(); got != 0 {
		t.Fatalf("Verify called %d times across malformed+unsupported+Abandon+Unbind traffic, want 0", got)
	}
	if got := r.callCount(); got != 0 {
		t.Fatalf("Roles called %d times across malformed+unsupported+Abandon+Unbind traffic, want 0", got)
	}

	// The server itself is unaffected: a final, ordinary Bind on a fresh
	// connection still succeeds and does increment both counters exactly
	// once.
	ok := dial(t, h.addr)
	defer ok.Close()
	env := sendAndReadEnvelope(t, ok, bindRequestBytes(9, testAliceDN, "s3cr3t", false))
	if result, _, _ := readLDAPResultFields(t, env.Content); result != int(resultSuccess) {
		t.Fatalf("final Bind result = %d, want success", result)
	}
	if got := v.callCount(); got != 1 {
		t.Fatalf("Verify called %d times after the final ordinary Bind, want exactly 1", got)
	}
	if got := r.callCount(); got != 1 {
		t.Fatalf("Roles called %d times after the final ordinary Bind, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------
// Bounded shutdown under many stalled connections
// ---------------------------------------------------------------------

// TestAdversarial_StopWithManyStalledConnectionsCompletesPromptly dials
// 50 connections that never send anything and never get admitted past
// framing, then proves Stop() still converges promptly: Stop closes
// every admitted connection directly rather than waiting out any read
// deadline, so this must not depend on (or wait for) readTimeout at all.
func TestAdversarial_StopWithManyStalledConnectionsCompletesPromptly(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), nil)

	const stalled = 50
	conns := make([]net.Conn, stalled)
	for i := range conns {
		conns[i] = dial(t, h.addr)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	// Give the accept loop a moment to actually admit all of them before
	// timing Stop.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.server.activeCountForTest() >= stalled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.server.activeCountForTest(); got != stalled {
		t.Fatalf("admitted connection count = %d, want %d before timing Stop", got, stalled)
	}

	start := time.Now()
	h.stopAndWait(t, 5*time.Second)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Stop took %v with %d stalled connections present", elapsed, stalled)
	}
}

// ---------------------------------------------------------------------
// Output-marker scan
// ---------------------------------------------------------------------

// markerPresent reports whether marker appears, as a literal byte
// sequence, in any of haystacks — the pure detection logic every marker
// scan below (and its own self-check) shares.
func markerPresent(marker string, haystacks ...[]byte) bool {
	m := []byte(marker)
	for _, h := range haystacks {
		if bytes.Contains(h, m) {
			return true
		}
	}
	return false
}

// assertMarkerAbsent fails the test if marker appears in any of
// haystacks.
func assertMarkerAbsent(t *testing.T, marker string, haystacks ...[]byte) {
	t.Helper()
	if markerPresent(marker, haystacks...) {
		t.Fatalf("marker %q leaked into captured output", marker)
	}
}

// TestAdversarial_MarkerScanSelfCheckDetectsInjectedMarker is this suite's
// own doneWhen self-check: it proves markerPresent (the scanner every
// no-leak assertion below relies on) actually detects a deliberately
// injected marker, in both a response-shaped byte slice and a
// log-line-shaped JSON blob, rather than vacuously passing.
func TestAdversarial_MarkerScanSelfCheckDetectsInjectedMarker(t *testing.T) {
	const marker = "profile-test-marker: self-check-injected-value"

	respLike := []byte("some response bytes ... " + marker + " ... more bytes")
	if !markerPresent(marker, respLike) {
		t.Fatal("markerPresent did not detect a marker deliberately embedded in response-shaped bytes")
	}

	fields := map[string]any{"op": "bind", "reason": "verification failed", "leaked": marker}
	serialized, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !markerPresent(marker, serialized) {
		t.Fatalf("markerPresent did not detect a marker deliberately embedded in a captured log line: %s", serialized)
	}

	// Negative control: an unrelated haystack must not report a false
	// positive.
	if markerPresent(marker, []byte("nothing interesting here")) {
		t.Fatal("markerPresent reported a false positive on an unrelated haystack")
	}
}

// TestAdversarial_MarkerScanAcrossHostileInputsNeverLeaks binds/searches
// with a marker-bearing JWT-shaped password, a hostile Bind DN, and
// injected verifier/resolver error markers, capturing both the response
// bytes and the application log line (at TRACE level, the most permissive
// level this package ever logs at) for each, and asserts the marker never
// appears in either.
func TestAdversarial_MarkerScanAcrossHostileInputsNeverLeaks(t *testing.T) {
	t.Run("jwt_shaped_password_on_successful_bind", func(t *testing.T) {
		v := newFakeVerifier().withSuccess(markerJWTPassword, newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
		r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := dial(t, h.addr)
		defer conn.Close()

		var env Envelope
		fields := captureLog(t, zerolog.TraceLevel, func() {
			env = sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, markerJWTPassword, false))
		})
		if result, _, _ := readLDAPResultFields(t, env.Content); result != int(resultSuccess) {
			t.Fatalf("Bind result = %d, want success", result)
		}
		serialized, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("json.Marshal(fields): %v", err)
		}
		assertMarkerAbsent(t, markerJWTPassword, serialized)
	})

	t.Run("hostile_bind_dn", func(t *testing.T) {
		v := newFakeVerifier()
		r := newFakeResolver()
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := dial(t, h.addr)
		defer conn.Close()

		var env Envelope
		fields := captureLog(t, zerolog.TraceLevel, func() {
			env = sendAndReadEnvelope(t, conn, bindRequestBytes(1, markerHostileDN, "whatever", false))
		})
		result, _, diag := readLDAPResultFields(t, env.Content)
		if result != int(resultInvalidCredentials) {
			t.Fatalf("Bind result = %d, want invalidCredentials", result)
		}
		serialized, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("json.Marshal(fields): %v", err)
		}
		assertMarkerAbsent(t, markerHostileDN, []byte(diag), serialized)
	})

	t.Run("verifier_error_marker", func(t *testing.T) {
		v := newFakeVerifier().withFailure("alice-pw", fmt.Errorf("%s", markerVerifierError))
		r := newFakeResolver()
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := dial(t, h.addr)
		defer conn.Close()

		var env Envelope
		fields := captureLog(t, zerolog.TraceLevel, func() {
			env = sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false))
		})
		result, _, diag := readLDAPResultFields(t, env.Content)
		if result != int(resultInvalidCredentials) {
			t.Fatalf("Bind result = %d, want invalidCredentials", result)
		}
		serialized, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("json.Marshal(fields): %v", err)
		}
		assertMarkerAbsent(t, markerVerifierError, []byte(diag), serialized)
	})

	t.Run("resolver_error_marker", func(t *testing.T) {
		v := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
		r := newFakeResolver().withError(fmt.Errorf("%s", markerResolverError))
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := dial(t, h.addr)
		defer conn.Close()

		var env Envelope
		fields := captureLog(t, zerolog.TraceLevel, func() {
			env = sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "alice-pw", false))
		})
		result, _, diag := readLDAPResultFields(t, env.Content)
		if result != int(resultInvalidCredentials) {
			t.Fatalf("Bind result = %d, want invalidCredentials", result)
		}
		serialized, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("json.Marshal(fields): %v", err)
		}
		assertMarkerAbsent(t, markerResolverError, []byte(diag), serialized)
	})
}

// ---------------------------------------------------------------------
// Deliberate narrowings (characterize, do not preserve — plan's
// "Cancellation compatibility" section)
// ---------------------------------------------------------------------

// TestProfileNarrowing_PeerDisconnectDuringBlockingVerifyDoesNotCancel
// characterizes the plan's "Deliberate peer-disconnect narrowing": unlike
// legacy's independent per-request reader, this connection's single
// synchronous loop is not reading while blocked inside Verify, so an
// abrupt client disconnect during that wait is not observed until Verify
// itself returns (via Stop/root cancellation) — never immediately. Phase
// 3 must explicitly accept this narrowing before cutover (plan
// "Cancellation compatibility", the peer-disconnect item).
func TestProfileNarrowing_PeerDisconnectDuringBlockingVerifyDoesNotCancel(t *testing.T) {
	block := make(chan struct{}) // never closed
	v := newFakeVerifier().withBlock(block)
	r := newFakeResolver()
	h := newRunningServer(t, v, r, nil)

	conn := dial(t, h.addr)
	if _, err := conn.Write(bindRequestBytes(1, testAliceDN, "whatever", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for v.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if v.callCount() != 1 {
		t.Fatalf("Verify call count = %d, want 1 (must already be in flight)", v.callCount())
	}

	// Abrupt disconnect while Verify is still blocked.
	if err := conn.Close(); err != nil {
		t.Fatalf("close conn: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if ctx := v.contextSeen(); ctx == nil || ctx.Err() != nil {
		t.Fatal("peer disconnect during a blocking Verify appears to have canceled it — this profile deliberately does not observe EOF while blocked in Verify")
	}

	// Clean up: unblock Verify and converge shutdown, proving the
	// blocked call eventually resolves once Stop/root cancellation (not
	// the earlier disconnect) reaches it.
	close(block)
	h.stopAndWait(t, 5*time.Second)
}

// TestProfileNarrowing_OrdinaryAbandonDoesNotCancelBlockingVerify
// characterizes the plan's "Deliberate ordinary-Abandon narrowing":
// legacy's vendored RouteMux looks up the target request and cancels it;
// this profile's Abandon decodes and drops its target unconditionally,
// with no lookup of any kind. An Abandon queued behind an in-flight,
// still-blocked Bind must not reach in and cancel that Bind's Verify
// call — it is read (and silently dropped) only after the Bind's own
// dispatch returns, per the connection's single synchronous loop (plan
// "Cancellation compatibility", the ordinary-Abandon item).
func TestProfileNarrowing_OrdinaryAbandonDoesNotCancelBlockingVerify(t *testing.T) {
	block := make(chan struct{})
	v := newFakeVerifier().withBlock(block).withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	if _, err := conn.Write(bindRequestBytes(1, testAliceDN, "s3cr3t", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for v.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if v.callCount() != 1 {
		t.Fatalf("Verify call count = %d, want 1 (must already be in flight)", v.callCount())
	}

	// An Abandon naming the in-flight Bind's own messageID, queued right
	// behind it on the same connection while Verify is still blocked. It
	// cannot be read by the server yet (the connection's single reader
	// loop is still inside dispatching the Bind), so this only proves
	// what happens once it eventually is: nothing, to the Bind.
	if _, err := conn.Write(abandonRequestBytes(2, minimalIntegerContent(1), false)); err != nil {
		t.Fatalf("write abandon: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if ctx := v.contextSeen(); ctx == nil || ctx.Err() != nil {
		t.Fatal("a queued ordinary Abandon appears to have canceled the blocking Verify it named as its target")
	}
	if v.callCount() != 1 {
		t.Fatalf("Verify called %d times while Abandon sat queued, want 1", v.callCount())
	}

	close(block)

	env := readEnvelope(t, conn)
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response tag = %#x, want BindResponse", byte(env.ProtocolOp))
	}
	if result, _, _ := readLDAPResultFields(t, env.Content); result != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success (the queued Abandon must not have poisoned it)", result)
	}

	// The queued Abandon is now read and dropped: no response, and the
	// connection stays open and usable.
	assertNoBytesWithin(t, conn, 200*time.Millisecond)
	if _, err := conn.Write(unbindRequestBytes(3)); err != nil {
		t.Fatalf("write unbind: %v", err)
	}
	expectNoResponseThenClosed(t, conn)
}

// TestProfileNarrowing_NonCriticalCancelDoesNotCancelBlockingVerify
// characterizes the plan's "Deliberate Cancel narrowing": this profile
// has no Cancel control plane at all — a non-critical RFC 3909 Cancel
// Extended request is dispatched as an ordinary unsupported Extended
// request (result 53), never decoded for its target messageID, and
// (like Abandon above) cannot reach in and cancel an in-flight, still
// blocked Verify it is queued behind (plan "Cancellation compatibility",
// the ordinary-Cancel item).
func TestProfileNarrowing_NonCriticalCancelDoesNotCancelBlockingVerify(t *testing.T) {
	block := make(chan struct{})
	v := newFakeVerifier().withBlock(block).withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	if _, err := conn.Write(bindRequestBytes(1, testAliceDN, "s3cr3t", false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for v.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if v.callCount() != 1 {
		t.Fatalf("Verify call count = %d, want 1 (must already be in flight)", v.callCount())
	}

	// A non-critical Cancel-shaped ExtendedRequest (dispatch never
	// decodes an Extended request's content/OID, so any opaque bytes
	// exercise the identical "no Cancel control plane" path a real RFC
	// 3909 Cancel naming this Bind's messageID would), queued right
	// behind the still-blocked Bind.
	if _, err := conn.Write(opaqueRequestBytes(2, byte(tagExtendedRequest), false)); err != nil {
		t.Fatalf("write cancel-shaped extended request: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if ctx := v.contextSeen(); ctx == nil || ctx.Err() != nil {
		t.Fatal("a queued non-critical Cancel-shaped request appears to have canceled the blocking Verify it named as its target")
	}
	if v.callCount() != 1 {
		t.Fatalf("Verify called %d times while Cancel sat queued, want 1", v.callCount())
	}

	close(block)

	env := readEnvelope(t, conn)
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response tag = %#x, want BindResponse", byte(env.ProtocolOp))
	}
	if result, _, _ := readLDAPResultFields(t, env.Content); result != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success (the queued Cancel must not have poisoned it)", result)
	}

	// The queued Cancel is now dispatched as an ordinary unsupported
	// Extended request: result 53, no cancellation of anything.
	cancelEnv := readEnvelope(t, conn)
	if cancelEnv.ProtocolOp != tagExtendedResponse {
		t.Fatalf("response tag = %#x, want ExtendedResponse", byte(cancelEnv.ProtocolOp))
	}
	if result, _, diag := readLDAPResultFields(t, cancelEnv.Content); result != int(resultUnwillingToPerform) || diag != diagOperationUnsupported.text() {
		t.Fatalf("Cancel result/diagnostic = %d/%q, want %d/%q", result, diag, resultUnwillingToPerform, diagOperationUnsupported.text())
	}
}
