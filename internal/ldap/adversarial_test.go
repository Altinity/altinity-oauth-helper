package ldap

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldapclient "github.com/go-ldap/ldap/v3"
	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers the phase-2 plan's remaining High-risk adversarial proofs
// against the real production server over TCP, complementing
// protocol_test.go (disjoint file, same package, same "client TCP ->
// ldapserver BER parsing -> production route -> connectionHandler/session ->
// production response -> client decode" harness; only verifier/roleResolver
// are test fakes). It intentionally goes beyond protocol_test.go's existing
// cancellation/sentinel/alias/race/malformed-BER tests in the ways that
// matter for the sabotage cases in the plan's invariant map:
//
//   - the shutdown test here explicitly asserts Serve itself returns (the
//     server terminates), not only that the blocked verifier observes
//     cancellation;
//   - the sentinel test here captures the real OS-level stdout file
//     descriptor, not just the application zerolog writer — this is the
//     only way to actually catch the dependency's own packet-hex logger if
//     the mandatory ldapserver.Logger = ldapserver.DiscardingLogger line is
//     ever removed, since that logger is a fixed *log.Logger created at
//     package-init time against the os.Stdout *os.File value at that
//     instant; merely reassigning the os.Stdout package variable in a test
//     does not redirect writes already bound to that *os.File;
//   - the concurrency test here asserts an actual per-response correctness
//     invariant under overlapping traffic (never a stale/foreign principal's
//     role), not only "runs clean under -race";
//   - the malformed-input test here exercises several distinct malformed
//     BER shapes, not one;
//   - the oversized-declared-length test here proves the fix in
//     third_party/ldapserver/PATCHES.md by bounding the actual allocation a
//     malicious 6-byte header can provoke, not merely that the server
//     survives it — see that PATCHES.md for the full vulnerability writeup.

// ---- 0. no-deadline partial-body stall ------------------------------------

// TestNewSetsNonzeroReadAndWriteTimeouts is a narrow unit check that New's
// production wiring actually sets both deadline fields on the vendored
// ldapserver.Server, rather than leaving them at their Go zero value (which
// the dependency treats as "no deadline" — see server.go's ReadTimeout/
// WriteTimeout doc comments). This is the one-line assertion the TCP-level
// test below builds on: it proves the exact defect the finding raised
// (deadlines are optional, and nothing ever set them) is fixed.
func TestNewSetsNonzeroReadAndWriteTimeouts(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	srv, err := New(context.Background(), protoConfig(), newFakeVerifier(acct), newFakeRoles(acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.ldapSrv.ReadTimeout == 0 {
		t.Fatalf("ReadTimeout = 0, want nonzero — an unauthenticated client can pin a connection's goroutine/buffer/fd forever in io.ReadFull")
	}
	if srv.ldapSrv.WriteTimeout == 0 {
		t.Fatalf("WriteTimeout = 0, want nonzero — a non-reading client can pin a connection's writer goroutine forever, and block graceful shutdown")
	}
}

// TestAdversarial_StalledPartialBodyReadTimesOutWithoutBlockingShutdown
// proves the fix for the finding that a partial, never-completed message
// body can pin a connection's goroutine, buffer, and file descriptor
// indefinitely: third_party/ldapserver/packet.go's readBytes allocates the
// declared body length up front, then blocks in io.ReadFull waiting for the
// rest of it, and — before this fix — nothing on the production path ever
// set a read deadline to interrupt that wait (see server.go's
// ldapConnReadTimeout/ldapConnWriteTimeout). This drives that exact
// scenario against the real production server over TCP: a valid header
// declaring a body, followed by only part of that body, then silence.
//
// It overrides srv.ldapSrv.ReadTimeout with a short value purely so this
// test completes quickly and deterministically — it still exercises the
// identical mechanism New wires up in production (the vendored
// ldapserver.Server's ReadTimeout field, read by client.serve()'s
// SetReadDeadline call immediately before every ReadPacket), just with a
// smaller bound than the 30s production default.
func TestAdversarial_StalledPartialBodyReadTimesOutWithoutBlockingShutdown(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})

	rootCtx, cancel := context.WithCancel(context.Background())
	srv, err := New(rootCtx, protoConfig(), newFakeVerifier(acct), newFakeRoles(acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.ldapSrv.ReadTimeout = 300 * time.Millisecond
	srv.ldapSrv.WriteTimeout = 5 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	addr := ln.Addr().String()

	// A valid 2-byte header declaring a 64-byte body (0x30 = SEQUENCE,
	// 0x40 = short-form length 64), well under the 64 KiB
	// maxMessageBodyLength cap — this is deliberately NOT the
	// oversized-declared-length case
	// (TestAdversarial_OversizedDeclaredLengthRejectedWithoutBoundedAllocation
	// above, which is rejected before any read is even attempted); it
	// proves the distinct case where the declared length is entirely
	// legitimate but the client just stops sending partway through the
	// body, which readTagAndLength's cap does nothing to prevent.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := raw.Write([]byte{0x30, 0x40}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := raw.Write([]byte{0x02, 0x01, 0x03}); err != nil {
		t.Fatalf("write partial body: %v", err)
	}
	// Deliberately never send the remaining 61 declared-but-undelivered
	// bytes.

	// Without a read deadline, the server's io.ReadFull for this body
	// blocks forever; with one, the connection must be closed once the
	// deadline elapses — proven the same way as the oversized-length test
	// above: a prompt read failure, not a timeout on our own read.
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, readErr := raw.Read(buf)
	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("server never closed the stalled partial-body connection — looks like it is still blocked in io.ReadFull with no read deadline")
	}
	if n != 0 {
		t.Fatalf("expected the server to close the connection without sending any bytes, got %d bytes", n)
	}
	raw.Close()

	// The stalled connection's own goroutine, buffer, and fd must not
	// survive graceful shutdown either — closing only the client-visible
	// half of the connection while leaving the server-side goroutine/wg
	// entry pinned would still fail this.
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}
	select {
	case <-serveErr:
	case <-time.After(3 * time.Second):
		t.Fatalf("Serve never returned after closing the listener")
	}

	stopDone := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("Stop() never returned — the stalled partial-body connection blocked graceful shutdown")
	}
	cancel()
}

// ---- 0b. bounded per-client in-flight requests / write-deadline shutdown --

// rawSimpleBindMessage BER-encodes one complete LDAPv3 simple-Bind
// LDAPMessage envelope, built the same way
// TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak's sendRaw
// helper builds its raw Bind request, factored out here so the two tests
// below can each generate volume (many copies, or many distinct message
// IDs) without duplicating the BER construction.
func rawSimpleBindMessage(messageID int, dn, token string) []byte {
	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, token, "simple"))

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(bindReq)
	return env.Bytes()
}

// rawAbandonMessage BER-encodes one complete AbandonRequest LDAPMessage
// envelope (RFC 4511 §4.11: `AbandonRequest ::= [APPLICATION 16] MessageID`,
// a primitive INTEGER, not a SEQUENCE), with messageID as this envelope's
// own message ID and targetMessageID as the operation being abandoned.
func rawAbandonMessage(messageID, targetMessageID int) []byte {
	abandonReq := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ldapserver.ApplicationAbandonRequest, targetMessageID, "AbandonRequest")

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(abandonReq)
	return env.Bytes()
}

// TestAdversarial_BoundedInFlightGoroutinesPerClient proves the fix
// documented in third_party/ldapserver/PATCHES.md's third item: one client
// connection may not have more than ldapserver.MaxInFlightRequestsPerClient
// ProcessRequestMessage executions concurrently live, however many requests
// it pipelines. It pipelines far more raw Binds than the cap on one
// connection, all sharing a fake verifier blocked on fv.block, and never
// reads a single response.
//
// This counts live goroutines via runtime.NumGoroutine() rather than
// counting handler entries directly (contrast the oversized-length test
// above, which asserts against allocation, not entry): internal/ldap's own
// handleBind holds the connection's single per-connection operation lock
// (session.go) for its entire duration, including the blocked Verify call,
// so only the very first dispatched Bind ever actually reaches the fake
// verifier — every other dispatched one queues on that same lock instead.
// Both are still live, blocked goroutines for as long as fv.block stays
// closed-less, so the total goroutine count attributable to this
// connection's dispatch is a faithful, mechanism-agnostic proxy for how
// many ProcessRequestMessage executions the server actually started —
// without needing a custom, non-serializing handler the way a test written
// directly against third_party/ldapserver could use instead (see that
// package's PATCHES.md for why its own regression tests live here).
func TestAdversarial_BoundedInFlightGoroutinesPerClient(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.block = make(chan struct{}) // never closed: Verify blocks on ctx.Done() alone

	addr, rootCancel, stop := startTestServer(t, fv, newFakeRoles(acct))
	// Registered AFTER startTestServer's own t.Cleanup(stop), so it runs
	// BEFORE that cleanup (t.Cleanup is LIFO, per testing.T.Cleanup's
	// documented order): every one of the up to `total` handlers this test
	// dispatches derives its own per-request context from rootCtx and is
	// blocked either directly on fv.block-or-ctx.Done() (the very first
	// one to acquire the connection's session lock) or on that same lock
	// (every other one) — either way, canceling rootCtx is what lets every
	// one of them unwind (see requestContext/handleBind's
	// `if requestCtx.Err() != nil { return }` short-circuit). Without this
	// registered here, a Fatalf below that skips the explicit rootCancel()
	// call at the bottom of this function would leave every one of those
	// goroutines permanently blocked, and stop()'s Server.Stop() — which
	// waits on exactly this connection's wg — would hang forever.
	// context.CancelFunc is safe to call more than once, so this is
	// redundant-safe with the explicit call on the non-failing path below.
	t.Cleanup(rootCancel)

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	one := rawSimpleBindMessage(1, protoBindDN("alice"), "jwt-alice")

	// Let this connection's own always-present goroutines (the writer, the
	// shutdown-listener) spin up and settle before taking the baseline, so
	// they aren't mistaken for dispatch-attributable goroutines below.
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	before := runtime.NumGoroutine()

	// `extra` is deliberately large relative to the cap (not just cap+a
	// few): each dispatched Bind attributes at least one goroutine
	// (client.go's ProcessRequestMessage wrapper) and in production also a
	// second (requestContext's Message.Done bridging goroutine in
	// server.go), so an uncapped implementation's goroutine count scales
	// with the total pipelined, not with the cap. Making `extra` this much
	// larger than the cap is what makes "bounded near the cap" and "scales
	// with the pipelined total" unmistakably distinguishable, regardless of
	// exactly how many goroutines each dispatched request attributes.
	const extra = 100
	total := ldapserver.MaxInFlightRequestsPerClient + extra
	payload := bytes.Repeat(one, total)
	if _, err := rawConn.Write(payload); err != nil {
		t.Fatalf("write pipelined binds: %v", err)
	}

	var peak int
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if n := runtime.NumGoroutine() - before; n > peak {
			peak = n
		}
	}

	// Lower bound: the cap must still let this many requests actually
	// dispatch (not over-restrict) — true regardless of how many
	// goroutines each dispatched request attributes, since that can only
	// add to the count, never subtract from it.
	if peak < ldapserver.MaxInFlightRequestsPerClient {
		t.Fatalf("goroutines attributable to this connection peaked at %d, want at least %d (MaxInFlightRequestsPerClient) — the cap should still let that many requests dispatch",
			peak, ldapserver.MaxInFlightRequestsPerClient)
	}
	// Upper bound: generous enough to allow several goroutines per
	// dispatched request plus incidental overhead, but far below what
	// scaling with `total` (120) would produce — an unbounded
	// implementation would peak at roughly total, or a multiple of it.
	upperBound := 5 * ldapserver.MaxInFlightRequestsPerClient
	if peak > upperBound {
		t.Fatalf("goroutines attributable to this connection peaked at %d, want at most %d — the %d extra pipelined requests (total %d) should have been backpressured by MaxInFlightRequestsPerClient (%d) instead of each spawning more goroutines",
			peak, upperBound, extra, total, ldapserver.MaxInFlightRequestsPerClient)
	}

	rootCancel()
	stop()
}

// rawSearchMessage BER-encodes one complete LDAPv3 SearchRequest LDAPMessage
// envelope matching handleSearch's exact required shape (base=base,
// scope=wholeSubtree, filter=`(&(objectClass=groupOfNames)(member=memberDN))`),
// built directly rather than through goldapclient.Conn because that client
// runs its own background reader goroutine that continuously drains the
// connection — incompatible with this file's non-reading-client tests,
// which need to control precisely when (and whether) anything is read.
func rawSearchMessage(messageID int, base, memberDN string) []byte {
	equalityFilter := func(attr, value string) *ber.Packet {
		f := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equalityMatch")
		f.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "attributeDesc"))
		f.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "assertionValue"))
		return f
	}
	andFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "and")
	andFilter.AppendChild(equalityFilter("objectClass", "groupOfNames"))
	andFilter.AppendChild(equalityFilter("member", memberDN))

	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "baseObject"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope")) // wholeSubtree
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "derefAliases"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "sizeLimit"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "timeLimit"))
	searchReq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	searchReq.AppendChild(andFilter)
	searchReq.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(searchReq)
	return env.Bytes()
}

// TestAdversarial_WriteDeadlineClosesStalledConnectionAndUnblocksGracefulShutdown
// proves the other half of third_party/ldapserver/PATCHES.md's third item:
// a real non-reading client must have its connection actively closed once
// the server's WriteTimeout elapses, and must not be able to block
// Server.Stop() from completing.
//
// This drives the real production server over TCP with a single very large
// response (one role whose mapped value is 20 MiB, producing one Search
// entry response that large) rather than many small ones, and rather than
// trying to shrink the connection's OS receive buffer: both alternatives
// were tried and found unreliable in practice — shrinking the receive
// buffer via SetReadBuffer does not reliably take effect on every platform,
// and this environment's default buffer comfortably absorbed tens of
// thousands of small pipelined responses without ever stalling. A single
// write far larger than any realistic default buffer size is what reliably
// forces the server's bw.Write/Flush call to genuinely block against an
// unread connection, regardless of the platform's exact buffer sizing.
func TestAdversarial_WriteDeadlineClosesStalledConnectionAndUnblocksGracefulShutdown(t *testing.T) {
	hugeRole := strings.Repeat("x", 20<<20) // 20 MiB — see doc comment above.
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{hugeRole})

	rootCtx, cancel := context.WithCancel(context.Background())
	srv, err := New(rootCtx, protoConfig(), newFakeVerifier(acct), newFakeRoles(acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A short write deadline, overriding the production 30s value purely so
	// this test completes quickly and deterministically — it still
	// exercises the identical mechanism New wires up in production
	// (third_party/ldapserver/client.go's writeMessage), just with a
	// smaller bound.
	srv.ldapSrv.WriteTimeout = 300 * time.Millisecond
	srv.ldapSrv.ReadTimeout = 10 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	addr := ln.Addr().String()

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer rawConn.Close()

	// Bind first, over the same raw connection, and read its (small)
	// response normally — the huge role only appears in the Search
	// response below, so this does not affect the scenario this test is
	// about.
	if _, err := rawConn.Write(rawSimpleBindMessage(1, protoBindDN("alice"), "jwt-alice")); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	bindBuf := make([]byte, 4096)
	if _, err := rawConn.Read(bindBuf); err != nil {
		t.Fatalf("read bind response: %v", err)
	}

	// Issue the Search that will produce the one huge entry response, then
	// deliberately read nothing at all for well past WriteTimeout: any read
	// here, even a small one, could drain enough of the response to mask a
	// genuine stall.
	if _, err := rawConn.Write(rawSearchMessage(2, protoGroupBaseDN, protoBindDN("alice"))); err != nil {
		t.Fatalf("write search: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	// Only now drain whatever is available. A server that is still healthy
	// (bug present) either blocks until our own read deadline below, or
	// eventually delivers the entire ~20 MiB+ response; a server that
	// correctly enforced WriteTimeout instead closes the connection after
	// writing only a small fraction of it, which io.Copy surfaces as a
	// clean EOF (nil error) well before the full size.
	rawConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	total, copyErr := io.Copy(io.Discard, rawConn)
	if copyErr != nil {
		t.Fatalf("expected the server to have closed the connection cleanly (EOF) after its write deadline elapsed, got error instead: %v (bytes drained: %d)", copyErr, total)
	}
	const fullResponseFloor = 20 << 20 // the huge role value alone, ignoring envelope/DN overhead
	const truncatedCeiling = 15 << 20  // generous margin above the buffer this environment was observed to actually admit (~1-2 MiB) and well below fullResponseFloor
	if total >= truncatedCeiling {
		t.Fatalf("drained %d bytes (>= %d) before the connection closed — expected the response to be truncated well short of the full ~%d+ byte entry, proving the server never actually stalled on the write",
			total, truncatedCeiling, fullResponseFloor)
	}

	// The stalled connection must not prevent graceful shutdown.
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}
	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve never returned — the stalled non-reading client appears to have blocked shutdown")
	}

	stopDone := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("Stop() never returned — the stalled non-reading client blocked graceful shutdown (the exact defect PATCHES.md's third item fixes)")
	}
	cancel()

	// A completely independent, fresh connection against the still-running
	// server would be the usual final proof, but the server is already
	// stopped above (proving graceful shutdown is exactly this test's
	// point) — there is deliberately no listener left to dial here.
}

// ---- 1. blocking-verifier cancellation: root cancellation + Stop ----------

// TestAdversarial_ShutdownCancelsBlockedVerifierAndServerTerminates is the
// plan's "Runtime context and cancellation" lifecycle test: start a Bind,
// wait until the fake verifier is blocked in flight, cancel the root/process
// context and invoke Stop, then assert both that the blocked verifier
// observes cancellation AND that the server itself terminates (Serve
// returns) rather than leaving the JWKS/verification operation detached.
func TestAdversarial_ShutdownCancelsBlockedVerifierAndServerTerminates(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed: Verify blocks on ctx.Done() alone
	fv.returned = make(chan error, 1)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	srv, err := New(rootCtx, protoConfig(), fv, newFakeRoles(acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	bindDone := make(chan struct{})
	go func() {
		defer close(bindDone)
		conn, err := goldapclient.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		bindAs(conn, protoBindDN("alice"), "jwt-alice")
	}()

	select {
	case <-fv.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("fake verifier was never entered")
	}

	// Cancel ONLY the root/process context first, deliberately without
	// touching the connection or calling Stop yet. This isolates the
	// invariant this test is actually about — root-context propagation
	// into the in-flight request — from the independent Message.Done
	// (connection-teardown) cancellation path that Stop() would otherwise
	// also trigger and that TestProtocol_ConnectionCloseCancelsInFlightVerify
	// already covers on its own. Conflating the two (as calling Stop()
	// here too would) would let a broken root-context wire-up hide behind
	// Stop()'s independent cancellation and still pass.
	rootCancel()

	select {
	case err := <-fv.returned:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked verifier's Verify returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked verifier never observed root cancellation (with the connection still open and Stop not yet called)")
	}

	// Only now invoke server shutdown, and assert the server itself
	// terminates — Serve must return — not merely that the one already-
	// canceled request was abandoned. A hung Serve here would mean a
	// leaked accept loop/goroutine surviving process shutdown.
	//
	// Close OUR OWN listener reference directly rather than calling
	// srv.Stop() first — see cmd/ch-oauth-ldap/main.go's run() for the full
	// explanation. The vendored vjeantet/ldapserver dependency stores the
	// listener in a plain, unsynchronized struct field, written by the
	// background Serve goroutine and read by Stop with no lock between
	// them; calling Stop() concurrently with that goroutine is a genuine
	// data race. Closing ln here unblocks Serve's Accept() call, and
	// receiving from serveErr below is a channel synchronization point
	// that makes the subsequent srv.Stop() call (still needed for its
	// wg.Wait() graceful-drain semantics) race-free.
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}

	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve never returned after closing the listener: server did not terminate")
	}

	srv.Stop()

	select {
	case <-bindDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("bind goroutine never returned after shutdown")
	}
}

// ---- 2. sentinel log test: capture every output channel -------------------

// captureRealStdout redirects the OS-level stdout file descriptor (not just
// the mutable os.Stdout package variable) to an in-memory pipe for the
// duration of the test, and returns a stop func that restores the original
// fd and returns everything written in the meantime.
//
// This is deliberately more invasive than swapping os.Stdout: the
// dependency's default logger (see logger.go's init()) is
// `log.New(os.Stdout, "", log.LstdFlags)`, constructed once at package-init
// time against the *os.File value os.Stdout held then. Reassigning the
// os.Stdout variable afterward does not change what that already-constructed
// *log.Logger writes to — only redirecting the underlying fd does, because
// os.File.Write ultimately issues a syscall against the numeric fd, and
// dup2'ing a new target onto that fd number changes what "fd 1" resolves to
// for every writer, including one holding an older *os.File value.
func captureRealStdout(t *testing.T) func() string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	stdoutFd := int(os.Stdout.Fd())
	savedFd, err := syscall.Dup(stdoutFd)
	if err != nil {
		t.Fatalf("syscall.Dup(stdout): %v", err)
	}
	if err := syscall.Dup2(int(w.Fd()), stdoutFd); err != nil {
		t.Fatalf("syscall.Dup2: %v", err)
	}

	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(&buf, r)
	}()

	var once sync.Once
	stop := func() string {
		once.Do(func() {
			// Restore the real stdout fd first so nothing else writes into
			// the pipe, then close the write end so the copy goroutine's
			// io.Copy observes EOF and returns.
			_ = syscall.Dup2(savedFd, stdoutFd)
			_ = syscall.Close(savedFd)
			_ = w.Close()
			<-copyDone
			_ = r.Close()
		})
		return buf.String()
	}
	// Safety net: if the test fails/fatals between capture and the explicit
	// stop() call below, this Cleanup still restores the real stdout fd —
	// without it, a redirected fd 1 would silently swallow every other
	// test's output for the rest of this test binary's process, since fd 1
	// is process-global, not per-goroutine.
	t.Cleanup(func() { stop() })

	return stop
}

// explicitFalseControlOID is an arbitrary OID this server does not
// implement, used only by rawSentinelBindWithExplicitFalseControl below —
// its exact value never matters (the server implements no controls of its
// own to distinguish by OID), only that a control element is present at
// all. Named distinctly from any similarly-purposed OID constant that may
// exist elsewhere in this package, since this file must stay self-contained
// within its own declared scope.
const explicitFalseControlOID = "1.2.3.4.5.6.999.9"

// rawSentinelBindWithExplicitFalseControl BER-encodes one complete
// LDAPMessage: messageID + a simple BindRequest(dn, token) + one [0]
// Controls element carrying explicitFalseControlOID with its criticality
// BOOLEAN EXPLICITLY present and set to FALSE.
//
// LDAP's restricted BER (RFC 4511's BOOLEAN encoding note) requires a field
// at its default value to be omitted entirely — an ordinary non-critical
// control (criticality defaults to FALSE) must never encode the BOOLEAN at
// all. Encoding it explicitly anyway is itself malformed:
// third_party/goldap/message/control.go's readComponents reads the BOOLEAN
// whenever its tag is present, and rejects the ENTIRE LDAPMessage with
// "criticality default value FALSE should not be specified" the moment the
// decoded value is false. That decode failure happens entirely inside the
// vendored goldap dependency, invoked from
// third_party/ldapserver/client.go's readMessagePacket loop, before any
// production route handler in this package — including any control-policy
// guard that may sit in front of routing — ever sees the message; see that
// loop's `Logger.Printf("Error reading Message : %s\n\t%x", ...); continue`
// (client.go ~line 299), which is the vendored decode-error logger site
// this helper exists to exercise (plan §5.9/§7.5/§6/§23.6). The loop
// continues to the connection's next request rather than closing it, which
// is why a subsequent valid Bind on the SAME connection must still succeed.
func rawSentinelBindWithExplicitFalseControl(messageID int, dn, token string) []byte {
	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, token, "simple"))

	ctrl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
	ctrl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, explicitFalseControlOID, "controlType"))
	ctrl.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "criticality"))
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	controls.AppendChild(ctrl)

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(bindReq)
	env.AppendChild(controls)
	return env.Bytes()
}

// TestAdversarial_SentinelAbsentFromEveryCapturedOutputChannel binds with a
// unique sentinel JWT/password while capturing BOTH the application zerolog
// writer AND the real OS stdout file descriptor, and asserts the sentinel
// (and the ordinary real password, for the successful-Bind case that most
// plausibly triggers the dependency's own packet-hex logger) appears in
// neither. See captureRealStdout's doc comment for why stdout capture must
// be fd-level to actually prove the dependency's packet logger is disabled.
//
// Extended for phase-5 §5.9/§7.5/§6/§23.6 (do not build a second server
// elsewhere — this is the one production test server every "vendored logger
// stays disabled" proof in the manifest points to): it additionally asserts
// the package-level ldapserver.Logger identity immediately after
// startTestServer's own New() call and again at the very end, and drives a
// third, sentinel-bearing raw connection through the explicit-FALSE
// malformed-control boundary (§7.5) — a hand-encoded Bind whose password is
// the sentinel and whose attached control explicitly encodes BOOLEAN FALSE
// for criticality, which goldap's decoder rejects before any production
// route handler ever runs (see rawSentinelBindWithExplicitFalseControl
// above), exercising the vendored client.go:299 "%x" decode-error
// Logger.Printf — followed by a valid Bind on that SAME connection, which
// must still succeed.
func TestAdversarial_SentinelAbsentFromEveryCapturedOutputChannel(t *testing.T) {
	const sentinelToken = "SENTINEL-ADV-8e21c4f0-do-not-log-me"
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	// (1) DiscardingLogger identity, checked immediately after New (called
	// synchronously inside startTestServer, above) — see server.go's New,
	// which unconditionally reassigns this package-level dependency global
	// before returning.
	if ldapserver.Logger != ldapserver.DiscardingLogger {
		t.Fatalf("ldapserver.Logger != ldapserver.DiscardingLogger immediately after New — the vendored dependency's own packet-hex logger is not disabled")
	}

	var appLog bytes.Buffer
	prevLogger := log.Logger
	log.Logger = zerolog.New(&appLog)
	t.Cleanup(func() { log.Logger = prevLogger })

	stopCapture := captureRealStdout(t)

	// (2) The failing case whose password IS the sentinel: the case most
	// likely to leak, since a naive implementation might log the raw
	// verifier-call arguments on failure.
	conn := dialTest(t, addr)
	requireInvalidCredentials(t, "sentinel bind", bindAs(conn, protoBindDN("alice"), sentinelToken))

	// (3) A successful Bind using the real password, to prove the
	// dependency's own hex-packet logger (client.go's "<<< ... hex=%x" on
	// every inbound message, which necessarily contains the password) is
	// disabled too.
	conn2 := dialTest(t, addr)
	requireSuccess(t, "real bind", bindAs(conn2, protoBindDN("alice"), "jwt-alice"))

	// (4) Explicit-FALSE malformed boundary, on a fresh third connection: a
	// raw Bind whose password is the sentinel and whose attached control
	// explicitly encodes criticality=FALSE. The decode fails before any
	// production handler runs, so no response is ever sent — a bounded read
	// deadline distinguishes that from "the server is still processing it".
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial (explicit-FALSE malformed): %v", err)
	}
	defer rawConn.Close()

	malformed := rawSentinelBindWithExplicitFalseControl(1, protoBindDN("alice"), sentinelToken)
	if _, err := rawConn.Write(malformed); err != nil {
		t.Fatalf("write explicit-FALSE malformed sentinel bind: %v", err)
	}
	rawConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	noRespBuf := make([]byte, 16)
	n, readErr := rawConn.Read(noRespBuf)
	if n != 0 {
		t.Fatalf("got %d unexpected response bytes for the malformed explicit-FALSE message, want none", n)
	}
	if netErr, ok := readErr.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("Read after explicit-FALSE malformed message returned (n=%d, err=%v), want a read-deadline timeout (no response ever sent)", n, readErr)
	}

	// (5) The same connection remains usable: the vendored decoder loops to
	// the next request rather than closing the connection (see
	// rawSentinelBindWithExplicitFalseControl's doc comment) — a subsequent
	// valid Bind on it, reusing this file's own rawSimpleBindMessage helper,
	// must succeed.
	if _, err := rawConn.Write(rawSimpleBindMessage(2, protoBindDN("alice"), "jwt-alice")); err != nil {
		t.Fatalf("write valid bind after explicit-FALSE malformed message: %v", err)
	}
	rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respPkt, err := ber.ReadPacket(rawConn)
	if err != nil {
		t.Fatalf("read bind response after explicit-FALSE malformed message: %v", err)
	}
	if len(respPkt.Children) < 2 || len(respPkt.Children[1].Children) < 1 {
		t.Fatalf("bind response after explicit-FALSE malformed message: malformed packet %+v", respPkt)
	}
	if gotID := respPkt.Children[0].Value.(int64); gotID != 2 {
		t.Fatalf("bind response after explicit-FALSE malformed message: messageID = %d, want 2", gotID)
	}
	if gotTag := respPkt.Children[1].Tag; gotTag != 1 {
		t.Fatalf("bind response after explicit-FALSE malformed message: op tag = %d, want 1 (BindResponse)", gotTag)
	}
	if gotCode := respPkt.Children[1].Children[0].Value.(int64); gotCode != int64(ldapserver.LDAPResultSuccess) {
		t.Fatalf("bind after explicit-FALSE malformed message: resultCode = %d, want %d (success) — same connection must remain usable", gotCode, ldapserver.LDAPResultSuccess)
	}

	stdout := stopCapture()

	// The dependency's own packet logger renders raw packet bytes with
	// "%x" (see client.go's "<<< ... hex=%x"), so a leaked credential shows
	// up there as its hex encoding, not as literal readable text — check
	// both forms in both captured channels.
	sentinelHex := hex.EncodeToString([]byte(sentinelToken))
	passwordHex := hex.EncodeToString([]byte("jwt-alice"))

	if strings.Contains(appLog.String(), sentinelToken) || strings.Contains(stdout, sentinelToken) ||
		strings.Contains(appLog.String(), sentinelHex) || strings.Contains(stdout, sentinelHex) {
		t.Fatalf("sentinel credential leaked into captured output:\napp log:\n%s\nstdout:\n%s", appLog.String(), stdout)
	}
	if strings.Contains(appLog.String(), "jwt-alice") || strings.Contains(stdout, "jwt-alice") ||
		strings.Contains(appLog.String(), passwordHex) || strings.Contains(stdout, passwordHex) {
		t.Fatalf("real bind password leaked into captured output:\napp log:\n%s\nstdout:\n%s", appLog.String(), stdout)
	}

	// (6) The logger identity must still be DiscardingLogger at the end —
	// nothing this test did (including the malformed-decode path, which
	// exercises the vendored Logger.Printf call directly) may have re-armed
	// it.
	if ldapserver.Logger != ldapserver.DiscardingLogger {
		t.Fatalf("ldapserver.Logger != ldapserver.DiscardingLogger at end of test — something re-armed the vendored dependency's packet logger")
	}
}

// ---- 3. alias mutation -----------------------------------------------------

// TestAdversarial_RepeatedAliasMutationNeverAffectsStoredOrFutureSearches
// mutates the resolver-owned role slice repeatedly, interleaved with
// repeated Searches on the already-authenticated connection, and asserts
// every Search response is unaffected throughout — a stronger, multi-step
// version of the single-mutation proof, closing the gap where a defensive
// copy taken once but re-aliased on a later internal read could still leak.
func TestAdversarial_RepeatedAliasMutationNeverAffectsStoredOrFutureSearches(t *testing.T) {
	mutableRoles := []string{"ch_a", "ch_b"}
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", mutableRoles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	mutations := []string{"MUTATED-1", "MUTATED-2", "MUTATED-3"}
	for i, mv := range mutations {
		mutableRoles[0] = mv
		mutableRoles[1] = mv + "-b"

		res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
		if err != nil {
			t.Fatalf("search #%d: %v", i, err)
		}
		for _, e := range res.Entries {
			cn := e.GetAttributeValue("cn")
			if strings.Contains(cn, "MUTATED") {
				t.Fatalf("search #%d after mutation %q: entry cn = %q, leaked resolver-slice mutation", i, mv, cn)
			}
		}
		wantCNs := map[string]bool{protoCNPrefix + "ch_a": true, protoCNPrefix + "ch_b": true}
		if len(res.Entries) != 2 {
			t.Fatalf("search #%d: entries = %d, want 2 (unaffected by aliasing)", i, len(res.Entries))
		}
		for _, e := range res.Entries {
			if !wantCNs[e.GetAttributeValue("cn")] {
				t.Fatalf("search #%d: unexpected entry cn %q", i, e.GetAttributeValue("cn"))
			}
		}
	}
}

// ---- 4. concurrent overlapping traffic -------------------------------------

// TestAdversarial_OverlappingReBindSearchNeverExposesForeignPrincipal
// overlaps re-Bind(A)/re-Bind(B) with Search-for-A/Search-for-B on one
// shared connection, and — rather than only checking the race detector, per
// the plan's requirement for "only legal serialized outcomes" — asserts a
// correctness invariant that holds regardless of interleaving: because
// Search's filter authorization requires the queried member DN to
// structurally equal whatever principal is bound *at the instant of that
// Search*, a successful "membership query for A" response can only ever
// legally carry A's own role, never B's (and vice versa). A stale read of a
// no-longer-current principal is exactly what this would expose. Run this
// package with -race to also catch any unsynchronized access.
func TestAdversarial_OverlappingReBindSearchNeverExposesForeignPrincipal(t *testing.T) {
	alice := account("race-alice", "https://idp.test/", "sub-race-alice", "jwt-race-alice", []string{"ch_race_alice"})
	bob := account("race-bob", "https://idp.test/", "sub-race-bob", "jwt-race-bob", []string{"ch_race_bob"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice, bob), newFakeRoles(alice, bob))

	conn := dialTest(t, addr)
	requireSuccess(t, "initial bind", bindAs(conn, protoBindDN("race-alice"), "jwt-race-alice"))

	// Kept modest, well clear of any connection-lifetime concern, since what
	// this test is proving is the "only legal serialized outcomes" race
	// property below, not message-ID-range behavior — that's covered
	// separately and specifically by
	// TestAdversarial_MessageIDBoundaryPreservesResponseCorrelation, which
	// drives a connection's message ID across exactly the 127/128/129
	// boundary the pinned goldap dependency's BER INTEGER writer used to
	// mis-encode (missing sign-disambiguation padding once a message ID
	// reached the 128-255 range); that defect is now patched locally, see
	// third_party/goldap/PATCHES.md.
	const rounds = 20
	var violations []string
	var violationsMu sync.Mutex
	recordViolation := func(msg string) {
		violationsMu.Lock()
		violations = append(violations, msg)
		violationsMu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			bindAs(conn, protoBindDN("race-bob"), "jwt-race-bob")
			bindAs(conn, protoBindDN("race-alice"), "jwt-race-alice")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("race-alice"), nil)); err == nil {
				for _, e := range res.Entries {
					if cn := e.GetAttributeValue("cn"); cn != protoCNPrefix+"ch_race_alice" {
						recordViolation(fmt.Sprintf("round %d: membership query for alice returned foreign/stale entry cn=%q", i, cn))
					}
				}
			}
			if res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("race-bob"), nil)); err == nil {
				for _, e := range res.Entries {
					if cn := e.GetAttributeValue("cn"); cn != protoCNPrefix+"ch_race_bob" {
						recordViolation(fmt.Sprintf("round %d: membership query for bob returned foreign/stale entry cn=%q", i, cn))
					}
				}
			}
		}
	}()
	wg.Wait()

	if len(violations) > 0 {
		t.Fatalf("%d illegal (non-serialized) outcomes observed, e.g.: %s", len(violations), violations[0])
	}
}

// TestAdversarial_SimultaneousMultiConnectionTrafficStaysIsolated drives many
// independent connections concurrently, each repeatedly Binding and
// Searching as one of two distinct principals, and asserts every single
// connection's Search response is exactly its own principal's role,
// throughout — the plan's "simultaneous multi-connection traffic" case,
// checked for actual correctness rather than only crash/race-safety.
func TestAdversarial_SimultaneousMultiConnectionTrafficStaysIsolated(t *testing.T) {
	alice := account("multi-alice", "https://idp.test/", "sub-multi-alice", "jwt-multi-alice", []string{"ch_multi_alice"})
	bob := account("multi-bob", "https://idp.test/", "sub-multi-bob", "jwt-multi-bob", []string{"ch_multi_bob"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice, bob), newFakeRoles(alice, bob))

	const conns = 8
	const rounds = 15

	var wg sync.WaitGroup
	errCh := make(chan string, conns*rounds)

	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			who := alice
			if i%2 == 1 {
				who = bob
			}
			username := who.result.Principal.Username
			dn := protoBindDN(username)
			wantCN := protoCNPrefix + who.rolesOf[0]

			conn, err := goldapclient.Dial("tcp", addr)
			if err != nil {
				errCh <- fmt.Sprintf("conn %d: dial: %v", i, err)
				return
			}
			defer conn.Close()

			for r := 0; r < rounds; r++ {
				if err := bindAs(conn, dn, who.token); err != nil {
					errCh <- fmt.Sprintf("conn %d round %d: bind: %+v", i, r, err)
					return
				}
				res, err := conn.Search(membershipSearch(protoGroupBaseDN, dn, nil))
				if err != nil {
					errCh <- fmt.Sprintf("conn %d round %d: search: %v", i, r, err)
					return
				}
				if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("cn") != wantCN {
					errCh <- fmt.Sprintf("conn %d round %d: entries = %+v, want exactly [%s]", i, r, res.Entries, wantCN)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
}

// ---- 5. malformed-BER survival ---------------------------------------------

// TestAdversarial_MalformedBERVariantsSurviveThenFreshConnectionWorks
// broadens protocol_test.go's single malformed-BER case to several distinct
// malformed shapes (arbitrary garbage, an invalid/reserved tag, a truncated
// declared-length sequence, a syntactically-valid-but-empty envelope, and a
// truncated Bind-shaped packet), each on its own throwaway raw connection,
// and asserts a fresh, ordinary connection still Binds and Searches
// correctly afterward every time — proving the production handler path
// survives representative malformed input rather than panicking the
// process.
func TestAdversarial_MalformedBERVariantsSurviveThenFreshConnectionWorks(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	payloads := map[string][]byte{
		"arbitrary short garbage":          {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		"invalid/reserved leading tag":     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"truncated long-form declared len": {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		"empty but well-formed sequence":   {0x30, 0x00},
		"truncated bind-shaped envelope":   {0x30, 0x05, 0x02, 0x01, 0x01, 0x60},
	}

	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if _, err := raw.Write(payload); err != nil {
				t.Fatalf("write malformed payload: %v", err)
			}
			raw.Close()

			conn := dialTest(t, addr)
			requireSuccess(t, "bind after "+name, bindAs(conn, protoBindDN("alice"), "jwt-alice"))

			res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
			if err != nil || len(res.Entries) != 1 {
				t.Fatalf("search after %s: res=%+v, err=%v, want the one entry", name, res, err)
			}
		})
	}
}

// TestAdversarial_OversizedDeclaredLengthRejectedWithoutBoundedAllocation
// proves the fix documented in third_party/ldapserver/PATCHES.md: the exact
// 6-byte header used as the "truncated long-form declared len" case above
// (0x30 0x84 0x7f 0xff 0xff 0xff — SEQUENCE, long-form length, decoding to
// 0x7fffffff, ~2 GiB) must be rejected by closing the connection WITHOUT
// ever attempting the advertised allocation, not merely "survived" the way
// the test above only checks. Both the vulnerable and the fixed dependency
// eventually error out on this exact input (the connection has no more
// bytes to satisfy the declared length either way), so a plain
// "did the server return an error" assertion cannot tell them apart; only
// bounding the actual memory the server allocated handling it can. This
// test therefore asserts two things a bounded-allocation fix — and only a
// bounded-allocation fix — produces: the connection is closed promptly
// (never blocked trying to fill a ~2 GiB buffer that will never arrive),
// and total process allocation attributable to handling it stays far below
// what a single such attempt would cost.
func TestAdversarial_OversizedDeclaredLengthRejectedWithoutBoundedAllocation(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	oversizedHeader := []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := raw.Write(oversizedHeader); err != nil {
		t.Fatalf("write oversized header: %v", err)
	}

	// A fixed server rejects the declared length before trying to read the
	// ~2 GiB body it advertised, and closes the connection immediately —
	// it must never sit blocked waiting for bytes that will never arrive.
	// A bounded read deadline distinguishes "server closed it" (read
	// returns promptly, with 0 bytes) from "server is still blocked trying
	// to fill the advertised buffer" (read times out).
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, readErr := raw.Read(buf)
	raw.Close()

	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("server never closed the connection after the oversized declared length (read timed out) — looks like it is still blocked trying to fill the advertised ~2 GiB buffer")
	}
	if n != 0 {
		t.Fatalf("expected the server to close the connection without sending any bytes, got %d bytes", n)
	}

	runtime.ReadMemStats(&after)

	// 8 MiB is generous headroom over third_party/ldapserver's (much
	// smaller, as of this fix) maxMessageBodyLength cap plus ordinary
	// test/runtime allocation noise
	// (goroutine stacks, GC bookkeeping, the client dial itself); the
	// vulnerable code path would have attempted make([]byte, 0x7fffffff)
	// (~2 GiB) here — two orders of magnitude past this budget, so this
	// assertion cannot pass by accident.
	const allocBudget = 8 << 20 // 8 MiB
	if delta := after.TotalAlloc - before.TotalAlloc; delta > allocBudget {
		t.Fatalf("handling the oversized declared length allocated %d bytes (budget %d) — looks like the server attempted the advertised ~2 GiB allocation before rejecting the header", delta, allocBudget)
	}

	// A fresh, ordinary connection must still work correctly afterward —
	// preserving the "survives, then works" proof this test extends.
	conn := dialTest(t, addr)
	requireSuccess(t, "bind after oversized declared length", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("search after oversized declared length: res=%+v, err=%v, want the one entry", res, err)
	}
}

// TestAdversarial_ManyMalformedConnectionsInterleavedWithLegitimateTraffic
// opens a burst of malformed raw connections concurrently with ordinary
// Bind/Search traffic on separate legitimate connections, and asserts every
// legitimate connection still completes correctly — a fresh valid connection
// surviving malformed input is not sufficient evidence if concurrent
// malformed input could still corrupt shared server-level state (the accept
// loop, the handler-source, or process-wide data); this drives both at once
// under the race detector.
func TestAdversarial_ManyMalformedConnectionsInterleavedWithLegitimateTraffic(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				continue
			}
			_, _ = raw.Write([]byte{0x30, 0x7f, byte(i), 0xff, 0xff})
			raw.Close()
		}
	}()

	errCh := make(chan string, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := goldapclient.Dial("tcp", addr)
			if err != nil {
				errCh <- fmt.Sprintf("legit conn %d: dial: %v", i, err)
				return
			}
			defer conn.Close()
			if err := bindAs(conn, protoBindDN("alice"), "jwt-alice"); err != nil {
				errCh <- fmt.Sprintf("legit conn %d: bind: %+v", i, err)
				return
			}
			res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
			if err != nil || len(res.Entries) != 1 {
				errCh <- fmt.Sprintf("legit conn %d: search res=%+v err=%v", i, res, err)
			}
		}(i)
	}

	wg.Wait()

	// Give the server's own accept loop a moment to fully settle every
	// connection this test fired at it (including the malformed ones,
	// which this test's own goroutine only waits for on the *client* side
	// — closing a raw net.Conn does not wait for the server's
	// corresponding accept/registration to finish). Without this, the
	// server can still be mid-accept for a connection this test dialed
	// when the surrounding t.Cleanup(stop) below fires Stop() — the exact
	// window a sync.WaitGroup Add()-after-Wait() misuse in the pinned
	// vjeantet/ldapserver dependency's own Server.Stop()/serve() turns
	// into a real, independently-confirmed data race (Server.Stop() calls
	// s.wg.Wait() while Server.serve()'s accept loop can still be about to
	// call s.wg.Add(1) for a connection already queued in the OS backlog —
	// undefined for sync.WaitGroup — observed racing against this
	// package's own ldapserver.Logger assignment in New()). This sleep
	// only reduces how often this test's own connection burst lands in
	// that pre-existing dependency window; it does not paper over
	// anything wrong in this test's own assertions, and no production file
	// changes.
	time.Sleep(100 * time.Millisecond)

	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
}

// ---- 6. message ID boundary correlation -------------------------------------

// TestAdversarial_MessageIDBoundaryPreservesResponseCorrelation drives one
// real, long-lived TCP connection's message ID sequence across exactly
// 127/128/129 — the boundary the pinned goldap dependency's generic BER
// INTEGER writer used to mis-encode (a value >= 128 needs a leading
// sign-disambiguation 0x00 byte to stay positive; the unpatched writer
// omitted it, so message ID 128 went out as `02 01 80`, which decodes back
// as -128, desynchronizing every response after it from its request) — and
// asserts every response in that range still correlates correctly. This is
// what third_party/goldap/PATCHES.md item 1 fixes; adversarial_test.go's
// TestAdversarial_OverlappingReBindSearchNeverExposesForeignPrincipal and
// protocol_test.go's TestProtocol_ConcurrentReBindAndSearchRace both
// deliberately stay under 128 total messages because, before this fix, this
// exact boundary would have made them flaky for a reason unrelated to what
// they're proving.
//
// go-ldap/v3's Conn assigns message IDs sequentially starting at 1 for the
// very first request issued on a connection (see conn.go's processMessages:
// `var messageID int64 = 1`, incremented once per dispatched request,
// covering every operation type on that connection — Bind included). The
// initial Bind below is message 1; the 125 warm-up Searches that follow
// consume messages 2 through 126; the three Searches after that are
// messages 127, 128 and 129 exactly.
func TestAdversarial_MessageIDBoundaryPreservesResponseCorrelation(t *testing.T) {
	acct := account("mid-alice", "https://idp.test/", "sub-mid-alice", "jwt-mid-alice", []string{"ch_mid"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	// Without this, a response desynchronized by the pre-fix bug would hang
	// the affected request until the test binary's own overall timeout
	// instead of failing promptly with a clear cause.
	conn.SetTimeout(5 * time.Second)

	requireSuccess(t, "bind (messageID 1)", bindAs(conn, protoBindDN("mid-alice"), "jwt-mid-alice"))

	const warmupRounds = 125 // consumes messageIDs 2..126
	for i := 0; i < warmupRounds; i++ {
		if _, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("mid-alice"), nil)); err != nil {
			t.Fatalf("warm-up search #%d (messageID %d): %v", i, i+2, err)
		}
	}

	for _, id := range []int{127, 128, 129} {
		res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("mid-alice"), nil))
		if err != nil {
			t.Fatalf("search at messageID %d: %v (response/request desynchronized?)", id, err)
		}
		if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("cn") != protoCNPrefix+"ch_mid" {
			t.Fatalf("search at messageID %d: entries = %+v, want exactly one clickhouse_ch_mid entry", id, res.Entries)
		}
	}
}

// ---- Cancel (RFC 3909) carve-out proof -------------------------------------

// rfc3909CancelValue mirrors the vendored vjeantet/ldapserver dependency's
// own (unexported) cancelRequestValue ASN.1 shape from its cancel.go:
// cancelRequestValue ::= SEQUENCE { cancelID MessageID }. This test builds
// the raw wire bytes itself (rather than driving a handler function
// directly) so it exercises the real dependency-internal Cancel handling
// this package never sees — see unsupported.go's handleNotFound doc comment
// for why Cancel bypasses this package's own fail-closed
// Extended-operation handling entirely.
type rfc3909CancelValue struct {
	CancelID int
}

// cancelRequestValuePacket BER-encodes an RFC 3909 Cancel requestValue as
// the [CONTEXT 1] primitive octet string goldap/ldapserver expects.
func cancelRequestValuePacket(messageID int) *ber.Packet {
	data, _ := asn1.Marshal(rfc3909CancelValue{CancelID: messageID})
	pkt := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "requestValue")
	pkt.Value = data
	pkt.Data.Write(data)
	return pkt
}

// TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak proves, over
// the real production server and a real TCP connection, the benign-carve-out
// claim documented on handleNotFound: the RFC 3909 Cancel
// Extended operation (OID 1.3.6.1.1.8) — served entirely inside the vendored
// vjeantet/ldapserver dependency, never reaching this package's own
// fail-closed catch-all — cannot cancel an in-flight Bind (the one operation
// that carries credential material) and cannot disclose or corrupt anything
// this package owns. This is checked against the real dependency behavior,
// not merely inferred from reading cancel.go.
func TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed until this test explicitly does so
	fv.returned = make(chan error, 1)

	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	// ---- (a) Cancel of a message ID that was never issued fails closed,
	// with no side effect beyond the fixed protocol error. ----
	t.Run("NonexistentTargetGetsNoSuchOperation", func(t *testing.T) {
		conn := dialTest(t, addr)
		req := goldapclient.NewExtendedRequest("1.3.6.1.1.8", cancelRequestValuePacket(999999))
		_, err := conn.Extended(req)
		ldapErr := asLDAPError(err)
		if ldapErr == nil {
			t.Fatalf("cancel of nonexistent operation: got success, want NoSuchOperation")
		}
		if int(ldapErr.ResultCode) != ldapserver.LDAPResultNoSuchOperation {
			t.Fatalf("cancel of nonexistent operation: ResultCode = %d, want %d (NoSuchOperation)",
				ldapErr.ResultCode, ldapserver.LDAPResultNoSuchOperation)
		}
	})

	// ---- (b) Cancel targeting an in-flight Bind on the SAME connection
	// must not abort it: the dependency's handleCancel explicitly refuses
	// Bind targets (LDAPResultCannotCancel), and the blocked Bind must go on
	// to complete normally once unblocked. ----
	t.Run("CannotAbortInFlightBindWhichThenSucceeds", func(t *testing.T) {
		rawConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("raw dial: %v", err)
		}
		defer rawConn.Close()

		sendRaw := func(messageID int, appPacket *ber.Packet) {
			env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
			env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
			env.AppendChild(appPacket)
			if _, err := rawConn.Write(env.Bytes()); err != nil {
				t.Fatalf("write message %d: %v", messageID, err)
			}
		}

		// 1. Simple Bind (messageID=1) as alice with the correct token. The
		// production handler calls fv.Verify, which blocks on fv.block, so
		// this request stays registered on the connection's own
		// requestList — in flight — until this test unblocks it below.
		bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
		bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
		bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, protoBindDN("alice"), "name"))
		bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "jwt-alice", "simple"))
		sendRaw(1, bindReq)

		select {
		case <-fv.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("fake verifier was never entered — Bind never went in flight")
		}

		// 2. Cancel Extended request (messageID=2) targeting the in-flight
		// Bind's message ID (1), on the SAME connection.
		extReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 23, nil, "ExtendedRequest")
		extReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.1.8", "requestName"))
		extReq.AppendChild(cancelRequestValuePacket(1))
		sendRaw(2, extReq)

		// 3. The Cancel response must arrive first (the Bind is still
		// blocked) and must be CannotCancel, not Canceled/Success — proving
		// the dependency's Bind-target refusal is real, not theoretical.
		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		cancelPkt, err := ber.ReadPacket(rawConn)
		if err != nil {
			t.Fatalf("read cancel response: %v", err)
		}
		if len(cancelPkt.Children) < 2 || len(cancelPkt.Children[1].Children) < 1 {
			t.Fatalf("cancel response: malformed packet %+v", cancelPkt)
		}
		if gotID := cancelPkt.Children[0].Value.(int64); gotID != 2 {
			t.Fatalf("first response messageID = %d, want 2 (Cancel) — Bind must still be blocked", gotID)
		}
		if gotTag := cancelPkt.Children[1].Tag; gotTag != 24 {
			t.Fatalf("first response op tag = %d, want 24 (ExtendedResponse)", gotTag)
		}
		if gotCode := cancelPkt.Children[1].Children[0].Value.(int64); gotCode != int64(ldapserver.LDAPResultCannotCancel) {
			t.Fatalf("cancel response resultCode = %d, want %d (CannotCancel)", gotCode, ldapserver.LDAPResultCannotCancel)
		}

		// 4. Now unblock the Bind's Verify call. If Cancel had actually
		// aborted it, the Bind would never complete (or would complete as a
		// failure/abandonment) instead of succeeding normally.
		close(fv.block)

		select {
		case err := <-fv.returned:
			if err != nil {
				t.Fatalf("verifier's Verify returned %v after Cancel attempt, want nil (unaffected)", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("blocked verifier never returned after unblocking")
		}

		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		bindPkt, err := ber.ReadPacket(rawConn)
		if err != nil {
			t.Fatalf("read bind response: %v", err)
		}
		if len(bindPkt.Children) < 2 || len(bindPkt.Children[1].Children) < 1 {
			t.Fatalf("bind response: malformed packet %+v", bindPkt)
		}
		if gotID := bindPkt.Children[0].Value.(int64); gotID != 1 {
			t.Fatalf("second response messageID = %d, want 1 (Bind)", gotID)
		}
		if gotTag := bindPkt.Children[1].Tag; gotTag != 1 {
			t.Fatalf("second response op tag = %d, want 1 (BindResponse)", gotTag)
		}
		if gotCode := bindPkt.Children[1].Children[0].Value.(int64); gotCode != int64(ldapserver.LDAPResultSuccess) {
			t.Fatalf("bind resultCode = %d, want %d (Success) — Cancel must not have aborted the Bind", gotCode, ldapserver.LDAPResultSuccess)
		}

		if fv.callCount() != 1 {
			t.Fatalf("verifier calls = %d, want exactly 1 — Cancel must not have triggered a retry/side effect", fv.callCount())
		}

		// 5. No leakage: nothing about the credential or the cancel attempt
		// should have reached a fresh, unrelated connection's state, and the
		// server must still be healthy for ordinary traffic afterward.
		fresh := dialTest(t, addr)
		requireSuccess(t, "bind on fresh connection after cancel attempt", bindAs(fresh, protoBindDN("alice"), "jwt-alice"))
	})
}

// ---- 7. fragmented message body reassembly ---------------------------------

// TestAdversarial_FragmentedMessageBodyStillProcessedCorrectly proves the fix
// documented in third_party/ldapserver/PATCHES.md's second item: a message
// body delivered to the real production server across several separate
// small writes (ordinary TCP fragmentation, not malicious input) must still
// be reassembled and processed correctly, instead of being silently
// truncated into a header-only, no-error packet the way the pre-fix
// readBytes (a single conn.Read call) plus readLdapMessageBytes (which
// discarded readBytes' return values entirely) used to do.
//
// Genuine OS-level TCP segmentation cannot be reliably forced from a
// loopback test — the kernel is free to coalesce small, closely-spaced
// writes into a single segment, and often does on loopback. What this test
// does instead is the standard, practical approximation: write one complete,
// valid LDAP Bind message's raw bytes to the real server in several small
// net.Conn.Write calls with a short sleep between each. That reliably
// encourages (though cannot strictly guarantee) the server's bufio.Reader to
// observe more than one underlying Read while assembling the message body —
// exactly the condition the pre-fix readBytes assumed could never happen.
// This is a known, accepted limitation of testing this class of bug without
// a raw packet-capture-level harness; the assertions below still fail
// loudly (rather than passing vacuously) if the OS happens to coalesce the
// writes, because in that case the pre-fix code would have worked too — the
// real regression-proof value here is that this test would have reliably
// failed against the pre-fix code in ordinary local test runs.
func TestAdversarial_FragmentedMessageBodyStillProcessedCorrectly(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	// Build one complete, valid Bind message's raw wire bytes exactly the
	// way TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak's
	// sendRaw helper does, but here we need the encoded bytes themselves
	// (to slice and fragment) rather than a single Write.
	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, protoBindDN("alice"), "name"))
	bindReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "jwt-alice", "simple"))

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "messageID"))
	env.AppendChild(bindReq)
	raw := env.Bytes()

	const chunkSize = 3
	if len(raw) < chunkSize*4 {
		t.Fatalf("test fixture message too short to fragment meaningfully: %d bytes", len(raw))
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Write the whole message in small, non-BER-boundary-aligned chunks
	// with a short pause between each, instead of one single Write.
	for i := 0; i < len(raw); i += chunkSize {
		end := i + chunkSize
		if end > len(raw) {
			end = len(raw)
		}
		if _, err := conn.Write(raw[i:end]); err != nil {
			t.Fatalf("fragmented write [%d:%d]: %v", i, end, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respPkt, err := ber.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read bind response: %v (fragmented message body was not reassembled correctly)", err)
	}
	if len(respPkt.Children) < 2 || len(respPkt.Children[1].Children) < 1 {
		t.Fatalf("bind response: malformed packet %+v", respPkt)
	}
	if gotID := respPkt.Children[0].Value.(int64); gotID != 1 {
		t.Fatalf("response messageID = %d, want 1", gotID)
	}
	if gotTag := respPkt.Children[1].Tag; gotTag != 1 {
		t.Fatalf("response op tag = %d, want 1 (BindResponse)", gotTag)
	}
	if gotCode := respPkt.Children[1].Children[0].Value.(int64); gotCode != int64(ldapserver.LDAPResultSuccess) {
		t.Fatalf("bind resultCode = %d, want %d (Success) — fragmented message body was not reassembled correctly",
			gotCode, ldapserver.LDAPResultSuccess)
	}

	// The connection, and the server, must remain fully usable afterward: a
	// fresh, ordinary client-driven Bind+Search proves the fragmented
	// request left no shared server-level state corrupted.
	fresh := dialTest(t, addr)
	requireSuccess(t, "bind on fresh connection after fragmented bind", bindAs(fresh, protoBindDN("alice"), "jwt-alice"))
	res, err := fresh.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("search after fragmented-bind test: res=%+v, err=%v, want the one entry", res, err)
	}
}

// ---- 8. aggregate cross-connection memory bound (review pass 3) -----------

// TestAdversarial_ConcurrentMaxLengthStalledConnectionsAreBounded proves the
// fix for the P1 finding that aggregate pre-auth memory across connections
// was unbounded: third_party/ldapserver/packet.go's maxMessageBodyLength
// bounds a single connection's declared body length, and server.go's
// ReadTimeout (wired by New) bounds how long any ONE connection may hold
// that buffer, but before this fix nothing bounded how many connections
// could do this AT ONCE — server.go's serve() accept loop had no cap on
// concurrent accepted connections. This drives exactly the attack the
// finding described: many concurrent sockets, each sending only a 5-byte
// header declaring a body AT the maxMessageBodyLength cap and then nothing
// further, and asserts both that a burst within the new MaxConnections cap
// behaves the way the existing single-connection
// TestAdversarial_OversizedDeclaredLengthRejectedWithoutBoundedAllocation
// proves, and that every connection beyond the cap is rejected immediately
// — closed with no bytes ever sent back — rather than accepted and allowed
// to allocate its own body buffer too.
//
// It overrides srv.ldapSrv.MaxConnections to a small value purely so this
// test completes quickly and deterministically with a handful of real
// sockets — it still exercises the identical mechanism New wires into
// production (third_party/ldapserver/server.go's serve() accept loop).
func TestAdversarial_ConcurrentMaxLengthStalledConnectionsAreBounded(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(rootCtx, protoConfig(), newFakeVerifier(acct), newFakeRoles(acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const maxConnections = 4
	srv.ldapSrv.MaxConnections = maxConnections
	srv.ldapSrv.ReadTimeout = 5 * time.Second
	srv.ldapSrv.WriteTimeout = 5 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	addr := ln.Addr().String()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-serveErr:
		case <-time.After(3 * time.Second):
		}
		stopDone := make(chan struct{})
		go func() { srv.Stop(); close(stopDone) }()
		select {
		case <-stopDone:
		case <-time.After(3 * time.Second):
		}
	})

	// 0x30 0x83 0x01 0x00 0x00: SEQUENCE, long-form length (3 length
	// bytes), decoding to 0x010000 = 65536 — third_party/ldapserver's
	// current maxMessageBodyLength cap exactly (AT the cap passes the
	// packet.go "> cap" check, the same way the finding's own
	// "30 83 10 00 00" example header was AT the pre-fix 1 MiB cap). Every
	// dialed connection below sends only this 5-byte header, then nothing
	// — enough, pre-fix, to make readBytes attempt a 65536-byte allocation
	// per connection and then block forever in io.ReadFull, with no cap on
	// how many connections could do it at once.
	const perConnBodyBudget = 65536
	atCapHeader := []byte{0x30, 0x83, 0x01, 0x00, 0x00}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	within := make([]net.Conn, 0, maxConnections)
	for i := 0; i < maxConnections; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial within-cap %d: %v", i, err)
		}
		t.Cleanup(func() { c.Close() })
		if _, err := c.Write(atCapHeader); err != nil {
			t.Fatalf("write at-cap header %d: %v", i, err)
		}
		within = append(within, c)
	}

	// Give the server time to have read every header and allocated its
	// per-connection body buffer before measuring — isolated from the
	// over-cap assertion below, so a failure here specifically means "an
	// at-cap-but-within-the-connection-limit burst costs more than
	// expected", not "the connection limit itself doesn't work".
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	var afterWithinCap runtime.MemStats
	runtime.ReadMemStats(&afterWithinCap)

	// Generous headroom over maxConnections*perConnBodyBudget for goroutine
	// stacks, GC bookkeeping, and the dials themselves.
	withinCapBudget := uint64(maxConnections*perConnBodyBudget) + 4<<20
	if delta := afterWithinCap.TotalAlloc - before.TotalAlloc; delta > withinCapBudget {
		t.Fatalf("handling %d at-cap stalled connections allocated %d bytes (budget %d)", maxConnections, delta, withinCapBudget)
	}

	// Now exceed the connection cap: every one of these must be rejected —
	// connection closed immediately, no bytes exchanged, no body buffer
	// allocated for it — proving the process-wide MaxConnections limit
	// itself, distinct from the per-message cap proven above.
	const extraOverCap = 3
	overCap := make([]net.Conn, 0, extraOverCap)
	for i := 0; i < extraOverCap; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial over-cap %d: %v", i, err)
		}
		t.Cleanup(func() { c.Close() })
		overCap = append(overCap, c)

		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, readErr := c.Read(buf)
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatalf("over-cap connection %d was never rejected (read timed out) — the process-wide MaxConnections cap does not appear to be enforced", i)
		}
		if n != 0 {
			t.Fatalf("over-cap connection %d: got %d bytes, want the connection closed with none", i, n)
		}
	}

	runtime.GC()
	var afterOverCap runtime.MemStats
	runtime.ReadMemStats(&afterOverCap)

	// If MaxConnections were not enforced, each of the extraOverCap
	// connections would additionally have been accepted and allocated its
	// own perConnBodyBudget-sized buffer; assert the total stayed close to
	// the within-cap figure instead.
	overCapBudget := withinCapBudget + 1<<20
	if delta := afterOverCap.TotalAlloc - before.TotalAlloc; delta > overCapBudget {
		t.Fatalf("total allocation after dialing %d over-cap connections was %d bytes (budget %d) — looks like the process-wide MaxConnections cap let them allocate their own body buffers too", extraOverCap, delta, overCapBudget)
	}

	// Free the within-cap slots, then prove a fresh connection is accepted
	// and works correctly again once a slot is available.
	for _, c := range within {
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)

	conn := dialTest(t, addr)
	requireSuccess(t, "bind after connection-cap burst", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("search after connection-cap burst: res=%+v, err=%v, want the one entry", res, err)
	}
}

// ---- 9. Abandon/Cancel starvation behind saturated ordinary work ----------

// saturateOrdinaryWorkSlots pipelines exactly
// ldapserver.MaxInFlightRequestsPerClient raw simple-Bind messages over
// rawConn, all sharing fv (whose fv.block must already be a never-closed
// channel), and blocks until the first has definitely entered the fake
// verifier. Internal/ldap's own handleBind holds the connection's single
// per-connection session lock for its entire duration (see
// TestAdversarial_BoundedInFlightGoroutinesPerClient's doc), so only that
// first dispatched Bind ever actually reaches fv.Verify; every other one
// queues behind that same lock instead — both are still live, blocked
// ProcessRequestMessage executions occupying one of the connection's
// MaxInFlightRequestsPerClient slots, which is what "saturated" means here.
// None of them ever completes on their own, because fv.block is never
// closed — only canceling their context (directly, via Abandon, or via
// requestList's client.close() broadcast) unblocks any of them.
func saturateOrdinaryWorkSlots(t *testing.T, rawConn net.Conn, fv *fakeVerifier) {
	t.Helper()

	for i := 1; i <= ldapserver.MaxInFlightRequestsPerClient; i++ {
		if _, err := rawConn.Write(rawSimpleBindMessage(i, protoBindDN("alice"), "jwt-alice")); err != nil {
			t.Fatalf("write saturating bind %d: %v", i, err)
		}
	}
	select {
	case <-fv.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("fake verifier was never entered — saturating binds never dispatched")
	}
	// Give the read loop time to have read and dispatched (acquired an
	// ordinary-work slot for) every one of the MaxInFlightRequestsPerClient
	// pipelined Binds above, not just the first.
	time.Sleep(200 * time.Millisecond)
}

// TestAdversarial_AbandonRunsPromptlyDespiteSaturatedOrdinaryWork proves the
// fix documented in third_party/ldapserver/PATCHES.md's fifth item: Abandon
// dispatches against its own dedicated capacity
// (MaxInFlightControlOperationsPerClient), not the ordinary-work semaphore.
// It saturates every ordinary-work slot on one connection with Binds that
// can never complete on their own (fv.block is never closed), then sends an
// Abandon targeting every one of those saturating message IDs and asserts
// the verifier's Verify call returns promptly with context.Canceled — proof
// some Abandon actually ran, not merely that the connection survived.
// Before the fix this would deadlock: an Abandon message would itself queue
// behind the same exhausted MaxInFlightRequestsPerClient semaphore that
// will never free a slot within this test (fv.block stays open), so
// fv.returned would never fire and this test would time out.
//
// Abandon targets every saturating message ID (1..MaxInFlightRequestsPerClient),
// not just messageID 1, deliberately: which of those N pipelined Binds is
// the one that actually wins internal/ldap's per-connection session-lock
// race and ends up blocked inside fv.Verify is NOT determined by dispatch
// order. saturateOrdinaryWorkSlots's own doc explains why only one Bind
// ever reaches Verify (the rest queue behind handleBind's session.Lock()),
// but session.Lock() is a plain sync.Mutex, and Go's Mutex fast path allows
// an arriving goroutine to barge ahead of goroutines that have been
// waiting for less than ~1ms — it makes no FIFO promise between the N
// goroutines client.go's read loop spawns (in message-ID order) to run
// ProcessRequestMessage for each pipelined Bind. Under -race, scheduling
// perturbation makes a non-messageID-1 winner materially more likely,
// which is what an earlier version of this test (assuming messageID 1
// always wins) intermittently hit: Abandon(1) would land on a Bind that
// was never in Verify to begin with (still queued on the mutex, its
// context cancellation is checked only once it acquires the lock — see
// bind.go's requestCtx.Err() guard — so it never unblocks the actual
// winner), and fv.returned would never fire. Targeting every saturating ID
// guarantees the real winner (whichever numeric ID it turns out to be)
// gets its Abandon.
func TestAdversarial_AbandonRunsPromptlyDespiteSaturatedOrdinaryWork(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed by this test
	fv.returned = make(chan error, 1)

	addr, rootCancel, _ := startTestServer(t, fv, newFakeRoles(acct))
	// LIFO: rootCancel runs before startTestServer's own registered stop(),
	// unblocking every still-queued Bind so Server.Stop()'s wg.Wait() does
	// not hang on this test's own cleanup.
	t.Cleanup(rootCancel)

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	saturateOrdinaryWorkSlots(t, rawConn, fv)

	// Abandon every saturating message ID — see the doc comment above for
	// why the winner of the session-lock race cannot be assumed to be
	// messageID 1. Each Abandon envelope needs its own messageID, distinct
	// from the 1..N range it targets.
	for target := 1; target <= ldapserver.MaxInFlightRequestsPerClient; target++ {
		abandonMessageID := ldapserver.MaxInFlightRequestsPerClient + target
		if _, err := rawConn.Write(rawAbandonMessage(abandonMessageID, target)); err != nil {
			t.Fatalf("write abandon for target %d: %v", target, err)
		}
	}

	select {
	case err := <-fv.returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("verifier's Verify returned %v after Abandon under saturation, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Abandon never ran while ordinary-work slots were saturated — the blocked Bind's Verify call never observed cancellation")
	}
}

// TestAdversarial_CancelRunsPromptlyDespiteSaturatedOrdinaryWork is
// TestAdversarial_AbandonRunsPromptlyDespiteSaturatedOrdinaryWork's Cancel
// counterpart. cancel.go's handleCancel explicitly refuses a Bind target
// (LDAPResultCannotCancel — see
// TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak), so this
// does not prove the target Bind was aborted; it proves the Cancel
// operation itself was DISPATCHED and produced its response promptly
// despite every ordinary-work slot being saturated by Binds that (unlike
// that other test) never get unblocked here, since fv.block stays open for
// this entire test. Before the fix this would deadlock exactly like the
// Abandon case: the Cancel would itself queue behind the exhausted
// MaxInFlightRequestsPerClient semaphore, which nothing in this test would
// ever free, so the response read below would time out.
func TestAdversarial_CancelRunsPromptlyDespiteSaturatedOrdinaryWork(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed by this test
	fv.returned = make(chan error, 1)

	addr, rootCancel, _ := startTestServer(t, fv, newFakeRoles(acct))
	t.Cleanup(rootCancel)

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	saturateOrdinaryWorkSlots(t, rawConn, fv)

	cancelMessageID := ldapserver.MaxInFlightRequestsPerClient + 1
	extReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 23, nil, "ExtendedRequest")
	extReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.1.8", "requestName"))
	extReq.AppendChild(cancelRequestValuePacket(1))
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cancelMessageID, "messageID"))
	env.AppendChild(extReq)
	if _, err := rawConn.Write(env.Bytes()); err != nil {
		t.Fatalf("write cancel: %v", err)
	}

	// The only response that can ever arrive on this connection during this
	// test is the Cancel's own (every Bind is permanently blocked, since
	// fv.block never closes) — a prompt read here, despite full ordinary-
	// work saturation, is exactly what a deadlocked-behind-the-semaphore
	// Cancel could not produce.
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	pkt, err := ber.ReadPacket(rawConn)
	if err != nil {
		t.Fatalf("read cancel response: %v (Cancel never ran while ordinary-work slots were saturated)", err)
	}
	if len(pkt.Children) < 2 || len(pkt.Children[1].Children) < 1 {
		t.Fatalf("cancel response: malformed packet %+v", pkt)
	}
	if gotID := pkt.Children[0].Value.(int64); gotID != int64(cancelMessageID) {
		t.Fatalf("response messageID = %d, want %d (Cancel)", gotID, cancelMessageID)
	}
	if gotTag := pkt.Children[1].Tag; gotTag != 24 {
		t.Fatalf("response op tag = %d, want 24 (ExtendedResponse)", gotTag)
	}
	if gotCode := pkt.Children[1].Children[0].Value.(int64); gotCode != int64(ldapserver.LDAPResultCannotCancel) {
		t.Fatalf("cancel response resultCode = %d, want %d (CannotCancel, since the target is a Bind)", gotCode, ldapserver.LDAPResultCannotCancel)
	}
}

// TestAdversarial_ConnectionCloseDetectedPromptlyAfterControlOpDespiteSaturation
// proves the read-loop-stall half of the same fix: before it, the read loop
// dispatching an already-decoded Abandon/Cancel message had to acquire an
// ordinary-work slot first, so while every slot was saturated the loop
// could not get back to ReadPacket to notice a subsequent peer disconnect
// either. This saturates one connection's ordinary-work slots exactly as
// the two tests above do, sends an Abandon (now dispatched against its own
// capacity, never blocking the read loop), immediately closes the raw
// connection with no further reads or writes, and asserts the goroutines
// attributable to this connection drop back near their pre-saturation
// baseline promptly — only possible if the server actually noticed the
// close and ran client.close()'s cleanup (which broadcasts an Abandon
// signal to every request still registered on the connection, canceling
// each one's context; internal/ldap's handleBind checks that context
// immediately after acquiring the session lock and returns without ever
// calling Verify, so the remaining queued Binds unwind in a rapid cascade).
// Before the fix, this connection's read loop would still be stuck
// acquiring an ordinary-work slot for message 21 — a slot nothing in this
// test ever frees, since fv.block stays open — so none of that cleanup
// would run within this test's short window at all.
func TestAdversarial_ConnectionCloseDetectedPromptlyAfterControlOpDespiteSaturation(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed by this test

	addr, rootCancel, _ := startTestServer(t, fv, newFakeRoles(acct))
	t.Cleanup(rootCancel)

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	before := runtime.NumGoroutine()

	saturateOrdinaryWorkSlots(t, rawConn, fv)

	if _, err := rawConn.Write(rawAbandonMessage(ldapserver.MaxInFlightRequestsPerClient+1, 1)); err != nil {
		t.Fatalf("write abandon: %v", err)
	}
	if err := rawConn.Close(); err != nil {
		t.Fatalf("close raw connection: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var attributable int
	for time.Now().Before(deadline) {
		runtime.GC()
		attributable = runtime.NumGoroutine() - before
		if attributable <= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if attributable > 2 {
		t.Fatalf("goroutines attributable to this connection still elevated at %d, %v after closing it post-Abandon under saturation — looks like the read loop never noticed the disconnect (still stuck acquiring an ordinary-work slot)", attributable, 3*time.Second)
	}
}
