package ldap

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers plan-19p5 §14/§6's "Unbind/close mid-Search" gap: Unbind
// arriving while a Search is still emitting entries, and an abrupt TCP close
// during that same window. It reuses protocol_test.go's
// account/newFakeVerifier/newFakeRoles/protoConfig/protoBindDN/dialTest/
// bindAs/requireSuccess fixtures, adversarial_test.go's
// rawSimpleBindMessage/rawSearchMessage raw-BER encoders, and
// hostile_dn_test.go's readRawEnvelope/bindResponseFields/swapAppLog/
// requireNoLeak; no existing file is modified.
//
// Pacing mechanism (deliberately NOT a custom slow ResponseWriter): the
// vendored client.go's per-client response channel (chanOut) is
// unbuffered, and every handler write to it is only actually consumed once
// the single per-client writer goroutine's own blocking bw.Write/Flush call
// to the real socket returns. This package's own handleSearch
// (internal/ldap/search.go) holds the connection's session lock for its
// entire entry-emission loop and never re-checks context cancellation
// inside that loop, so a test client that stops reading immediately after
// issuing Search drives the server into a blocked write once accumulated
// unread response bytes exceed the OS socket buffers, at which point the
// server's own WriteTimeout (or, in the abrupt-close variant below, an
// immediate write error from the closed peer) is what actually unblocks it.
// Many small pipelined responses do not reliably reach that point — a
// default socket buffer can absorb tens of thousands of them without ever
// stalling — so, while this sub-task's description asks for "many roles",
// manyLargeRoles below uses a handful of large role values rather than a
// large count of small ones.
//
// Note precisely what that does and does not underwrite. These two tests
// deliberately stay on real TCP, because a real socket being Unbound or
// severed mid-emission is the subject; the stall is only their setup. But
// payload-size-versus-socket-buffer is a host-dependent way to reach a
// stall: see
// TestAdversarial_WriteDeadlineClosesStalledConnectionAndUnblocksGracefulShutdown
// (adversarial_test.go), whose write-deadline proof moved to an unbuffered
// net.Pipe precisely because a hosted Linux runner absorbed an entire
// ~40 MiB response without the server's write ever blocking. These tests
// tolerate that outcome, which is why they may keep the real socket: if the
// stall fails to materialize on some host, the mid-emission window merely
// narrows, and their goroutine-unwind, no-leak and bounded-shutdown
// assertions all still hold. They are not the write-deadline proof.

// manyLargeRoles returns n distinct role names, each individually large
// (sizeEach extra bytes of padding), so a real Search response emitting
// them reliably exceeds ordinary OS socket buffer capacity within the
// first one or two entries — see this file's header doc comment.
func manyLargeRoles(n, sizeEach int) []string {
	roles := make([]string, n)
	for i := range roles {
		roles[i] = fmt.Sprintf("ch_midsearch_role_%02d_", i) + strings.Repeat("x", sizeEach)
	}
	return roles
}

// rawUnbindMessage BER-encodes one complete UnbindRequest LDAPMessage
// envelope (RFC 4511 §4.3: `UnbindRequest ::= [APPLICATION 2] NULL`, a
// primitive, zero-length application tag), with messageID as this
// envelope's own message ID.
func rawUnbindMessage(messageID int) []byte {
	unbindReq := ber.Encode(ber.ClassApplication, ber.TypePrimitive, ldapserver.ApplicationUnbindRequest, nil, "UnbindRequest")
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(unbindReq)
	return env.Bytes()
}

// waitForGoroutineCountNear polls runtime.NumGoroutine() until it returns to
// within slack of baseline, or fails the test after timeout — the
// goroutine-count evidence this sub-task's description asks for that
// request/writer goroutines actually unwound rather than leaking.
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
			t.Fatalf("goroutine count did not settle within %v: current=%d, baseline=%d, slack=%d — request/writer goroutines may have leaked", timeout, cur, baseline, slack)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startMidSearchServer wires the real production server with a short
// WriteTimeout (so the pacing mechanism above resolves quickly and
// deterministically) and returns everything the two tests below need to
// both drive it and assert bounded shutdown explicitly.
func startMidSearchServer(t *testing.T, v verifier, r roleResolver) (addr string, ln net.Listener, serveErr chan error, stop func()) {
	t.Helper()
	rootCtx, cancel := context.WithCancel(context.Background())

	srv, err := New(rootCtx, protoConfig(), v, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.ldapSrv.ReadTimeout = 5 * time.Second
	srv.ldapSrv.WriteTimeout = 300 * time.Millisecond

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	// startServing (protocol_test.go) registers the fail-safe teardown
	// before this function returns, so an assertion that aborts one of the
	// tests below — before it ever reaches requireBoundedShutdown — cannot
	// leak a live server into the next test. See that function's doc for
	// why a leaked server is a data race and not merely untidy.
	serveErr, stop = startServing(t, srv, ln, cancel)
	return ln.Addr().String(), ln, serveErr, stop
}

// requireBoundedShutdown closes ln, requires Serve to return, then requires
// srv.Stop() to return — both within generous bounds — proving the
// mid-Search termination did not leave anything pinning graceful shutdown.
// It drives the final step through startServing's idempotent stop closure
// so the fail-safe cleanup registered at start becomes a no-op rather than
// a second, panicking Stop().
func requireBoundedShutdown(t *testing.T, ln net.Listener, serveErr chan error, stop func()) {
	t.Helper()
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}
	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve never returned")
	}
	stopDone := make(chan struct{})
	go func() { stop(); close(stopDone) }()
	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("Stop() never returned within bound")
	}
}

// requireFreshConnectionUnaffected proves connection-local state died with
// the terminated connection (a brand-new, never-Bound connection is still
// unauthenticated) and that the server remains fully healthy for ordinary
// traffic (a normal Bind+Search on a small account succeeds).
func requireFreshConnectionUnaffected(t *testing.T, addr string) {
	t.Helper()

	unauth := dialTest(t, addr)
	res, err := unauth.Search(membershipSearch(protoGroupBaseDN, protoBindDN("bob"), nil))
	if err == nil && res != nil && len(res.Entries) > 0 {
		t.Fatalf("fresh unauthenticated connection got search results: %+v", res)
	}

	ok := dialTest(t, addr)
	requireSuccess(t, "bind bob on fresh connection", bindAs(ok, protoBindDN("bob"), "jwt-bob"))
	resBob, err := ok.Search(membershipSearch(protoGroupBaseDN, protoBindDN("bob"), nil))
	if err != nil || len(resBob.Entries) != 1 {
		t.Fatalf("search for bob on fresh connection: res=%+v, err=%v, want 1 entry", resBob, err)
	}
}

// ---- Unbind during Search result emission ----------------------------------

func TestMidSearch_UnbindDuringResultEmissionUnwindsCleanly(t *testing.T) {
	const sentinelToken = "MIDSEARCH-UNBIND-SENTINEL-TOKEN"
	bigRoles := manyLargeRoles(5, 5<<20) // 5 roles, 5 MiB padding each — see file header doc comment
	big := account("alice", "https://idp.test/", "sub-alice", sentinelToken, bigRoles)
	small := account("bob", "https://idp.test/", "sub-bob", "jwt-bob", []string{"ch_bob_role"})

	addr, ln, serveErr, stop := startMidSearchServer(t, newFakeVerifier(big, small), newFakeRoles(big, small))
	appLog := swapAppLog(t)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := raw.Write(rawSimpleBindMessage(1, protoBindDN("alice"), sentinelToken)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	pkt := readRawEnvelope(t, raw, 5*time.Second)
	code, _, _ := bindResponseFields(t, pkt, 1)
	if code != int64(ldapserver.LDAPResultSuccess) {
		t.Fatalf("bind resultCode = %d, want success", code)
	}

	if _, err := raw.Write(rawSearchMessage(2, protoGroupBaseDN, protoBindDN("alice"))); err != nil {
		t.Fatalf("write search: %v", err)
	}
	// Pipeline Unbind immediately, on the same connection, WITHOUT reading
	// any Search response bytes — see this file's header doc comment for
	// why this reliably lands mid-emission.
	if _, err := raw.Write(rawUnbindMessage(3)); err != nil {
		t.Fatalf("write unbind: %v", err)
	}

	// The connection must actually be closed server-side once the
	// WriteTimeout-bounded stall resolves and Unbind's own "stop serving"
	// path runs.
	if err := raw.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		if _, rerr := raw.Read(buf); rerr != nil {
			break
		}
	}
	raw.Close()

	// Request/writer goroutines attributable to this one connection must
	// have unwound.
	waitForGoroutineCountNear(t, baseline, 5, 5*time.Second)

	requireNoLeak(t, appLog, sentinelToken)
	for i := range bigRoles {
		requireNoLeak(t, appLog, fmt.Sprintf("ch_midsearch_role_%02d_", i))
	}

	requireFreshConnectionUnaffected(t, addr)
	requireBoundedShutdown(t, ln, serveErr, stop)
}

// ---- abrupt TCP close during Search result emission ------------------------

func TestMidSearch_AbruptCloseDuringResultEmissionUnwindsCleanly(t *testing.T) {
	const sentinelToken = "MIDSEARCH-CLOSE-SENTINEL-TOKEN"
	bigRoles := manyLargeRoles(5, 5<<20)
	big := account("alice", "https://idp.test/", "sub-alice", sentinelToken, bigRoles)
	small := account("bob", "https://idp.test/", "sub-bob", "jwt-bob", []string{"ch_bob_role"})

	addr, ln, serveErr, stop := startMidSearchServer(t, newFakeVerifier(big, small), newFakeRoles(big, small))
	appLog := swapAppLog(t)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := raw.Write(rawSimpleBindMessage(1, protoBindDN("alice"), sentinelToken)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	pkt := readRawEnvelope(t, raw, 5*time.Second)
	code, _, _ := bindResponseFields(t, pkt, 1)
	if code != int64(ldapserver.LDAPResultSuccess) {
		t.Fatalf("bind resultCode = %d, want success", code)
	}

	if _, err := raw.Write(rawSearchMessage(2, protoGroupBaseDN, protoBindDN("alice"))); err != nil {
		t.Fatalf("write search: %v", err)
	}

	// Give the search handler a brief moment to actually start emitting
	// (and, per this file's header doc comment, to be at or near blocked on
	// the first large entry) before abruptly severing the TCP connection
	// from underneath it — the abrupt-close counterpart to the
	// graceful-Unbind test above.
	time.Sleep(150 * time.Millisecond)
	raw.Close()

	waitForGoroutineCountNear(t, baseline, 5, 5*time.Second)

	requireNoLeak(t, appLog, sentinelToken)
	for i := range bigRoles {
		requireNoLeak(t, appLog, fmt.Sprintf("ch_midsearch_role_%02d_", i))
	}

	requireFreshConnectionUnaffected(t, addr)
	requireBoundedShutdown(t, ln, serveErr, stop)
}
