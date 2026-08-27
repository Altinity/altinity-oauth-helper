package ldap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	goldapclient "github.com/go-ldap/ldap/v3"
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
//     BER shapes, not one.

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

	// Exactly the plan's described shutdown sequence: cancel the root/
	// process context AND invoke server shutdown.
	rootCancel()
	srv.Stop()

	select {
	case err := <-fv.returned:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked verifier's Verify returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked verifier never observed root cancellation/shutdown")
	}

	// The server itself must terminate — Serve must return — not merely
	// abandon the one in-flight request. A hung Serve here would mean a
	// leaked accept loop/goroutine surviving process shutdown.
	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve never returned after Stop: server did not terminate")
	}

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

// TestAdversarial_SentinelAbsentFromEveryCapturedOutputChannel binds with a
// unique sentinel JWT/password while capturing BOTH the application zerolog
// writer AND the real OS stdout file descriptor, and asserts the sentinel
// (and the ordinary real password, for the successful-Bind case that most
// plausibly triggers the dependency's own packet-hex logger) appears in
// neither. See captureRealStdout's doc comment for why stdout capture must
// be fd-level to actually prove the dependency's packet logger is disabled.
func TestAdversarial_SentinelAbsentFromEveryCapturedOutputChannel(t *testing.T) {
	const sentinelToken = "SENTINEL-ADV-8e21c4f0-do-not-log-me"
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	var appLog bytes.Buffer
	prevLogger := log.Logger
	log.Logger = zerolog.New(&appLog)
	t.Cleanup(func() { log.Logger = prevLogger })

	stopCapture := captureRealStdout(t)

	// The failing case whose password IS the sentinel: the case most likely
	// to leak, since a naive implementation might log the raw verifier-call
	// arguments on failure.
	conn := dialTest(t, addr)
	requireInvalidCredentials(t, "sentinel bind", bindAs(conn, protoBindDN("alice"), sentinelToken))

	// A successful Bind using the real password, to prove the dependency's
	// own hex-packet logger (client.go's "<<< ... hex=%x" on every inbound
	// message, which necessarily contains the password) is disabled too.
	conn2 := dialTest(t, addr)
	requireSuccess(t, "real bind", bindAs(conn2, protoBindDN("alice"), "jwt-alice"))

	stdout := stopCapture()

	if strings.Contains(appLog.String(), sentinelToken) || strings.Contains(stdout, sentinelToken) {
		t.Fatalf("sentinel credential leaked into captured output:\napp log:\n%s\nstdout:\n%s", appLog.String(), stdout)
	}
	if strings.Contains(appLog.String(), "jwt-alice") || strings.Contains(stdout, "jwt-alice") {
		t.Fatalf("real bind password leaked into captured output:\napp log:\n%s\nstdout:\n%s", appLog.String(), stdout)
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

	// Kept modest and well under 128 total messages on this one connection,
	// for the same reason as protocol_test.go's
	// TestProtocol_ConcurrentReBindAndSearchRace: the pinned goldap
	// dependency's generic BER INTEGER writer mis-encodes a message ID once
	// it reaches the 128-255 range (missing sign-disambiguation padding),
	// which desynchronizes response correlation on a long-lived connection.
	// That is an independent, already-documented dependency defect, not
	// something this test is trying to exercise.
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
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
}
