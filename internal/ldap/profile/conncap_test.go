package profile

// This file is the test suite for server.go's 256-connection admission
// cap: TestProfile_ConnectionCap256AndSlotReuse (2.1 exact 256 cap, from
// the plan's Tests-mapped table) proves the exact boundary, the 257th
// connection's silent no-goroutine rejection, and slot reuse by
// visibility of the active-map deletion; the second test below is the
// sub-task's shortened-deadline stalled-body variant proving the cap
// holds under a burst of concurrent, otherwise-idle connections.

import (
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// wantConnectionCap is this test's OWN expectation of the admission cap,
// deliberately a literal rather than a reference to server.go's
// maxConnections constant: a sabotage changing that constant (e.g.
// 256->257) must make this test fail, which referencing the same symbol
// the production code was sabotaged in would silently defeat.
const wantConnectionCap = 256

func TestProfile_ConnectionCap256AndSlotReuse(t *testing.T) {
	v := newFakeVerifier().withSuccess("s3cr3t", newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix()))
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})

	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 10*time.Second)

	conns := make([]net.Conn, 0, wantConnectionCap)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	for i := 0; i < wantConnectionCap; i++ {
		conn := dial(t, h.addr)
		env := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
		result, _, _ := readLDAPResultFields(t, env.Content)
		if result != int(resultSuccess) {
			t.Fatalf("connection %d: Bind result = %d, want success", i, result)
		}
		conns = append(conns, conn)
	}
	if got := h.server.activeCountForTest(); got != wantConnectionCap {
		t.Fatalf("active connections after admitting %d = %d, want %d", wantConnectionCap, got, wantConnectionCap)
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	// The 257th connection: no request-body allocation, no goroutine, no
	// response bytes -- just closed.
	rejected := dial(t, h.addr)
	expectNoResponseThenClosed(t, rejected)
	_ = rejected.Close()

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if diff := after - baseline; diff < -2 || diff > 2 {
		t.Fatalf("NumGoroutine changed by %d (baseline=%d, after=%d) rejecting the 257th connection; want ~unchanged (no goroutine spawned for it)", diff, baseline, after)
	}

	if got := v.callCount(); got != int32(wantConnectionCap) {
		t.Fatalf("Verify called %d times, want exactly %d (one per admitted connection, none for the rejected 257th)", got, wantConnectionCap)
	}

	// Slot reuse: close one admitted connection, wait for the server to
	// notice (via the deferred active-map deletion in serveConnection),
	// then a new connection can both Bind and Search successfully.
	conns[0].Close()
	conns = conns[1:]

	deadline := time.Now().Add(3 * time.Second)
	for h.server.activeCountForTest() >= wantConnectionCap {
		if time.Now().After(deadline) {
			t.Fatal("server did not free the closed connection's slot within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	reused := dial(t, h.addr)
	defer reused.Close()

	env := sendAndReadEnvelope(t, reused, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
	result, _, _ := readLDAPResultFields(t, env.Content)
	if result != int(resultSuccess) {
		t.Fatalf("reused-slot Bind result = %d, want success", result)
	}

	groupBase := newTestConfig().GroupBaseDN
	if _, err := reused.Write(searchRequestBytes(2, groupBase, testAliceDN, 10, 10)); err != nil {
		t.Fatalf("write search: %v", err)
	}
	entries, doneEnv := collectSearchResult(t, reused)
	doneResult, _, _ := readLDAPResultFields(t, doneEnv.Content)
	if doneResult != int(resultSuccess) {
		t.Fatalf("reused-slot Search result = %d, want success", doneResult)
	}
	if len(entries) != 1 {
		t.Fatalf("reused-slot Search entries = %d, want 1", len(entries))
	}
}

// collectSearchResult reads frames off conn until it decodes a
// SearchResultDone, returning every SearchResultEntry seen before it.
func collectSearchResult(t *testing.T, conn net.Conn) (entries []Envelope, done Envelope) {
	t.Helper()
	for {
		env := readEnvelope(t, conn)
		if env.ProtocolOp == tagSearchResultDone {
			return entries, env
		}
		entries = append(entries, env)
	}
}

// TestProfile_ConnectionCapHoldsUnderStalledBodyLoad is the sub-task's
// shortened-deadline stalled-body variant: a burst of concurrent
// connections that each connect and then send nothing at all, proving the
// 256 cap holds (aggregate admitted-connection/body-buffer count never
// exceeds it) even under load well beyond the cap, before the shortened
// read deadline drops every one of them.
func TestProfile_ConnectionCapHoldsUnderStalledBodyLoad(t *testing.T) {
	h := newRunningServer(t, newFakeVerifier(), newFakeResolver(), func(s *Server) {
		s.readTimeout = 150 * time.Millisecond
	})
	defer h.stopAndWait(t, 10*time.Second)

	const attempts = 400

	var mu sync.Mutex
	maxObserved := 0
	stop := make(chan struct{})
	pollerDone := make(chan struct{})
	go func() {
		defer close(pollerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n := h.server.activeCountForTest()
			mu.Lock()
			if n > maxObserved {
				maxObserved = n
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", h.addr, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			// Deliberately send nothing: a stalled-body connection,
			// dropped once the server's shortened read deadline fires.
			time.Sleep(500 * time.Millisecond)
		}()
	}
	wg.Wait()
	close(stop)
	<-pollerDone

	mu.Lock()
	got := maxObserved
	mu.Unlock()
	if got > wantConnectionCap {
		t.Fatalf("observed %d simultaneously admitted connections (attempts=%d), want <= %d", got, attempts, wantConnectionCap)
	}

	deadline := time.Now().Add(3 * time.Second)
	for h.server.activeCountForTest() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("server did not drop every stalled connection within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
