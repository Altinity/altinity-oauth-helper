package ldap

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers plan-19p5 §13/§24's "exact production connection cap"
// gate: TestAdversarial_DefaultConnectionCapRejects257thAndRecovers below
// constructs the real production server exactly the way the existing
// TestAdversarial_ConcurrentMaxLengthStalledConnectionsAreBounded
// (adversarial_test.go) does, but — unlike that test, which deliberately
// shrinks MaxConnections to 4 to stay fast — asserts the actual production
// default (256) and leaves it unchanged, shortening only the connection
// Read/Write timeouts. It reuses protocol_test.go's
// account/newFakeVerifier/newFakeRoles/protoConfig/protoBindDN fixtures and
// adversarial_test.go's rawSimpleBindMessage/rawSearchMessage raw-BER
// encoders, plus hostile_dn_test.go's readRawEnvelope/bindResponseFields; no
// existing file is modified.

// readSearchResults reads raw LDAPMessage responses from conn until a
// SearchResultDone arrives, asserting every message's ID equals
// wantMessageID, and returns the number of SearchResultEntry messages seen
// plus the final result code. Shared by this file and hostile_dn_test.go.
func readSearchResults(t *testing.T, conn net.Conn, wantMessageID int, timeout time.Duration) (entries int, doneCode int64) {
	t.Helper()
	for {
		pkt := readRawEnvelope(t, conn, timeout)
		if len(pkt.Children) < 2 {
			t.Fatalf("malformed search response envelope: %+v", pkt)
		}
		gotID, _ := pkt.Children[0].Value.(int64)
		if gotID != int64(wantMessageID) {
			t.Fatalf("search response messageID = %d, want %d", gotID, wantMessageID)
		}
		op := pkt.Children[1]
		switch op.Tag {
		case ldapserver.ApplicationSearchResultEntry:
			entries++
		case ldapserver.ApplicationSearchResultDone:
			if len(op.Children) < 1 {
				t.Fatalf("malformed SearchResultDone: %+v", op)
			}
			doneCode, _ = op.Children[0].Value.(int64)
			return entries, doneCode
		default:
			t.Fatalf("unexpected response op tag %d while reading search results", op.Tag)
		}
	}
}

// TestAdversarial_DefaultConnectionCapRejects257thAndRecovers is the
// plan's §13/§24 "exact production connection cap" gate: it proves the
// unmodified production default of 256 concurrent connections
// (server.go's ldapMaxConnections) is exactly enforced — the 256th client
// Binds successfully, the 257th is rejected outright with no response, and
// once a slot is freed a replacement client Binds and Searches normally —
// against a real accepted-connection count, not a reduced test double.
func TestAdversarial_DefaultConnectionCapRejects257thAndRecovers(t *testing.T) {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		t.Fatalf("syscall.Getrlimit(RLIMIT_NOFILE): %v", err)
	}
	t.Logf("effective RLIMIT_NOFILE at test execution time: soft=%d hard=%d", rlim.Cur, rlim.Max)

	// This test holds, at its peak, roughly 256 (accepted-and-kept-open
	// clients) + 1 (the 257th rejection probe) + a couple more (replacement
	// dial cycle) client-side file descriptors, each paired with one
	// accepted server-side descriptor for the connections still open at
	// once — since client and server both run in this same test process,
	// that is the same descriptor table. 600 is a conservative, generous
	// budget over the ~515 peak this test actually needs concurrently,
	// leaving headroom for whatever else this process/environment already
	// holds open. This is a property of the EXECUTION environment, not a
	// repository invariant — see server.go's ldapMaxConnections doc — so
	// this test skips rather than ever raising the limit itself.
	const minNeededFDs = 600
	if rlim.Cur < minNeededFDs {
		t.Skipf("environment RLIMIT_NOFILE soft limit %d is below the %d file descriptors this test needs to open ~256 real concurrent connections; skipping rather than raising the limit", rlim.Cur, minNeededFDs)
	}

	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(rootCtx, protoConfig(), fv, newFakeRoles(acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The load-bearing assertion this test exists for: the production
	// default must be exactly 256, and this test must not change it —
	// only the connection Read/Write timeouts are shortened, purely so
	// this test completes quickly and deterministically.
	if srv.ldapSrv.MaxConnections != ldapMaxConnections {
		t.Fatalf("srv.ldapSrv.MaxConnections = %d, want the unchanged production constant ldapMaxConnections (%d)", srv.ldapSrv.MaxConnections, ldapMaxConnections)
	}
	if srv.ldapSrv.MaxConnections != 256 {
		t.Fatalf("srv.ldapSrv.MaxConnections = %d, want exactly 256 per this sub-task's doneWhen", srv.ldapSrv.MaxConnections)
	}
	srv.ldapSrv.ReadTimeout = 10 * time.Second
	srv.ldapSrv.WriteTimeout = 10 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	serveErr, stop := startServing(t, srv, ln, cancel)
	addr := ln.Addr().String()

	const capacity = 256
	conns := make([]net.Conn, capacity)
	bindErrs := make([]error, capacity)

	// 1-3. Open and Bind all 256 clients concurrently, under one shared
	// deadline.
	sharedDeadline := time.Now().Add(20 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < capacity; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, dialErr := net.Dial("tcp", addr)
			if dialErr != nil {
				bindErrs[i] = fmt.Errorf("dial %d: %w", i, dialErr)
				return
			}
			conns[i] = c
			if err := c.SetDeadline(sharedDeadline); err != nil {
				bindErrs[i] = fmt.Errorf("set deadline %d: %w", i, err)
				return
			}
			if _, werr := c.Write(rawSimpleBindMessage(1, protoBindDN("alice"), "jwt-alice")); werr != nil {
				bindErrs[i] = fmt.Errorf("write bind %d: %w", i, werr)
				return
			}
			pkt, rerr := ber.ReadPacket(c)
			if rerr != nil {
				bindErrs[i] = fmt.Errorf("read bind response %d: %w", i, rerr)
				return
			}
			code, matchedDN, diagnostic := bindResponseFields(t, pkt, 1)
			if code != int64(ldapserver.LDAPResultSuccess) {
				bindErrs[i] = fmt.Errorf("bind %d: resultCode=%d matchedDN=%q diagnostic=%q, want success", i, code, matchedDN, diagnostic)
			}
		}(i)
	}

	allDone := make(chan struct{})
	go func() { wg.Wait(); close(allDone) }()
	select {
	case <-allDone:
	case <-time.After(25 * time.Second):
		t.Fatalf("binding %d concurrent clients did not complete within the shared deadline", capacity)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	})
	for i, e := range bindErrs {
		if e != nil {
			t.Fatalf("client %d: %v", i, e)
		}
	}

	// 4-6. Keep all 256 sockets open, then dial the 257th: it must be
	// rejected promptly (connection closed, no bytes at all — in
	// particular, no BindResponse), proving the process-wide
	// MaxConnections cap is what actually rejects it, not some
	// coincidental client-side failure.
	over, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 257th connection: %v", err)
	}
	defer over.Close()
	if err := over.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline (257th): %v", err)
	}
	buf := make([]byte, 16)
	n, readErr := over.Read(buf)
	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("257th connection was never rejected (read timed out) — the 256-connection production cap does not appear to be enforced")
	}
	if n != 0 {
		t.Fatalf("257th connection: got %d bytes (want the connection closed with none — no BindResponse should ever be sent)", n)
	}

	// 7-9. Free exactly one accepted slot, wait for it to be released
	// server-side, then a replacement client both Binds AND Searches
	// successfully — proving the freed slot is genuinely usable again, not
	// merely that a new TCP handshake completes.
	conns[0].Close()
	conns[0] = nil

	var repl net.Conn
	waitDeadline := time.Now().Add(10 * time.Second)
	for {
		c, dialErr := net.Dial("tcp", addr)
		if dialErr != nil {
			t.Fatalf("dial replacement client: %v", dialErr)
		}
		if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("SetDeadline (replacement): %v", err)
		}
		if _, werr := c.Write(rawSimpleBindMessage(2, protoBindDN("alice"), "jwt-alice")); werr != nil {
			_ = c.Close()
			if time.Now().After(waitDeadline) {
				t.Fatalf("write replacement bind: %v (slot never freed within bound)", werr)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		pkt, rerr := ber.ReadPacket(c)
		if rerr != nil {
			_ = c.Close()
			if time.Now().After(waitDeadline) {
				t.Fatalf("read replacement bind response: %v (slot never freed within bound)", rerr)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		code, _, _ := bindResponseFields(t, pkt, 2)
		if code == int64(ldapserver.LDAPResultSuccess) {
			repl = c
			break
		}
		_ = c.Close()
		if time.Now().After(waitDeadline) {
			t.Fatalf("replacement bind resultCode = %d, want success (slot never freed within bound)", code)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := repl.Write(rawSearchMessage(3, protoGroupBaseDN, protoBindDN("alice"))); err != nil {
		t.Fatalf("write replacement search: %v", err)
	}
	entries, doneCode := readSearchResults(t, repl, 3, 5*time.Second)
	if entries != 1 || doneCode != int64(ldapserver.LDAPResultSuccess) {
		t.Fatalf("replacement search: entries=%d doneCode=%d, want 1 entry and success", entries, doneCode)
	}
	repl.Close()

	// 10. Close every remaining client and require the server itself shuts
	// down within a bound.
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close: %v", err)
	}
	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatalf("Serve never returned after closing the listener")
	}

	// stop() (see startServing) performs the remaining srv.Stop() step and
	// is idempotent, so the fail-safe cleanup registered when the server
	// started — which is what keeps an aborted assertion above from leaking
	// a live server into the next test — is a no-op afterwards.
	stopDone := make(chan struct{})
	go func() { stop(); close(stopDone) }()
	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("Stop() never returned within bound after the connection-cap exercise")
	}
}
