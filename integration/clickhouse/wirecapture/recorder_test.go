package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecorder_ReadinessFileWrittenAfterListenSucceeds(t *testing.T) {
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "run", "ldap-wirecapture", "ready")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	if _, err := os.Stat(readyPath); !os.IsNotExist(err) {
		t.Fatalf("readiness file must not exist before Serve is called")
	}

	rec := &Recorder{
		Mode:          "pass",
		RawDir:        filepath.Join(dir, "raw"),
		ReadyFilePath: readyPath,
		Dial: func(ctx context.Context) (net.Conn, error) {
			t.Fatal("Dial must not be invoked merely by Serve/readiness")
			return nil, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.Serve(ctx, ln)

	deadline := time.Now().Add(2 * time.Second)
	for {
		info, err := os.Stat(readyPath)
		if err == nil {
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("readiness file mode = %v, want 0600", info.Mode().Perm())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness file was never created after Listen succeeded")
		}
		time.Sleep(time.Millisecond)
	}
}

// fakeUpstreamServer is a minimal in-process TCP server used as the
// recorder's forwarding target in the real-TCP loopback test below: it
// records every byte it receives and, once it has seen at least
// wantBindLen bytes, writes back a fixed BindResponse.
type fakeUpstreamServer struct {
	ln       net.Listener
	received chan []byte
}

func startFakeUpstream(t *testing.T, bindResponse []byte) *fakeUpstreamServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	f := &fakeUpstreamServer{ln: ln, received: make(chan []byte, 1)}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		got := make([]byte, n)
		copy(got, buf[:n])
		f.received <- got
		_, _ = conn.Write(bindResponse)
		// Keep the connection open briefly so the recorder's io.Copy has
		// time to relay the response before this goroutine returns.
		time.Sleep(50 * time.Millisecond)
	}()
	return f
}

func TestRecorder_PassMode_RealTCPLoopback(t *testing.T) {
	dir := t.TempDir()
	bindReq := buildBindRequest(1, "uid=alice,dc=test", "not-a-real-jwt")
	bindResp := buildBindResponse(1)

	upstream := startFakeUpstream(t, bindResp)
	defer upstream.ln.Close()

	rec := &Recorder{
		Mode:         "pass",
		UpstreamAddr: upstream.ln.Addr().String(),
		RawDir:       filepath.Join(dir, "raw"),
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upstream.ln.Addr().String())
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("recorder listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.Serve(ctx, ln)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial recorder: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(bindReq); err != nil {
		t.Fatalf("write bind request: %v", err)
	}

	// Expect the exact BindResponse bytes forwarded back unchanged.
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, len(bindResp))
	if _, err := readFull(client, resp); err != nil {
		t.Fatalf("read forwarded bind response: %v", err)
	}
	if !bytes.Equal(resp, bindResp) {
		t.Fatalf("forwarded response = %x, want %x", resp, bindResp)
	}

	// Confirm the upstream received the exact request bytes, unmodified.
	select {
	case got := <-upstream.received:
		if !bytes.Equal(got, bindReq) {
			t.Fatalf("upstream received %x, want %x", got, bindReq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the forwarded request")
	}

	client.Close()
	// Give the recorder a moment to record the raw file before inspecting it.
	rawFile := filepath.Join(dir, "raw", "conn-0001", "001-client-request.ber")
	deadline := time.Now().Add(2 * time.Second)
	for {
		content, err := os.ReadFile(rawFile)
		if err == nil {
			if !bytes.Equal(content, bindReq) {
				t.Fatalf("raw capture content = %x, want %x", content, bindReq)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("raw capture file was never written: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestRecorder_StallAfterBind_InjectedDeadline_SimulatedAbandon drives the
// stall-after-bind state machine end to end over net.Pipe (fast, no real
// network) with a millisecond-scale injected deadline (plan §23): it sends
// Bind, expects the Bind response forwarded, sends Search, confirms the
// recorder withholds any Search response from the client while draining it
// from upstream, then has the "client" send Abandon before the deadline and
// confirms the recorder forwards it upstream and records it, followed by
// Unbind ending the session cleanly.
func TestRecorder_StallAfterBind_InjectedDeadline_SimulatedAbandon(t *testing.T) {
	dir := t.TempDir()

	clientSideRecorder, clientSideTest := net.Pipe()
	upstreamSideRecorder, upstreamSideTest := net.Pipe()

	results := make(chan ConnResult, 1)
	rec := &Recorder{
		Mode:          "stall-after-bind",
		RawDir:        filepath.Join(dir, "raw"),
		StallDeadline: 300 * time.Millisecond,
		Results:       results,
		Dial: func(ctx context.Context) (net.Conn, error) {
			return upstreamSideRecorder, nil
		},
	}

	go rec.handleConn(context.Background(), clientSideRecorder, 7)

	bindReq := buildBindRequest(1, "uid=alice,dc=test", "not-a-real-jwt")
	if _, err := clientSideTest.Write(bindReq); err != nil {
		t.Fatalf("write bind: %v", err)
	}

	// Recorder forwards Bind upstream — the fake upstream reads it, then
	// replies with a BindResponse.
	upstreamR := bufio.NewReader(upstreamSideTest)
	fwdBind, err := readLDAPMessage(upstreamR)
	if err != nil {
		t.Fatalf("upstream read forwarded bind: %v", err)
	}
	if !bytes.Equal(fwdBind.raw, bindReq) {
		t.Fatalf("upstream saw %x, want %x", fwdBind.raw, bindReq)
	}
	bindResp := buildBindResponse(1)
	if _, err := upstreamSideTest.Write(bindResp); err != nil {
		t.Fatalf("upstream write bind response: %v", err)
	}

	clientSideTest.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotResp := make([]byte, len(bindResp))
	if _, err := readFull(clientSideTest, gotResp); err != nil {
		t.Fatalf("client read bind response: %v", err)
	}
	if !bytes.Equal(gotResp, bindResp) {
		t.Fatalf("client saw bind response %x, want %x", gotResp, bindResp)
	}

	searchReq := buildSearchRequest(2)
	if _, err := clientSideTest.Write(searchReq); err != nil {
		t.Fatalf("write search: %v", err)
	}
	fwdSearch, err := readLDAPMessage(upstreamR)
	if err != nil {
		t.Fatalf("upstream read forwarded search: %v", err)
	}
	if !bytes.Equal(fwdSearch.raw, searchReq) {
		t.Fatalf("upstream saw search %x, want %x", fwdSearch.raw, searchReq)
	}

	// The recorder must NOT deliver anything to the client in response to
	// Search: prove that within a short window nothing arrives.
	clientSideTest.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	probe := make([]byte, 1)
	if _, err := clientSideTest.Read(probe); err == nil {
		t.Fatal("client unexpectedly received bytes after Search — Search response must be withheld")
	}

	// Now the simulated client abandons, as a real libldap client would
	// after its own Search timeout.
	abandonReq := buildAbandonRequest(3, 2)
	if _, err := clientSideTest.Write(abandonReq); err != nil {
		t.Fatalf("write abandon: %v", err)
	}

	fwdAbandon, err := readLDAPMessage(upstreamR)
	if err != nil {
		t.Fatalf("upstream read forwarded abandon: %v", err)
	}
	if !bytes.Equal(fwdAbandon.raw, abandonReq) {
		t.Fatalf("upstream saw abandon %x, want %x", fwdAbandon.raw, abandonReq)
	}

	unbindReq := buildUnbindRequest(4)
	if _, err := clientSideTest.Write(unbindReq); err != nil {
		t.Fatalf("write unbind: %v", err)
	}
	clientSideTest.Close()

	select {
	case res := <-results:
		if res.Err != nil {
			t.Fatalf("connection result error: %v", res.Err)
		}
		if len(res.PDUs) != 4 {
			t.Fatalf("recorded %d PDUs, want 4 (bind, search, abandon, unbind)", len(res.PDUs))
		}
		wantOps := []string{"bind", "search", "abandon", "unbind"}
		for i, op := range wantOps {
			if res.PDUs[i].Operation != op {
				t.Fatalf("PDU[%d].Operation = %q, want %q", i, res.PDUs[i].Operation, op)
			}
		}
		if !res.PDUs[2].HasAbandon || res.PDUs[2].AbandonTarget != 2 {
			t.Fatalf("abandon PDU target = %+v, want target 2", res.PDUs[2])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection result never published")
	}

	rawDir := filepath.Join(dir, "raw", "conn-0007")
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		t.Fatalf("read raw dir: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("raw dir has %d files, want 4", len(entries))
	}
}

// TestRecorder_StallAfterBind_DeadlineExceeded_WithNoAbandon proves the
// hard deadline actually fires (as a config field, not a real ~20-40s
// sleep) when the simulated client never sends Abandon or Unbind.
func TestRecorder_StallAfterBind_DeadlineExceeded_WithNoAbandon(t *testing.T) {
	dir := t.TempDir()

	clientSideRecorder, clientSideTest := net.Pipe()
	upstreamSideRecorder, upstreamSideTest := net.Pipe()
	defer upstreamSideTest.Close()

	results := make(chan ConnResult, 1)
	rec := &Recorder{
		Mode:          "stall-after-bind",
		RawDir:        filepath.Join(dir, "raw"),
		StallDeadline: 30 * time.Millisecond,
		Results:       results,
		Dial: func(ctx context.Context) (net.Conn, error) {
			return upstreamSideRecorder, nil
		},
	}

	go rec.handleConn(context.Background(), clientSideRecorder, 1)

	bindReq := buildBindRequest(1, "uid=alice,dc=test", "not-a-real-jwt")
	if _, err := clientSideTest.Write(bindReq); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	upstreamR := bufio.NewReader(upstreamSideTest)
	if _, err := readLDAPMessage(upstreamR); err != nil {
		t.Fatalf("upstream read bind: %v", err)
	}
	if _, err := upstreamSideTest.Write(buildBindResponse(1)); err != nil {
		t.Fatalf("upstream write bind response: %v", err)
	}
	clientSideTest.SetReadDeadline(time.Now().Add(2 * time.Second))
	discard := make([]byte, len(buildBindResponse(1)))
	if _, err := readFull(clientSideTest, discard); err != nil {
		t.Fatalf("client read bind response: %v", err)
	}

	searchReq := buildSearchRequest(2)
	if _, err := clientSideTest.Write(searchReq); err != nil {
		t.Fatalf("write search: %v", err)
	}
	if _, err := readLDAPMessage(upstreamR); err != nil {
		t.Fatalf("upstream read search: %v", err)
	}

	// Deliberately never send Abandon or Unbind: the injected 30ms deadline
	// must still terminate the connection handling promptly.
	select {
	case res := <-results:
		if res.StalledOn == "" {
			t.Fatalf("expected StalledOn to report a deadline exceeded outcome, got result: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stall-after-bind handler never returned after its injected deadline elapsed")
	}
}
