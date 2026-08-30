package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// defaultStallDeadline is the recorder's live default hard deadline for
// stall-after-bind mode (plan §23): long enough for the real ~20s libldap
// Search timeout (LDAPClient.h's Search timeout default) to actually occur
// before the recorder itself gives up. Tests inject a much smaller value
// through Recorder.StallDeadline rather than hard-coding a sleep here.
const defaultStallDeadline = 40 * time.Second

// RecordedPDU is this package's own in-memory record of one client request
// PDU captured during a connection, independent of how/whether it was
// written to disk. It intentionally mirrors only the fields the recorder
// itself needs to decide behavior and hand results to a caller/test — it is
// NOT the committed wire-fixture schema (that is internal/wirefixture.PDU).
type RecordedPDU struct {
	Sequence      int
	Filename      string
	Operation     string
	MessageID     int
	AbandonTarget int
	HasAbandon    bool
	Raw           []byte
}

// ConnResult summarizes one accepted connection's outcome for callers and
// tests: what was recorded, and how the connection ended.
type ConnResult struct {
	ConnID    int
	Dir       string
	PDUs      []RecordedPDU
	StalledOn string // non-empty only for a stall-after-bind deadline exceeded
	Err       error
}

// Recorder is the ldap-wire-recorder proxy. Every timing value is a
// constructor/config field (plan §23), never a hard-coded sleep, so unit
// tests can inject millisecond-scale deadlines.
type Recorder struct {
	Mode          string        // "pass" or "stall-after-bind"
	UpstreamAddr  string        // e.g. "ldap-helper-upstream:389"
	RawDir        string        // e.g. "/run/ldap-wirecapture/raw"
	ReadyFilePath string        // e.g. "/run/ldap-wirecapture/ready"; empty disables readiness-file writing
	StallDeadline time.Duration // hard deadline for stall-after-bind's wait-for-Abandon/Unbind window; 0 means defaultStallDeadline

	// Dial opens the upstream connection. Defaults to a plain net.Dialer
	// against UpstreamAddr; tests inject an in-process fake upstream.
	Dial func(ctx context.Context) (net.Conn, error)

	// Results, if non-nil, receives one ConnResult per accepted connection.
	// Tests use this to observe outcomes without parsing on-disk files.
	Results chan<- ConnResult

	connSeq int32
}

func (r *Recorder) deadline() time.Duration {
	if r.StallDeadline <= 0 {
		return defaultStallDeadline
	}
	return r.StallDeadline
}

func (r *Recorder) dial(ctx context.Context) (net.Conn, error) {
	if r.Dial != nil {
		return r.Dial(ctx)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", r.UpstreamAddr)
}

// writeReadyFile is Amendment 1's non-LDAP readiness signal: written once,
// only after Listen has already succeeded, so Compose can healthcheck with
// `test -f` instead of opening an LDAP TCP connection that would itself
// count toward the N==1 session invariant (plan §8.4/§21). Every accepted
// client TCP connection counts toward N, including one that sends zero
// PDUs — this file is deliberately not itself such a connection.
func (r *Recorder) writeReadyFile() error {
	if r.ReadyFilePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.ReadyFilePath), 0o700); err != nil {
		return fmt.Errorf("wirecapture: create readiness directory: %w", err)
	}
	if err := os.WriteFile(r.ReadyFilePath, []byte("ready\n"), 0o600); err != nil {
		return fmt.Errorf("wirecapture: write readiness file: %w", err)
	}
	return nil
}

// ListenAndServe binds addr, writes the readiness file, and serves until ctx
// is done or Accept fails.
func (r *Recorder) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("wirecapture: listen %s: %w", addr, err)
	}
	defer ln.Close()
	return r.Serve(ctx, ln)
}

// Serve writes the readiness file (Listen has already succeeded by the time
// a caller has a net.Listener) and then accepts connections until ctx is
// done or Accept returns an error.
func (r *Recorder) Serve(ctx context.Context, ln net.Listener) error {
	if err := r.writeReadyFile(); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("wirecapture: accept: %w", err)
			}
		}
		connID := int(atomic.AddInt32(&r.connSeq, 1))
		go r.handleConn(ctx, conn, connID)
	}
}

func (r *Recorder) handleConn(ctx context.Context, conn net.Conn, connID int) {
	defer conn.Close()
	res := ConnResult{ConnID: connID}

	connDir := filepath.Join(r.RawDir, fmt.Sprintf("conn-%04d", connID))
	res.Dir = connDir
	// Every accepted connection counts toward N (Amendment 1), including a
	// zero-PDU one — create its directory immediately on accept, not lazily
	// on first recorded PDU.
	if err := os.MkdirAll(connDir, 0o700); err != nil {
		res.Err = errMalformedFrame("create raw connection directory", err)
		r.publish(res)
		return
	}

	upstream, err := r.dial(ctx)
	if err != nil {
		res.Err = errProxy("dial upstream", err)
		r.publish(res)
		return
	}
	defer upstream.Close()

	switch r.Mode {
	case "stall-after-bind":
		r.stallAfterBind(conn, upstream, connDir, &res)
	default: // "pass" and any unset/legacy value behave as pass-through
		r.pass(conn, upstream, connDir, &res)
	}
	r.publish(res)
}

func (r *Recorder) publish(res ConnResult) {
	if r.Results != nil {
		r.Results <- res
	}
}

// recordAndForward reads one client LDAPMessage, writes it to connDir as
// the next sequential raw client-request file, appends it to res.PDUs, and
// forwards the exact bytes read to upstream. It returns the decoded pdu so
// callers can branch on its operation.
func (r *Recorder) recordAndForward(clientR *bufio.Reader, upstream io.Writer, connDir string, res *ConnResult) (pdu, error) {
	seq := len(res.PDUs) + 1
	msg, err := readLDAPMessage(clientR)
	if err != nil {
		return pdu{}, err
	}
	filename := fmt.Sprintf("%03d-client-request.ber", seq)
	if err := writeRawFile(connDir, filename, msg.raw); err != nil {
		return pdu{}, err
	}
	rp := RecordedPDU{
		Sequence:  seq,
		Filename:  filename,
		Operation: operationLabel(msg.opTag),
		MessageID: msg.messageID,
		Raw:       msg.raw,
	}
	if msg.hasAbandon {
		rp.HasAbandon = true
		rp.AbandonTarget = msg.abandonTarget
	}
	res.PDUs = append(res.PDUs, rp)
	if _, err := upstream.Write(msg.raw); err != nil {
		return msg, errProxy("forward client request upstream", err)
	}
	return msg, nil
}

func writeRawFile(dir, name string, content []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errMalformedFrame("create raw connection directory", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
		return errMalformedFrame("write raw PDU file", err)
	}
	return nil
}

// pass implements "serve --mode pass" (plan §22): forward client and server
// bytes unchanged; record every client request PDU. The client direction is
// framed PDU-by-PDU so each can be recorded; the raw bytes forwarded are
// exactly the bytes readLDAPMessage read, so forwarding stays byte-for-byte
// exact even though it passes through PDU framing. The server direction is
// a plain byte copy since only client requests are in scope for recording.
func (r *Recorder) pass(client net.Conn, upstream net.Conn, connDir string, res *ConnResult) {
	clientR := bufio.NewReader(client)

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		_, _ = io.Copy(client, upstream)
	}()

	for {
		_, err := r.recordAndForward(clientR, upstream, connDir, res)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			res.Err = err
			break
		}
	}
	_ = upstream.Close()
	<-upstreamDone
}

// stallAfterBind implements "serve --mode stall-after-bind" (plan §22/§23):
// forward Bind and its response normally, forward the Search request, then
// withhold every Search response from the client while draining them from
// upstream, and wait (up to the injected deadline) for the client's own
// Abandon, forwarding it upstream if the connection is still usable, then
// retain the connection for an observed Unbind or EOF.
func (r *Recorder) stallAfterBind(client net.Conn, upstream net.Conn, connDir string, res *ConnResult) {
	clientR := bufio.NewReader(client)
	upstreamR := bufio.NewReader(upstream)

	bindReq, err := r.recordAndForward(clientR, upstream, connDir, res)
	if err != nil {
		res.Err = err
		return
	}
	if bindReq.opTag != tagBindRequest {
		res.Err = errMalformedFrame("stall-after-bind expects Bind first",
			fmt.Errorf("got operation %q", operationLabel(bindReq.opTag)))
		return
	}

	bindResp, err := readLDAPMessage(upstreamR)
	if err != nil {
		res.Err = errProxy("read Bind response from upstream", err)
		return
	}
	if _, err := client.Write(bindResp.raw); err != nil {
		res.Err = errProxy("forward Bind response to client", err)
		return
	}

	searchReq, err := r.recordAndForward(clientR, upstream, connDir, res)
	if err != nil {
		res.Err = err
		return
	}
	if searchReq.opTag == tagUnbindRequest {
		// Client ended the session before issuing Search; nothing to stall.
		return
	}
	if searchReq.opTag != tagSearchRequest {
		res.Err = errMalformedFrame("stall-after-bind expects Search after Bind",
			fmt.Errorf("got operation %q", operationLabel(searchReq.opTag)))
		return
	}

	// Drain and drop every Search response from upstream so its write side
	// never blocks, without ever forwarding any of it to the client.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			if _, err := readLDAPMessage(upstreamR); err != nil {
				return
			}
		}
	}()

	if err := client.SetReadDeadline(time.Now().Add(r.deadline())); err != nil {
		res.Err = errProxy("set stall deadline", err)
		_ = upstream.Close()
		<-drainDone
		return
	}

	for {
		msg, err := r.recordAndForward(clientR, io.Discard, connDir, res)
		if err != nil {
			// recordAndForward already recorded/appended nothing on read
			// failure; distinguish EOF, timeout and malformed framing.
			if errors.Is(err, io.EOF) {
				break
			}
			if ne, ok := errUnwrapNetError(err); ok && ne.Timeout() {
				res.StalledOn = "deadline-exceeded-awaiting-abandon-or-unbind"
				break
			}
			res.Err = err
			break
		}
		switch msg.opTag {
		case tagAbandonRequest:
			if _, werr := upstream.Write(msg.raw); werr != nil {
				// "forward it upstream if possible" — upstream may already
				// be gone; that is not fatal to observing the Abandon.
				_ = errProxy("forward Abandon upstream", werr)
			}
			continue
		case tagUnbindRequest:
			return
		default:
			res.Err = errMalformedFrame("unexpected PDU while awaiting Abandon/Unbind",
				fmt.Errorf("got operation %q", operationLabel(msg.opTag)))
			return
		}
	}

	_ = upstream.Close()
	<-drainDone
}

// errUnwrapNetError finds a net.Error (for its Timeout() check) anywhere in
// err's wrap chain, without ever formatting err's own text (which may be
// this package's own errMalformedFrame/errProxy output and must not be
// re-embedded here in any way that could duplicate raw content downstream).
func errUnwrapNetError(err error) (net.Error, bool) {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne, true
	}
	return nil, false
}
