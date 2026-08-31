package profile

// This file implements the plan's "Server lifecycle", "Connection and
// framing model" (production shape), "Operation dispatch", "Abandon", and
// "Unbind" sections: the public Server type (New/Serve/Stop), the
// 256-connection admission cap, the package's one production goroutine
// spawn, the per-connection read/dispatch/respond loop, and dispatch on
// application tag for Bind/Search/Abandon/Unbind/the six recognizable
// unsupported operations/critical controls. Bind/Search's own decoders
// live in bind.go/search.go; this file routes to them and owns
// everything generic to every other operation.

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// lifecycleState is Server's one-shot lifecycle state machine: new ->
// serving -> stopping -> stopped. No other transition is legal.
type lifecycleState uint8

const (
	stateNew lifecycleState = iota
	stateServing
	stateStopping
	stateStopped
)

// Fixed construction/lifecycle errors: sentinels so callers/tests compare
// with errors.Is/== rather than a formatted string, none ever echoing
// caller-supplied text (New's "fixed non-credential construction error"
// guard). errServeAlreadyCalled is a duplicate/concurrent Serve while a
// prior one is still (or already) running; errServerStopped is Serve
// called after Stop (including Stop-before-Serve); errUnbindRequested is
// handleUnbindRequest's signal that the connection loop must exit —
// Unbind sends no response and is not itself an error, but shares the
// loop's one "non-nil return means stop reading this connection" path.
var (
	errNilRootCtx         = errors.New("ldap: rootCtx must not be nil")
	errNilVerifier        = errors.New("ldap: verifier must not be nil")
	errNilRoleResolver    = errors.New("ldap: roleResolver must not be nil")
	errServeAlreadyCalled = errors.New("ldap/profile: Serve already called")
	errServerStopped      = errors.New("ldap/profile: server already stopped")
	errUnbindRequested    = errors.New("ldap/profile: unbind requested")
)

// maxConnections is the hard, process-wide cap on concurrently admitted
// connections (see "Admission" in the plan): 256 * maxBodyBytes (64 KiB)
// bounds aggregate pre-auth request-body memory at 16 MiB, not RSS.
const maxConnections = 256

// Server is the profile compatibility server's production surface: New,
// Serve, Stop. It owns only lifecycle state — an active-connection set
// for admission/shutdown bookkeeping, never a request-indexed map,
// registry, or scheduler (see "Connection and framing model"). mu is
// never held across a wait on serveDone, connWG, network I/O, or another
// completion channel (see "Stop lock discipline") — only the small state
// transitions themselves.
type Server struct {
	cfg      parsedConfig
	ctx      context.Context
	cancel   context.CancelFunc
	verifier Verifier
	roles    RoleResolver

	mu       sync.Mutex
	state    lifecycleState
	listener net.Listener
	active   map[net.Conn]struct{}
	connWG   sync.WaitGroup

	serveDone chan struct{}
	stopDone  chan struct{}

	// readTimeout/writeTimeout/clock: unexported, unconfigurable from
	// outside the package by design (plan's "no exported options") —
	// production gets 30s/time.Now; package-local tests shorten/swap
	// them directly on the *Server New returns, before calling Serve.
	readTimeout  time.Duration
	writeTimeout time.Duration
	clock        func() time.Time
}

// New validates cfg, rootCtx, v, and r, and returns a Server ready to
// Serve, matching current production's construction guards exactly
// (error text included; see "New construction guards"). rootCtx governs
// every in-flight operation for as long as the server runs: New derives
// its own cancelable lifecycle context from it, so either rootCtx's own
// cancellation or a later Stop() cancels every connection's in-flight
// Verify/Search the same way (see "Cancellation compatibility").
func New(rootCtx context.Context, cfg Config, v Verifier, r RoleResolver) (*Server, error) {
	if rootCtx == nil {
		return nil, errNilRootCtx
	}
	if v == nil {
		return nil, errNilVerifier
	}
	if r == nil {
		return nil, errNilRoleResolver
	}

	// parseConfig's own sentinels are already fixed, non-credential
	// errors (see config.go) — nothing to wrap here.
	parsed, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(rootCtx)
	return &Server{
		cfg:      parsed,
		ctx:      ctx,
		cancel:   cancel,
		verifier: v,
		roles:    r,

		state:  stateNew,
		active: make(map[net.Conn]struct{}),

		serveDone: make(chan struct{}),
		stopDone:  make(chan struct{}),

		readTimeout:  defaultDeadline,
		writeTimeout: defaultDeadline,
		clock:        time.Now,
	}, nil
}

// Serve accepts and serves connections on l until Stop is called or a
// fatal Accept error occurs. The caller owns creating l (this package
// never calls net.Listen itself — see doc.go "Phase 2 status"). A
// duplicate/concurrent call (state already serving) returns
// errServeAlreadyCalled; a call after Stop (stopping/stopped, including
// Stop-before-Serve) returns errServerStopped. serveDone closes exactly
// once, via defer, whichever way the accept loop below exits.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	switch s.state {
	case stateServing:
		s.mu.Unlock()
		return errServeAlreadyCalled
	case stateStopping, stateStopped:
		s.mu.Unlock()
		return errServerStopped
	}
	s.state = stateServing
	s.listener = l
	s.mu.Unlock()

	defer close(s.serveDone)

	for {
		conn, err := l.Accept()
		if err != nil {
			// Preserve current policy: a timeout retries; every other
			// error is terminal (never busy-loop).
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				ourStop := s.state == stateStopping || s.state == stateStopped
				s.mu.Unlock()
				if ourStop {
					// The listener closed as part of our own Stop: a
					// clean, expected shutdown, not a caller-visible error.
					return nil
				}
				// An external caller closed l out from under us — still
				// terminal, but distinguishable via errors.Is(net.ErrClosed).
				return err
			}
			return err
		}

		s.admit(conn)
	}
}

// admit applies the 256-connection cap and, if room remains, spawns the
// package's one production goroutine to serve conn. A connection that
// fails admission never has a request body read or allocated for it, and
// gets no goroutine at all — it is closed immediately.
func (s *Server) admit(conn net.Conn) {
	s.mu.Lock()
	if s.state != stateServing || len(s.active) >= maxConnections {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.active[conn] = struct{}{}
	s.connWG.Add(1)
	s.mu.Unlock()

	go s.serveConnection(conn)
}

// serveConnection is the package's sole per-connection goroutine body: it
// builds the one connection value this socket ever uses, then loops
// reading one bounded LDAPMessage, dispatching it synchronously, and
// writing whatever bounded response(s) that produced, until a read,
// dispatch, or write failure ends the loop. Its deferred cleanup closes
// the socket, deletes it from the active set, and marks it done — slot
// reuse is defined by the visibility of that deletion ("Connection exit").
func (s *Server) serveConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		delete(s.active, conn)
		s.mu.Unlock()
		s.connWG.Done()
	}()

	// ctx is the lifecycle context, not context.Background(): Stop() and
	// root-context cancellation must cancel an in-flight Verify (see
	// "Root/process cancellation retained").
	c := &connection{
		nc:           conn,
		ctx:          s.ctx,
		cfg:          &s.cfg,
		verifier:     s.verifier,
		roles:        s.roles,
		clock:        s.clock,
		readTimeout:  s.readTimeout,
		writeTimeout: s.writeTimeout,
	}

	for {
		if err := conn.SetReadDeadline(s.clock().Add(s.readTimeout)); err != nil {
			return
		}
		// Malformed frame/envelope/Controls, a stalled/expired read, or a
		// transport failure all close the connection without resync.
		env, err := readMessage(conn)
		if err != nil {
			return
		}
		// dispatchOperation's error covers errUnbindRequested (Unbind:
		// exit the loop, no response) and errMalformed (unknown tag, or
		// recognized-but-invalid content) alike — both close the
		// connection the same way.
		if err := dispatchOperation(c, env); err != nil {
			return
		}
	}
}

// dispatchOperation routes one decoded LDAPMessage by its protocolOp
// application tag ("Operation dispatch"). It never decodes
// operation-specific payload fields for the six unsupported shapes, and
// never resynchronizes on an unrecognized tag — including a client-sent
// response tag, which has no safe fixed mapping and closes just like a
// malformed frame.
func dispatchOperation(c *connection, env Envelope) error {
	switch env.ProtocolOp {
	case tagBindRequest:
		return c.handleBind(env.MessageID, env.Content, env.HasCritical)
	case tagSearchRequest:
		return c.handleSearch(env.MessageID, env.Content, env.HasCritical)
	case tagAbandonRequest:
		return handleAbandonRequest(env.Content, env.HasCritical)
	case tagUnbindRequest:
		return handleUnbindRequest(env.Content)
	case tagAddRequest:
		return c.handleUnsupported(env.MessageID, byte(tagAddResponse), opAdd, false, env.HasCritical)
	case tagModifyRequest:
		return c.handleUnsupported(env.MessageID, byte(tagModifyResponse), opModify, false, env.HasCritical)
	case tagDelRequest:
		return c.handleUnsupported(env.MessageID, byte(tagDelResponse), opDelete, false, env.HasCritical)
	case tagCompareRequest:
		return c.handleUnsupported(env.MessageID, byte(tagCompareResponse), opCompare, false, env.HasCritical)
	case tagModifyDNRequest:
		return c.handleUnsupported(env.MessageID, byte(tagModifyDNResponse), opModifyDN, false, env.HasCritical)
	case tagExtendedRequest:
		// Includes non-critical Cancel, deliberately treated as an
		// ordinary unsupported Extended request ("Deliberate Cancel
		// narrowing"): no target lookup/scheduling ever happens here.
		return c.handleUnsupported(env.MessageID, byte(tagExtendedResponse), opExtended, true, env.HasCritical)
	default:
		return errMalformed
	}
}

// handleAbandonRequest implements "Abandon": content is AbandonRequest's
// [APPLICATION 16] IMPLICIT MessageID content bytes (Envelope.Content,
// already tag/length-stripped and wire-identical to a plain INTEGER's
// content per Amendment 6), validated with the same minimalPositiveInt32
// rule the envelope MessageID uses. The decoded target is never looked
// up or acted on: no response, no cancellation, no retained target, no
// Verify/Roles invocation, regardless of criticality. A critical Abandon
// additionally emits the fixed critical-control-rejection log (still no
// response/target action); non-critical logs nothing — silently dropped.
func handleAbandonRequest(content []byte, hasCritical bool) error {
	if _, err := minimalPositiveInt32(content); err != nil {
		return errMalformed
	}
	if hasCritical {
		logCriticalControlRejected(opAbandon)
	}
	return nil
}

// handleUnbindRequest implements "Unbind": UnbindRequest is
// [APPLICATION 2] with no content at all, so any non-empty content is not
// a recognizable Unbind and closes the same way a malformed frame would.
// A valid (empty) Unbind sends no response and signals the loop to exit
// and destroy state via errUnbindRequested — criticality is irrelevant
// either way (critical-controls table's Unbind row: "close; no response"
// unconditionally).
func handleUnbindRequest(content []byte) error {
	if len(content) != 0 {
		return errMalformed
	}
	return errUnbindRequested
}

// handleUnsupported implements the fixed mapped response for one of the
// six recognizable-but-unsupported request shapes (Add/Modify/Delete/
// Compare/ModifyDN/Extended incl. non-critical Cancel): appTag is the
// matching *Response tag as a byte, o is the fixed op literal for
// logging, and extended selects the Extended-only diagnostic text versus
// every other operation's empty diagnostic. Payload fields (and, for
// Extended, the requested OID) are never decoded — env.Content is not
// even passed in.
func (c *connection) handleUnsupported(msgID int32, appTag byte, o op, extended bool, hasCritical bool) error {
	if hasCritical {
		d := diagEmpty
		if extended {
			d = diagCriticalControl
		}
		logCriticalControlRejected(o)
		return c.writeUnsupportedResponse(msgID, appTag, resultUnavailableCriticalExtension, d)
	}

	d := diagEmpty
	if extended {
		d = diagOperationUnsupported
	}
	logOperationUnsupported(o)
	return c.writeUnsupportedResponse(msgID, appTag, resultUnwillingToPerform, d)
}

// writeUnsupportedResponse encodes and writes one of the six mapped
// unsupported-operation responses, setting the write deadline
// immediately before writing, matching every other response writer in
// this package (bind.go's writeBindResponse, search.go's
// writeSearchResultDone).
func (c *connection) writeUnsupportedResponse(msgID int32, appTag byte, result int32, d diagnostic) error {
	resp, err := encodeUnsupportedResponse(msgID, appTag, int(result), d)
	if err != nil {
		return err
	}
	if err := c.nc.SetWriteDeadline(c.clock().Add(c.writeTimeout)); err != nil {
		return err
	}
	_, err = c.nc.Write(resp)
	return err
}

// Stop gracefully shuts down the server: stops accepting new connections,
// cancels the lifecycle context (unblocking any in-flight Verify), closes
// every currently admitted connection, and waits for all of them to
// finish before returning. Repeated/concurrent Stop calls all converge on
// the same shutdown completing exactly once ("stopDone"). The lifecycle
// mutex is held only for the small state-transition/snapshot steps below
// — never across closing the listener, serveDone, closing connections,
// or connWG ("Stop lock discipline").
func (s *Server) Stop() {
	s.mu.Lock()
	switch s.state {
	case stateNew:
		// Serve was never called: nothing to wait for ("Stop-before-Serve").
		s.state = stateStopped
		s.cancel()
		close(s.stopDone)
		s.mu.Unlock()
		return
	case stateStopping, stateStopped:
		// Another Stop is already in progress or finished: converge
		// rather than repeat shutdown work.
		s.mu.Unlock()
		<-s.stopDone
		return
	}

	s.state = stateStopping
	s.cancel()
	listener := s.listener
	s.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	<-s.serveDone

	s.mu.Lock()
	active := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		active = append(active, conn)
	}
	s.mu.Unlock()

	for _, conn := range active {
		_ = conn.Close()
	}
	s.connWG.Wait()

	s.mu.Lock()
	s.state = stateStopped
	close(s.stopDone)
	s.mu.Unlock()
}
