package ldapserver

import (
	"bufio"
	"net"
	"sync"
	"time"

	ldap "github.com/vjeantet/goldap/message"
)

// MaxInFlightRequestsPerClient bounds how many ProcessRequestMessage
// executions (goroutines, or the synchronous StartTLS call in serve()) one
// client connection may have concurrently live — see acquireRequestSlot/
// releaseRequestSlot below and PATCHES.md's third item. Without this cap, a
// client that keeps sending requests while never reading its own responses
// could make the server spawn one handler goroutine per inbound message
// forever, each one eventually piling up blocked trying to send its
// response on chanOut once the single writer goroutine itself blocks on a
// stalled write. 20 matches this file's own long-standing (if previously
// unenforced) intent — see the stale "buffered to 20" comment this same
// fix replaces in serve() below.
const MaxInFlightRequestsPerClient = 20

type client struct {
	Numero        int
	srv           *Server
	rwc           net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	chanOut       chan *ldap.LDAPMessage
	inFlight      chan struct{} // semaphore, capacity MaxInFlightRequestsPerClient
	wg            sync.WaitGroup
	closing       chan bool
	shutdownDone  chan struct{}
	requestList   map[int]*Message
	mutex         sync.Mutex
	writeDone     chan bool
	rawData       []byte
	data          any
	handler       Handler
	hasOwnHandler bool
}

// acquireRequestSlot blocks until this client has fewer than
// MaxInFlightRequestsPerClient ProcessRequestMessage executions live, or
// the server is shutting down (s.chDone closed), and returns false only in
// the latter case. Selecting on srv.chDone here (rather than only on
// c.closing, which is closed by this same client's own close() — too late
// to help unblock the goroutine that close() is waiting on) is what keeps
// a client stuck waiting for a slot — every slot held by a handler blocked
// writing to a peer that has stopped reading its responses, until the
// write-deadline fix in writeMessage below frees them again — from itself
// blocking server-wide Stop().
func (c *client) acquireRequestSlot() bool {
	select {
	case c.inFlight <- struct{}{}:
		return true
	case <-c.srv.chDone:
		return false
	}
}

// releaseRequestSlot frees one in-flight slot acquired by
// acquireRequestSlot. Every acquire must have exactly one matching release,
// on every return path (success, panic-recovered handler, or abandonment)
// — see the two call sites in serve() below, both of which release via
// defer.
func (c *client) releaseRequestSlot() {
	<-c.inFlight
}

func (c *client) GetConn() net.Conn {
	return c.rwc
}

func (c *client) GetRaw() []byte {
	return c.rawData
}

// GetData returns the custom data associated with this client connection.
func (c *client) GetData() any {
	return c.data
}

// SetData associates arbitrary custom data with this client connection.
// This can be used by handlers to store per-connection state such as
// authentication results or session information.
func (c *client) SetData(data any) {
	c.data = data
}

func (c *client) SetConn(conn net.Conn) {
	c.rwc = conn
	c.br = bufio.NewReader(c.rwc)
	c.bw = bufio.NewWriter(c.rwc)
}

func (c *client) GetMessageByID(messageID int) (*Message, bool) {
	c.mutex.Lock()
	requestToAbandon, ok := c.requestList[messageID]
	c.mutex.Unlock()
	if ok {
		return requestToAbandon, true
	}
	return nil, false
}

func (c *client) Addr() net.Addr {
	return c.rwc.RemoteAddr()
}

func (c *client) ReadPacket() (*messagePacket, error) {
	mP, err := readMessagePacket(c.br)
	c.rawData = make([]byte, len(mP.bytes))
	copy(c.rawData, mP.bytes)
	return mP, err
}

func (c *client) callOnClose() {
	if c == nil || c.srv == nil || c.srv.OnClientClose == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			Logger.Printf("panic in OnClientClose for client [%d]: %v", c.Numero, r)
		}
	}()

	c.srv.OnClientClose(c.rwc, c.data)
}

func (c *client) serve() {
	defer c.close()

	c.closing = make(chan bool)
	c.shutdownDone = make(chan struct{})

	// Create the ldap response queue to be written to client. This channel
	// is deliberately unbuffered: bounding how many responses can be
	// in-flight at once is MaxInFlightRequestsPerClient's job (it bounds
	// how many ProcessRequestMessage executions — and therefore how many
	// goroutines can ever be trying to send on this channel at once — a
	// client may have live), not this channel's buffer size. See
	// acquireRequestSlot/releaseRequestSlot above.
	c.chanOut = make(chan *ldap.LDAPMessage)
	c.inFlight = make(chan struct{}, MaxInFlightRequestsPerClient)
	c.writeDone = make(chan bool)
	// for each message in c.chanOut send it to client. Once one write
	// fails (see writeMessage's WriteTimeout enforcement), stop attempting
	// further writes to this now-presumed-dead connection — but keep
	// draining chanOut without blocking, so every handler goroutine
	// (including ones still to come) that is, or will be, blocked trying
	// to send its response here is promptly unblocked rather than left
	// waiting forever. That in turn is what lets close() below's wg.Wait()
	// (and, transitively, Server.Stop()'s own wg.Wait()) complete instead
	// of hanging on a client that stopped reading its responses. See
	// PATCHES.md's third item.
	go func() {
		writeFailed := false
		for msg := range c.chanOut {
			if writeFailed {
				continue
			}
			if err := c.writeMessage(msg); err != nil {
				Logger.Printf("client %d write error, closing connection: %s", c.Numero, err)
				writeFailed = true
				c.rwc.Close()
			}
		}
		close(c.writeDone)
	}()

	// Listen for server signal to shutdown
	go func() {
		defer close(c.shutdownDone)
		for {
			select {
			case <-c.srv.chDone: // server signals shutdown process
				r := NewExtendedResponse(LDAPResultUnwillingToPerform)
				r.SetDiagnosticMessage("server is about to stop")
				r.SetResponseName(NoticeOfDisconnection)

				m := ldap.NewLDAPMessageWithProtocolOp(r)

				c.chanOut <- m
				c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
				return
			case <-c.closing:
				return
			}
		}
	}()

	if onc := c.srv.OnNewConnection; onc != nil {
		if err := onc(c.rwc); err != nil {
			Logger.Printf("Erreur OnNewConnection: %s", err)
			return
		}
	}

	c.requestList = make(map[int]*Message)

	for {

		if c.srv.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
		}
		// WriteTimeout is deliberately NOT re-armed here on a fixed
		// per-read-loop-iteration schedule (as it used to be, and as
		// ReadTimeout still is above): a deadline set here would keep
		// getting pushed further into the future every time this client
		// merely sends another request, even while the single writer
		// goroutine sits blocked trying to flush an earlier response to a
		// peer that has stopped reading entirely — exactly defeating the
		// bound this deadline exists to enforce. writeMessage (see below)
		// instead sets WriteTimeout immediately before each actual
		// bw.Write/Flush call, so the deadline is tied to a real pending
		// write, not to unrelated read activity on the same connection.
		// See PATCHES.md's third item.

		//Read client input as a ASN1/BER binary message
		messagePacket, err := c.ReadPacket()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				Logger.Printf("Sorry client %d, i can not wait anymore (reading timeout) ! %s", c.Numero, err)
			} else {
				Logger.Printf("Error readMessagePacket: %s", err)
			}
			return
		}

		//Convert ASN1 binaryMessage to a ldap Message
		message, err := messagePacket.readMessage()

		if err != nil {
			Logger.Printf("Error reading Message : %s\n\t%x", err.Error(), messagePacket.bytes)
			continue
		}
		Logger.Printf("<<< %d - %s - hex=%x", c.Numero, message.ProtocolOpName(), messagePacket)

		// When message is an UnbindRequest, stop serving
		if _, ok := message.ProtocolOp().(ldap.UnbindRequest); ok {
			return
		}

		// Bound how many ProcessRequestMessage executions this client may
		// have concurrently live before dispatching this one — see
		// acquireRequestSlot/MaxInFlightRequestsPerClient above and
		// PATCHES.md's third item. A false return means the server is
		// shutting down while we were waiting for a slot; stop serving
		// rather than dispatch into a closing server.
		if !c.acquireRequestSlot() {
			return
		}

		// If client requests a startTls, do not handle it in a
		// goroutine, connection has to remain free until TLS is OK
		// @see RFC https://tools.ietf.org/html/rfc4511#section-4.14.1
		if req, ok := message.ProtocolOp().(ldap.ExtendedRequest); ok {
			if req.RequestName() == NoticeOfStartTLS {
				c.wg.Add(1)
				c.ProcessRequestMessage(&message)
				c.releaseRequestSlot()
				continue
			}
		}

		// TODO: go/non go routine choice should be done in the ProcessRequestMessage
		// not in the client.serve func
		c.wg.Add(1)
		go func() {
			defer c.releaseRequestSlot()
			c.ProcessRequestMessage(&message)
		}()
	}

}

// close closes client,
// * stop reading from client
// * signals to all currently running request processor to stop
// * wait for all request processor to end
// * close client connection
// * signal to server that client shutdown is ok
func (c *client) close() {
	Logger.Printf("client %d close()", c.Numero)
	defer c.srv.wg.Done()

	close(c.closing)
	<-c.shutdownDone // wait for shutdown-listener goroutine to finish

	// stop reading from client
	c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
	Logger.Printf("client %d close() - stop reading from client", c.Numero)

	// signals to all currently running request processor to stop
	c.mutex.Lock()
	for messageID, request := range c.requestList {
		Logger.Printf("Client %d close() - sent abandon signal to request[messageID = %d]", c.Numero, messageID)
		go request.Abandon()
	}
	c.mutex.Unlock()
	Logger.Printf("client %d close() - Abandon signal sent to processors", c.Numero)

	c.wg.Wait()      // wait for all current running request processor to end
	close(c.chanOut) // No more message will be sent to client, close chanOUT
	Logger.Printf("client [%d] request processors ended", c.Numero)

	<-c.writeDone // Wait for the last message sent to be written
	c.callOnClose()
	c.rwc.Close() // close client connection
	Logger.Printf("client [%d] connection closed", c.Numero)
}

// writeMessage serializes and writes m to the client, returning any error
// from the write/flush so the caller (the single per-client writer
// goroutine in serve() above) can stop attempting further writes to a dead
// connection instead of looping forever.
//
// The write deadline is set here, immediately before the actual
// bw.Write/Flush call, rather than only relying on the per-read-loop-
// iteration SetWriteDeadline call in serve() below: that call only bounds
// how long a client may take between finishing one read and starting the
// next, but this writer goroutine runs independently of the read loop and
// can be asked to write at any time — including while the read loop is
// itself blocked waiting on a request slot (see acquireRequestSlot above).
// Without enforcing the deadline at the point of the actual write, a peer
// that stops reading its own responses could block this goroutine (and,
// transitively, every handler blocked sending to chanOut, and the
// shutdown-listener goroutine's own Notice-of-Disconnection send)
// indefinitely. See PATCHES.md's third item for the full writeup.
func (c *client) writeMessage(m *ldap.LDAPMessage) error {
	data, _ := m.Write()
	Logger.Printf(">>> %d - %s - hex=%x", c.Numero, m.ProtocolOpName(), data.Bytes())

	if c.srv.WriteTimeout != 0 {
		if err := c.rwc.SetWriteDeadline(time.Now().Add(c.srv.WriteTimeout)); err != nil {
			return err
		}
	}
	if _, err := c.bw.Write(data.Bytes()); err != nil {
		return err
	}
	return c.bw.Flush()
}

// ResponseWriter interface is used by an LDAP handler to
// construct an LDAP response.
type ResponseWriter interface {
	// Write writes the LDAPResponse to the connection as part of an LDAP reply.
	Write(po ldap.ProtocolOp)
}

type responseWriterImpl struct {
	chanOut   chan *ldap.LDAPMessage
	messageID int
}

func (w responseWriterImpl) Write(po ldap.ProtocolOp) {
	m := ldap.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	w.chanOut <- m
}

func (w responseWriterImpl) writeWithControls(po ldap.ProtocolOp, controls ldap.Controls) {
	m := ldap.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	m.SetControls(controls.Pointer())
	w.chanOut <- m
}

// controlsWriter is an optional interface for ResponseWriter implementations
// that support attaching controls to an LDAP response message.
type controlsWriter interface {
	writeWithControls(po ldap.ProtocolOp, controls ldap.Controls)
}

// WriteWithControls writes an LDAP response with the given controls attached
// to the LDAPMessage envelope. If the ResponseWriter does not support controls,
// it falls back to w.Write(po).
func WriteWithControls(w ResponseWriter, po ldap.ProtocolOp, controls ...ldap.Control) {
	if cw, ok := w.(controlsWriter); ok {
		cw.writeWithControls(po, ldap.Controls(controls))
		return
	}
	w.Write(po)
}

func (c *client) ProcessRequestMessage(message *ldap.LDAPMessage) {
	defer c.wg.Done()

	var m Message
	m = Message{
		LDAPMessage: message,
		Done:        make(chan bool, 2),
		Client:      c,
	}

	c.registerRequest(&m)
	defer c.unregisterRequest(&m)

	var w responseWriterImpl
	w.chanOut = c.chanOut
	w.messageID = m.MessageID().Int()

	if c.handler != nil {
		c.handler.ServeLDAP(w, &m)
	} else {
		c.srv.Handler.ServeLDAP(w, &m)
	}
}

func (c *client) registerRequest(m *Message) {
	c.mutex.Lock()
	c.requestList[m.MessageID().Int()] = m
	c.mutex.Unlock()
}

func (c *client) unregisterRequest(m *Message) {
	c.mutex.Lock()
	delete(c.requestList, m.MessageID().Int())
	c.mutex.Unlock()
}
