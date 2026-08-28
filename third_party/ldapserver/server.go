package ldapserver

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

type HandlerSource interface {
	GetHandler() Handler
}

type ClientCloseHandler func(conn net.Conn, data any)

// Server is an LDAP server.
type Server struct {
	Listener     net.Listener
	ReadTimeout  time.Duration // optional read timeout
	WriteTimeout time.Duration // optional write timeout
	// MaxConnections optionally bounds how many connections this server
	// serves concurrently. Zero (the Go default) means unbounded, preserving
	// prior behavior for any caller that never sets it. This is a distinct
	// property from ReadTimeout/WriteTimeout above: those bound how long any
	// ONE accepted connection may hold its per-message body buffer (see
	// packet.go's maxMessageBodyLength and readBytes), but neither bounds
	// how many connections can do that AT ONCE — an unauthenticated client
	// need only complete the length-declaring header (a handful of bytes)
	// to make readBytes allocate that buffer before ever blocking, so N
	// concurrent sockets each doing that pins N*maxMessageBodyLength bytes
	// of live server memory for up to ReadTimeout, with nothing capping N.
	// serve() below enforces this cap by rejecting (closing immediately,
	// before any per-connection buffer is created) any connection accepted
	// once MaxConnections are already live — turning
	// MaxConnections*maxMessageBodyLength into an explicit, arithmetic
	// worst-case bound on aggregate pre-auth memory instead of an unbounded
	// one. See PATCHES.md's fourth item.
	MaxConnections int
	wg             sync.WaitGroup // group of goroutines (1 by client)
	chDone         chan bool      // Channel Done, value => shutdown
	// connSlots is the buffered-channel semaphore enforcing MaxConnections,
	// capacity MaxConnections, lazily created by serve() the first time it
	// runs. nil when MaxConnections is zero (unbounded).
	connSlots chan struct{}

	// TLSConfig optionally provides a TLS configuration for use by ServeTLS.
	TLSConfig *tls.Config

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// OnClientClose, if non-nil, is called once when a client session ends.
	// It runs after request processing has stopped and before the connection is
	// closed. The hook must not block because it runs on the shutdown path and
	// a blocking hook prevents Stop from completing. Data may be nil because
	// the hook runs for every closed connection, including connections rejected
	// by OnNewConnection or closed before SetData is called.
	OnClientClose ClientCloseHandler

	// Handler handles ldap message received from client
	// it SHOULD "implement" RequestHandler interface
	Handler          Handler
	useHandlerSource bool
	handlerSource    HandlerSource
}

// NewServer return a LDAP Server
func NewServer() *Server {
	return &Server{
		chDone: make(chan bool),
	}
}

// NewServer returns an LDAP Server, with a dedicated handler for each connection
// different to the "Handler", this allows one struct (object) for each connection.
// this is intented to pass information from one handle function to another, for
// example, if Bind() fails, a flag may be set in the source to decline subsequent searches
// (or limit them in scope).
func NewServerWithHandlerSource(hs HandlerSource) *Server {
	return &Server{
		handlerSource:    hs,
		useHandlerSource: true,
		chDone:           make(chan bool),
	}
}

// Handle registers the handler for the server.
// If a handler already exists for pattern, Handle panics
func (s *Server) Handle(h Handler) {
	if s.useHandlerSource {
		panic("LDAP: attempt to register handler and a handlersource")
	}
	if s.Handler != nil {
		panic("LDAP: multiple Handler registrations")
	}
	s.Handler = h
}

// Serve accepts incoming LDAP connections on the given listener.
// The Server takes ownership of the listener and will close it when Stop is called.
func (s *Server) Serve(listener net.Listener) error {
	s.Listener = listener
	return s.serve()
}

// ServeTLS wraps the given listener with TLS using s.TLSConfig
// and accepts incoming LDAP connections.
func (s *Server) ServeTLS(listener net.Listener) error {
	s.Listener = tls.NewListener(listener, s.TLSConfig)
	return s.serve()
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe(addr string, options ...func(*Server)) error {
	if addr == "" {
		addr = ":389"
	}

	var e error
	s.Listener, e = net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	Logger.Printf("Listening on %s\n", addr)

	for _, option := range options {
		option(s)
	}

	return s.serve()
}

// Handle requests messages on the ln listener
func (s *Server) serve() error {
	if s.Handler == nil && !s.useHandlerSource {
		Logger.Panicln("No LDAP Request Handler defined")
	}

	i := 0

	if s.MaxConnections > 0 {
		s.connSlots = make(chan struct{}, s.MaxConnections)
	}

	for {
		rw, err := s.Listener.Accept()
		if err != nil {
			select {
			case <-s.chDone:
				Logger.Print("Stopping server")
				return nil
			default:
			}
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			Logger.Println(err)
			return err
		}

		// Enforce MaxConnections before any per-connection buffer is ever
		// created for this socket (see the field doc above): a non-blocking
		// acquire attempt means an already-saturated server rejects this
		// connection immediately rather than growing an accept-side queue of
		// its own or blocking Accept for connections that could otherwise be
		// served once a slot frees.
		if s.connSlots != nil {
			select {
			case s.connSlots <- struct{}{}:
			default:
				rw.Close()
				continue
			}
		}

		if s.ReadTimeout != 0 {
			rw.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 {
			rw.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		cli, err := s.newClient(rw)
		if err != nil {
			if s.connSlots != nil {
				<-s.connSlots
			}
			continue
		}

		i = i + 1
		cli.Numero = i
		Logger.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
		s.wg.Add(1)
		go func(c *client) {
			c.serve()
			if s.connSlots != nil {
				<-s.connSlots
			}
		}(cli)
	}
}

// Return a new session with the connection
// client has a writer and reader buffer
func (s *Server) newClient(rwc net.Conn) (c *client, err error) {
	c = &client{
		srv: s,
		rwc: rwc,
		br:  bufio.NewReader(rwc),
		bw:  bufio.NewWriter(rwc),
	}
	if s.useHandlerSource {
		c.handler = s.handlerSource.GetHandler()
	}
	return c, nil
}

// Termination of the LDAP session is initiated by the server sending a
// Notice of Disconnection.  In this case, each
// protocol peer gracefully terminates the LDAP session by ceasing
// exchanges at the LDAP message layer, tearing down any SASL layer,
// tearing down any TLS layer, and closing the transport connection.
// A protocol peer may determine that the continuation of any
// communication would be pernicious, and in this case, it may abruptly
// terminate the session by ceasing communication and closing the
// transport connection.
// In either case, when the LDAP session is terminated.
func (s *Server) Stop() {
	close(s.chDone)
	s.Listener.Close()
	Logger.Print("gracefully closing client connections...")
	s.wg.Wait()
	Logger.Print("all clients connection closed")
}
