// Package ldap implements the phase-2 standalone LDAP protocol server:
// connection lifecycle, LDAPv3 simple Bind against the shared verifier,
// and a restricted ClickHouse role-mapping Search, safely rendered from
// per-connection state captured once at Bind time. See the phase-2 plan
// for the full design; this file owns configuration, construction,
// process lifecycle and the per-connection handler-allocation mechanism.
package ldap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/verification"

	ldapserver "github.com/vjeantet/ldapserver"
)

// ldapConnReadTimeout and ldapConnWriteTimeout bound how long the vendored
// ldapserver.Server (constructed in New below) may block on a single read
// or write to one accepted connection. Both are "optional" fields on that
// dependency (see third_party/ldapserver/server.go's doc comments: zero
// disables the deadline) — leaving them at their Go zero value here would
// mean an unauthenticated client that declares a message body up to
// third_party/ldapserver/packet.go's 1 MiB maxMessageBodyLength cap, then
// never finishes sending it, pins that connection's goroutine, buffer, and
// file descriptor indefinitely: client.serve() blocks forever inside
// io.ReadFull with no deadline to interrupt it. This is the same class of
// pre-auth resource exhaustion the sibling ch-jwt-verify command already
// guards against on its own listener via a hardcoded 10s Read/WriteTimeout
// on its http.Server (see cmd/ch-jwt-verify/main.go).
//
// 30s is generous for this consumer's Bind-then-Search exchange over an
// already-accepted TCP connection while still bounding a stalled or
// slow-loris-style client to a small, fixed resource cost instead of an
// unbounded one. WriteTimeout additionally bounds a client that stops
// reading its own responses — see third_party/ldapserver/client.go's
// writeMessage, which enforces this deadline at the actual write/flush
// call, and PATCHES.md's third item for the full writeup of why that,
// combined with a bounded per-client in-flight request count, is what
// keeps such a client from blocking graceful shutdown indefinitely too.
const (
	ldapConnReadTimeout  = 30 * time.Second
	ldapConnWriteTimeout = 30 * time.Second
)

// ldapMaxConnections is a hard, process-wide cap on how many LDAP
// connections the vendored ldapserver.Server (constructed in New below)
// accepts and serves concurrently — see third_party/ldapserver/server.go's
// Server.MaxConnections doc. ldapConnReadTimeout above bounds how long any
// ONE accepted connection may hold its per-message body buffer (declaring,
// but never finishing, a message body up to
// third_party/ldapserver/packet.go's maxMessageBodyLength cap); it does not
// bound how many connections can do that AT ONCE. Without a connection cap,
// an unauthenticated attacker opening many concurrent sockets — each
// sending only the handful of bytes needed to declare a maximal-length
// body — can still pressure aggregate process memory with no ceiling other
// than available file descriptors, even though no single connection can
// hold more than one buffer for longer than ldapConnReadTimeout.
//
// 256 is far more concurrent connections than this consumer
// (cmd/ch-oauth-ldap fronting a single ClickHouse instance's LDAP external
// authentication) ever legitimately opens at once, while combined with
// maxMessageBodyLength it turns aggregate pre-auth memory into an explicit,
// justified arithmetic bound (256 * 64 KiB = 16 MiB worst case) rather than
// an unbounded one.
const ldapMaxConnections = 256

// Config is the immutable external configuration for one LDAP Server,
// converted by the command from the `ldap:` YAML section. See "Configuration
// design" in the phase-2 plan.
type Config struct {
	// Listen is the TCP address the command listens on. internal/ldap never
	// calls net.Listen itself — the caller creates the net.Listener (per
	// "Process and server lifecycle" in the plan) and hands it to
	// Server.Serve — so this field is carried through only for the
	// command's own use/validation, not consumed by this package.
	Listen string
	// UserBaseDN is ldap.user_base_dn: the configured base every valid
	// simple-Bind DN must be exactly one RDN below.
	UserBaseDN string
	// GroupBaseDN is ldap.group_base_dn: the configured base every
	// restricted Search's base object must structurally equal, and the
	// base every synthetic group entry's DN is built under.
	GroupBaseDN string
	// UserRDNAttribute is ldap.user_rdn_attribute: the attribute type a
	// valid Bind DN's leading RDN must carry.
	UserRDNAttribute string
	// RoleCNPrefix is ldap.role_cn_prefix: the transport-representation
	// prefix applied to every mapped role to produce a synthetic group's
	// cn. It is never interpreted or validated against ClickHouse.
	RoleCNPrefix string
}

// verifier is the narrow slice of *verification.Verifier this package
// depends on. Matching the phase-1 API exactly (rather than importing the
// concrete type everywhere) keeps internal/ldap's production code testable
// with small deterministic fakes and makes the dependency direction
// explicit: internal/ldap consumes verification, it never re-implements it.
type verifier interface {
	Verify(ctx context.Context, requestedUsername, token string) (*verification.Result, error)
}

// roleResolver is the narrow slice of *roles.Pipeline this package depends
// on, for the same reason as verifier above.
type roleResolver interface {
	Roles(claims *oauth.Claims) ([]string, error)
}

// Server wraps the vjeantet/ldapserver dependency's connection lifecycle
// (accept loop, per-connection goroutines, graceful shutdown) behind a
// small production surface: New, Serve, Stop.
//
// At most one Server may exist per process at a time. Construct a new one
// only after any prior instance has fully stopped (its Stop call has
// returned) — never concurrently with a still-live or still-tearing-down
// instance. This is not a property of Server itself, but of New's mandatory
// dependency logging hardening below: ldapserver.Logger is a package-level
// global in the vendored dependency, not scoped per-instance, so a second
// concurrent New()/Serve() while a prior instance is still closing
// connections races against that same assignment (see also the related,
// independently-observed Server.wg.Add()/Server.wg.Wait() race against this
// same reassignment documented in adversarial_test.go). That underlying
// dependency race is a known, accepted limitation — out of scope to fix
// here — but the "one Server per process, constructed only after the prior
// one's Stop has returned" discipline this package requires is what avoids
// hitting it in cmd/ch-oauth-ldap's actual usage (exactly one New() call for
// the life of the process).
type Server struct {
	ldapSrv *ldapserver.Server
}

// New validates and parses cfg, and returns a Server ready to Serve. It
// fails construction when the configured user or group base DN cannot be
// parsed (see dn.go) — the plan's "fail startup on invalid configured DNs"
// requirement — or when verifier/roles is nil.
//
// Per the Server type doc above, at most one Server may exist per process
// at a time: New must not be called again until any prior instance's Stop
// has returned, because it unconditionally reassigns the vendored
// dependency's package-level ldapserver.Logger.
//
// rootCtx is the runtime lifecycle context, deliberately a constructor
// argument rather than a Config field: it is not static configuration, it
// governs every handler's cancellation for as long as the server runs (see
// "Runtime context and cancellation" in the phase-2 plan). Every
// per-connection handler this Server ever allocates derives its per-request
// context from rootCtx, and no LDAP verification-path code may substitute
// context.Background()/context.TODO() for it.
func New(rootCtx context.Context, cfg Config, v verifier, roles roleResolver) (*Server, error) {
	if rootCtx == nil {
		return nil, errors.New("ldap: rootCtx must not be nil")
	}
	if v == nil {
		return nil, errors.New("ldap: verifier must not be nil")
	}
	if roles == nil {
		return nil, errors.New("ldap: roleResolver must not be nil")
	}

	userBase, err := NewUserBaseDN(cfg.UserBaseDN, cfg.UserRDNAttribute)
	if err != nil {
		return nil, err
	}
	groupBase, err := NewGroupBaseDN(cfg.GroupBaseDN)
	if err != nil {
		return nil, err
	}

	// Mandatory dependency logging hardening (see the plan section of that
	// name): the dependency's default logger writes every inbound LDAP
	// packet in hex, and a simple-Bind packet carries the JWT/password.
	// This MUST happen before any listener ever serves traffic; doing it
	// here, inside the constructor every call site must invoke before it
	// can Serve, is what guarantees that ordering rather than relying on
	// caller discipline. This is also the assignment the Server type doc's
	// "at most one Server per process at a time" constraint above exists to
	// protect: ldapserver.Logger is package-level, not per-instance.
	ldapserver.Logger = ldapserver.DiscardingLogger

	hs := &handlerSource{
		rootCtx:      rootCtx,
		verifier:     v,
		roles:        roles,
		userBase:     userBase,
		groupBase:    groupBase,
		roleCNPrefix: cfg.RoleCNPrefix,
	}

	ldapSrv := ldapserver.NewServerWithHandlerSource(hs)
	ldapSrv.ReadTimeout = ldapConnReadTimeout
	ldapSrv.WriteTimeout = ldapConnWriteTimeout
	ldapSrv.MaxConnections = ldapMaxConnections

	return &Server{ldapSrv: ldapSrv}, nil
}

// Serve accepts and serves LDAP connections on listener until Stop is
// called or a fatal accept error occurs. The caller owns creating listener
// (typically via net.Listen("tcp", cfg.Listen)) — this package never binds
// a socket itself, and never serves TLS or any HTTP endpoint.
func (s *Server) Serve(listener net.Listener) error {
	return s.ldapSrv.Serve(listener)
}

// Stop gracefully shuts down the server: it stops accepting new
// connections, signals every in-progress client to close, and waits for
// all of them to finish before returning.
func (s *Server) Stop() {
	s.ldapSrv.Stop()
}

// handlerSource allocates one fresh connectionHandler (and, inside it, one
// fresh session) per accepted TCP connection, via GetHandler — the
// dependency calls this exactly once per accepted client and assigns the
// returned Handler only to that client (see ldapserver's Server.newClient).
// This is the sole mechanism this package uses for connection-local state:
// no package-level connection map, no remote-address keying, no shared
// mutable object. See "Exact connection-local state design" in the plan.
type handlerSource struct {
	rootCtx      context.Context
	verifier     verifier
	roles        roleResolver
	userBase     *UserBaseDN
	groupBase    *GroupBaseDN
	roleCNPrefix string
}

// GetHandler implements ldapserver.HandlerSource.
func (hs *handlerSource) GetHandler() ldapserver.Handler {
	h := &connectionHandler{
		rootCtx:      hs.rootCtx,
		verifier:     hs.verifier,
		roles:        hs.roles,
		userBase:     hs.userBase,
		groupBase:    hs.groupBase,
		roleCNPrefix: hs.roleCNPrefix,
		session:      newSession(),
	}

	routes := ldapserver.NewRouteMux()
	routes.Bind(h.handleBind)
	routes.Search(h.handleSearch)
	routes.Add(h.handleAdd)
	routes.Modify(h.handleModify)
	routes.Delete(h.handleDelete)
	routes.Compare(h.handleCompare)
	// Extended requests (StartTLS, password modify, WhoAmI, and every
	// other OID) are deliberately never registered via .Extended(...): the
	// dependency's route matcher treats an Extended route with no
	// RequestName() set as matching only a request whose RequestName() is
	// the empty string, which no real Extended request ever is — so an
	// .Extended(...) registration here would silently never fire. Routing
	// every Extended request through NotFound, instead, is what actually
	// makes handleNotFound a true catch-all. ModifyDN has no RouteMux method
	// at all (route.go defines routes only for the operations registered
	// above plus Extended/Abandon/Cancel), so it lands on this same
	// catch-all unconditionally — see unsupported.go's handleNotFound.
	// Unbind needs no route (the dependency's normal connection-close path
	// handles it before any handler runs) and Abandon is deliberately left
	// unregistered so the dependency's own built-in Abandon-signaling
	// fallback keeps running unmodified — see unsupported.go.
	routes.NotFound(h.handleNotFound)

	return routes
}

// connectionHandler owns everything specific to exactly one accepted LDAP
// connection: its authenticated session/operation lock, and every route
// handler (Bind, Search, and the fail-closed operations) that reads or
// mutates it. rootCtx, verifier, roles and the parsed configuration are
// shared, read-only references copied in at allocation time; session is the
// only mutable, connection-owned state.
type connectionHandler struct {
	rootCtx      context.Context
	verifier     verifier
	roles        roleResolver
	userBase     *UserBaseDN
	groupBase    *GroupBaseDN
	roleCNPrefix string

	session *session
}

// requestContext derives a context from rootCtx for one Bind/Search
// request, additionally canceled when m.Done fires — the dependency's
// signal for request abandonment or connection teardown (see cancel.go's
// Abandon and client.go's close(), which sends on every registered
// request's Done channel). The caller must defer the returned cancel so
// this bridging goroutine cannot leak once the request is done either way.
//
// This is the only source of per-request context on the Bind/Search path:
// no handler may substitute context.Background()/context.TODO(), because
// doing so would let an in-flight Verify call outlive process shutdown or
// connection teardown.
func requestContext(rootCtx context.Context, m *ldapserver.Message) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(rootCtx)
	go func() {
		select {
		case <-m.Done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// correlationID returns a stable, non-reversible hash of a verified (iss,
// sub) pair, safe to log per the plan's allowed-fields list ("stable
// hashed/correlation ID based on (iss, sub) where available"). It never
// receives or exposes the token, password, or any other credential
// material — only already-verified identity metadata.
func correlationID(issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return hex.EncodeToString(sum[:8])
}
