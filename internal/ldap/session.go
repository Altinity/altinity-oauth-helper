package ldap

import "sync"

// authenticatedState is the complete per-connection authenticated identity
// captured by the most recent successful simple Bind on this connection.
// See "Exact connection-local state design" in the phase-2 plan: these are
// the only fields a same-connection Search is permitted to read.
//
// Deliberately absent — never stored here or anywhere else on the
// connection — per the plan: the JWT/password, the raw Bind packet, the
// complete verification.Result, raw claim maps, and source IdP groups.
type authenticatedState struct {
	// Username is the canonical visible username from
	// verification.Result.Principal.
	Username string
	// Issuer and Subject are the stable (iss, sub) pair from
	// Principal.StableSubject(), when that succeeds; otherwise both empty.
	Issuer  string
	Subject string
	// BoundDN is the exact successfully authenticated raw Bind DN string,
	// preserved verbatim because Search's member-DN authorization is
	// defined in terms of it.
	BoundDN string
	// ExpiresAt is token expiration metadata (unix seconds). It is stored
	// for observability only: Search must never re-evaluate it, per the
	// plan's "Role snapshot semantics" section.
	ExpiresAt int64
	// Roles is the defensively-copied final mapped role list computed once
	// by the role pipeline at Bind time.
	Roles []string
}

// cloneRoles returns a fresh copy of roles, or nil for an empty/nil input.
// Cloning on both the way in (replace) and the way out (snapshot) is what
// makes the stored role slice immune to aliasing: neither a caller
// mutating the slice it handed to replace, nor a caller mutating the slice
// snapshot handed back, can reach session-owned state.
func cloneRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	cloned := make([]string, len(roles))
	copy(cloned, roles)
	return cloned
}

// session is the per-connection authenticated state plus the single
// operation mutex shared by Bind and Search on that connection (see
// "Per-connection operation ordering" in the phase-2 plan). Exactly one
// session is allocated per accepted TCP connection — via
// handlerSource.GetHandler() — and it is never shared across connections
// or looked up by remote address; disconnect makes it unreachable and thus
// destroys the state structurally.
type session struct {
	// mu is the per-connection operation lock. Every Bind and Search
	// handler must: derive its request context, acquire mu, re-check
	// cancellation, perform its state transition, then release mu — so
	// Bind/Search state transitions on one connection are always linear.
	mu sync.Mutex

	state *authenticatedState // nil when the connection is unauthenticated
}

// newSession returns a fresh, unauthenticated per-connection session.
func newSession() *session {
	return &session{}
}

// Lock and Unlock expose the per-connection operation mutex. Callers must
// hold it for the whole of a Bind or Search state transition, including
// the post-acquisition cancellation re-check the plan requires; they must
// not read or mutate state without holding it.
func (s *session) Lock()   { s.mu.Lock() }
func (s *session) Unlock() { s.mu.Unlock() }

// clear removes any previously authenticated state. The caller must hold
// the operation lock. This is required to be the first state mutation of
// every Bind attempt — before verification runs — so that a concurrent
// Search which obtains the lock after a new Bind has begun can never
// observe the previous principal's state.
func (s *session) clear() {
	s.state = nil
}

// replace installs newly authenticated state, defensively cloning Roles so
// that mutating the caller's original slice afterward cannot change what
// is stored. The caller must hold the operation lock.
func (s *session) replace(state authenticatedState) {
	stored := state
	stored.Roles = cloneRoles(state.Roles)
	s.state = &stored
}

// snapshot returns a defensive copy of the current authenticated state, or
// ok=false when the connection is unauthenticated. Roles in the returned
// copy is itself a fresh clone, so a caller mutating it cannot reach or
// change the stored state. The caller must hold the operation lock.
func (s *session) snapshot() (state authenticatedState, ok bool) {
	if s.state == nil {
		return authenticatedState{}, false
	}
	copied := *s.state
	copied.Roles = cloneRoles(s.state.Roles)
	return copied, true
}
