package profile

import (
	"context"
	"net"
	"time"
)

// authState is the per-connection authenticated identity captured by the
// most recent successful simple Bind (see "Authentication state" in the
// plan) — the only fields a same-connection Search may read. Deliberately
// absent, per "Credential-copy accounting": the JWT/password, the raw Bind
// frame, the complete *verification.Result, raw claim maps, source groups.
type authState struct {
	// Username is verification.Result.Principal.Username.
	Username string
	// Issuer/Subject are the stable (iss, sub) pair from
	// Principal.StableSubject(), when that succeeds; otherwise both empty.
	Issuer  string
	Subject string
	// BoundDN is the exact successfully authenticated raw Bind DN text,
	// preserved verbatim because Search's member-DN check uses it.
	BoundDN string
	// boundDN is BoundDN's parsed structural form (see DN.Equal's doc
	// comment on why structural, not rendered-text, comparison matters).
	boundDN DN
	// ExpiresAt is observability-only metadata: Search must never
	// re-evaluate it (no Search-time role recomputation).
	ExpiresAt int64
	// Roles is the mapped role list computed once, at Bind time.
	Roles []string
}

// cloneRoles returns a fresh copy of roles, or nil for empty/nil. Cloning
// on the way in (replaceAuth) is what makes the stored slice immune to a
// caller mutating the slice it handed in afterward.
func cloneRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	cloned := make([]string, len(roles))
	copy(cloned, roles)
	return cloned
}

// connection is all per-connection state owned by the single goroutine
// that reads, processes, and responds on one accepted TCP connection (see
// "Connection and framing model"). No mutex: exactly one goroutine ever
// touches these fields, so a mutex would only hide a violated invariant
// rather than prevent a real race.
//
// No password/frame reference field may exist here — see
// "Credential-copy accounting": Bind's temporary password/JWT string is
// bounded by the request cap, never retained past the call that used it.
type connection struct {
	nc  net.Conn
	ctx context.Context

	cfg      *parsedConfig
	verifier Verifier
	roles    RoleResolver
	// clock returns the current time; production wiring is time.Now,
	// tests inject fakeClock (fakes_test.go) for deterministic deadlines.
	clock func() time.Time

	readTimeout  time.Duration
	writeTimeout time.Duration

	auth          authState
	authenticated bool
}

// clearAuth resets c to UNAUTHENTICATED. Every failed/critical/non-v3
// Bind — and every Bind attempt before verification runs — must call this
// first, so a prior principal's state can never survive a rejected
// re-Bind.
func (c *connection) clearAuth() {
	c.auth = authState{}
	c.authenticated = false
}

// replaceAuth installs newState as c's complete state, wholesale — never
// merged field-by-field with what was there before, so a second
// successful Bind fully replaces the first rather than layering onto it.
// Roles is cloned so mutating the caller's slice afterward cannot reach
// stored state. This is the only path setting c.authenticated = true.
func (c *connection) replaceAuth(newState authState) {
	newState.Roles = cloneRoles(newState.Roles)
	c.auth = newState
	c.authenticated = true
}
