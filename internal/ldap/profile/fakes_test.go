package profile

// This file is the CANONICAL home for this package's test fakes, per
// Amendment 7 (coordinator-approved) in the Phase 2 plan: the plan forbids
// a non-test internal/ldap/testsupport package, and Go _test.go files
// cannot be shared across package boundaries, so fakeVerifier/fakeResolver/
// fakeClock/marker constants/newTestConfig live here exactly once and every
// later profile-package *_test.go file (bind_test.go, search_test.go,
// server_test.go, ...) must reuse these definitions rather than redefining
// an equivalent type. (internal/ldap/profile_compat_test.go, package
// ldap_test, and the Phase 4 internal/ldap/profile/compat_external_test.go,
// package profile_test, are separate package boundaries this file's
// unexported names cannot reach — those accept the documented duplication.)

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// ---- marker constants -----------------------------------------------------
//
// Every marker below is a distinctive, greppable literal so a test can
// assert both that the right one appears where expected AND that it never
// appears somewhere it must not (a log line, an LDAP diagnosticMessage, a
// returned error) — the same technique the shipped redaction tests use.

const (
	// markerJWTPassword is shaped like a real compact JWT (three
	// dot-separated base64url-ish segments) without being a validly signed
	// token, so a test asserting a Bind password/credential never reaches a
	// log or error string exercises a realistic-shaped value rather than a
	// short, easy-to-avoid fake token.
	markerJWTPassword = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcm9maWxlLXRlc3QifQ.profile-test-marker-signature-must-never-leak"

	// markerHostileDN is a Bind-DN-shaped string carrying an unescaped '+'
	// (multi-valued-RDN shape) and a filter-injection-shaped suffix, for
	// tests proving the restricted DN grammar and structural authorization
	// reject or neutralize it rather than accepting/interpolating it.
	markerHostileDN = `uid=evil+description=hostile,ou=users,dc=profile,dc=test)(uid=*`

	// markerVerifierError / markerResolverError are distinct substrings a
	// test can grep a captured log/response for, to prove which injected
	// dependency failure (if either) actually surfaced, and that it
	// surfaced only where expected.
	markerVerifierError = "profile-test-marker: verifier injected failure"
	markerResolverError = "profile-test-marker: resolver injected failure"

	// markerLegitimateRole is an ordinary-shaped mapped role name later
	// Search/entry-rendering tests use as the unremarkable case.
	markerLegitimateRole = "clickhouse_reader"
)

// markerOversizedRole is long enough that a single synthetic groupOfNames
// entry rendered for it exceeds encode.go's maxBodyBytes (65536) response
// cap on its own — used by later response-size-preflight tests. It is a
// var, not a const, only because Go constants cannot hold the result of
// strings.Repeat.
var markerOversizedRole = strings.Repeat("R", maxBodyBytes+1024)

// newTestConfig returns a valid Config every profile-package test can use
// as its starting fixture, customizing only the fields a given test cares
// about.
func newTestConfig() Config {
	return Config{
		UserBaseDN:       "ou=users,dc=profile,dc=test",
		GroupBaseDN:      "ou=groups,dc=profile,dc=test",
		UserRDNAttribute: "uid",
		RoleCNPrefix:     "clickhouse_",
	}
}

// newVerificationResult builds a *verification.Result for the given
// username/issuer/subject/expiry — the minimal shape fakeVerifier's success
// map and Bind-time state both need. Centralizing it here, rather than
// having each later Bind/Search test hand-roll the nested
// Claims/Principal struct literal, is exactly the kind of duplication
// Amendment 7 asks this file to own.
func newVerificationResult(username, issuer, subject string, expiresAt int64) *verification.Result {
	return &verification.Result{
		Claims: oauth.Claims{
			Subject:   subject,
			Issuer:    issuer,
			ExpiresAt: expiresAt,
		},
		Principal: identity.Principal{
			Username: username,
			Issuer:   issuer,
			Subject:  subject,
		},
	}
}

// ---- fakeVerifier ----------------------------------------------------------

// fakeVerifier is the canonical in-package Verifier fake. It supports:
//
//   - a per-password success/failure map (Verify's password argument
//     selects the outcome, matching how a real simple-Bind password
//     selects a verification outcome);
//   - error injection carrying markerVerifierError so a test can prove
//     which failure surfaced;
//   - a blocking-until-ctx-done mode, for tests proving Bind's Verify call
//     observes context cancellation rather than running unbounded;
//   - an atomic call counter, for "Verify called exactly once"/"never
//     called from Search" proofs;
//   - the last ctx it was called with, for tests proving the connection's
//     request-scoped context (not some unrelated context) reached Verify.
type fakeVerifier struct {
	mu      sync.Mutex
	success map[string]*verification.Result
	failure map[string]error

	block chan struct{} // non-nil: Verify blocks on this or ctx.Done() before consulting the maps

	calls   atomic.Int32
	lastCtx atomic.Value // holds context.Context
}

func newFakeVerifier() *fakeVerifier {
	return &fakeVerifier{
		success: make(map[string]*verification.Result),
		failure: make(map[string]error),
	}
}

// withSuccess registers password as authenticating successfully to result.
func (f *fakeVerifier) withSuccess(password string, result *verification.Result) *fakeVerifier {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.success[password] = result
	return f
}

// withFailure registers password as failing verification with err (which
// should normally wrap or equal markerVerifierError for a test to assert
// against).
func (f *fakeVerifier) withFailure(password string, err error) *fakeVerifier {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure[password] = err
	return f
}

// withBlock puts f into blocking mode: every Verify call waits on block
// being closed, or on ctx being done, before proceeding.
func (f *fakeVerifier) withBlock(block chan struct{}) *fakeVerifier {
	f.block = block
	return f
}

func (f *fakeVerifier) Verify(ctx context.Context, _ string, password string) (*verification.Result, error) {
	f.calls.Add(1)
	f.lastCtx.Store(ctx)

	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failure[password]; ok {
		return nil, err
	}
	if result, ok := f.success[password]; ok {
		return result, nil
	}
	return nil, errUnrecognizedFakePassword
}

func (f *fakeVerifier) callCount() int32 { return f.calls.Load() }

// contextSeen returns the ctx the most recent Verify call was made with, or
// nil if Verify was never called.
func (f *fakeVerifier) contextSeen() context.Context {
	ctx, _ := f.lastCtx.Load().(context.Context)
	return ctx
}

// errUnrecognizedFakePassword is fakeVerifier's default outcome for a
// password neither withSuccess nor withFailure registered. It deliberately
// does not embed the presented password.
var errUnrecognizedFakePassword = errors.New("fakeVerifier: unrecognized password")

// ---- fakeResolver -----------------------------------------------------------

// fakeResolver is the canonical in-package RoleResolver fake. It supports:
//
//   - roles keyed by claims.Subject;
//   - error injection carrying markerResolverError;
//   - an atomic call counter, for "Roles called exactly once from Bind,
//     never from Search" proofs;
//   - returning the SAME underlying slice on every call for a given
//     subject (never a defensive copy) — deliberately, so a test proves
//     connection.replaceAuth's cloning (not some cloning already done by
//     the resolver) is what protects stored state: the test mutates the
//     slice fakeResolver handed back and asserts the connection's stored
//     Roles is unaffected.
type fakeResolver struct {
	mu        sync.Mutex
	bySubject map[string][]string
	err       error

	calls atomic.Int32
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{bySubject: make(map[string][]string)}
}

// withRoles registers subject as mapping to roles (the same slice value
// returned verbatim by every subsequent Roles call for that subject).
func (f *fakeResolver) withRoles(subject string, roles []string) *fakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bySubject[subject] = roles
	return f
}

// withError puts f into failure mode: every Roles call fails with err
// (which should normally wrap or equal markerResolverError).
func (f *fakeResolver) withError(err error) *fakeResolver {
	f.err = err
	return f
}

func (f *fakeResolver) Roles(claims *oauth.Claims) ([]string, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	if claims == nil {
		return nil, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bySubject[claims.Subject], nil
}

func (f *fakeResolver) callCount() int32 { return f.calls.Load() }

// ---- fakeClock --------------------------------------------------------------

// fakeClock is the canonical in-package clock fake: a settable Now with an
// advance helper, so deadline/expiry-adjacent tests are deterministic
// without a real sleep. fc.Now (the method value) matches connection.clock's
// func() time.Time shape directly.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the fake clock forward by d.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// set moves the fake clock to exactly t.
func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}
