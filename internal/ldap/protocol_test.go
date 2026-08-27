package ldap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	goldapclient "github.com/go-ldap/ldap/v3"
	ldapserver "github.com/vjeantet/ldapserver"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// This file drives the real production server — internal/ldap.New wired to
// ldapserver.NewServerWithHandlerSource under the hood — over an actual TCP
// connection using a real LDAPv3 client (github.com/go-ldap/ldap/v3), per
// "Protocol test harness" in the phase-2 plan:
//
//	client TCP -> ldapserver BER parsing -> production route ->
//	connectionHandler/session -> production Bind/Search response -> client decode
//
// Only the verifier and roleResolver are test fakes; everything else in the
// path is production code. No test here calls a handler method directly.

// ---- fixed test topology -------------------------------------------------

const (
	protoUserBaseDN  = "ou=users,dc=proto,dc=test"
	protoGroupBaseDN = "ou=groups,dc=proto,dc=test"
	protoRDNAttr     = "uid"
	protoCNPrefix    = "clickhouse_"
)

func protoBindDN(username string) string {
	return "uid=" + username + "," + protoUserBaseDN
}

func protoConfig() Config {
	return Config{
		Listen:           "127.0.0.1:0",
		UserBaseDN:       protoUserBaseDN,
		GroupBaseDN:      protoGroupBaseDN,
		UserRDNAttribute: protoRDNAttr,
		RoleCNPrefix:     protoCNPrefix,
	}
}

// ---- fake verifier/roleResolver ------------------------------------------

// fakeAccount is one valid (token -> verification outcome) pairing a
// fakeVerifier can serve.
type fakeAccount struct {
	token   string
	result  *verification.Result
	rolesOf []string // roles fakeRoleResolver returns for this account's claims.Subject
}

// fakeVerifier is a narrow, deterministic stand-in for *verification.Verifier.
// It counts calls (for the "exactly once" proofs) and, optionally, blocks on
// context cancellation to make in-flight-cancellation tests deterministic.
type fakeVerifier struct {
	mu      sync.Mutex
	calls   int
	byToken map[string]*verification.Result

	entered  chan struct{} // if non-nil, signaled (best-effort) on every call entry
	block    chan struct{} // if non-nil, Verify waits on this or ctx.Done()
	returned chan error    // if non-nil, receives the error Verify is about to return
}

func newFakeVerifier(accounts ...fakeAccount) *fakeVerifier {
	v := &fakeVerifier{byToken: make(map[string]*verification.Result)}
	for _, a := range accounts {
		v.byToken[a.token] = a.result
	}
	return v
}

func (f *fakeVerifier) report(err error) error {
	if f.returned != nil {
		select {
		case f.returned <- err:
		default:
		}
	}
	return err
}

func (f *fakeVerifier) Verify(ctx context.Context, _ string, token string) (*verification.Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()

	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}

	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, f.report(ctx.Err())
		}
	}

	select {
	case <-ctx.Done():
		return nil, f.report(ctx.Err())
	default:
	}

	f.mu.Lock()
	result, ok := f.byToken[token]
	f.mu.Unlock()
	if !ok {
		return nil, f.report(errors.New("fake verifier: invalid token"))
	}
	return result, f.report(nil)
}

func (f *fakeVerifier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeRoles is a narrow, deterministic stand-in for *roles.Pipeline, keyed
// by claims.Subject so it can be driven from the same fixture as fakeVerifier.
type fakeRoles struct {
	mu      sync.Mutex
	calls   int
	bySub   map[string][]string
	failErr error // if set, every call fails with this error (malformed-claim simulation)
}

func newFakeRoles(accounts ...fakeAccount) *fakeRoles {
	r := &fakeRoles{bySub: make(map[string][]string)}
	for _, a := range accounts {
		r.bySub[a.result.Principal.Subject] = a.rolesOf
	}
	return r
}

func (f *fakeRoles) Roles(claims *oauth.Claims) ([]string, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.failErr != nil {
		return nil, f.failErr
	}
	return f.bySub[claims.Subject], nil
}

func (f *fakeRoles) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// account builds one fixture: a principal identified by username/issuer/
// subject, authenticated by token, mapped to roles.
func account(username, issuer, subject, token string, roles []string) fakeAccount {
	return fakeAccount{
		token: token,
		result: &verification.Result{
			Claims: oauth.Claims{
				Subject:   subject,
				Issuer:    issuer,
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			Principal: identity.Principal{
				Username: username,
				Issuer:   issuer,
				Subject:  subject,
			},
		},
		rolesOf: roles,
	}
}

// ---- server/client test scaffolding --------------------------------------

// startTestServer wires the real internal/ldap.Server to a real TCP
// listener and returns its address plus a stop func safe to call more than
// once (also registered as t.Cleanup). rootCancel lets a test explicitly
// drive root-context cancellation (for the shutdown-cancellation proof)
// without racing the automatic cleanup's own Stop/cancel.
func startTestServer(t *testing.T, v verifier, r roleResolver) (addr string, rootCancel context.CancelFunc, stop func()) {
	t.Helper()

	rootCtx, cancel := context.WithCancel(context.Background())
	srv, err := New(rootCtx, protoConfig(), v, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			// Close OUR OWN listener reference directly instead of calling
			// srv.Stop() first — see cmd/ch-oauth-ldap/main.go's run() for
			// the full explanation. The vendored vjeantet/ldapserver
			// dependency stores the listener in a plain, unsynchronized
			// struct field, written by the background Serve goroutine and
			// read by Stop with no lock between them; calling Stop()
			// concurrently with that goroutine is a genuine data race.
			// Closing ln here unblocks Serve's Accept() call, and
			// receiving from serveErr below is a channel synchronization
			// point that makes the subsequent srv.Stop() call race-free.
			_ = ln.Close()
			<-serveErr
			srv.Stop()
			cancel()
		})
	}
	t.Cleanup(stop)

	return ln.Addr().String(), cancel, stop
}

func dialTest(t *testing.T, addr string) *goldapclient.Conn {
	t.Helper()
	conn, err := goldapclient.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// bindAs performs a simple Bind and returns the resulting *ldap.Error (nil
// on success), the way go-ldap's SimpleBind naturally exposes result code,
// matched DN and diagnostic message together.
func bindAs(conn *goldapclient.Conn, dn, password string) *goldapclient.Error {
	_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
		Username:           dn,
		Password:           password,
		AllowEmptyPassword: true,
	})
	return asLDAPError(err)
}

func asLDAPError(err error) *goldapclient.Error {
	if err == nil {
		return nil
	}
	var ldapErr *goldapclient.Error
	if errors.As(err, &ldapErr) {
		return ldapErr
	}
	return &goldapclient.Error{Err: err}
}

func membershipSearch(baseDN, boundDN string, attrs []string) *goldapclient.SearchRequest {
	filter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", boundDN)
	return goldapclient.NewSearchRequest(baseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
}

// requireSuccess fails the test unless err is nil.
func requireSuccess(t *testing.T, label string, err *goldapclient.Error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: got LDAP error %+v, want success", label, err)
	}
}

// requireInvalidCredentials fails the test unless err is exactly the fixed
// Bind non-disclosure boundary: code 49, empty matched DN, fixed diagnostic.
func requireInvalidCredentials(t *testing.T, label string, err *goldapclient.Error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got success, want invalidCredentials", label)
	}
	if int(err.ResultCode) != ldapserver.LDAPResultInvalidCredentials {
		t.Fatalf("%s: ResultCode = %d, want %d", label, err.ResultCode, ldapserver.LDAPResultInvalidCredentials)
	}
	if err.MatchedDN != "" {
		t.Fatalf("%s: MatchedDN = %q, want empty", label, err.MatchedDN)
	}
	if err.Err == nil || err.Err.Error() != invalidCredentialsDiagnostic {
		t.Fatalf("%s: diagnostic = %v, want %q", label, err.Err, invalidCredentialsDiagnostic)
	}
}

func requireUnwillingToPerform(t *testing.T, err error) {
	t.Helper()
	ldapErr := asLDAPError(err)
	if ldapErr == nil {
		t.Fatalf("got success, want LDAPResultUnwillingToPerform")
	}
	if int(ldapErr.ResultCode) != ldapserver.LDAPResultUnwillingToPerform {
		t.Fatalf("ResultCode = %d, want %d (UnwillingToPerform)", ldapErr.ResultCode, ldapserver.LDAPResultUnwillingToPerform)
	}
}

// ---- 1. valid Bind then Search returns snapshotted role -------------------

func TestProtocol_BindThenSearchReturnsSnapshottedRole(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("search entries = %d, want 1", len(res.Entries))
	}
	if got := res.Entries[0].GetAttributeValue("cn"); got != "clickhouse_ch_engineer" {
		t.Fatalf("entry cn = %q, want clickhouse_ch_engineer", got)
	}
}

// ---- 2. invalid token returns invalidCredentials --------------------------

func TestProtocol_InvalidTokenReturnsInvalidCredentials(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	fv := newFakeVerifier(acct)
	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireInvalidCredentials(t, "wrong token", bindAs(conn, protoBindDN("alice"), "not-the-right-jwt"))
	if fv.callCount() != 1 {
		t.Fatalf("verifier calls = %d, want 1", fv.callCount())
	}
}

// ---- 3. anonymous/empty Bind rejected identically, and nondisclosure -----

func TestProtocol_EmptyBindRejectedSameAsOtherFailures(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	cases := map[string]struct{ dn, password string }{
		"empty DN, empty password":    {"", ""},
		"empty DN, valid-shaped pass": {"", "jwt-alice"},
		"valid DN, empty password":    {protoBindDN("alice"), ""},
	}

	var errs []*goldapclient.Error
	for name, c := range cases {
		conn := dialTest(t, addr)
		err := bindAs(conn, c.dn, c.password)
		requireInvalidCredentials(t, name, err)
		errs = append(errs, err)
	}

	// Nondisclosure: every failure class above must be byte-for-byte
	// identical to the client's view of an unrelated failure class (wrong
	// token on a valid-looking DN).
	wrongToken := bindAs(dialTest(t, addr), protoBindDN("alice"), "garbage")
	requireInvalidCredentials(t, "wrong token (for equality check)", wrongToken)
	for _, e := range errs {
		if e.ResultCode != wrongToken.ResultCode || e.MatchedDN != wrongToken.MatchedDN || e.Err.Error() != wrongToken.Err.Error() {
			t.Fatalf("failure classes are distinguishable: %+v vs %+v", e, wrongToken)
		}
	}
}

// ---- 4. malformed/unexpected Bind DN safely rejected ----------------------

func TestProtocol_MalformedBindDNVariantsRejected(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	fv := newFakeVerifier(acct)
	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	cases := map[string]string{
		"not a DN at all":         "not-a-valid-dn-no-equals-sign",
		"wrong RDN attribute":     "cn=alice," + protoUserBaseDN,
		"wrong base":              "uid=alice,ou=wrong,dc=proto,dc=test",
		"extra RDN":               "cn=extra,uid=alice," + protoUserBaseDN,
		"multivalued leading RDN": "uid=alice+cn=extra," + protoUserBaseDN,
	}

	for name, dn := range cases {
		t.Run(name, func(t *testing.T) {
			conn := dialTest(t, addr)
			requireInvalidCredentials(t, name, bindAs(conn, dn, "jwt-alice"))
		})
	}

	if fv.callCount() != 0 {
		t.Fatalf("verifier calls = %d, want 0 (DN parsing must reject before Verify)", fv.callCount())
	}
}

// ---- 5. Search before Bind rejected ---------------------------------------

func TestProtocol_SearchBeforeBindRejected(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err == nil {
		t.Fatalf("search before bind: got success with %d entries, want failure", len(res.Entries))
	}
	if res != nil && len(res.Entries) != 0 {
		t.Fatalf("search before bind: got %d entries, want 0", len(res.Entries))
	}
}

// ---- 6. connection state isolated across connections ----------------------

func TestProtocol_ConnectionStateIsolated(t *testing.T) {
	alice := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_alice_role"})
	bob := account("bob", "https://idp.test/", "sub-bob", "jwt-bob", []string{"ch_bob_role"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice, bob), newFakeRoles(alice, bob))

	connA := dialTest(t, addr)
	requireSuccess(t, "bind alice", bindAs(connA, protoBindDN("alice"), "jwt-alice"))

	connB := dialTest(t, addr)
	requireSuccess(t, "bind bob", bindAs(connB, protoBindDN("bob"), "jwt-bob"))

	resA, err := connA.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil || len(resA.Entries) != 1 || resA.Entries[0].GetAttributeValue("cn") != protoCNPrefix+"ch_alice_role" {
		t.Fatalf("connA search = %+v, err=%v, want alice's role only", resA, err)
	}

	resB, err := connB.Search(membershipSearch(protoGroupBaseDN, protoBindDN("bob"), nil))
	if err != nil || len(resB.Entries) != 1 || resB.Entries[0].GetAttributeValue("cn") != protoCNPrefix+"ch_bob_role" {
		t.Fatalf("connB search = %+v, err=%v, want bob's role only", resB, err)
	}
}

// ---- 7 & 8. re-Bind replaces on success, clears on failure -----------------

func TestProtocol_SuccessfulReBindReplacesPrincipalAndRoles(t *testing.T) {
	alice := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	bob := account("bob", "https://idp.test/", "sub-bob", "jwt-bob", []string{"ch_b"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice, bob), newFakeRoles(alice, bob))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind alice", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
	requireSuccess(t, "rebind bob", bindAs(conn, protoBindDN("bob"), "jwt-bob"))

	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("bob"), nil))
	if err != nil || len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("cn") != protoCNPrefix+"ch_b" {
		t.Fatalf("search after re-bind = %+v, err=%v, want only bob's role", res, err)
	}

	// Alice's own membership query must no longer succeed on this connection.
	resAlice, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err == nil && len(resAlice.Entries) > 0 {
		t.Fatalf("search for alice's membership after re-bind as bob succeeded: %+v", resAlice)
	}
}

func TestProtocol_FailedReBindLeavesSearchUnauthenticated(t *testing.T) {
	alice := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice), newFakeRoles(alice))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind alice", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
	requireInvalidCredentials(t, "failed rebind", bindAs(conn, protoBindDN("alice"), "wrong-token"))

	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err == nil && res != nil && len(res.Entries) > 0 {
		t.Fatalf("search after failed re-bind = %+v, want unauthenticated failure", res)
	}
}

// ---- 9. expected Search returns transport-prefixed cn, full attributes ---

func TestProtocol_SearchReturnsFullSyntheticEntry(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(res.Entries))
	}
	e := res.Entries[0]
	wantDN := "cn=clickhouse_ch_engineer," + protoGroupBaseDN
	if e.DN != wantDN {
		t.Fatalf("entry DN = %q, want %q", e.DN, wantDN)
	}
	if got := e.GetAttributeValue("objectClass"); got != "groupOfNames" {
		t.Fatalf("objectClass = %q, want groupOfNames", got)
	}
	if got := e.GetAttributeValue("cn"); got != "clickhouse_ch_engineer" {
		t.Fatalf("cn = %q, want clickhouse_ch_engineer", got)
	}
	if got := e.GetAttributeValue("member"); got != protoBindDN("alice") {
		t.Fatalf("member = %q, want %q", got, protoBindDN("alice"))
	}
}

// ---- 10. bound user with zero roles gets successful empty Search ---------

func TestProtocol_ZeroRoleBindGetsSuccessfulEmptySearch(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", nil)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil {
		t.Fatalf("search: %v, want success", err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(res.Entries))
	}
}

// ---- 11. other member DN rejected ------------------------------------------

func TestProtocol_OtherMemberDNRejected(t *testing.T) {
	alice := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	bob := account("bob", "https://idp.test/", "sub-bob", "jwt-bob", []string{"ch_b"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice, bob), newFakeRoles(alice, bob))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind alice", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	// Valid query shape, but naming bob's DN as member on alice's connection.
	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("bob"), nil))
	if err == nil && res != nil && len(res.Entries) > 0 {
		t.Fatalf("search for bob's membership on alice's connection succeeded: %+v", res)
	}
}

// ---- 12. wrong base/scope/filter table -------------------------------------

func TestProtocol_WrongBaseScopeFilterTable(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	boundDN := protoBindDN("alice")
	validFilter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", boundDN)

	cases := map[string]*goldapclient.SearchRequest{
		"wrong base": goldapclient.NewSearchRequest(
			"ou=other,dc=proto,dc=test", goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false, validFilter, nil, nil),
		"base-object scope": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeBaseObject, goldapclient.NeverDerefAliases, 0, 0, false, validFilter, nil, nil),
		"single-level scope": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeSingleLevel, goldapclient.NeverDerefAliases, 0, 0, false, validFilter, nil, nil),
		"OR filter": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(|(objectClass=groupOfNames)(member=%s))", boundDN), nil, nil),
		"substring filter": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=groupOfNames)(member=uid=al*))", nil, nil),
		"present-only filter": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=groupOfNames)(member=*))", nil, nil),
		"wrong objectClass": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&(objectClass=person)(member=%s))", boundDN), nil, nil),
		"bare equality (no AND)": goldapclient.NewSearchRequest(
			protoGroupBaseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, 0, 0, false,
			"(objectClass=groupOfNames)", nil, nil),
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			conn := dialTest(t, addr)
			requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
			res, err := conn.Search(req)
			if err == nil && res != nil && len(res.Entries) > 0 {
				t.Fatalf("%s: search succeeded with entries %+v, want rejection", name, res.Entries)
			}
		})
	}
}

// ---- 13. unsupported operations fail closed, incl. SASL-after-success -----

func TestProtocol_UnsupportedOperationsFailClosed(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	t.Run("Add", func(t *testing.T) {
		conn := dialTest(t, addr)
		requireUnwillingToPerform(t, conn.Add(goldapclient.NewAddRequest("cn=x,"+protoGroupBaseDN, nil)))
	})
	t.Run("Modify", func(t *testing.T) {
		conn := dialTest(t, addr)
		mr := goldapclient.NewModifyRequest("cn=x,"+protoGroupBaseDN, nil)
		mr.Replace("cn", []string{"y"})
		requireUnwillingToPerform(t, conn.Modify(mr))
	})
	t.Run("Delete", func(t *testing.T) {
		conn := dialTest(t, addr)
		requireUnwillingToPerform(t, conn.Del(goldapclient.NewDelRequest("cn=x,"+protoGroupBaseDN, nil)))
	})
	t.Run("Compare", func(t *testing.T) {
		conn := dialTest(t, addr)
		_, err := conn.Compare("cn=x,"+protoGroupBaseDN, "cn", "x")
		requireUnwillingToPerform(t, err)
	})
	t.Run("ModifyDN", func(t *testing.T) {
		// The pinned vjeantet/ldapserver dependency's RouteMux exposes no
		// ModifyDN route method at all (route.go defines routes only for
		// Bind/Search/Add/Modify/Delete/Compare/Extended/Abandon/Cancel), so
		// every ModifyDNRequest falls through to the same NotFound catch-all
		// as an unregistered Extended OID — see unsupported.go's
		// handleNotFound. Before that handler learned to recognize
		// message.ModifyDNRequest, this request got no response at all
		// (conn.ModifyDN would hang until a client-side timeout), not a
		// clear fail-closed LDAP result.
		conn := dialTest(t, addr)
		conn.SetTimeout(5 * time.Second)
		err := conn.ModifyDN(goldapclient.NewModifyDNRequest("cn=x,"+protoGroupBaseDN, "cn=y", true, ""))
		requireUnwillingToPerform(t, err)
	})
	t.Run("Extended WhoAmI", func(t *testing.T) {
		conn := dialTest(t, addr)
		_, err := conn.WhoAmI(nil)
		requireUnwillingToPerform(t, err)
	})
	t.Run("Extended StartTLS", func(t *testing.T) {
		conn := dialTest(t, addr)
		requireUnwillingToPerform(t, conn.StartTLS(nil))
	})

	t.Run("SASL-after-success clears state", func(t *testing.T) {
		conn := dialTest(t, addr)
		requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

		saslErr := asLDAPError(conn.ExternalBind())
		if saslErr == nil || int(saslErr.ResultCode) != ldapserver.LDAPResultAuthMethodNotSupported {
			t.Fatalf("SASL bind result = %+v, want AuthMethodNotSupported", saslErr)
		}

		res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
		if err == nil && res != nil && len(res.Entries) > 0 {
			t.Fatalf("search after SASL bind attempt succeeded: %+v, want state cleared", res)
		}
	})
}

// ---- 14. disconnect removes state ------------------------------------------

func TestProtocol_DisconnectRemovesState(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
	conn.Close()

	fresh := dialTest(t, addr)
	res, err := fresh.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err == nil && res != nil && len(res.Entries) > 0 {
		t.Fatalf("fresh connection search succeeded without binding: %+v", res)
	}
}

// ---- 15. malformed requests do not panic the process -----------------------

func TestProtocol_MalformedBERSurvival(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Deliberately invalid BER: a long, incomplete tag/length sequence.
	if _, err := raw.Write([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	raw.Close()

	// The server must still be alive and correct for a fresh connection.
	conn := dialTest(t, addr)
	requireSuccess(t, "bind after malformed input", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
}

// ---- additional high-risk proofs ------------------------------------------

func TestProtocol_OneVerifyOneRolesAcrossManySearches(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a", "ch_b"})
	fv := newFakeVerifier(acct)
	fr := newFakeRoles(acct)
	addr, _, _ := startTestServer(t, fv, fr)

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	for i := 0; i < 5; i++ {
		if _, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil)); err != nil {
			t.Fatalf("search #%d: %v", i, err)
		}
	}

	if fv.callCount() != 1 {
		t.Fatalf("verifier calls = %d, want exactly 1", fv.callCount())
	}
	if fr.callCount() != 1 {
		t.Fatalf("roles calls = %d, want exactly 1", fr.callCount())
	}
}

func TestProtocol_MalformedGroupsClaimAsVisibleAsOtherAuthFailure(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", nil)
	fr := newFakeRoles(acct)
	fr.failErr = errors.New("malformed configured groups claim: not a list")
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), fr)

	conn := dialTest(t, addr)
	requireInvalidCredentials(t, "role pipeline failure", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
}

func TestProtocol_RootCancellationCancelsInFlightVerify(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed: Verify blocks until ctx is canceled
	fv.returned = make(chan error, 1)

	addr, rootCancel, stop := startTestServer(t, fv, newFakeRoles(acct))

	bindDone := make(chan struct{})
	go func() {
		defer close(bindDone)
		conn, err := goldapclient.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer conn.Close()
		bindAs(conn, protoBindDN("alice"), "jwt-alice")
	}()

	select {
	case <-fv.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("fake verifier was never entered")
	}

	rootCancel()
	stop()

	select {
	case err := <-fv.returned:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("verifier's Verify returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked verifier never observed root cancellation")
	}

	select {
	case <-bindDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("bind goroutine never returned after shutdown")
	}
}

func TestProtocol_ConnectionCloseCancelsInFlightVerify(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed by the test
	fv.returned = make(chan error, 1)

	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	conn := dialTest(t, addr)
	bindDone := make(chan struct{})
	go func() {
		defer close(bindDone)
		bindAs(conn, protoBindDN("alice"), "jwt-alice")
	}()

	select {
	case <-fv.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("fake verifier was never entered")
	}

	// Closing the connection while Verify is blocked must abandon the
	// in-flight request (via Message.Done) and cancel the request context
	// the fake verifier is waiting on.
	conn.Close()

	select {
	case err := <-fv.returned:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("verifier's Verify returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked verifier never observed connection close")
	}

	select {
	case <-bindDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("bind goroutine never returned after connection close")
	}

	// Unblock the shared fake verifier so the independent check below
	// exercises "the abandoned request left no shared lock/resource
	// behind", not "this fake happens to block forever on every call".
	close(fv.block)

	// An independent Bind on a fresh connection must still complete
	// promptly: the abandoned request must not have left the server
	// holding any shared lock or resource.
	conn2 := dialTest(t, addr)
	done := make(chan struct{})
	go func() {
		defer close(done)
		bindAs(conn2, protoBindDN("alice"), "jwt-alice")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("independent bind on a fresh connection did not complete after abandonment")
	}
}

func TestProtocol_ResolverRoleSliceMutationCannotAffectStoredRoles(t *testing.T) {
	mutableRoles := []string{"ch_a", "ch_b"}
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", mutableRoles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	// Mutate the slice backing the fixture after Bind has already
	// completed and stored its own defensive copy (session.replace clones).
	mutableRoles[0] = "MUTATED"

	res, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	for _, e := range res.Entries {
		if strings.Contains(e.GetAttributeValue("cn"), "MUTATED") {
			t.Fatalf("post-bind mutation of the resolver's role slice leaked into stored state: %+v", e)
		}
	}
}

func TestProtocol_SentinelCredentialAbsentFromLogs(t *testing.T) {
	const sentinelToken = "SENTINEL-JWT-3f9a7c21-do-not-log-me"
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	var buf bytes.Buffer
	prevLogger := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prevLogger })

	// A failing Bind whose password IS the sentinel: this is the case most
	// likely to leak, since a naive implementation might log the raw
	// verifier-call arguments on failure.
	conn := dialTest(t, addr)
	requireInvalidCredentials(t, "sentinel bind", bindAs(conn, protoBindDN("alice"), sentinelToken))

	// And a successful Bind using the real password, to prove the
	// dependency's own packet logger (which logs hex-encoded raw packets,
	// necessarily containing the password) is disabled too.
	conn2 := dialTest(t, addr)
	requireSuccess(t, "real bind", bindAs(conn2, protoBindDN("alice"), "jwt-alice"))

	if strings.Contains(buf.String(), sentinelToken) {
		t.Fatalf("captured logs contain the sentinel credential:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "jwt-alice") {
		t.Fatalf("captured logs contain the real bind password:\n%s", buf.String())
	}
}

func TestProtocol_ConcurrentReBindAndSearchRace(t *testing.T) {
	alice := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	bob := account("bob", "https://idp.test/", "sub-bob", "jwt-bob", []string{"ch_b"})
	addr, _, _ := startTestServer(t, newFakeVerifier(alice, bob), newFakeRoles(alice, bob))

	conn := dialTest(t, addr)
	requireSuccess(t, "initial bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	// A fixed, modest iteration count (rather than a time-boxed loop) keeps
	// this connection's total message count well clear of any concern
	// about a long-lived connection's request-ID growth — irrelevant to
	// what this test is actually proving, which is that the per-connection
	// operation lock linearizes overlapping Bind/Search on one connection
	// without deadlocking or racing, checked by running with -race.
	const rounds = 25

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			bindAs(conn, protoBindDN("bob"), "jwt-bob")
			bindAs(conn, protoBindDN("alice"), "jwt-alice")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_, _ = conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
			_, _ = conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("bob"), nil))
		}
	}()
	wg.Wait()
}
