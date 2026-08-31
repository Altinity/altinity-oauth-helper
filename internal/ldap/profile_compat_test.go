package ldap_test

// This file implements the phase-2 plan's "Shared old/new compatibility
// tests" section (plan lines ~1391-1434): it drives BOTH the legacy
// production server (internal/ldap, imported as ldap below) and the new
// compatibility profile (internal/ldap/profile, imported as profileldap)
// over real TCP with a real go-ldap/v3 client, for every case the plan
// claims parity on, and asserts the two backends' OBSERVED behavior is
// equal — not merely that each independently passes some expectation.
//
// # Amendment 7 (fakes ownership)
//
// The Phase 2 plan's coordinator-approved Amendment 7 states that Go
// _test.go files cannot be shared across package boundaries, so the
// fakeVerifier/fakeResolver test fakes below are a DELIBERATE, ACCEPTED
// duplication of the ones already defined in
// internal/ldap/profile/fakes_test.go (package profile) and in
// protocol_test.go (package ldap, this same directory) — this file lives
// in ITS OWN package, ldap_test (an external test package that can import
// both internal/ldap and internal/ldap/profile at once, which is exactly
// why the shared compat test has to live here rather than in either
// backend's own internal test package). The CANONICAL copy of these fakes
// is internal/ldap/profile/fakes_test.go; every later profile-package test
// file must reuse that one, but this file's own copy is independent by
// design.
//
// # Correlation ID
//
// internal/ldap/profile/logging.go's correlationID is a byte-identical
// REIMPLEMENTATION of internal/ldap/server.go's sha256(issuer+"\x00"+
// subject) truncate-to-8-bytes-hex algorithm — never an import — so this
// file's TestProfileCompatibility_CorrelationIDExactValue below compares
// the actual captured hex string from both backends' logs, not merely
// field presence, per "Correlation ID ownership" in the plan.
//
// # Explicitly excluded from equality (plan lines ~1416-1434)
//
// The following are deliberate replacement narrowings, not regressions,
// and this file MUST NOT weaken any assertion below to paper over one of
// them — they belong to profile's own package-local tests
// (internal/ldap/profile/*_test.go), never here:
//
//   - Bind version != 3 (legacy tolerates v1/v2/v4+; profile requires
//     exactly 3 and returns protocolError instead);
//   - Search derefAliases != 0 (legacy tolerates; profile returns 50);
//   - Search typesOnly == true (legacy renders typesOnly semantics;
//     profile returns 50);
//   - an empty Search attribute selection (legacy returns every fixed
//     attribute; profile returns 50 — exactly one attribute is required);
//   - Search attribute selection "*" (same reason as above);
//   - Search attribute selection "1.1" (legacy honors RFC 4511's "no
//     attributes" convention; profile returns 50);
//   - a non-"cn" or multi-attribute Search projection (legacy projects
//     objectClass/member too; profile only ever renders "cn");
//   - ordinary (non-critical) Abandon's cancellation behavior (legacy's
//     vendored dependency actually cancels the target request; profile
//     recognizes and drops Abandon with no cancellation at all);
//   - ordinary (non-critical) RFC 3909 Cancel's result/target semantics
//     (legacy's vendored RouteMux serves Cancel with real vendored
//     target/result behavior; profile treats it as an ordinary unsupported
//     Extended operation, always result 53);
//   - generic filters/routes/concurrency (out of scope for a fixed
//     ClickHouse compatibility profile entirely).
//
// # Non-parallel discipline
//
// Several cases below swap the process-global zerolog log.Logger for the
// duration of one Bind/Search call (see captureCompatLog) — following the
// same discipline internal/ldap/redaction_boundary_test.go's
// captureAppLog already established in this package: none of the tests in
// this file may run in parallel with each other or with anything else
// touching that same process global, and none of them call t.Parallel().

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldapclient "github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
	ldap "github.com/altinity/altinity-oauth-helper/internal/ldap"
	profileldap "github.com/altinity/altinity-oauth-helper/internal/ldap/profile"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// ---- fixed test topology (independent of either backend's own fixtures) --

const (
	compatUserBaseDN  = "ou=users,dc=compat,dc=test"
	compatGroupBaseDN = "ou=groups,dc=compat,dc=test"
	compatRDNAttr     = "uid"
	compatCNPrefix    = "clickhouse_"
)

func compatBindDN(username string) string {
	return compatRDNAttr + "=" + username + "," + compatUserBaseDN
}

// ---- fakes (Amendment 7: duplicated by accepted decision) -----------------

// fakeVerifier is a narrow, deterministic stand-in for *verification.Verifier
// satisfying both internal/ldap's unexported verifier interface and
// internal/ldap/profile's exported Verifier interface at once (their method
// sets are structurally identical), keyed by the presented password so one
// fixture can drive both backends from the same table.
type fakeVerifier struct {
	mu      sync.Mutex
	success map[string]*verification.Result
	failure map[string]error
}

func newFakeVerifier() *fakeVerifier {
	return &fakeVerifier{success: map[string]*verification.Result{}, failure: map[string]error{}}
}

func (f *fakeVerifier) withSuccess(password string, result *verification.Result) *fakeVerifier {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.success[password] = result
	return f
}

func (f *fakeVerifier) withFailure(password string, err error) *fakeVerifier {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure[password] = err
	return f
}

var errCompatUnrecognizedPassword = errors.New("fakeVerifier: unrecognized password")

func (f *fakeVerifier) Verify(_ context.Context, _ string, password string) (*verification.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failure[password]; ok {
		return nil, err
	}
	if result, ok := f.success[password]; ok {
		return result, nil
	}
	return nil, errCompatUnrecognizedPassword
}

// fakeResolver is a narrow, deterministic stand-in for *roles.Pipeline,
// keyed by claims.Subject. It deliberately returns the SAME underlying
// slice value on every call for a given subject (never a defensive copy),
// so TestProfileCompatibility_RoleSnapshotCloning can mutate the slice it
// registered and prove neither backend's stored session state is affected
// — only replaceAuth/session.replace's own cloning protects against that.
type fakeResolver struct {
	mu        sync.Mutex
	bySubject map[string][]string
	err       error
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{bySubject: map[string][]string{}}
}

func (f *fakeResolver) withRoles(subject string, roles []string) *fakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bySubject[subject] = roles
	return f
}

func (f *fakeResolver) withError(err error) *fakeResolver {
	f.err = err
	return f
}

func (f *fakeResolver) Roles(claims *oauth.Claims) ([]string, error) {
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

// newVerificationResult builds the minimal *verification.Result shape both
// backends' successful-Bind flow needs.
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

// ---- backend starters ------------------------------------------------------

// startLegacyBackend starts the real production internal/ldap.Server on a
// fresh loopback listener and registers its (ordering-sensitive — see
// protocol_test.go's startServing doc) teardown via t.Cleanup: close OUR OWN
// listener reference first (unblocks Accept), wait for Serve to return, THEN
// call Stop — the vendored vjeantet/ldapserver dependency stores its
// listener in a plain unsynchronized field, so any other order risks a real
// data race.
func startLegacyBackend(t *testing.T, v *fakeVerifier, r *fakeResolver) string {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := ldap.Config{
		Listen:           "127.0.0.1:0",
		UserBaseDN:       compatUserBaseDN,
		GroupBaseDN:      compatGroupBaseDN,
		UserRDNAttribute: compatRDNAttr,
		RoleCNPrefix:     compatCNPrefix,
	}
	srv, err := ldap.New(ctx, cfg, v, r)
	if err != nil {
		t.Fatalf("legacy ldap.New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("legacy net.Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	t.Cleanup(func() {
		_ = ln.Close()
		<-errCh
		srv.Stop()
		cancel()
	})

	return ln.Addr().String()
}

// startProfileBackend starts the new internal/ldap/profile.Server on a
// fresh loopback listener. Unlike the legacy backend, profile.Server.Stop
// itself closes the listener and waits for Serve to return (mu-protected,
// no equivalent data race), so the simpler Stop-then-drain order is safe
// here.
func startProfileBackend(t *testing.T, v *fakeVerifier, r *fakeResolver) string {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := profileldap.Config{
		UserBaseDN:       compatUserBaseDN,
		GroupBaseDN:      compatGroupBaseDN,
		UserRDNAttribute: compatRDNAttr,
		RoleCNPrefix:     compatCNPrefix,
	}
	srv, err := profileldap.New(ctx, cfg, v, r)
	if err != nil {
		t.Fatalf("profile New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("profile net.Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	t.Cleanup(func() {
		srv.Stop()
		<-errCh
		cancel()
	})

	return ln.Addr().String()
}

// backendKind names one backend under test and how to start it fresh.
type backendKind struct {
	name  string
	start func(t *testing.T, v *fakeVerifier, r *fakeResolver) string
}

var compatBackends = []backendKind{
	{"legacy", startLegacyBackend},
	{"profile", startProfileBackend},
}

// ---- dial/request helpers ---------------------------------------------------

func dialCompat(t *testing.T, addr string) *goldapclient.Conn {
	t.Helper()
	conn, err := goldapclient.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func asLDAPErr(err error) *goldapclient.Error {
	if err == nil {
		return nil
	}
	var ldapErr *goldapclient.Error
	if errors.As(err, &ldapErr) {
		return ldapErr
	}
	return &goldapclient.Error{Err: err}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// compatSearchRequest builds the one fixed ClickHouse-shaped membership
// Search this whole file ever issues: exact base, whole-subtree scope,
// never-deref-aliases, the fixed (&(objectClass=groupOfNames)(member=...))
// filter. attrs must be explicit ([]string{"cn"} or {"CN"}) for every case
// this file claims parity on — an empty/"*"/"1.1" selection is one of the
// deliberately EXCLUDED narrowings (see file header) and must never appear
// in a parity assertion here.
func compatSearchRequest(baseDN, boundDN string, attrs []string, sizeLimit, timeLimit int, controls []goldapclient.Control) *goldapclient.SearchRequest {
	filter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", boundDN)
	return goldapclient.NewSearchRequest(baseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, sizeLimit, timeLimit, false, filter, attrs, controls)
}

// ---- critical control (Amendment: strict DER 0xFF criticality) ------------

// testUnknownControlOID is an arbitrary OID neither backend implements.
const testUnknownControlOID = "1.2.3.4.5.6.999.1"

// unknownControlValue implements goldapclient.Control directly, rather than
// using go-ldap/v3's own ControlString, exactly for the reason
// internal/ldap/controls_test.go's own unknownControlValue documents:
// ControlString.Encode() writes a critical=true BOOLEAN via ber.NewBoolean
// (content byte 0x01, permissive BER) — but both this repo's legacy goldap
// fork AND internal/ldap/profile's cryptobyte-based scanControls decode
// Controls' criticality BOOLEAN strictly (DER 0x00/0xFF only). Encoding a
// critical control with plain NewBoolean makes BOTH backends reject the
// entire LDAPMessage as malformed and silently drop the connection, never
// reaching either backend's critical-control guard at all — ber.NewLDAPBoolean
// is the RFC-4511-compliant (and cryptobyte-DER-compatible) encoder that
// avoids that.
type unknownControlValue struct {
	critical bool
}

func (c unknownControlValue) GetControlType() string { return testUnknownControlOID }
func (c unknownControlValue) String() string         { return testUnknownControlOID }
func (c unknownControlValue) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, testUnknownControlOID, "Control Type"))
	if c.critical {
		packet.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	}
	return packet
}

func unknownControl(critical bool) goldapclient.Control {
	return unknownControlValue{critical: critical}
}

// ---- parity comparison types -----------------------------------------------

// bindResult is a comparable (==-able) normalization of a Bind outcome:
// success, or the exact (resultCode, matchedDN, diagnostic) triple.
type bindResult struct {
	success    bool
	resultCode int
	matchedDN  string
	diagnostic string
}

func bindResultFrom(err error) bindResult {
	if err == nil {
		return bindResult{success: true}
	}
	ldapErr := asLDAPErr(err)
	return bindResult{
		resultCode: int(ldapErr.ResultCode),
		matchedDN:  ldapErr.MatchedDN,
		diagnostic: errText(ldapErr.Err),
	}
}

func requireBindParity(t *testing.T, label string, legacy, profile bindResult) {
	t.Helper()
	if legacy != profile {
		t.Fatalf("%s: parity mismatch: legacy=%+v profile=%+v", label, legacy, profile)
	}
}

// searchResult is a normalization of a Search outcome: the terminal
// (resultCode, diagnostic) plus the ordered list of returned entries' sole
// "cn" attribute value.
type searchResult struct {
	resultCode int
	diagnostic string
	cns        []string
}

func searchResultFrom(res *goldapclient.SearchResult, err error) searchResult {
	sr := searchResult{}
	if res != nil {
		for _, e := range res.Entries {
			sr.cns = append(sr.cns, e.GetAttributeValue("cn"))
		}
	}
	if err != nil {
		ldapErr := asLDAPErr(err)
		sr.resultCode = int(ldapErr.ResultCode)
		sr.diagnostic = errText(ldapErr.Err)
	}
	return sr
}

func requireSearchParity(t *testing.T, label string, legacy, profile searchResult) {
	t.Helper()
	if legacy.resultCode != profile.resultCode || legacy.diagnostic != profile.diagnostic || !reflect.DeepEqual(legacy.cns, profile.cns) {
		t.Fatalf("%s: parity mismatch: legacy=%+v profile=%+v", label, legacy, profile)
	}
}

// ---- log capture (non-parallel; see file header) ---------------------------

// captureCompatLog swaps the process-global zerolog log.Logger for a
// buffer-backed one, restoring it via t.Cleanup. See
// internal/ldap/redaction_boundary_test.go's captureAppLog for the
// established precedent this mirrors: every caller must avoid t.Parallel().
func captureCompatLog(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

// logLine is one parsed JSON log record.
type logLine map[string]any

// lastLogLine parses the final non-empty line of buf as JSON. Both
// backends emit exactly one zerolog record per Bind/Search terminal
// response, so the last line is always the one the immediately-preceding
// call produced.
func lastLogLine(t *testing.T, buf *strings.Builder) logLine {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("captured log is empty, want at least one record")
	}
	last := lines[len(lines)-1]
	var m map[string]any
	if err := json.Unmarshal([]byte(last), &m); err != nil {
		t.Fatalf("parse log line %q: %v", last, err)
	}
	return m
}

// logLineKeys returns the sorted field names of m, excluding zerolog's own
// ambient fields (level/time), which are logging-infrastructure metadata,
// not part of either backend's own logging contract.
func logLineKeys(m logLine) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "level" || k == "time" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func requireLogParity(t *testing.T, label string, legacy, profile logLine) {
	t.Helper()
	if legacy["message"] != profile["message"] {
		t.Fatalf("%s: message legacy=%v profile=%v", label, legacy["message"], profile["message"])
	}
	lk, pk := logLineKeys(legacy), logLineKeys(profile)
	if !reflect.DeepEqual(lk, pk) {
		t.Fatalf("%s: keys legacy=%v profile=%v", label, lk, pk)
	}
}

// assertNoSubstring fails the test if haystack contains marker.
func assertNoSubstring(t *testing.T, label, haystack, marker string) {
	t.Helper()
	if marker == "" {
		return
	}
	if strings.Contains(haystack, marker) {
		t.Fatalf("%s: marker %q leaked into %q", label, marker, haystack)
	}
}

// ============================================================================
// Parity cases
// ============================================================================

// TestProfileCompatibility_ValidSimpleBindV3 covers the plan's "valid
// LDAPv3 simple Bind" parity case.
func TestProfileCompatibility_ValidSimpleBindV3(t *testing.T) {
	results := map[string]bindResult{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
				Username: compatBindDN("alice"),
				Password: "jwt-alice",
			})
			results[b.name] = bindResultFrom(err)
		})
	}
	requireBindParity(t, "valid simple Bind", results["legacy"], results["profile"])
	if results["legacy"].success != true {
		t.Fatalf("valid simple Bind: got %+v, want success", results["legacy"])
	}
}

// TestProfileCompatibility_InvalidCredentials covers the plan's "invalid
// credentials" parity case: a wrong password converges on the fixed
// non-disclosing invalidCredentials boundary on both backends.
func TestProfileCompatibility_InvalidCredentials(t *testing.T) {
	results := map[string]bindResult{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
				Username: compatBindDN("alice"),
				Password: "not-the-right-jwt",
			})
			results[b.name] = bindResultFrom(err)
		})
	}
	requireBindParity(t, "invalid credentials", results["legacy"], results["profile"])
	if results["legacy"].success {
		t.Fatalf("invalid credentials: got success, want invalidCredentials")
	}
	if results["legacy"].resultCode != goldapclient.LDAPResultInvalidCredentials {
		t.Fatalf("invalid credentials: resultCode = %d, want %d", results["legacy"].resultCode, goldapclient.LDAPResultInvalidCredentials)
	}
}

// TestProfileCompatibility_SASLUnsupported covers the plan's "unsupported
// SASL result 7" parity case (Amendment 2: legacy's vendored decoder only
// ever recognizes context tags [0]/[3] for AuthenticationChoice, so result
// 7 is reachable only for [3] — the go-ldap DigestMD5Bind helper sends
// exactly that shape).
func TestProfileCompatibility_SASLUnsupported(t *testing.T) {
	results := map[string]bindResult{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier()
			r := newFakeResolver()
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			_, err := conn.DigestMD5Bind(&goldapclient.DigestMD5BindRequest{
				Host:     "localhost",
				Username: "irrelevant",
				Password: "irrelevant-password",
			})
			results[b.name] = bindResultFrom(err)
		})
	}
	requireBindParity(t, "SASL bind", results["legacy"], results["profile"])
	if results["legacy"].resultCode != goldapclient.LDAPResultAuthMethodNotSupported {
		t.Fatalf("SASL bind: resultCode = %d, want %d", results["legacy"].resultCode, goldapclient.LDAPResultAuthMethodNotSupported)
	}
	if results["legacy"].diagnostic != "only simple authentication is supported" {
		t.Fatalf("SASL bind: diagnostic = %q, want %q", results["legacy"].diagnostic, "only simple authentication is supported")
	}
}

// TestProfileCompatibility_SearchBeforeBind covers the plan's
// "Search-before-Bind" parity case: an unauthenticated connection's Search
// converges on 50/insufficient access on both backends.
func TestProfileCompatibility_SearchBeforeBind(t *testing.T) {
	results := map[string]searchResult{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier()
			r := newFakeResolver()
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			req := compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil)
			res, err := conn.Search(req)
			results[b.name] = searchResultFrom(res, err)
		})
	}
	requireSearchParity(t, "Search before Bind", results["legacy"], results["profile"])
	if results["legacy"].resultCode != goldapclient.LDAPResultInsufficientAccessRights {
		t.Fatalf("Search before Bind: resultCode = %d, want %d", results["legacy"].resultCode, goldapclient.LDAPResultInsufficientAccessRights)
	}
}

// TestProfileCompatibility_TwoConnectionIsolation covers the plan's
// "connection isolation" parity case: authenticating on one connection
// must never be visible to a second, unauthenticated connection to the
// SAME server instance.
func TestProfileCompatibility_TwoConnectionIsolation(t *testing.T) {
	type outcome struct {
		conn1Search searchResult
		conn2Search searchResult
	}
	results := map[string]outcome{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
			addr := b.start(t, v, r)

			conn1 := dialCompat(t, addr)
			if _, err := conn1.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
				t.Fatalf("conn1 bind: %v", err)
			}

			conn2 := dialCompat(t, addr)
			res2, err2 := conn2.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil))

			res1, err1 := conn1.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil))

			results[b.name] = outcome{
				conn1Search: searchResultFrom(res1, err1),
				conn2Search: searchResultFrom(res2, err2),
			}
		})
	}
	requireSearchParity(t, "isolated conn1 (authenticated)", results["legacy"].conn1Search, results["profile"].conn1Search)
	requireSearchParity(t, "isolated conn2 (never bound)", results["legacy"].conn2Search, results["profile"].conn2Search)
	if results["legacy"].conn2Search.resultCode != goldapclient.LDAPResultInsufficientAccessRights {
		t.Fatalf("conn2 (never bound): resultCode = %d, want %d", results["legacy"].conn2Search.resultCode, goldapclient.LDAPResultInsufficientAccessRights)
	}
	if len(results["legacy"].conn1Search.cns) != 1 {
		t.Fatalf("conn1 (authenticated): entries = %d, want 1", len(results["legacy"].conn1Search.cns))
	}
}

// TestProfileCompatibility_RebindReplaceAndClear is named explicitly by the
// plan (Tests mapped, L1350): a successful re-Bind as a DIFFERENT principal
// on the same connection REPLACES (never merges with) the prior state, and
// a subsequently FAILED re-Bind CLEARS it — a following Search must then
// observe unauthenticated, not the stale prior principal.
func TestProfileCompatibility_RebindReplaceAndClear(t *testing.T) {
	type outcome struct {
		afterBob      searchResult
		afterFailedRe searchResult
	}
	results := map[string]outcome{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().
				withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999)).
				withSuccess("jwt-bob", newVerificationResult("bob", "https://idp.test/", "sub-bob", 9999999999))
			r := newFakeResolver().
				withRoles("sub-alice", []string{"ch_alice_role"}).
				withRoles("sub-bob", []string{"ch_bob_role"})
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)

			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
				t.Fatalf("initial bind as alice: %v", err)
			}

			// Bob replaces alice.
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("bob"), Password: "jwt-bob"}); err != nil {
				t.Fatalf("re-bind as bob: %v", err)
			}
			resBob, errBob := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("bob"), []string{"cn"}, 0, 0, nil))

			// A failed re-Bind (wrong password) clears state entirely.
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("bob"), Password: "wrong-password"}); err == nil {
				t.Fatalf("failed re-bind unexpectedly succeeded")
			}
			resAfter, errAfter := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("bob"), []string{"cn"}, 0, 0, nil))

			results[b.name] = outcome{
				afterBob:      searchResultFrom(resBob, errBob),
				afterFailedRe: searchResultFrom(resAfter, errAfter),
			}
		})
	}

	requireSearchParity(t, "Search after Bob replaces Alice", results["legacy"].afterBob, results["profile"].afterBob)
	requireSearchParity(t, "Search after failed re-Bind clears state", results["legacy"].afterFailedRe, results["profile"].afterFailedRe)

	if got := results["legacy"].afterBob.cns; len(got) != 1 || got[0] != compatCNPrefix+"ch_bob_role" {
		t.Fatalf("after Bob replaces Alice: cns = %v, want [%s]", got, compatCNPrefix+"ch_bob_role")
	}
	if results["legacy"].afterFailedRe.resultCode != goldapclient.LDAPResultInsufficientAccessRights {
		t.Fatalf("after failed re-Bind: resultCode = %d, want %d (cleared)", results["legacy"].afterFailedRe.resultCode, goldapclient.LDAPResultInsufficientAccessRights)
	}
}

// TestProfileCompatibility_RoleSnapshotCloning covers the plan's "role
// snapshot cloning" parity case: mutating the role slice the fake resolver
// handed back, AFTER a successful Bind, must never change what a later
// Search on that connection observes — only replace/store-time cloning
// (not the resolver, which deliberately hands back the same underlying
// slice on every call) protects the stored snapshot.
func TestProfileCompatibility_RoleSnapshotCloning(t *testing.T) {
	results := map[string]searchResult{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			roles := []string{"ch_before_mutation"}
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver().withRoles("sub-alice", roles)
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
				t.Fatalf("bind: %v", err)
			}

			// Mutate the SAME backing array the resolver returned, AFTER
			// Bind has already stored its snapshot.
			roles[0] = "MUTATED-AFTER-BIND"

			res, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil))
			results[b.name] = searchResultFrom(res, err)
		})
	}
	requireSearchParity(t, "role snapshot cloning", results["legacy"], results["profile"])
	want := compatCNPrefix + "ch_before_mutation"
	if got := results["legacy"].cns; len(got) != 1 || got[0] != want {
		t.Fatalf("role snapshot cloning: cns = %v, want [%s] (unaffected by later mutation)", got, want)
	}
}

// TestProfileCompatibility_ZeroRoles covers the plan's "zero roles" parity
// case: a successfully Bound principal with no mapped roles gets a
// successful, zero-entry Search on both backends.
func TestProfileCompatibility_ZeroRoles(t *testing.T) {
	results := map[string]searchResult{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver() // no roles registered for sub-alice
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
				t.Fatalf("bind: %v", err)
			}

			res, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil))
			results[b.name] = searchResultFrom(res, err)
		})
	}
	requireSearchParity(t, "zero roles", results["legacy"], results["profile"])
	if results["legacy"].resultCode != goldapclient.LDAPResultSuccess || len(results["legacy"].cns) != 0 {
		t.Fatalf("zero roles: got %+v, want success/zero entries", results["legacy"])
	}
}

// TestProfileCompatibility_SupportedSearchShapeAndCNProjection covers the
// plan's "supported exact base/scope/filter/member Search" AND
// "exactly-one cn request in cn/CN variants" parity cases together: a
// correctly-shaped membership Search against the exact configured base,
// whole-subtree scope, never-deref-aliases, and the fixed membership
// filter returns exactly one entry carrying only a "cn" attribute, whether
// the client requested it as "cn" or "CN".
func TestProfileCompatibility_SupportedSearchShapeAndCNProjection(t *testing.T) {
	for _, attrCase := range []string{"cn", "CN"} {
		attrCase := attrCase
		t.Run("attr="+attrCase, func(t *testing.T) {
			results := map[string]searchResult{}
			attrNames := map[string][]string{}
			for _, b := range compatBackends {
				b := b
				t.Run(b.name, func(t *testing.T) {
					v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
					r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
					addr := b.start(t, v, r)

					conn := dialCompat(t, addr)
					if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
						t.Fatalf("bind: %v", err)
					}

					res, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{attrCase}, 0, 0, nil))
					results[b.name] = searchResultFrom(res, err)

					if res != nil && len(res.Entries) == 1 {
						names := make([]string, 0, len(res.Entries[0].Attributes))
						for _, a := range res.Entries[0].Attributes {
							names = append(names, a.Name)
						}
						attrNames[b.name] = names
					}
				})
			}
			requireSearchParity(t, "attr="+attrCase, results["legacy"], results["profile"])

			want := compatCNPrefix + "ch_engineer"
			if got := results["legacy"].cns; len(got) != 1 || got[0] != want {
				t.Fatalf("attr=%s: cns = %v, want [%s]", attrCase, got, want)
			}
			for _, name := range []string{"legacy", "profile"} {
				if names := attrNames[name]; len(names) != 1 || !strings.EqualFold(names[0], "cn") {
					t.Fatalf("attr=%s (%s): entry attributes = %v, want exactly [\"cn\"]", attrCase, name, names)
				}
			}
		})
	}
}

// TestProfileCompatibility_SizeLimit covers the plan's "sizeLimit 0 and N
// with <=N roles" parity case.
func TestProfileCompatibility_SizeLimit(t *testing.T) {
	roleSet := []string{"ch_role_a", "ch_role_b", "ch_role_c"}
	wantCNs := []string{
		compatCNPrefix + "ch_role_a",
		compatCNPrefix + "ch_role_b",
		compatCNPrefix + "ch_role_c",
	}

	for _, sizeLimit := range []int{0, 3} {
		sizeLimit := sizeLimit
		t.Run(fmt.Sprintf("sizeLimit=%d", sizeLimit), func(t *testing.T) {
			results := map[string]searchResult{}
			for _, b := range compatBackends {
				b := b
				t.Run(b.name, func(t *testing.T) {
					v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
					r := newFakeResolver().withRoles("sub-alice", roleSet)
					addr := b.start(t, v, r)

					conn := dialCompat(t, addr)
					if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
						t.Fatalf("bind: %v", err)
					}

					res, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, sizeLimit, 0, nil))
					results[b.name] = searchResultFrom(res, err)
				})
			}
			label := fmt.Sprintf("sizeLimit=%d", sizeLimit)
			requireSearchParity(t, label, results["legacy"], results["profile"])
			if results["legacy"].resultCode != goldapclient.LDAPResultSuccess {
				t.Fatalf("%s: resultCode = %d, want success", label, results["legacy"].resultCode)
			}
			got := append([]string(nil), results["legacy"].cns...)
			sort.Strings(got)
			wantSorted := append([]string(nil), wantCNs...)
			sort.Strings(wantSorted)
			if !reflect.DeepEqual(got, wantSorted) {
				t.Fatalf("%s: cns = %v, want %v", label, got, wantSorted)
			}
		})
	}
}

// TestProfileCompatibility_TimeLimit covers the plan's "timeLimit 0 and
// positive fast cases" parity case: a client-declared timeLimit that is
// never actually approached (the fixture completes far faster than the
// declared deadline) must succeed on both backends.
func TestProfileCompatibility_TimeLimit(t *testing.T) {
	for _, timeLimit := range []int{0, 30} {
		timeLimit := timeLimit
		t.Run(fmt.Sprintf("timeLimit=%d", timeLimit), func(t *testing.T) {
			results := map[string]searchResult{}
			for _, b := range compatBackends {
				b := b
				t.Run(b.name, func(t *testing.T) {
					v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
					r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
					addr := b.start(t, v, r)

					conn := dialCompat(t, addr)
					if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
						t.Fatalf("bind: %v", err)
					}

					res, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, timeLimit, nil))
					results[b.name] = searchResultFrom(res, err)
				})
			}
			label := fmt.Sprintf("timeLimit=%d", timeLimit)
			requireSearchParity(t, label, results["legacy"], results["profile"])
			if results["legacy"].resultCode != goldapclient.LDAPResultSuccess || len(results["legacy"].cns) != 1 {
				t.Fatalf("%s: got %+v, want success/1 entry", label, results["legacy"])
			}
		})
	}
}

// TestProfileCompatibility_UnknownNonCriticalControlIgnored covers the
// plan's "unknown non-critical Controls" parity case, on both Bind and
// Search.
func TestProfileCompatibility_UnknownNonCriticalControlIgnored(t *testing.T) {
	t.Run("bind", func(t *testing.T) {
		results := map[string]bindResult{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
				addr := b.start(t, v, r)

				conn := dialCompat(t, addr)
				_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
					Username: compatBindDN("alice"),
					Password: "jwt-alice",
					Controls: []goldapclient.Control{unknownControl(false)},
				})
				results[b.name] = bindResultFrom(err)
			})
		}
		requireBindParity(t, "bind with unknown non-critical control", results["legacy"], results["profile"])
		if !results["legacy"].success {
			t.Fatalf("bind with unknown non-critical control: got %+v, want success", results["legacy"])
		}
	})

	t.Run("search", func(t *testing.T) {
		results := map[string]searchResult{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
				addr := b.start(t, v, r)

				conn := dialCompat(t, addr)
				if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
					t.Fatalf("bind: %v", err)
				}

				res, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, []goldapclient.Control{unknownControl(false)}))
				results[b.name] = searchResultFrom(res, err)
			})
		}
		requireSearchParity(t, "search with unknown non-critical control", results["legacy"], results["profile"])
		if results["legacy"].resultCode != goldapclient.LDAPResultSuccess || len(results["legacy"].cns) != 1 {
			t.Fatalf("search with unknown non-critical control: got %+v, want success/1 entry", results["legacy"])
		}
	})
}

// TestProfileCompatibility_CriticalBindClearsState covers the plan's
// "critical Bind -> 12; prior state cleared" parity case.
func TestProfileCompatibility_CriticalBindClearsState(t *testing.T) {
	type outcome struct {
		criticalBind bindResult
		afterSearch  searchResult
	}
	results := map[string]outcome{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
				t.Fatalf("initial bind: %v", err)
			}

			_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
				Username:           compatBindDN("alice"),
				Password:           "jwt-alice",
				Controls:           []goldapclient.Control{unknownControl(true)},
				AllowEmptyPassword: true,
			})
			critical := bindResultFrom(err)

			res, searchErr := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil))

			results[b.name] = outcome{criticalBind: critical, afterSearch: searchResultFrom(res, searchErr)}
		})
	}

	if results["legacy"].criticalBind != results["profile"].criticalBind {
		t.Fatalf("critical Bind: parity mismatch: legacy=%+v profile=%+v", results["legacy"].criticalBind, results["profile"].criticalBind)
	}
	requireSearchParity(t, "Search after critical Bind", results["legacy"].afterSearch, results["profile"].afterSearch)

	if results["legacy"].criticalBind.resultCode != goldapclient.LDAPResultUnavailableCriticalExtension {
		t.Fatalf("critical Bind: resultCode = %d, want %d", results["legacy"].criticalBind.resultCode, goldapclient.LDAPResultUnavailableCriticalExtension)
	}
	if results["legacy"].afterSearch.resultCode != goldapclient.LDAPResultInsufficientAccessRights {
		t.Fatalf("Search after critical Bind: resultCode = %d, want %d (state cleared)", results["legacy"].afterSearch.resultCode, goldapclient.LDAPResultInsufficientAccessRights)
	}
}

// TestProfileCompatibility_CriticalSearchPreservesState covers the plan's
// "critical Search -> 12; auth state unchanged" parity case.
func TestProfileCompatibility_CriticalSearchPreservesState(t *testing.T) {
	type outcome struct {
		criticalSearch searchResult
		afterSearch    searchResult
	}
	results := map[string]outcome{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
			r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
			addr := b.start(t, v, r)

			conn := dialCompat(t, addr)
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
				t.Fatalf("bind: %v", err)
			}

			criticalReq := compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), nil, 0, 0, []goldapclient.Control{unknownControl(true)})
			criticalRes, criticalErr := conn.Search(criticalReq)

			normalRes, normalErr := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil))

			results[b.name] = outcome{
				criticalSearch: searchResultFrom(criticalRes, criticalErr),
				afterSearch:    searchResultFrom(normalRes, normalErr),
			}
		})
	}

	requireSearchParity(t, "critical Search", results["legacy"].criticalSearch, results["profile"].criticalSearch)
	requireSearchParity(t, "Search after critical Search", results["legacy"].afterSearch, results["profile"].afterSearch)

	if results["legacy"].criticalSearch.resultCode != goldapclient.LDAPResultUnavailableCriticalExtension || len(results["legacy"].criticalSearch.cns) != 0 {
		t.Fatalf("critical Search: got %+v, want result 12/zero entries", results["legacy"].criticalSearch)
	}
	if results["legacy"].afterSearch.resultCode != goldapclient.LDAPResultSuccess || len(results["legacy"].afterSearch.cns) != 1 {
		t.Fatalf("Search after critical Search: got %+v, want success/1 entry (state preserved)", results["legacy"].afterSearch)
	}
}

// TestProfileCompatibility_SupportedProfileLogLines covers the plan's
// "supported-profile logs" parity case: bind succeeded/failed, both
// search-succeeded variants (unlimited and zero-roles), the fixed
// unsupported-operation (53) response, and the critical-control (12)
// response all emit the IDENTICAL message string and field-name set on
// both backends. Each subtest captures the log around exactly ONE
// triggering call (see captureCompatLog's non-parallel discipline in the
// file header).
func TestProfileCompatibility_SupportedProfileLogLines(t *testing.T) {
	t.Run("bind_succeeded", func(t *testing.T) {
		lines := map[string]logLine{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
				addr := b.start(t, v, r)

				buf := captureCompatLog(t)
				conn := dialCompat(t, addr)
				if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
					t.Fatalf("bind: %v", err)
				}
				lines[b.name] = lastLogLine(t, buf)
			})
		}
		requireLogParity(t, "bind succeeded", lines["legacy"], lines["profile"])
		if lines["legacy"]["message"] != "ldap bind succeeded" {
			t.Fatalf("bind succeeded: message = %v, want %q", lines["legacy"]["message"], "ldap bind succeeded")
		}
	})

	t.Run("bind_failed", func(t *testing.T) {
		lines := map[string]logLine{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
				addr := b.start(t, v, r)

				buf := captureCompatLog(t)
				conn := dialCompat(t, addr)
				if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "wrong-password"}); err == nil {
					t.Fatalf("bind unexpectedly succeeded")
				}
				lines[b.name] = lastLogLine(t, buf)
			})
		}
		requireLogParity(t, "bind failed", lines["legacy"], lines["profile"])
		if lines["legacy"]["message"] != "ldap bind failed" {
			t.Fatalf("bind failed: message = %v, want %q", lines["legacy"]["message"], "ldap bind failed")
		}
	})

	t.Run("search_succeeded", func(t *testing.T) {
		lines := map[string]logLine{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
				addr := b.start(t, v, r)

				conn := dialCompat(t, addr)
				if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
					t.Fatalf("bind: %v", err)
				}

				buf := captureCompatLog(t)
				if _, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil)); err != nil {
					t.Fatalf("search: %v", err)
				}
				lines[b.name] = lastLogLine(t, buf)
			})
		}
		requireLogParity(t, "search succeeded", lines["legacy"], lines["profile"])
		if lines["legacy"]["message"] != "ldap search succeeded" {
			t.Fatalf("search succeeded: message = %v, want %q", lines["legacy"]["message"], "ldap search succeeded")
		}
	})

	t.Run("search_succeeded_zero_roles", func(t *testing.T) {
		lines := map[string]logLine{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver()
				addr := b.start(t, v, r)

				conn := dialCompat(t, addr)
				if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
					t.Fatalf("bind: %v", err)
				}

				buf := captureCompatLog(t)
				if _, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), []string{"cn"}, 0, 0, nil)); err != nil {
					t.Fatalf("search: %v", err)
				}
				lines[b.name] = lastLogLine(t, buf)
			})
		}
		requireLogParity(t, "search succeeded (zero roles)", lines["legacy"], lines["profile"])
		if lines["legacy"]["message"] != "ldap search succeeded (zero roles)" {
			t.Fatalf("search succeeded (zero roles): message = %v, want %q", lines["legacy"]["message"], "ldap search succeeded (zero roles)")
		}
	})

	t.Run("unsupported_53", func(t *testing.T) {
		lines := map[string]logLine{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier()
				r := newFakeResolver()
				addr := b.start(t, v, r)

				buf := captureCompatLog(t)
				conn := dialCompat(t, addr)
				err := conn.Add(goldapclient.NewAddRequest("cn=irrelevant,"+compatGroupBaseDN, nil))
				if err == nil {
					t.Fatalf("add unexpectedly succeeded")
				}
				lines[b.name] = lastLogLine(t, buf)
			})
		}
		requireLogParity(t, "unsupported operation (53)", lines["legacy"], lines["profile"])
		if lines["legacy"]["message"] != "ldap operation rejected: unsupported" {
			t.Fatalf("unsupported operation: message = %v, want %q", lines["legacy"]["message"], "ldap operation rejected: unsupported")
		}
		if int(lines["legacy"]["result"].(float64)) != goldapclient.LDAPResultUnwillingToPerform {
			t.Fatalf("unsupported operation: result = %v, want %d", lines["legacy"]["result"], goldapclient.LDAPResultUnwillingToPerform)
		}
	})

	t.Run("critical_control_12", func(t *testing.T) {
		lines := map[string]logLine{}
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withSuccess("jwt-alice", newVerificationResult("alice", "https://idp.test/", "sub-alice", 9999999999))
				r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
				addr := b.start(t, v, r)

				conn := dialCompat(t, addr)
				if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"}); err != nil {
					t.Fatalf("bind: %v", err)
				}

				buf := captureCompatLog(t)
				_, err := conn.Search(compatSearchRequest(compatGroupBaseDN, compatBindDN("alice"), nil, 0, 0, []goldapclient.Control{unknownControl(true)}))
				if err == nil {
					t.Fatalf("critical search unexpectedly succeeded")
				}
				lines[b.name] = lastLogLine(t, buf)
			})
		}
		requireLogParity(t, "critical control (12)", lines["legacy"], lines["profile"])
		if lines["legacy"]["message"] != "ldap operation rejected: unsupported critical control" {
			t.Fatalf("critical control: message = %v, want %q", lines["legacy"]["message"], "ldap operation rejected: unsupported critical control")
		}
	})
}

// TestProfileCompatibility_CorrelationIDExactValue covers the plan's
// "exact correlation_id VALUE equality for the same fake (issuer, subject)"
// parity case: this is the ONE test in this file that compares the actual
// hash string both backends produce, not merely field presence. The
// literal expected value is independently verified against
// internal/ldap/profile/logging_test.go's own hard-coded
// TestCorrelationID_KnownVector fixture (same (issuer, subject) pair),
// which in turn is checked directly against
// sha256("https://idp.example.com/\x00user-42")[:8] in hex.
func TestProfileCompatibility_CorrelationIDExactValue(t *testing.T) {
	const (
		issuer  = "https://idp.example.com/"
		subject = "user-42"
		want    = "7c28a3bb8ee79fb3"
	)

	values := map[string]string{}
	for _, b := range compatBackends {
		b := b
		t.Run(b.name, func(t *testing.T) {
			v := newFakeVerifier().withSuccess("jwt-carol", newVerificationResult("carol", issuer, subject, 9999999999))
			r := newFakeResolver().withRoles(subject, []string{"ch_engineer"})
			addr := b.start(t, v, r)

			buf := captureCompatLog(t)
			conn := dialCompat(t, addr)
			if _, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("carol"), Password: "jwt-carol"}); err != nil {
				t.Fatalf("bind: %v", err)
			}
			line := lastLogLine(t, buf)
			cid, ok := line["correlation_id"].(string)
			if !ok {
				t.Fatalf("correlation_id missing or not a string: %v", line)
			}
			values[b.name] = cid
		})
	}

	if values["legacy"] != values["profile"] {
		t.Fatalf("correlation_id VALUE mismatch: legacy=%q profile=%q", values["legacy"], values["profile"])
	}
	if values["legacy"] != want {
		t.Fatalf("correlation_id = %q, want known vector %q", values["legacy"], want)
	}
}

// TestProfileCompatibility_CredentialRedaction covers the plan's
// "credential redaction" parity case: a marker-shaped password, a
// hostile/malformed Bind DN, and a marker-carrying verifier failure must
// never surface — in the Bind response's diagnostic/matchedDN OR in the
// captured log — on either backend.
func TestProfileCompatibility_CredentialRedaction(t *testing.T) {
	const (
		markerJWTPassword   = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjb21wYXQtdGVzdCJ9.compat-test-marker-signature-must-never-leak"
		markerHostileDN     = `uid=evil+description=hostile,ou=users,dc=compat,dc=test)(uid=*`
		markerVerifierError = "compat-test-marker: verifier injected failure"
	)

	t.Run("marker_password", func(t *testing.T) {
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier() // markerJWTPassword deliberately never registered as success
				r := newFakeResolver()
				addr := b.start(t, v, r)

				buf := captureCompatLog(t)
				conn := dialCompat(t, addr)
				_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: markerJWTPassword})
				bindRes := bindResultFrom(err)

				assertNoSubstring(t, b.name+" diagnostic", bindRes.diagnostic, markerJWTPassword)
				assertNoSubstring(t, b.name+" matchedDN", bindRes.matchedDN, markerJWTPassword)
				assertNoSubstring(t, b.name+" log", buf.String(), markerJWTPassword)
				if bindRes.resultCode != goldapclient.LDAPResultInvalidCredentials {
					t.Fatalf("%s: resultCode = %d, want %d", b.name, bindRes.resultCode, goldapclient.LDAPResultInvalidCredentials)
				}
			})
		}
	})

	t.Run("hostile_dn", func(t *testing.T) {
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier()
				r := newFakeResolver()
				addr := b.start(t, v, r)

				buf := captureCompatLog(t)
				conn := dialCompat(t, addr)
				_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: markerHostileDN, Password: "irrelevant-password"})
				bindRes := bindResultFrom(err)

				assertNoSubstring(t, b.name+" diagnostic", bindRes.diagnostic, markerHostileDN)
				assertNoSubstring(t, b.name+" matchedDN", bindRes.matchedDN, markerHostileDN)
				assertNoSubstring(t, b.name+" log", buf.String(), markerHostileDN)
				if bindRes.resultCode != goldapclient.LDAPResultInvalidCredentials {
					t.Fatalf("%s: resultCode = %d, want %d", b.name, bindRes.resultCode, goldapclient.LDAPResultInvalidCredentials)
				}
			})
		}
	})

	t.Run("verifier_error_marker", func(t *testing.T) {
		for _, b := range compatBackends {
			b := b
			t.Run(b.name, func(t *testing.T) {
				v := newFakeVerifier().withFailure("jwt-alice", errors.New(markerVerifierError))
				r := newFakeResolver()
				addr := b.start(t, v, r)

				buf := captureCompatLog(t)
				conn := dialCompat(t, addr)
				_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{Username: compatBindDN("alice"), Password: "jwt-alice"})
				bindRes := bindResultFrom(err)

				assertNoSubstring(t, b.name+" diagnostic", bindRes.diagnostic, markerVerifierError)
				assertNoSubstring(t, b.name+" log", buf.String(), markerVerifierError)
				if bindRes.resultCode != goldapclient.LDAPResultInvalidCredentials {
					t.Fatalf("%s: resultCode = %d, want %d", b.name, bindRes.resultCode, goldapclient.LDAPResultInvalidCredentials)
				}
			})
		}
	})
}
