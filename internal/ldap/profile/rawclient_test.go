package profile

// This file is the local, test-only fixed-profile LDAP client
// protocol_test.go's real-TCP black-box suite drives against the real
// profile.Server: a minimal net.Conn-based Bind/Search client built
// entirely from this package's own raw-PDU builders and decoders
// (frame_test.go's tlv/berInteger/buildMessage/buildControl(s),
// bind_test.go's bindOp, search_test.go's searchOp/validMembershipFilter,
// server_test.go's dial/sendAndReadEnvelope/readEnvelope/
// readLDAPResultFields, and conncap_test.go's collectSearchResult).
//
// Historical note: earlier revisions of protocol_test.go additionally
// drove the server with github.com/go-ldap/ldap/v3, a general third-party
// LDAPv3 client library, as a test-only import that never reached this
// package's production dependency closure. Issue #33 Phase 4 removes
// github.com/go-ldap/ldap/v3 from the entire repository -- production,
// tests, and integration tooling alike (see the Phase 4 plan's "Test-only
// LDAP client decision: remove go-ldap from the root module completely")
// -- so this file replaces that go-ldap-based client with the
// fixed-profile helpers below. The suite still dials a real TCP listener
// and exercises real wire bytes end to end; only the test's client-side
// library changed, not the real-TCP boundary itself.
//
// These helpers are deliberately narrow rather than a general LDAP client
// implementation: this profile's server implements exactly one simple
// Bind shape and one fixed membership Search shape (see doc.go), so the
// client only ever needs to construct those two requests, decode the
// shared LDAPResult envelope every response type here carries, and
// collect the fixed cn-only SearchResultEntry shape encode.go emits --
// nothing a general client interface would otherwise provide (arbitrary
// filters, arbitrary requested attributes, SASL, paging, referrals, ...)
// is needed or built here.

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// ---- client-visible result/entry shapes ------------------------------------

// rawLDAPError is the minimal client-visible LDAP failure shape this
// suite's assertions depend on: ResultCode, MatchedDN, and a
// diagnosticMessage string -- decoded directly off the wire's own
// LDAPResult via readLDAPResultFields, mirroring the historical
// *ldap.Error fields these tests once read through go-ldap.
type rawLDAPError struct {
	ResultCode int32
	MatchedDN  string
	Diagnostic string
}

func (e *rawLDAPError) Error() string {
	return fmt.Sprintf("LDAP Result Code %d: matchedDN=%q diagnostic=%q", e.ResultCode, e.MatchedDN, e.Diagnostic)
}

// errorFromLDAPResult converts one decoded LDAPResult into a
// *rawLDAPError, or nil on resultSuccess.
func errorFromLDAPResult(result int, matchedDN, diag string) *rawLDAPError {
	if result == int(resultSuccess) {
		return nil
	}
	return &rawLDAPError{ResultCode: int32(result), MatchedDN: matchedDN, Diagnostic: diag}
}

// searchEntry mirrors go-ldap's *ldap.Entry down to the single accessor
// this suite needs. This profile's fixed Search response shape
// (encode.go) emits at most one cn attribute with at most one value per
// entry, and decodeSearchResultEntry below fails the test if that ever
// stops being true, so GetAttributeValue never needs to consult anything
// beyond that one field.
type searchEntry struct {
	DN string
	cn string
}

// GetAttributeValue returns the entry's cn value for a case-insensitive
// "cn" attr, and "" for anything else -- including "objectClass" and
// "member", which this profile's fixed Search response shape never
// emits.
func (e *searchEntry) GetAttributeValue(attr string) string {
	if strings.EqualFold(attr, "cn") {
		return e.cn
	}
	return ""
}

// searchResponse mirrors go-ldap's *ldap.SearchResult down to the one
// field this suite reads.
type searchResponse struct {
	Entries []*searchEntry
}

// ---- rawConn: the fixed-profile client -------------------------------------

// rawConn is a minimal, test-only LDAP client over one real net.Conn: a
// monotonically increasing message ID plus exactly the two client
// operations this profile's server implements -- simple Bind and the
// fixed membership Search.
type rawConn struct {
	t      *testing.T
	conn   net.Conn
	nextID int64
}

// rawDial dials addr over real TCP and returns a *rawConn whose
// underlying connection closes automatically at test cleanup.
func rawDial(t *testing.T, addr string) *rawConn {
	t.Helper()
	c := &rawConn{t: t, conn: dial(t, addr), nextID: 1}
	t.Cleanup(func() { c.conn.Close() })
	return c
}

func (c *rawConn) nextMsgID() int64 {
	id := c.nextID
	c.nextID++
	return id
}

// Close closes the underlying connection early (before test cleanup),
// for tests that must observe post-disconnect behavior on a fresh
// connection.
func (c *rawConn) Close() error {
	return c.conn.Close()
}

// simpleBind performs an ordinary (no controls) LDAPv3 simple Bind and
// returns the resulting *rawLDAPError (nil on success).
func (c *rawConn) simpleBind(dn, password string) *rawLDAPError {
	c.t.Helper()
	return c.bindWithControls(dn, password, nil)
}

// bindWithControls performs a simple Bind carrying the given complete,
// already-[0]-tagged Controls element (nil for none) -- see
// unknownNonCriticalControl below.
func (c *rawConn) bindWithControls(dn, password string, controls []byte) *rawLDAPError {
	c.t.Helper()
	msgID := c.nextMsgID()
	raw := buildMessage(berInteger(msgID), tlv(byte(tagBindRequest), bindOp(3, dn, authTagSimple, []byte(password))), controls)
	env := sendAndReadEnvelope(c.t, c.conn, raw)
	if env.ProtocolOp != tagBindResponse {
		c.t.Fatalf("bind response tag = %#x, want BindResponse", byte(env.ProtocolOp))
	}
	result, matchedDN, diag := readLDAPResultFields(c.t, env.Content)
	return errorFromLDAPResult(result, matchedDN, diag)
}

// search performs the fixed membership Search (scope wholeSubtree, deref
// never, no size/time limit, typesOnly false, filter
// "(&(objectClass=groupOfNames)(member=memberDN))") for the given attrs,
// carrying no controls, and collects every SearchResultEntry up to
// SearchResultDone. It returns a non-nil *searchResponse only when
// SearchResultDone itself reports resultSuccess.
func (c *rawConn) search(base, memberDN string, attrs []string) (*searchResponse, *rawLDAPError) {
	c.t.Helper()
	return c.searchWithControls(base, memberDN, attrs, nil)
}

// searchWithControls is search's controls-carrying variant (see
// bindWithControls).
func (c *rawConn) searchWithControls(base, memberDN string, attrs []string, controls []byte) (*searchResponse, *rawLDAPError) {
	c.t.Helper()
	msgID := c.nextMsgID()
	op := searchOp(base, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(memberDN), attrs...)
	raw := buildMessage(berInteger(msgID), tlv(byte(tagSearchRequest), op), controls)
	if _, err := c.conn.Write(raw); err != nil {
		c.t.Fatalf("write search request: %v", err)
	}
	entries, done := collectSearchResult(c.t, c.conn)
	result, matchedDN, diag := readLDAPResultFields(c.t, done.Content)
	if result != int(resultSuccess) {
		return nil, errorFromLDAPResult(result, matchedDN, diag)
	}
	resp := &searchResponse{}
	for _, e := range entries {
		if e.ProtocolOp != tagSearchResultEntry {
			c.t.Fatalf("search response tag = %#x, want SearchResultEntry", byte(e.ProtocolOp))
		}
		objectName, attrType, attrValue := decodeSearchResultEntry(c.t, e.Content)
		if !strings.EqualFold(attrType, "cn") {
			c.t.Fatalf("entry attribute type = %q, want cn", attrType)
		}
		resp.Entries = append(resp.Entries, &searchEntry{DN: objectName, cn: attrValue})
	}
	return resp, nil
}

// unsupportedOp sends a minimal opaque request under appTag (see
// opaqueRequestBytes) and decodes its LDAPResult-shaped response.
// dispatchOperation (server.go) routes every one of Add/Modify/Delete/
// Compare/ModifyDN/Extended purely on the LDAPMessage's application tag
// and never decodes their payload, so the client side needs only send
// the bare tag -- not construct any operation-specific request shape a
// general client library would otherwise provide.
func (c *rawConn) unsupportedOp(appTag byte) *rawLDAPError {
	c.t.Helper()
	msgID := c.nextMsgID()
	env := sendAndReadEnvelope(c.t, c.conn, opaqueRequestBytes(msgID, appTag, false))
	result, matchedDN, diag := readLDAPResultFields(c.t, env.Content)
	return errorFromLDAPResult(result, matchedDN, diag)
}

// ---- shared result-code assertions -----------------------------------------

func requireSuccess(t *testing.T, label string, err *rawLDAPError) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: got LDAP error %+v, want success", label, err)
	}
}

// requireInvalidCredentials fails the test unless err is exactly the fixed
// Bind non-disclosure boundary: result 49, empty matched DN, the fixed
// "invalid credentials" diagnostic.
func requireInvalidCredentials(t *testing.T, label string, err *rawLDAPError) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got success, want invalidCredentials", label)
	}
	if err.ResultCode != resultInvalidCredentials {
		t.Fatalf("%s: ResultCode = %d, want %d", label, err.ResultCode, resultInvalidCredentials)
	}
	if err.MatchedDN != "" {
		t.Fatalf("%s: MatchedDN = %q, want empty", label, err.MatchedDN)
	}
	if err.Diagnostic != diagInvalidCredentials.text() {
		t.Fatalf("%s: diagnostic = %q, want %q", label, err.Diagnostic, diagInvalidCredentials.text())
	}
}

// requireUnwillingToPerform fails the test unless err is result 53 with the
// empty diagnostic -- the fixed mapped response for Add/Modify/Delete/
// Compare/ModifyDN.
func requireUnwillingToPerform(t *testing.T, err *rawLDAPError) {
	t.Helper()
	if err == nil {
		t.Fatal("got success, want unwillingToPerform (53)")
	}
	if err.ResultCode != resultUnwillingToPerform {
		t.Fatalf("ResultCode = %d, want %d (unwillingToPerform)", err.ResultCode, resultUnwillingToPerform)
	}
	if err.Diagnostic != diagEmpty.text() {
		t.Fatalf("diagnostic = %q, want empty", err.Diagnostic)
	}
}

// requireOperationNotSupported fails the test unless err is result 53 with
// the "operation not supported" diagnostic -- the fixed mapped response
// for Extended requests specifically.
func requireOperationNotSupported(t *testing.T, err *rawLDAPError) {
	t.Helper()
	if err == nil {
		t.Fatal("got success, want operation-not-supported (53)")
	}
	if err.ResultCode != resultUnwillingToPerform {
		t.Fatalf("ResultCode = %d, want %d", err.ResultCode, resultUnwillingToPerform)
	}
	if err.Diagnostic != diagOperationUnsupported.text() {
		t.Fatalf("diagnostic = %q, want %q", err.Diagnostic, diagOperationUnsupported.text())
	}
}

// ---- unknown non-critical control fixture ----------------------------------

// unknownNonCriticalControl returns a complete, already-[0]-tagged
// Controls element carrying exactly one unrecognized, non-critical
// control -- the fixed "recognized-but-ignored" fixture
// TestProfile_UnknownNonCriticalControlIgnored exercises on both Bind and
// Search.
func unknownNonCriticalControl() []byte {
	return buildControls(buildControl("1.2.3.4.5.6.7.8.9", falseVal(), nil))
}
