package ldap

import (
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldapclient "github.com/go-ldap/ldap/v3"
	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers the phase-5 "unsupported LDAP controls" plan section
// (§7.6's eight-case matrix) against the real production server over TCP,
// using the same "client TCP -> ldapserver BER parsing -> production route
// -> connectionHandler/session -> production response -> client decode"
// harness protocol_test.go/adversarial_test.go establish — startTestServer,
// dialTest, bindAs, membershipSearch, requireSuccess, asLDAPError,
// fakeVerifier/fakeRoles/account are all reused unchanged from
// protocol_test.go; only verifier/roleResolver are test fakes, and no test
// here calls controls.go's criticalControlGuard directly.
//
// The redaction-inventory proof at the bottom of this file
// (TestControls_CriticalControlMarkerNeverReachesLogOrDiagnostic) additionally
// reuses redaction_boundary_test.go's captureAppLog/redactionCaptureModes —
// the same A2 non-parallel-capture discipline that file's header documents
// applies to that one test.
//
// Every control this file attaches uses an OID this server does not
// implement (testUnknownControlOID below), since the server implements no
// controls of its own (see controls.go's doc) — the only distinction that
// matters anywhere in this file is criticality, never a specific OID or
// value, matching hasCriticalControl's own contract.
//
// go-ldap/v3's request types (SimpleBindRequest, SearchRequest, AddRequest,
// ModifyRequest, DelRequest, ModifyDNRequest, ExtendedRequest) each expose a
// Controls []Control field the client encodes at the LDAPMessage envelope
// level via goldapclient.NewControlString(oid, criticality, value) — that
// library's ControlString.Encode (like this repo's own
// third_party/goldap/message/control.go) omits the criticality BOOLEAN
// entirely when false, producing a syntactically valid non-critical control
// rather than the malformed explicit-FALSE encoding §7.5 covers separately
// (and already characterizes via the local decoder's existing rejection —
// not retested here). CompareRequest is the one exception: go-ldap/v3
// v3.4.14's CompareRequest has no Controls field and Conn.Compare accepts
// none, so its case below (and the Cancel/Abandon cases, which need to
// target an in-flight message already identified by its own message ID)
// build the raw LDAPMessage envelope directly with the ber package, exactly
// as adversarial_test.go's rawSimpleBindMessage/rawSearchMessage/
// rawAbandonMessage/cancelRequestValuePacket helpers do.

const testUnknownControlOID = "1.2.3.4.5.6.999.1"

// unknownControlValue implements goldapclient.Control, encoding
// testUnknownControlOID with the given criticality. It deliberately does
// NOT use go-ldap/v3's own ControlString: that type's Encode() builds the
// criticality BOOLEAN with ber.NewBoolean, which writes Go's `true` as
// content byte 0x01 — valid permissive BER, but not the DER-style 0xFF RFC
// 4511's own BOOLEAN encoding note requires and this repo's local
// goldap/message fork enforces strictly (via encoding/asn1, see
// third_party/goldap/message/control.go's readBOOLEAN path). Encoding a
// critical control with plain NewBoolean makes the server's decoder reject
// the ENTIRE LDAPMessage as malformed and silently drop it, never reaching
// this file's guard assertions at all — ber.NewLDAPBoolean is the
// RFC-4511-compliant encoder that avoids that.
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

// requireResultCode fails the test unless err is a non-nil LDAP error with
// exactly the given result code.
func requireResultCode(t *testing.T, label string, err error, want int) {
	t.Helper()
	ldapErr := asLDAPError(err)
	if ldapErr == nil {
		t.Fatalf("%s: got success, want result code %d", label, want)
	}
	if int(ldapErr.ResultCode) != want {
		t.Fatalf("%s: ResultCode = %d, want %d", label, ldapErr.ResultCode, want)
	}
}

// ---- raw BER helpers for Compare/Cancel/Abandon ---------------------------
//
// These three operations cannot be driven through go-ldap/v3's high-level
// Conn methods with an attached critical control (CompareRequest has no
// Controls field at all; Cancel/Abandon need to target an in-flight
// message's own ID from a second, concurrently-pipelined message on the
// same connection), so they use the ber package directly, mirroring
// adversarial_test.go's established raw-BER pattern for this exact
// dependency (rawSimpleBindMessage, rawSearchMessage, rawAbandonMessage,
// cancelRequestValuePacket).

// rawControlsPacket BER-encodes a single-control [0] Controls element
// carrying testUnknownControlOID with the given criticality — omitting the
// criticality BOOLEAN entirely when false, exactly like goldap's own
// Control.write (third_party/goldap/message/control.go) requires for a
// syntactically valid non-critical control.
//
// The TRUE case deliberately uses ber.NewLDAPBoolean, not ber.NewBoolean:
// the latter encodes Go's `true` as content byte 0x01, which is valid
// permissive BER but not the strict DER-style encoding (content byte 0xFF)
// goldap/message's readBOOLEAN (backed by encoding/asn1.Unmarshal) requires
// — encoding a critical control with ber.NewBoolean makes goldap's decoder
// reject the entire message ("invalid boolean: should be 0x00 of 0xFF"),
// silently discarding it instead of ever reaching this test's guard
// assertions. RFC 4511's own BOOLEAN encoding note requires exactly this
// 0xFF/0x00 convention, which is what NewLDAPBoolean implements.
func rawControlsPacket(critical bool) *ber.Packet {
	ctrl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
	ctrl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, testUnknownControlOID, "controlType"))
	if critical {
		ctrl.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality"))
	}
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	controls.AppendChild(ctrl)
	return controls
}

// rawEnvelope BER-encodes one complete LDAPMessage carrying op as
// messageID's protocolOp, optionally followed by rawControlsPacket(true).
func rawEnvelope(messageID int, op *ber.Packet, critical bool) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(op)
	if critical {
		env.AppendChild(rawControlsPacket(true))
	}
	return env.Bytes()
}

// rawBindRequest BER-encodes a BindRequest protocolOp, factored out of
// rawEnvelope so this file's raw tests can attach a critical control at the
// envelope level the same way rawCompareRequest/rawCancelRequest/
// rawAbandonRequest below do.
func rawBindRequest(dn, token string) *ber.Packet {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	req.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, token, "simple"))
	return req
}

// rawCompareRequest BER-encodes a CompareRequest protocolOp:
// `[APPLICATION 14] SEQUENCE { entry LDAPDN, ava SEQUENCE { attributeDesc,
// assertionValue } }` (RFC 4511 §4.10).
func rawCompareRequest(dn, attr, value string) *ber.Packet {
	ava := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ava")
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "attributeDesc"))
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "assertionValue"))

	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 14, nil, "CompareRequest")
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "entry"))
	req.AppendChild(ava)
	return req
}

// rawAbandonRequest BER-encodes an AbandonRequest protocolOp (RFC 4511
// §4.11: `[APPLICATION 16] MessageID`, a primitive INTEGER) targeting
// targetMessageID, matching adversarial_test.go's rawAbandonMessage shape.
func rawAbandonRequest(targetMessageID int) *ber.Packet {
	return ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ldapserver.ApplicationAbandonRequest, targetMessageID, "AbandonRequest")
}

// rawCancelRequest BER-encodes the RFC 3909 Cancel Extended request
// protocolOp targeting targetMessageID, reusing this package's own
// cancelRequestValuePacket helper (adversarial_test.go).
func rawCancelRequest(targetMessageID int) *ber.Packet {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 23, nil, "ExtendedRequest")
	req.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.1.8", "requestName"))
	req.AppendChild(cancelRequestValuePacket(targetMessageID))
	return req
}

// readRawResponse reads one raw LDAPMessage response from r within
// deadline, asserting its messageID and protocolOp application tag, and
// returns its LDAPResult resultCode (the first child of every *Response
// protocolOp this file decodes) — the same field-access pattern
// adversarial_test.go's TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak
// uses.
func readRawResponse(t *testing.T, r net.Conn, deadline time.Duration, wantMessageID, wantOpTag int) int {
	t.Helper()
	r.SetReadDeadline(time.Now().Add(deadline))
	pkt, err := ber.ReadPacket(r)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(pkt.Children) < 2 || len(pkt.Children[1].Children) < 1 {
		t.Fatalf("malformed response packet: %+v", pkt)
	}
	if gotID := pkt.Children[0].Value.(int64); gotID != int64(wantMessageID) {
		t.Fatalf("response messageID = %d, want %d", gotID, wantMessageID)
	}
	if gotTag := int(pkt.Children[1].Tag); gotTag != wantOpTag {
		t.Fatalf("response op tag = %d, want %d", gotTag, wantOpTag)
	}
	return int(pkt.Children[1].Children[0].Value.(int64))
}

// requireNoResponseWithin fails the test if any bytes at all arrive on r
// before deadline elapses, or if the read fails some other way than a
// deadline timeout.
func requireNoResponseWithin(t *testing.T, r net.Conn, deadline time.Duration) {
	t.Helper()
	r.SetReadDeadline(time.Now().Add(deadline))
	buf := make([]byte, 16)
	n, err := r.Read(buf)
	if n != 0 {
		t.Fatalf("got %d unexpected response bytes, want none (Abandon has no response)", n)
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("Read returned (n=%d, err=%v), want a read-deadline timeout (no response ever sent)", n, err)
	}
}

// ---- 1. valid Bind + non-critical unknown control succeeds ----------------

func TestControls_NonCriticalUnknownControlOnBindDelegates(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	fv := newFakeVerifier(acct)
	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	conn := dialTest(t, addr)
	_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
		Username:           protoBindDN("alice"),
		Password:           "jwt-alice",
		Controls:           []goldapclient.Control{unknownControl(false)},
		AllowEmptyPassword: true,
	})
	if err != nil {
		t.Fatalf("bind with non-critical unknown control: got error %v, want success", err)
	}
	if fv.callCount() != 1 {
		t.Fatalf("verifier callCount = %d, want 1", fv.callCount())
	}
}

// ---- 2. critical Bind -> code 12, verifier untouched -----------------------

func TestControls_CriticalBindRejectedWithoutCallingVerifier(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	fv := newFakeVerifier(acct)
	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	conn := dialTest(t, addr)
	_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
		Username:           protoBindDN("alice"),
		Password:           "jwt-alice",
		Controls:           []goldapclient.Control{unknownControl(true)},
		AllowEmptyPassword: true,
	})
	requireResultCode(t, "critical bind", err, ldapserver.LDAPResultUnavailableCriticalExtension)
	if fv.callCount() != 0 {
		t.Fatalf("verifier callCount = %d, want 0 — critical Bind must never call the verifier", fv.callCount())
	}
}

// ---- 3. successful Bind -> critical re-Bind -> later Search unauthenticated

func TestControls_SuccessfulBindThenCriticalReBindLeavesSearchUnauthenticated(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "initial bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
		Username:           protoBindDN("alice"),
		Password:           "jwt-alice",
		Controls:           []goldapclient.Control{unknownControl(true)},
		AllowEmptyPassword: true,
	})
	requireResultCode(t, "critical re-bind", err, ldapserver.LDAPResultUnavailableCriticalExtension)

	_, err = conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	// The exact rejection failSearch (search.go) returns for an
	// unauthenticated session — not just "no entries", which a wrongly
	// SUCCESSFUL empty-result Search could also produce.
	requireResultCode(t, "search after critical re-bind", err, ldapserver.LDAPResultInsufficientAccessRights)
}

// ---- 4. critical Search -> zero entries/code 12; later normal Search
// succeeds ---------------------------------------------------------------

func TestControls_CriticalSearchRejectedThenNormalSearchSucceeds(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	req := membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil)
	req.Controls = []goldapclient.Control{unknownControl(true)}
	res, err := conn.Search(req)
	requireResultCode(t, "critical search", err, ldapserver.LDAPResultUnavailableCriticalExtension)
	if len(res.Entries) != 0 {
		t.Fatalf("critical search returned %d entries, want zero", len(res.Entries))
	}

	res2, err := conn.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil {
		t.Fatalf("normal search after critical search: %v, want success (a critical Search must not clear a valid session)", err)
	}
	if len(res2.Entries) != 1 {
		t.Fatalf("normal search after critical search: got %d entries, want 1", len(res2.Entries))
	}
}

// ---- 5. non-critical Search control -> normal Search -----------------------

func TestControls_NonCriticalSearchControlDelegates(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	req := membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil)
	req.Controls = []goldapclient.Control{unknownControl(false)}
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with non-critical unknown control: %v, want success", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}
}

// ---- 6. critical Cancel does not cancel target -----------------------------

func TestControls_CriticalCancelDoesNotCancelTarget(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed until this test explicitly does so
	fv.returned = make(chan error, 1)

	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	// 1. Simple Bind (messageID=1), which blocks in the fake verifier — the
	// target this critical Cancel will attempt (and must fail) to cancel.
	if _, err := rawConn.Write(rawEnvelope(1, rawBindRequest(protoBindDN("alice"), "jwt-alice"), false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	select {
	case <-fv.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("fake verifier was never entered — Bind never went in flight")
	}

	// 2. Critical Cancel (messageID=2) targeting the in-flight Bind.
	if _, err := rawConn.Write(rawEnvelope(2, rawCancelRequest(1), true)); err != nil {
		t.Fatalf("write critical cancel: %v", err)
	}

	// 3. The guard must respond ExtendedResponse(12) itself — never
	// RouteMux's own built-in Cancel dispatch, which would instead respond
	// CannotCancel (121) for a Bind target (see
	// TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak).
	code := readRawResponse(t, rawConn, 5*time.Second, 2, 24) // ExtendedResponse
	if code != ldapserver.LDAPResultUnavailableCriticalExtension {
		t.Fatalf("critical cancel resultCode = %d, want %d (unavailableCriticalExtension)", code, ldapserver.LDAPResultUnavailableCriticalExtension)
	}

	// 4. Unblock the Bind's Verify call. If the critical Cancel had somehow
	// still reached RouteMux's Abandon signaling, the Bind's context would
	// already be canceled and Verify would observe that instead of
	// completing normally.
	close(fv.block)
	select {
	case verr := <-fv.returned:
		if verr != nil {
			t.Fatalf("blocked verifier returned %v after critical Cancel, want nil — its target must not have been cancelled", verr)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked verifier never returned — critical Cancel must not have aborted its target")
	}

	code = readRawResponse(t, rawConn, 5*time.Second, 1, 1) // BindResponse
	if code != ldapserver.LDAPResultSuccess {
		t.Fatalf("bind resultCode = %d, want %d (success) — critical Cancel must not have aborted the Bind", code, ldapserver.LDAPResultSuccess)
	}
	if fv.callCount() != 1 {
		t.Fatalf("verifier callCount = %d, want 1", fv.callCount())
	}
}

// ---- 7. critical Abandon does not abandon target ---------------------------

func TestControls_CriticalAbandonDoesNotAbandonTarget(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	fv.entered = make(chan struct{}, 1)
	fv.block = make(chan struct{}) // never closed until this test explicitly does so
	fv.returned = make(chan error, 1)

	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	// 1. Simple Bind (messageID=1), which blocks in the fake verifier — the
	// target this critical Abandon will attempt (and must fail) to abandon.
	if _, err := rawConn.Write(rawEnvelope(1, rawBindRequest(protoBindDN("alice"), "jwt-alice"), false)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	select {
	case <-fv.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("fake verifier was never entered — Bind never went in flight")
	}

	// 2. Critical Abandon (messageID=2) targeting the in-flight Bind.
	if _, err := rawConn.Write(rawEnvelope(2, rawAbandonRequest(1), true)); err != nil {
		t.Fatalf("write critical abandon: %v", err)
	}

	// 3. Abandon has no response in the LDAP protocol at all, critical or
	// not — a bounded window with no bytes at all is the only way to be
	// sure nothing was written for it, before the still-blocked target's
	// eventual Bind response could otherwise be mistaken for one.
	requireNoResponseWithin(t, rawConn, 500*time.Millisecond)

	// 4. Unblock the Bind's Verify call. If the critical Abandon had
	// actually reached RouteMux's built-in Abandon signaling, the Bind's
	// context would already be canceled and Verify would observe that
	// instead of completing normally.
	close(fv.block)
	select {
	case verr := <-fv.returned:
		if verr != nil {
			t.Fatalf("blocked verifier returned %v after critical Abandon, want nil — its target must not have been abandoned", verr)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked verifier never returned — critical Abandon must not have aborted its target")
	}

	code := readRawResponse(t, rawConn, 5*time.Second, 1, 1) // BindResponse
	if code != ldapserver.LDAPResultSuccess {
		t.Fatalf("bind resultCode = %d, want %d (success) — critical Abandon must not have aborted the Bind", code, ldapserver.LDAPResultSuccess)
	}
	if fv.callCount() != 1 {
		t.Fatalf("verifier callCount = %d, want 1", fv.callCount())
	}
}

// ---- 8. representative Add/Modify/Delete/Compare/ModifyDN/Extended return
// their correct typed result-12 response -----------------------------------

func TestControls_CriticalOperationsReturnTypedResult12(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	t.Run("Add", func(t *testing.T) {
		conn := dialTest(t, addr)
		req := goldapclient.NewAddRequest("cn=x,"+protoGroupBaseDN, []goldapclient.Control{unknownControl(true)})
		requireResultCode(t, "add", conn.Add(req), ldapserver.LDAPResultUnavailableCriticalExtension)
	})
	t.Run("Modify", func(t *testing.T) {
		conn := dialTest(t, addr)
		mr := goldapclient.NewModifyRequest("cn=x,"+protoGroupBaseDN, []goldapclient.Control{unknownControl(true)})
		mr.Replace("cn", []string{"y"})
		requireResultCode(t, "modify", conn.Modify(mr), ldapserver.LDAPResultUnavailableCriticalExtension)
	})
	t.Run("Delete", func(t *testing.T) {
		conn := dialTest(t, addr)
		req := goldapclient.NewDelRequest("cn=x,"+protoGroupBaseDN, []goldapclient.Control{unknownControl(true)})
		requireResultCode(t, "delete", conn.Del(req), ldapserver.LDAPResultUnavailableCriticalExtension)
	})
	t.Run("Compare", func(t *testing.T) {
		// go-ldap/v3's CompareRequest has no Controls field and Conn.Compare
		// accepts none (see this file's header comment) — built raw instead.
		rawConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawConn.Close()
		if _, err := rawConn.Write(rawEnvelope(1, rawCompareRequest("cn=x,"+protoGroupBaseDN, "cn", "x"), true)); err != nil {
			t.Fatalf("write compare: %v", err)
		}
		code := readRawResponse(t, rawConn, 5*time.Second, 1, 15) // CompareResponse
		if code != ldapserver.LDAPResultUnavailableCriticalExtension {
			t.Fatalf("compare resultCode = %d, want %d", code, ldapserver.LDAPResultUnavailableCriticalExtension)
		}
	})
	t.Run("ModifyDN", func(t *testing.T) {
		conn := dialTest(t, addr)
		conn.SetTimeout(5 * time.Second)
		req := goldapclient.NewModifyDNWithControlsRequest("cn=x,"+protoGroupBaseDN, "cn=y", true, "", []goldapclient.Control{unknownControl(true)})
		requireResultCode(t, "modifyDN", conn.ModifyDN(req), ldapserver.LDAPResultUnavailableCriticalExtension)
	})
	t.Run("Extended", func(t *testing.T) {
		conn := dialTest(t, addr)
		_, err := conn.WhoAmI([]goldapclient.Control{unknownControl(true)})
		requireResultCode(t, "extended", err, ldapserver.LDAPResultUnavailableCriticalExtension)
	})
}

// ---- 9. critical-control marker never reaches log or diagnostic -----------
//
// This is the redaction-inventory proof for controls.go's two new sinks
// (criticalControlGuard.ServeLDAP's three SetDiagnosticMessage(
// criticalControlDiagnostic) call sites, which the manifest's five-part key
// dedupes into one row, and logCriticalControlRejected's fixed Msg). Reading
// controls.go shows hasCriticalControl and every switch case below it only
// ever reference the fixed criticalControlDiagnostic constant and fixed op
// literals — never a control's actual OID or value — so this is a
// structural fact provable by inspection. This test proves it dynamically
// too: goldap's LDAPOID is read as a plain octet string with no
// numeric-OID-format enforcement (see third_party/goldap/message/oid.go's
// readLDAPOID), so a distinctive marker string can stand in for a real OID
// on the wire, and this test attaches it to both a critical Bind and a
// critical Search, capturing the application log at both the default and
// (per A2) Trace global level, then asserts the marker appears in neither
// the captured log nor the client-visible diagnostic text either response
// returns.

// markerControlValue implements goldapclient.Control like unknownControlValue
// above, except its controlType is an arbitrary caller-supplied string
// rather than a fixed test OID, so it can carry a distinguishing marker.
type markerControlValue struct {
	oid      string
	critical bool
}

func (c markerControlValue) GetControlType() string { return c.oid }
func (c markerControlValue) String() string         { return c.oid }
func (c markerControlValue) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.oid, "Control Type"))
	if c.critical {
		packet.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	}
	return packet
}

func markerControl(oid string, critical bool) goldapclient.Control {
	return markerControlValue{oid: oid, critical: critical}
}

func TestControls_CriticalControlMarkerNeverReachesLogOrDiagnostic(t *testing.T) {
	const controlMarker = "CRITICAL-CONTROL-MARKER-9c1f0a3d-should-never-be-logged-or-diagnosed"

	for _, mode := range redactionCaptureModes {
		t.Run(mode.name, func(t *testing.T) {
			acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
			addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))
			buf := captureAppLog(t, mode)

			// Critical Bind carrying the marker as its control's OID.
			conn := dialTest(t, addr)
			_, err := conn.SimpleBind(&goldapclient.SimpleBindRequest{
				Username:           protoBindDN("alice"),
				Password:           "jwt-alice",
				Controls:           []goldapclient.Control{markerControl(controlMarker, true)},
				AllowEmptyPassword: true,
			})
			bindErr := asLDAPError(err)
			if bindErr == nil || int(bindErr.ResultCode) != ldapserver.LDAPResultUnavailableCriticalExtension {
				t.Fatalf("critical bind with marker control: err=%v, want result 12", err)
			}
			if strings.Contains(bindErr.Error(), controlMarker) {
				t.Fatalf("bind diagnostic contains the control marker: %v", bindErr)
			}

			// A real Bind, then a critical Search carrying the marker.
			requireSuccess(t, "real bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))
			req := membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil)
			req.Controls = []goldapclient.Control{markerControl(controlMarker, true)}
			_, searchErr := conn.Search(req)
			searchLdapErr := asLDAPError(searchErr)
			if searchLdapErr == nil || int(searchLdapErr.ResultCode) != ldapserver.LDAPResultUnavailableCriticalExtension {
				t.Fatalf("critical search with marker control: err=%v, want result 12", searchErr)
			}
			if strings.Contains(searchLdapErr.Error(), controlMarker) {
				t.Fatalf("search diagnostic contains the control marker: %v", searchLdapErr)
			}

			if strings.Contains(buf.String(), controlMarker) {
				t.Fatalf("captured application log contains the control marker:\n%s", buf.String())
			}
		})
	}
}
