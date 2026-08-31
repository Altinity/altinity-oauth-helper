package profile

// This file is the sub-task p2-09-tcp-protocol-port real-TCP black-box
// test suite: it drives the real profile.Server, over an actual loopback
// TCP listener, using BOTH this package's own local fixed-profile raw-PDU
// client (rawclient_test.go) and raw hand-built PDUs where exact bytes
// are the subject. It ports every row the plan's "Disposition of named
// legacy test files" table marks port/adapt for
// internal/ldap/protocol_test.go.
//
// This complements, rather than duplicates, two other real-TCP suites
// already in this package:
//
//   - server_test.go/conncap_test.go (p2-08) already drive raw BER over
//     real TCP for lifecycle/dispatch/admission (Abandon, Unbind, the six
//     unsupported operations, critical controls, unknown application
//     tags);
//   - bind_test.go/search_test.go (p2-06/p2-07) already drive
//     handleBind/handleSearch directly over net.Pipe for the exhaustive
//     field/state/filter tables.
//
// What only this file adds is the client-role black-box layer (proving a
// real LDAPv3 client -- not this package's own handler functions -- can
// drive the real server end to end over real TCP) plus two black-box
// proofs the plan names explicitly for this sub-task:
// TestProfile_OperationsAreSerial (serial, per-connection, synchronous
// processing observed from outside the process) and
// TestProfile_SearchFixedFieldPolicy (the full Search-shape narrowing
// table exercised end to end, not just at handler level).
//
// Historical note on the client library: earlier revisions of this file
// drove the server with github.com/go-ldap/ldap/v3, a general
// third-party LDAPv3 client, as a test-only import that never reached
// this package's production dependency closure (see
// internal/securitytest/profile_dependency_contract_test.go). Issue #33
// Phase 4 removes github.com/go-ldap/ldap/v3 from the entire repository,
// so this suite now drives the server through rawclient_test.go's local
// fixed-profile client instead -- the real-TCP boundary this file exists
// to prove is unchanged; only the client-side library is.
//
// # Legacy-only cases deliberately NOT ported (per the disposition table)
//
//   - same-connection concurrency: legacy's
//     TestProtocol_ConcurrentReBindAndSearchRace raced overlapping Bind/
//     Search on one connection under a per-connection operation lock this
//     profile does not have (and, per the plan's "Connection and framing
//     model", never will -- one goroutine processes one connection's
//     operations strictly synchronously, one at a time, which is exactly
//     what TestProfile_OperationsAreSerial below proves instead);
//   - generic attribute projection: legacy's
//     TestProtocol_MixedNoAttributesOIDSelectorIgnoresOneOne exercised the
//     old server's "1.1"-mixed-into-a-list special case, which this
//     profile's fixed one-cn-attribute authorization narrows away
//     entirely (any selection other than exactly one case-insensitive
//     "cn" is out of profile -- see TestProfile_SearchFixedFieldPolicy's
//     attrs_1.1/attrs_cn_and_member cases below, and Amendment 2's
//     narrowing table).

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// ---- raw-BER helpers specific to this file --------------------------------
//
// tlv/berInteger/enumTLV/boolTLV/attrsTLV/searchOp/validMembershipFilter/
// bindOp/fullMessage/bindRequestBytes/searchRequestBytes/
// opaqueRequestBytes/dial/sendAndReadEnvelope/readEnvelope/
// readLDAPResultFields/expectNoResponseThenClosed/assertNoBytesWithin/
// collectSearchResult all already exist (frame_test.go, bind_test.go,
// search_test.go, server_test.go, conncap_test.go) and are reused
// verbatim below; only the handful of builders/decoders genuinely
// specific to this file's exact-byte and general-shape-narrowing needs
// are added here.

// rawSearchRequestBytes assembles a complete SearchRequest LDAPMessage
// with every field independently controllable -- unlike
// server_test.go's fixed-shape searchRequestBytes -- for
// TestProfile_SearchFixedFieldPolicy's narrowing table.
func rawSearchRequestBytes(msgID int64, base string, scope, deref, sizeLimit, timeLimit int64, typesOnly bool, filterBytes []byte, critical bool, attrs ...string) []byte {
	op := searchOp(base, scope, deref, sizeLimit, timeLimit, typesOnly, filterBytes, attrs...)
	return fullMessage(msgID, byte(tagSearchRequest), op, critical)
}

// expectedBindResponseBody hand-builds the exact expected LDAPMessage body
// (messageID + protocolOp, i.e. readFrame's own return shape) for a
// BindResponse, using only frame_test.go's independent tlv/berInteger/
// enumTLV helpers -- never encode.go's own code -- so this is a genuine
// independent-encoding proof, not a tautology.
func expectedBindResponseBody(msgID, result int64, diag string) []byte {
	content := enumTLV(result)
	content = append(content, tlv(0x04, nil)...)
	content = append(content, tlv(0x04, []byte(diag))...)
	body := append([]byte{}, berInteger(msgID)...)
	return append(body, tlv(byte(tagBindResponse), content)...)
}

// decodeSearchResultEntry decodes a SearchResultEntry's content
// independently of encode.go's own encoder: objectName, then exactly one
// PartialAttribute's type and its exactly one value. It fails the test if
// the entry carries more than one attribute or more than one value --
// this profile's fixed cn-only shape.
func decodeSearchResultEntry(t *testing.T, content cryptobyte.String) (objectName, attrType, attrValue string) {
	t.Helper()
	var nameBytes []byte
	if !content.ReadASN1Bytes(&nameBytes, asn1.OCTET_STRING) {
		t.Fatal("SearchResultEntry: failed to read objectName")
	}
	var attrsSeq cryptobyte.String
	if !content.ReadASN1(&attrsSeq, asn1.SEQUENCE) {
		t.Fatal("SearchResultEntry: failed to read attributes SEQUENCE")
	}
	var attrSeq cryptobyte.String
	if !attrsSeq.ReadASN1(&attrSeq, asn1.SEQUENCE) {
		t.Fatal("SearchResultEntry: failed to read PartialAttribute SEQUENCE")
	}
	var typeBytes []byte
	if !attrSeq.ReadASN1Bytes(&typeBytes, asn1.OCTET_STRING) {
		t.Fatal("SearchResultEntry: failed to read attribute type")
	}
	var valsSet cryptobyte.String
	if !attrSeq.ReadASN1(&valsSet, asn1.SET) {
		t.Fatal("SearchResultEntry: failed to read attribute values SET")
	}
	var valBytes []byte
	if !valsSet.ReadASN1Bytes(&valBytes, asn1.OCTET_STRING) {
		t.Fatal("SearchResultEntry: failed to read attribute value")
	}
	if !valsSet.Empty() {
		t.Fatal("SearchResultEntry: more than one attribute value, want exactly one")
	}
	if !attrsSeq.Empty() {
		t.Fatal("SearchResultEntry: more than one PartialAttribute, want exactly one")
	}
	if !content.Empty() {
		t.Fatal("SearchResultEntry: trailing bytes after attributes")
	}
	return string(nameBytes), string(typeBytes), string(valBytes)
}

// cancelOID is RFC 3909's Cancel Operation OID -- used only to build a
// realistic-shaped ExtendedRequest; dispatchOperation never decodes an
// Extended request's OID or value (see server.go's "Deliberate Cancel
// narrowing"), so this is not exercising any OID-specific logic, only
// proving the real Cancel wire shape collapses to the same fixed
// unsupported-Extended outcome as any other Extended request.
const cancelOID = "1.3.6.1.1.8"

func cancelExtendedRequestBytes(msgID, targetMessageID int64) []byte {
	requestName := tlv(0x80, []byte(cancelOID))                // [0] LDAPOID
	cancelRequestSeq := tlv(0x30, berInteger(targetMessageID)) // CancelRequest ::= SEQUENCE { cancelID MessageID }
	requestValue := tlv(0x81, cancelRequestSeq)                // [1] OCTET STRING
	content := append(append([]byte{}, requestName...), requestValue...)
	return fullMessage(msgID, byte(tagExtendedRequest), content, false)
}

// ---- TestProfile_SimpleBindV3 ----------------------------------------------

func TestProfile_SimpleBindV3(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	groupBase := newTestConfig().GroupBaseDN

	t.Run("success_then_search_returns_snapshotted_role", func(t *testing.T) {
		v := newFakeVerifier().withSuccess("s3cr3t", acct)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := rawDial(t, h.addr)
		requireSuccess(t, "bind", conn.simpleBind(testAliceDN, "s3cr3t"))

		res, err := conn.search(groupBase, testAliceDN, []string{"cn"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("entries = %d, want 1", len(res.Entries))
		}
		e := res.Entries[0]
		wantCN := "clickhouse_ch_engineer"
		if got := e.GetAttributeValue("cn"); got != wantCN {
			t.Fatalf("cn = %q, want %q", got, wantCN)
		}
		if wantDN := "cn=" + wantCN + "," + groupBase; e.DN != wantDN {
			t.Fatalf("entry DN = %q, want %q", e.DN, wantDN)
		}
		// Deliberate profile narrowing versus legacy (see
		// search_test.go's TestHandleSearch_EntryIsCNOnlyNeverObjectClassOrMember
		// for the handler-level proof): this is the client-visible
		// confirmation that only cn is ever emitted.
		if got := e.GetAttributeValue("objectClass"); got != "" {
			t.Fatalf("objectClass = %q, want empty (never emitted)", got)
		}
		if got := e.GetAttributeValue("member"); got != "" {
			t.Fatalf("member = %q, want empty (never emitted)", got)
		}
	})

	t.Run("exact_bind_response_bytes_echo_messageid", func(t *testing.T) {
		v := newFakeVerifier().withSuccess("s3cr3t", acct)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := dial(t, h.addr)
		defer conn.Close()

		const msgID = 42
		if _, err := conn.Write(bindRequestBytes(msgID, testAliceDN, "s3cr3t", false)); err != nil {
			t.Fatalf("write bind: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		gotBody, err := readFrame(conn)
		if err != nil {
			t.Fatalf("readFrame: %v", err)
		}
		wantBody := expectedBindResponseBody(msgID, int64(resultSuccess), diagEmpty.text())
		if !bytes.Equal(gotBody, wantBody) {
			t.Fatalf("BindResponse body =\n% x\nwant\n% x", gotBody, wantBody)
		}
	})

	t.Run("invalid_credentials", func(t *testing.T) {
		fv := newFakeVerifier().withSuccess("s3cr3t", acct)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
		h := newRunningServer(t, fv, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := rawDial(t, h.addr)
		requireInvalidCredentials(t, "wrong token", conn.simpleBind(testAliceDN, "not-the-right-jwt"))
		if got := fv.callCount(); got != 1 {
			t.Fatalf("verifier calls = %d, want 1", got)
		}
	})

	t.Run("empty_and_wrong_nondisclosure", func(t *testing.T) {
		v := newFakeVerifier().withSuccess("s3cr3t", acct)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		cases := map[string]struct{ dn, password string }{
			"empty_dn_empty_password":    {"", ""},
			"empty_dn_valid_shaped_pass": {"", "s3cr3t"},
			"valid_dn_empty_password":    {testAliceDN, ""},
		}
		var errs []*rawLDAPError
		for name, c := range cases {
			err := rawDial(t, h.addr).simpleBind(c.dn, c.password)
			requireInvalidCredentials(t, name, err)
			errs = append(errs, err)
		}
		// Nondisclosure: every failure class above must be byte-for-byte
		// identical to an unrelated failure class's client-visible view
		// (wrong token on a valid-looking DN).
		wrongToken := rawDial(t, h.addr).simpleBind(testAliceDN, "garbage")
		requireInvalidCredentials(t, "wrong token (for equality check)", wrongToken)
		for _, e := range errs {
			if e.ResultCode != wrongToken.ResultCode || e.MatchedDN != wrongToken.MatchedDN || e.Diagnostic != wrongToken.Diagnostic {
				t.Fatalf("failure classes are distinguishable: %+v vs %+v", e, wrongToken)
			}
		}
	})

	t.Run("malformed_bind_dn_variants_rejected_before_verify", func(t *testing.T) {
		fv := newFakeVerifier().withSuccess("s3cr3t", acct)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_engineer"})
		h := newRunningServer(t, fv, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		userBase := newTestConfig().UserBaseDN
		cases := map[string]string{
			"not_a_dn_at_all":         "not-a-valid-dn-no-equals-sign",
			"wrong_rdn_attribute":     "cn=alice," + userBase,
			"wrong_base":              "uid=alice,ou=wrong,dc=profile,dc=test",
			"extra_rdn":               "cn=extra,uid=alice," + userBase,
			"multivalued_leading_rdn": "uid=alice+cn=extra," + userBase,
		}
		for name, dn := range cases {
			t.Run(name, func(t *testing.T) {
				conn := rawDial(t, h.addr)
				requireInvalidCredentials(t, name, conn.simpleBind(dn, "s3cr3t"))
			})
		}
		if got := fv.callCount(); got != 0 {
			t.Fatalf("verifier calls = %d, want 0 (DN parsing must reject before Verify)", got)
		}
	})
}

// ---- TestProfile_BindVersion2ProtocolError --------------------------------

func TestProfile_BindVersion2ProtocolError(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	// rawConn.simpleBind (rawclient_test.go) always sends version 3 on
	// the wire, so a v2 Bind must be hand-built here directly -- exactly
	// the raw-BER case this sub-task calls out.
	raw := fullMessage(1, byte(tagBindRequest), bindOp(2, testAliceDN, authTagSimple, []byte("s3cr3t")), false)
	env := sendAndReadEnvelope(t, conn, raw)
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response tag = %#x, want BindResponse", byte(env.ProtocolOp))
	}
	result, matchedDN, diag := readLDAPResultFields(t, env.Content)
	if result != int(resultProtocolError) {
		t.Fatalf("result = %d, want %d (protocolError)", result, resultProtocolError)
	}
	if matchedDN != "" {
		t.Fatalf("matchedDN = %q, want empty", matchedDN)
	}
	if diag != diagLDAPv3Required.text() {
		t.Fatalf("diagnostic = %q, want %q", diag, diagLDAPv3Required.text())
	}
	if got := v.callCount(); got != 0 {
		t.Fatalf("verifier calls = %d, want 0 (version check precedes Verify)", got)
	}

	// The connection must stay usable afterward (state cleared, not torn
	// down): a valid v3 Bind on the same connection still succeeds.
	env2 := sendAndReadEnvelope(t, conn, bindRequestBytes(2, testAliceDN, "s3cr3t", false))
	result2, _, _ := readLDAPResultFields(t, env2.Content)
	if result2 != int(resultSuccess) {
		t.Fatalf("follow-up v3 bind result = %d, want success", result2)
	}
}

// ---- re-Bind replace/clear, isolation, zero roles, membership ------------

func TestProfile_ReBindReplaceAndClear(t *testing.T) {
	alice := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	bob := newVerificationResult("bob", "https://idp.example/", "sub-bob", time.Now().Add(time.Hour).Unix())
	groupBase := newTestConfig().GroupBaseDN

	t.Run("successful_rebind_replaces", func(t *testing.T) {
		v := newFakeVerifier().withSuccess("alice-pw", alice).withSuccess("bob-pw", bob)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_a"}).withRoles("sub-bob", []string{"ch_b"})
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := rawDial(t, h.addr)
		requireSuccess(t, "bind alice", conn.simpleBind(testAliceDN, "alice-pw"))
		requireSuccess(t, "rebind bob", conn.simpleBind(testBobDN, "bob-pw"))

		res, err := conn.search(groupBase, testBobDN, []string{"cn"})
		if err != nil || len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("cn") != "clickhouse_ch_b" {
			t.Fatalf("search after re-bind = %+v, err=%v, want only bob's role", res, err)
		}

		// Alice's own membership query must no longer succeed on this
		// connection: re-Bind fully replaced, not merged.
		resAlice, err := conn.search(groupBase, testAliceDN, []string{"cn"})
		if err == nil && len(resAlice.Entries) > 0 {
			t.Fatalf("search for alice's membership after re-bind as bob succeeded: %+v", resAlice)
		}
	})

	t.Run("failed_rebind_clears", func(t *testing.T) {
		v := newFakeVerifier().withSuccess("alice-pw", alice)
		r := newFakeResolver().withRoles("sub-alice", []string{"ch_a"})
		h := newRunningServer(t, v, r, nil)
		defer h.stopAndWait(t, 5*time.Second)

		conn := rawDial(t, h.addr)
		requireSuccess(t, "bind alice", conn.simpleBind(testAliceDN, "alice-pw"))
		requireInvalidCredentials(t, "failed rebind", conn.simpleBind(testAliceDN, "wrong-token"))

		res, err := conn.search(groupBase, testAliceDN, []string{"cn"})
		if err == nil && res != nil && len(res.Entries) > 0 {
			t.Fatalf("search after failed re-bind = %+v, want unauthenticated failure", res)
		}
	})
}

func TestProfile_SearchBeforeBindRejected(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := rawDial(t, h.addr)
	res, err := conn.search(newTestConfig().GroupBaseDN, testAliceDN, []string{"cn"})
	if err == nil {
		t.Fatalf("search before bind: got success with %d entries, want failure", len(res.Entries))
	}
	if err.ResultCode != resultInsufficientAccessRights {
		t.Fatalf("search before bind: ResultCode = %d, want %d", err.ResultCode, resultInsufficientAccessRights)
	}
}

func TestProfile_ConnectionStateIsolated(t *testing.T) {
	alice := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	bob := newVerificationResult("bob", "https://idp.example/", "sub-bob", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("alice-pw", alice).withSuccess("bob-pw", bob)
	r := newFakeResolver().withRoles("sub-alice", []string{"ch_alice_role"}).withRoles("sub-bob", []string{"ch_bob_role"})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	groupBase := newTestConfig().GroupBaseDN

	connA := rawDial(t, h.addr)
	requireSuccess(t, "bind alice", connA.simpleBind(testAliceDN, "alice-pw"))

	connB := rawDial(t, h.addr)
	requireSuccess(t, "bind bob", connB.simpleBind(testBobDN, "bob-pw"))

	resA, err := connA.search(groupBase, testAliceDN, []string{"cn"})
	if err != nil || len(resA.Entries) != 1 || resA.Entries[0].GetAttributeValue("cn") != "clickhouse_ch_alice_role" {
		t.Fatalf("connA search = %+v, err=%v, want alice's role only", resA, err)
	}

	resB, err := connB.search(groupBase, testBobDN, []string{"cn"})
	if err != nil || len(resB.Entries) != 1 || resB.Entries[0].GetAttributeValue("cn") != "clickhouse_ch_bob_role" {
		t.Fatalf("connB search = %+v, err=%v, want bob's role only", resB, err)
	}

	// Bob's connection cannot see alice's snapshot, even though connB is
	// itself validly authenticated (as bob).
	resCross, err := connB.search(groupBase, testAliceDN, []string{"cn"})
	if err == nil && resCross != nil && len(resCross.Entries) > 0 {
		t.Fatalf("connB observed alice's membership: %+v", resCross)
	}
}

func TestProfile_ZeroRoleBindGetsSuccessfulEmptySearch(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver() // no roles registered for sub-alice
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := rawDial(t, h.addr)
	requireSuccess(t, "bind", conn.simpleBind(testAliceDN, "s3cr3t"))

	res, err := conn.search(newTestConfig().GroupBaseDN, testAliceDN, []string{"cn"})
	if err != nil {
		t.Fatalf("search: %v, want success", err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(res.Entries))
	}
}

func TestProfile_MembershipAuthorization(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("alice-pw", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	groupBase := newTestConfig().GroupBaseDN

	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := rawDial(t, h.addr)
	requireSuccess(t, "bind alice", conn.simpleBind(testAliceDN, "alice-pw"))

	t.Run("other_member_dn_rejected", func(t *testing.T) {
		res, err := conn.search(groupBase, testBobDN, []string{"cn"})
		if err == nil && res != nil && len(res.Entries) > 0 {
			t.Fatalf("search for bob's membership on alice's connection succeeded: %+v", res)
		}
	})

	t.Run("case_variant_attribute_type_accepted", func(t *testing.T) {
		variant := "UID=alice,OU=users,DC=profile,DC=test"
		res, err := conn.search(groupBase, variant, []string{"cn"})
		if err != nil {
			t.Fatalf("case-variant member search: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("case-variant member search entries = %d, want 1", len(res.Entries))
		}
	})

	t.Run("escaped_hex_spelling_of_own_dn_accepted", func(t *testing.T) {
		// "\61" is the RFC 4514 hex escape for 'a': this decodes to
		// exactly the same value ("alice") as testAliceDN's plain
		// spelling, proving DN.Equal compares decoded bytes, never raw
		// escaped text.
		escaped := `uid=\61lice,ou=users,dc=profile,dc=test`
		res, err := conn.search(groupBase, escaped, []string{"cn"})
		if err != nil {
			t.Fatalf("escaped-spelling member search: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("escaped-spelling member search entries = %d, want 1", len(res.Entries))
		}
	})

	t.Run("comma_and_plus_in_username_no_rfc4515_double_unescape", func(t *testing.T) {
		// A username containing a literal ',' and '+' -- both RFC 4514
		// value characters this profile's own grammar requires escaped
		// in the DN's own text -- proves the server performs no RFC 4515
		// filter-text unescaping of its own: it authorizes Search using
		// raw BER assertion-value bytes, decoded exactly once via the
		// restricted DN grammar (ParseDN), matching the plan's
		// "{bind_dn} filter pipeline" section. rawConn.search builds the
		// membership filter's assertion value directly as a BER OCTET
		// STRING (validMembershipFilter, in search_test.go) -- there is
		// no textual filter-string encode/decode step on the client side
		// at all, so the BER assertion value that reaches the server is
		// exactly hostileDN's raw text, unmodified.
		hostileDN := `uid=alice\,x\+y,ou=users,dc=profile,dc=test`
		hostileAcct := newVerificationResult("alice-hostile", "https://idp.example/", "sub-alice-hostile", time.Now().Add(time.Hour).Unix())
		hv := newFakeVerifier().withSuccess("hostile-pw", hostileAcct)
		hr := newFakeResolver().withRoles("sub-alice-hostile", []string{markerLegitimateRole})
		hh := newRunningServer(t, hv, hr, nil)
		defer hh.stopAndWait(t, 5*time.Second)

		hconn := rawDial(t, hh.addr)
		requireSuccess(t, "bind hostile-shaped DN", hconn.simpleBind(hostileDN, "hostile-pw"))

		res, err := hconn.search(groupBase, hostileDN, []string{"cn"})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("entries = %d, want 1", len(res.Entries))
		}
	})
}

// ---- unsupported operations, controls -------------------------------------

func TestProfile_UnsupportedOperationsRawClient(t *testing.T) {
	v := newFakeVerifier()
	r := newFakeResolver()
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	// dispatchOperation (server.go) routes each of these purely on the
	// LDAPMessage's application tag and never decodes their payload (see
	// opaqueRequestBytes and rawConn.unsupportedOp), so no
	// operation-specific request shape (target DN, modify changes,
	// compare attribute/value, ...) needs to be built here at all -- the
	// bare tag is the entire input dispatchOperation ever looks at.
	t.Run("Add", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		requireUnwillingToPerform(t, conn.unsupportedOp(byte(tagAddRequest)))
	})
	t.Run("Modify", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		requireUnwillingToPerform(t, conn.unsupportedOp(byte(tagModifyRequest)))
	})
	t.Run("Delete", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		requireUnwillingToPerform(t, conn.unsupportedOp(byte(tagDelRequest)))
	})
	t.Run("Compare", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		requireUnwillingToPerform(t, conn.unsupportedOp(byte(tagCompareRequest)))
	})
	t.Run("ModifyDN", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		requireUnwillingToPerform(t, conn.unsupportedOp(byte(tagModifyDNRequest)))
	})
	t.Run("Extended_WhoAmI", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		requireOperationNotSupported(t, conn.unsupportedOp(byte(tagExtendedRequest)))
	})
	t.Run("Extended_Cancel", func(t *testing.T) {
		// Unlike the opaque-content ops above, this one is built with
		// the real Cancel OID (see cancelExtendedRequestBytes) precisely
		// to prove a realistic, well-formed Extended request collapses
		// to the same fixed outcome as an opaque one -- dispatchOperation
		// routes it exactly like any other Extended request, per
		// server.go's "Deliberate Cancel narrowing".
		conn := dial(t, h.addr)
		defer conn.Close()
		env := sendAndReadEnvelope(t, conn, cancelExtendedRequestBytes(1, 1))
		if byte(env.ProtocolOp) != byte(tagExtendedResponse) {
			t.Fatalf("response tag = %#x, want ExtendedResponse", byte(env.ProtocolOp))
		}
		result, _, diag := readLDAPResultFields(t, env.Content)
		if result != int(resultUnwillingToPerform) {
			t.Fatalf("Cancel result = %d, want %d", result, resultUnwillingToPerform)
		}
		if diag != diagOperationUnsupported.text() {
			t.Fatalf("Cancel diagnostic = %q, want %q", diag, diagOperationUnsupported.text())
		}
	})

	if got := v.callCount(); got != 0 {
		t.Fatalf("Verify called %d times across every unsupported op, want 0", got)
	}
	if got := r.callCount(); got != 0 {
		t.Fatalf("Roles called %d times across every unsupported op, want 0", got)
	}
}

func TestProfile_UnknownNonCriticalControlIgnored(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	unknown := unknownNonCriticalControl()

	conn := rawDial(t, h.addr)
	requireSuccess(t, "bind with unknown non-critical control", conn.bindWithControls(testAliceDN, "s3cr3t", unknown))

	res, err := conn.searchWithControls(newTestConfig().GroupBaseDN, testAliceDN, []string{"cn"}, unknown)
	if err != nil {
		t.Fatalf("search with unknown non-critical control: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(res.Entries))
	}
}

// TestProfile_CriticalControlOnBindClearsAuth and
// TestProfile_CriticalControlOnSearchPreservesAuth deliberately build
// their critical control by hand (via bindRequestBytes/
// rawSearchRequestBytes' own critical parameter, which routes through
// frame_test.go's canonical buildControl/trueVal) rather than through
// rawConn's own bindWithControls/searchWithControls.
//
// Historical rationale (kept because it explains why this distinction
// matters at all, not because it still describes this suite's client):
// when this suite's client was github.com/go-ldap/ldap/v3, that
// library's ControlString.Encode used github.com/go-asn1-ber/asn1-ber's
// NewBoolean, which encoded a TRUE criticality as content byte 0x01
// rather than DER-canonical 0xff. This package's Controls scanner
// (frame.go's scanControls) deliberately uses cryptobyte's strict
// 0x00/0xff-only BOOLEAN rule (see frame.go's own comment on that
// choice), so a go-ldap-encoded critical control was itself malformed
// input from this server's point of view and would have simply closed
// the connection -- not the "recognized critical control" case these two
// tests exist to exercise. buildControl always emits DER-canonical
// 0x00/0xff (see frame_test.go), so the hand-built path below remains
// the correct -- and, with go-ldap gone, now the only -- way this suite
// constructs a *recognized* critical control.
func TestProfile_CriticalControlOnBindClearsAuth(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	bindEnv := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
	if result, _, _ := readLDAPResultFields(t, bindEnv.Content); result != int(resultSuccess) {
		t.Fatalf("setup bind result = %d, want success", result)
	}

	criticalEnv := sendAndReadEnvelope(t, conn, bindRequestBytes(2, testAliceDN, "s3cr3t", true))
	result, matchedDN, diag := readLDAPResultFields(t, criticalEnv.Content)
	if result != int(resultUnavailableCriticalExtension) {
		t.Fatalf("critical-control bind result = %d, want %d", result, resultUnavailableCriticalExtension)
	}
	if matchedDN != "" {
		t.Fatalf("critical-control bind matchedDN = %q, want empty", matchedDN)
	}
	if diag != diagCriticalControl.text() {
		t.Fatalf("critical-control bind diagnostic = %q, want %q", diag, diagCriticalControl.text())
	}

	// Auth was cleared: a Search that would have succeeded for the
	// previously bound alice now fails.
	searchEnv := sendAndReadEnvelope(t, conn, searchRequestBytes(3, newTestConfig().GroupBaseDN, testAliceDN, 10, 10))
	searchResult, _, _ := readLDAPResultFields(t, searchEnv.Content)
	if searchResult != int(resultInsufficientAccessRights) {
		t.Fatalf("search after critical-control bind result = %d, want %d (auth cleared)", searchResult, resultInsufficientAccessRights)
	}
}

func TestProfile_CriticalControlOnSearchPreservesAuth(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	bindEnv := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
	if result, _, _ := readLDAPResultFields(t, bindEnv.Content); result != int(resultSuccess) {
		t.Fatalf("setup bind result = %d, want success", result)
	}

	groupBase := newTestConfig().GroupBaseDN
	validFilter := validMembershipFilter(testAliceDN)

	criticalEnv := sendAndReadEnvelope(t, conn, rawSearchRequestBytes(2, groupBase, 2, 0, 0, 0, false, validFilter, true, "cn"))
	result, matchedDN, diag := readLDAPResultFields(t, criticalEnv.Content)
	if result != int(resultUnavailableCriticalExtension) {
		t.Fatalf("critical-control search result = %d, want %d", result, resultUnavailableCriticalExtension)
	}
	if matchedDN != "" {
		t.Fatalf("critical-control search matchedDN = %q, want empty", matchedDN)
	}
	if diag != diagCriticalControl.text() {
		t.Fatalf("critical-control search diagnostic = %q, want %q", diag, diagCriticalControl.text())
	}

	// Auth preserved: an ordinary follow-up Search (no critical control)
	// still succeeds on the same connection.
	followUpEnv := sendAndReadEnvelope(t, conn, rawSearchRequestBytes(3, groupBase, 2, 0, 0, 0, false, validFilter, false, "cn"))
	if followUpEnv.ProtocolOp != tagSearchResultEntry {
		t.Fatalf("follow-up search response tag = %#x, want SearchResultEntry (auth preserved)", byte(followUpEnv.ProtocolOp))
	}
	doneEnv := readEnvelope(t, conn)
	if doneEnv.ProtocolOp != tagSearchResultDone {
		t.Fatalf("follow-up search second response tag = %#x, want SearchResultDone", byte(doneEnv.ProtocolOp))
	}
	result2, _, _ := readLDAPResultFields(t, doneEnv.Content)
	if result2 != int(resultSuccess) {
		t.Fatalf("follow-up search result = %d, want success", result2)
	}
}

// ---- supported-profile log lines -------------------------------------------

func TestProfile_SupportedProfileLogLinesExact(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	groupBase := newTestConfig().GroupBaseDN
	conn := rawDial(t, h.addr)

	bindFields := captureLog(t, zerolog.InfoLevel, func() {
		requireSuccess(t, "bind", conn.simpleBind(testAliceDN, "s3cr3t"))
	})
	if bindFields["message"] != "ldap bind succeeded" {
		t.Fatalf("bind log message = %v, want %q", bindFields["message"], "ldap bind succeeded")
	}
	if bindFields["op"] != "bind" || bindFields["success"] != true || bindFields["result"] != float64(resultSuccess) {
		t.Fatalf("bind log fields = %+v", bindFields)
	}
	if bindFields["username"] != "alice" {
		t.Fatalf("bind log username = %v, want alice", bindFields["username"])
	}
	if bindFields["roles"] != float64(1) {
		t.Fatalf("bind log roles = %v, want 1", bindFields["roles"])
	}
	if got, want := bindFields["correlation_id"], correlationID("https://idp.example/", "sub-alice"); got != want {
		t.Fatalf("bind log correlation_id = %v, want %v", got, want)
	}

	searchFields := captureLog(t, zerolog.InfoLevel, func() {
		res, err := conn.search(groupBase, testAliceDN, []string{"cn"})
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("search: res=%+v err=%v", res, err)
		}
	})
	if searchFields["message"] != "ldap search succeeded" {
		t.Fatalf("search log message = %v, want %q", searchFields["message"], "ldap search succeeded")
	}
	if searchFields["op"] != "search" || searchFields["success"] != true || searchFields["result"] != float64(resultSuccess) {
		t.Fatalf("search log fields = %+v", searchFields)
	}
	if searchFields["username"] != "alice" {
		t.Fatalf("search log username = %v, want alice", searchFields["username"])
	}
	if searchFields["entries"] != float64(1) {
		t.Fatalf("search log entries = %v, want 1", searchFields["entries"])
	}
	if searchFields["types_only"] != false {
		t.Fatalf("search log types_only = %v, want false", searchFields["types_only"])
	}
}

// ---- Bind-time snapshot semantics ------------------------------------------

func TestProfile_BindTimeSnapshotIgnoresLaterResolverChange(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{"ch_a", "ch_b"})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := rawDial(t, h.addr)
	requireSuccess(t, "bind", conn.simpleBind(testAliceDN, "s3cr3t"))

	// Change the resolver's registered roles AFTER Bind: Search must
	// never re-invoke RoleResolver.Roles (Bind-time role snapshots, no
	// Search-time recomputation), so this later mutation can never reach
	// anything the connection returns.
	r.withRoles("sub-alice", []string{"MUTATED"})

	groupBase := newTestConfig().GroupBaseDN
	for i := 0; i < 5; i++ {
		res, err := conn.search(groupBase, testAliceDN, []string{"cn"})
		if err != nil {
			t.Fatalf("search #%d: %v", i, err)
		}
		for _, e := range res.Entries {
			if strings.Contains(e.GetAttributeValue("cn"), "MUTATED") {
				t.Fatalf("post-bind resolver mutation leaked into search #%d: %+v", i, e)
			}
		}
	}

	if got := v.callCount(); got != 1 {
		t.Fatalf("verifier calls = %d, want exactly 1", got)
	}
	if got := r.callCount(); got != 1 {
		t.Fatalf("resolver calls = %d, want exactly 1 (never invoked from Search)", got)
	}
}

// ---- TestProfile_OperationsAreSerial ---------------------------------------

func TestProfile_OperationsAreSerial(t *testing.T) {
	block := make(chan struct{})
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withBlock(block).withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})

	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	groupBase := newTestConfig().GroupBaseDN

	// Pipeline a Bind (which will block inside Verify) immediately
	// followed by a Search -- both fully written before any response is
	// read.
	pipelined := append(append([]byte{}, bindRequestBytes(1, testAliceDN, "s3cr3t", false)...),
		searchRequestBytes(2, groupBase, testAliceDN, 0, 0)...)
	if _, err := conn.Write(pipelined); err != nil {
		t.Fatalf("write pipelined bind+search: %v", err)
	}

	// Neither the Bind response nor any Search response byte may arrive
	// while Verify is still blocked: the already-fully-received,
	// pipelined Search cannot be serviced ahead of (or concurrently
	// with) the still-in-flight Bind -- synchronous, per-connection
	// operation processing.
	assertNoBytesWithin(t, conn, 200*time.Millisecond)

	// A second, independent connection must still be served while the
	// first is blocked inside Verify: the block is per-connection, not a
	// shared server-wide bottleneck. It exercises an operation that
	// never calls Verify (an unsupported Add), so it cannot itself block
	// on the same fakeVerifier.
	conn2 := dial(t, h.addr)
	defer conn2.Close()
	env2 := sendAndReadEnvelope(t, conn2, opaqueRequestBytes(1, byte(tagAddRequest), false))
	if byte(env2.ProtocolOp) != byte(tagAddResponse) {
		t.Fatalf("parallel connection response tag = %#x, want AddResponse", byte(env2.ProtocolOp))
	}
	result2, _, _ := readLDAPResultFields(t, env2.Content)
	if result2 != int(resultUnwillingToPerform) {
		t.Fatalf("parallel connection result = %d, want %d", result2, resultUnwillingToPerform)
	}

	if got := v.callCount(); got != 1 {
		t.Fatalf("verifier calls = %d, want exactly 1 (still blocked)", got)
	}

	close(block)

	bindEnv := readEnvelope(t, conn)
	if bindEnv.ProtocolOp != tagBindResponse {
		t.Fatalf("first response tag = %#x, want BindResponse (Bind must complete before Search is serviced)", byte(bindEnv.ProtocolOp))
	}
	bindResult, _, _ := readLDAPResultFields(t, bindEnv.Content)
	if bindResult != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success", bindResult)
	}

	entries, doneEnv := collectSearchResult(t, conn)
	doneResult, _, _ := readLDAPResultFields(t, doneEnv.Content)
	if doneResult != int(resultSuccess) {
		t.Fatalf("Search result = %d, want success", doneResult)
	}
	if len(entries) != 1 {
		t.Fatalf("Search entries = %d, want 1", len(entries))
	}
}

// ---- TestProfile_SearchFixedFieldPolicy ------------------------------------

func TestProfile_SearchFixedFieldPolicy(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	bindEnv := sendAndReadEnvelope(t, conn, bindRequestBytes(1, testAliceDN, "s3cr3t", false))
	if result, _, _ := readLDAPResultFields(t, bindEnv.Content); result != int(resultSuccess) {
		t.Fatalf("setup bind result = %d, want success", result)
	}

	groupBase := newTestConfig().GroupBaseDN
	validFilter := validMembershipFilter(testAliceDN)

	rejected := []struct {
		name  string
		base  string
		scope int64
		deref int64
		types bool
		attrs []string
	}{
		{"wrong_base", "ou=other,dc=profile,dc=test", 2, 0, false, []string{"cn"}},
		{"scope_baseObject", groupBase, 0, 0, false, []string{"cn"}},
		{"scope_singleLevel", groupBase, 1, 0, false, []string{"cn"}},
		{"deref_1", groupBase, 2, 1, false, []string{"cn"}},
		{"deref_2", groupBase, 2, 2, false, []string{"cn"}},
		{"deref_3", groupBase, 2, 3, false, []string{"cn"}},
		{"typesOnly_true", groupBase, 2, 0, true, []string{"cn"}},
		{"attrs_empty", groupBase, 2, 0, false, nil},
		{"attrs_star", groupBase, 2, 0, false, []string{"*"}},
		{"attrs_1.1", groupBase, 2, 0, false, []string{"1.1"}},
		{"attrs_member", groupBase, 2, 0, false, []string{"member"}},
		{"attrs_cn_and_member", groupBase, 2, 0, false, []string{"cn", "member"}},
	}
	var msgID int64 = 2
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			raw := rawSearchRequestBytes(msgID, tc.base, tc.scope, tc.deref, 0, 0, tc.types, validFilter, false, tc.attrs...)
			msgID++
			env := sendAndReadEnvelope(t, conn, raw)
			result, _, diag := readLDAPResultFields(t, env.Content)
			if result != int(resultInsufficientAccessRights) {
				t.Fatalf("result = %d, want %d", result, resultInsufficientAccessRights)
			}
			if diag != diagInsufficientAccess.text() {
				t.Fatalf("diagnostic = %q, want %q", diag, diagInsufficientAccess.text())
			}
		})
	}

	accepted := []struct {
		name string
		attr string
	}{
		{"cn_lowercase", "cn"},
		{"CN_uppercase", "CN"},
		{"Cn_mixed", "Cn"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			raw := rawSearchRequestBytes(msgID, groupBase, 2, 0, 0, 0, false, validFilter, false, tc.attr)
			msgID++
			if _, err := conn.Write(raw); err != nil {
				t.Fatalf("write: %v", err)
			}
			entryEnv := readEnvelope(t, conn)
			if entryEnv.ProtocolOp != tagSearchResultEntry {
				t.Fatalf("response tag = %#x, want SearchResultEntry", byte(entryEnv.ProtocolOp))
			}
			_, attrType, attrValue := decodeSearchResultEntry(t, entryEnv.Content)
			if attrType != "cn" {
				t.Fatalf("entry attribute type = %q, want lowercase %q regardless of requested spelling %q", attrType, "cn", tc.attr)
			}
			wantCN := newTestConfig().RoleCNPrefix + markerLegitimateRole
			if attrValue != wantCN {
				t.Fatalf("entry cn value = %q, want %q", attrValue, wantCN)
			}
			doneEnv := readEnvelope(t, conn)
			if doneEnv.ProtocolOp != tagSearchResultDone {
				t.Fatalf("second response tag = %#x, want SearchResultDone", byte(doneEnv.ProtocolOp))
			}
			result, _, _ := readLDAPResultFields(t, doneEnv.Content)
			if result != int(resultSuccess) {
				t.Fatalf("result = %d, want success", result)
			}
		})
	}
}

// ---- remaining legacy real-TCP proofs --------------------------------------

func TestProfile_MalformedBERSurvival(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	raw := dial(t, h.addr)
	// Deliberately invalid BER: a long, incomplete tag/length sequence
	// (see frame_test.go/frame_fuzz_test.go for the exhaustive malformed-
	// framing table this proof complements at the client-observable
	// level: a fresh connection afterward is served exactly as if
	// nothing had happened).
	if _, err := raw.Write([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	raw.Close()

	conn := rawDial(t, h.addr)
	requireSuccess(t, "bind after malformed input", conn.simpleBind(testAliceDN, "s3cr3t"))
}

func TestProfile_DisconnectRemovesState(t *testing.T) {
	acct := newVerificationResult("alice", "https://idp.example/", "sub-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-alice", []string{markerLegitimateRole})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := rawDial(t, h.addr)
	requireSuccess(t, "bind", conn.simpleBind(testAliceDN, "s3cr3t"))
	conn.Close()

	fresh := rawDial(t, h.addr)
	res, err := fresh.search(newTestConfig().GroupBaseDN, testAliceDN, []string{"cn"})
	if err == nil && res != nil && len(res.Entries) > 0 {
		t.Fatalf("fresh connection search succeeded without binding: %+v", res)
	}
}
