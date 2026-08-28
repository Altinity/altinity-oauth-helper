package ldap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldapclient "github.com/go-ldap/ldap/v3"
	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers the phase-5 plan's "Search sizeLimit"/"Search
// timeLimit"/"typesOnly"/"Safe Search telemetry" sections. Most cases drive
// the real production server over real TCP, reusing protocol_test.go's
// harness (startTestServer/dialTest/bindAs/account/newFakeVerifier/
// newFakeRoles); the deliberately-slow-writer timeLimit proof instead calls
// (*connectionHandler).handleSearch directly against a hand-decoded
// SearchRequest, because no real TCP client can be made to pace its own
// reads slowly enough on this handler's write side without the test itself
// racing the write buffer instead of the intended wall-clock deadline.

// ---- shared fixtures --------------------------------------------------

// manyRoles returns n distinct, always-renderable role names.
func manyRoles(n int) []string {
	roles := make([]string, n)
	for i := range roles {
		roles[i] = fmt.Sprintf("role_%03d", i)
	}
	return roles
}

// membershipSearchWithLimits is membershipSearch (protocol_test.go) extended
// with the three request fields this file exercises.
func membershipSearchWithLimits(baseDN, boundDN string, attrs []string, sizeLimit, timeLimit int, typesOnly bool) *goldapclient.SearchRequest {
	filter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", boundDN)
	return goldapclient.NewSearchRequest(baseDN, goldapclient.ScopeWholeSubtree, goldapclient.NeverDerefAliases, sizeLimit, timeLimit, typesOnly, filter, attrs, nil)
}

// captureSearchLog swaps the process-global zerolog logger for a buffer for
// the duration of the calling test, restoring it via t.Cleanup, and returns
// a function that yields everything captured so far. Not safe to run under
// t.Parallel() against other tests doing the same — none of the tests in
// this file do.
func captureSearchLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return func() string { return buf.String() }
}

// findLogLine parses captured (one zerolog JSON object per line) and
// returns the first line whose "op" field equals op, failing the test if
// none matches.
func findLogLine(t *testing.T, captured, op string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(captured), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["op"] == op {
			return m
		}
	}
	t.Fatalf("no captured log line with op=%q found in:\n%s", op, captured)
	return nil
}

// ---- 1. sizeLimit=0 is unlimited ------------------------------------------

func TestSearchLimits_SizeLimitZeroUnlimitedWithManyRoles(t *testing.T) {
	roles := manyRoles(30)
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", roles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	req := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, 0, 0, false)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with sizeLimit=0: got error %v, want success", err)
	}
	if len(res.Entries) != len(roles) {
		t.Fatalf("entries = %d, want %d (sizeLimit=0 must be unlimited)", len(res.Entries), len(roles))
	}
}

// ---- 2. sizeLimit == entry count succeeds; N+1 truncates at N -------------

func TestSearchLimits_SizeLimitEqualToEntryCountSucceeds(t *testing.T) {
	roles := manyRoles(5)
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", roles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	req := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, len(roles), 0, false)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with sizeLimit == entry count: got error %v, want success", err)
	}
	if len(res.Entries) != len(roles) {
		t.Fatalf("entries = %d, want %d", len(res.Entries), len(roles))
	}
}

func TestSearchLimits_SizeLimitExceededByOneReturnsSizeLimitExceeded(t *testing.T) {
	roles := manyRoles(5)
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", roles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	limit := len(roles) - 1 // one fewer than the entry count: N+1 direction
	req := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, limit, 0, false)
	res, err := conn.Search(req)
	ldapErr := asLDAPError(err)
	if ldapErr == nil {
		t.Fatalf("search: got success, want sizeLimitExceeded")
	}
	if int(ldapErr.ResultCode) != goldapclient.LDAPResultSizeLimitExceeded {
		t.Fatalf("ResultCode = %d, want %d (sizeLimitExceeded)", ldapErr.ResultCode, goldapclient.LDAPResultSizeLimitExceeded)
	}
	if len(res.Entries) != limit {
		t.Fatalf("entries = %d, want exactly %d (the sizeLimit)", len(res.Entries), limit)
	}

	// The other direction, on the very same connection: a follow-up Search
	// back under the limit must still succeed with every entry — a
	// sizeLimitExceeded result truncates one Search's results, it does not
	// corrupt the connection, session, or role snapshot.
	req2 := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, len(roles), 0, false)
	res2, err2 := conn.Search(req2)
	if err2 != nil {
		t.Fatalf("follow-up search under the limit: got error %v, want success", err2)
	}
	if len(res2.Entries) != len(roles) {
		t.Fatalf("follow-up entries = %d, want %d", len(res2.Entries), len(roles))
	}
}

// ---- 3. timeLimit=0 and a fast positive timeLimit both succeed -----------

func TestSearchLimits_TimeLimitZeroSucceeds(t *testing.T) {
	roles := []string{"ch_engineer", "ch_analyst"}
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", roles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	req := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, 0, 0, false)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with timeLimit=0: got error %v, want success", err)
	}
	if len(res.Entries) != len(roles) {
		t.Fatalf("entries = %d, want %d", len(res.Entries), len(roles))
	}
}

func TestSearchLimits_TimeLimitPositiveOnFastSearchSucceeds(t *testing.T) {
	roles := []string{"ch_engineer", "ch_analyst"}
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", roles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	req := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, 0, 30, false)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with a generous positive timeLimit: got error %v, want success", err)
	}
	if len(res.Entries) != len(roles) {
		t.Fatalf("entries = %d, want %d", len(res.Entries), len(roles))
	}
}

// ---- 4. timeLimit expiry mid-Search, via a direct-handler slow writer ----

// slowResponseWriter is a minimal ldapserver.ResponseWriter that sleeps
// delay before recording each write it receives, so a handler's own
// wall-clock timeLimit checks — not network/OS buffering — are what decide
// the outcome.
type slowResponseWriter struct {
	delay   time.Duration
	written []message.ProtocolOp
}

func (w *slowResponseWriter) Write(po message.ProtocolOp) {
	time.Sleep(w.delay)
	w.written = append(w.written, po)
}

// buildSearchRequestBytes BER-encodes one complete LDAPv3 SearchRequest
// LDAPMessage envelope matching handleSearch's required shape
// (base=base, scope=wholeSubtree,
// filter=(&(objectClass=groupOfNames)(member=memberDN))), with sizeLimit,
// timeLimit, typesOnly and the requested attribute list all explicitly
// controllable. See adversarial_test.go's rawSearchMessage, which this
// mirrors but for the wire fields that function hardcodes to their
// zero/false/empty defaults.
//
// typesOnly is deliberately encoded with ber.NewLDAPBoolean, not go-ldap/
// v3's own request encoder's ber.NewBoolean — see
// TestTypesOnly_WireSearchReturnsAttributeNamesWithoutValues's doc comment
// for why a real go-ldap/v3 client cannot be used to drive a typesOnly=true
// Search against this server at all.
func buildSearchRequestBytes(messageID int, base, memberDN string, sizeLimit, timeLimit int, typesOnly bool, attrs []string) []byte {
	equalityFilter := func(attr, value string) *ber.Packet {
		f := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equalityMatch")
		f.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "attributeDesc"))
		f.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "assertionValue"))
		return f
	}
	andFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "and")
	andFilter.AppendChild(equalityFilter("objectClass", "groupOfNames"))
	andFilter.AppendChild(equalityFilter("member", memberDN))

	attrSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range attrs {
		attrSeq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "attribute"))
	}

	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "baseObject"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope")) // wholeSubtree
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "derefAliases"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, sizeLimit, "sizeLimit"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, timeLimit, "timeLimit"))
	// NewLDAPBoolean (not NewBoolean) — see controls_test.go's identical
	// note: this local strict decoder demands an RFC 4511-compliant
	// 0x00/0xFF BOOLEAN encoding, which only NewLDAPBoolean produces for a
	// TRUE value.
	searchReq.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, typesOnly, "typesOnly"))
	searchReq.AppendChild(andFilter)
	searchReq.AppendChild(attrSeq)

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	env.AppendChild(searchReq)
	return env.Bytes()
}

// decodeSearchMessage decodes raw (built by buildSearchRequestBytes) back
// through the same goldap message decoder the production server's real TCP
// path uses, and wraps the result in a *ldapserver.Message ready to hand
// directly to a route handler — bypassing the network entirely so a test
// can control response pacing precisely.
func decodeSearchMessage(t *testing.T, raw []byte) *ldapserver.Message {
	t.Helper()
	decoded, err := message.ReadLDAPMessage(message.NewBytes(0, raw))
	if err != nil {
		t.Fatalf("decode raw search message: %v", err)
	}
	return &ldapserver.Message{LDAPMessage: &decoded, Done: make(chan bool)}
}

func TestSearchLimits_TimeLimitExceededBySlowWriterReturnsTimeLimitExceeded(t *testing.T) {
	groupBase, err := NewGroupBaseDN(protoGroupBaseDN)
	if err != nil {
		t.Fatalf("NewGroupBaseDN: %v", err)
	}

	h := &connectionHandler{
		rootCtx:      context.Background(),
		groupBase:    groupBase,
		roleCNPrefix: protoCNPrefix,
		session:      newSession(),
	}

	boundDN := protoBindDN("alice")
	roles := manyRoles(8)
	h.session.replace(authenticatedState{
		Username: "alice",
		BoundDN:  boundDN,
		Roles:    roles,
	})

	const timeLimitSeconds = 1
	raw := buildSearchRequestBytes(1, protoGroupBaseDN, boundDN, 0, timeLimitSeconds, false, nil)
	msg := decodeSearchMessage(t, raw)

	w := &slowResponseWriter{delay: 400 * time.Millisecond}

	stop := captureSearchLog(t)

	start := time.Now()
	h.handleSearch(w, msg)
	elapsed := time.Since(start)

	logged := stop()

	if elapsed < timeLimitSeconds*time.Second {
		t.Fatalf("elapsed = %v, want at least %v (400ms/write against a %ds timeLimit)", elapsed, timeLimitSeconds*time.Second, timeLimitSeconds)
	}
	if len(w.written) == 0 {
		t.Fatalf("handler wrote nothing at all")
	}
	entriesWritten := len(w.written) - 1 // exclude the final SearchResultDone
	if entriesWritten < 0 {
		t.Fatalf("handler's only write was not preceded by any entry")
	}
	if entriesWritten >= len(roles) {
		t.Fatalf("entries written = %d, want fewer than all %d roles (timeLimit should have truncated the Search)", entriesWritten, len(roles))
	}

	line := findLogLine(t, logged, "search")
	if got, ok := line["result"].(float64); !ok || int(got) != ldapserver.LDAPResultTimeLimitExceeded {
		t.Fatalf("log field result = %v, want %d (timeLimitExceeded)", line["result"], ldapserver.LDAPResultTimeLimitExceeded)
	}
	if got, ok := line["time_limit"].(float64); !ok || int(got) != timeLimitSeconds {
		t.Fatalf("log field time_limit = %v, want %d", line["time_limit"], timeLimitSeconds)
	}
	if got, ok := line["entries"].(float64); !ok || int(got) != entriesWritten {
		t.Fatalf("log field entries = %v, want %d", line["entries"], entriesWritten)
	}
}

// ---- 5. typesOnly over real wire -------------------------------------------

// rawSearchEntry and rawAttr hold one decoded SearchResultEntry response for
// TestTypesOnly_WireSearchReturnsAttributeNamesWithoutValues below.
type rawSearchEntry struct {
	dn    string
	attrs []rawAttr
}

type rawAttr struct {
	name   string
	values []string
}

// readRawSearchResponses reads raw LDAPMessage responses from conn until a
// SearchResultDone (tag 5) arrives, decoding every SearchResultEntry (tag 4)
// seen before it, and returns them plus the final result code. It never
// goes through goldapclient — see this test's doc comment for why a real
// go-ldap/v3 client cannot drive this particular request at all — so it
// must decode the PartialAttributeList/PartialAttribute/SET-OF-values shape
// itself, the same raw *ber.Packet field-access pattern
// controls_test.go's readRawResponse and adversarial_test.go already use.
func readRawSearchResponses(t *testing.T, conn net.Conn, deadline time.Duration) (entries []rawSearchEntry, resultCode int) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(deadline))
	for {
		pkt, err := ber.ReadPacket(conn)
		if err != nil {
			t.Fatalf("read search response: %v", err)
		}
		if len(pkt.Children) < 2 {
			t.Fatalf("malformed LDAPMessage response: %+v", pkt)
		}
		op := pkt.Children[1]
		switch op.Tag {
		case 4: // searchResEntry
			dn, _ := op.Children[0].Value.(string)
			entry := rawSearchEntry{dn: dn}
			if len(op.Children) > 1 {
				for _, pa := range op.Children[1].Children {
					if len(pa.Children) == 0 {
						continue
					}
					name, _ := pa.Children[0].Value.(string)
					attr := rawAttr{name: name}
					if len(pa.Children) > 1 {
						for _, v := range pa.Children[1].Children {
							s, _ := v.Value.(string)
							attr.values = append(attr.values, s)
						}
					}
					entry.attrs = append(entry.attrs, attr)
				}
			}
			entries = append(entries, entry)
		case 5: // searchResDone
			if len(op.Children) == 0 {
				t.Fatalf("searchResDone has no resultCode: %+v", op)
			}
			return entries, int(op.Children[0].Value.(int64))
		default:
			t.Fatalf("unexpected response protocolOp tag %d, want 4 (entry) or 5 (done)", op.Tag)
		}
	}
}

// TestTypesOnly_WireSearchReturnsAttributeNamesWithoutValues drives a
// typesOnly=true Search over a real TCP connection against the real
// production server, using raw BER for both the Bind and the Search — not
// goldapclient.Conn.Search() — because go-ldap/v3 v3.4.14's own
// SearchRequest encoder (search.go's newSearchRequest) builds the
// typesOnly BOOLEAN with ber.NewBoolean, which writes Go's `true` as
// content byte 0x01: valid permissive BER, but not the strict DER-style
// 0x00/0xFF encoding this repo's local goldap/message fork's readBOOLEAN
// requires (backed by encoding/asn1, see search_request.go's typesOnly
// decode and boolean.go's readBOOLEAN — the identical class of problem
// controls_test.go's unknownControlValue/rawControlsPacket doc comments
// already document for the criticality BOOLEAN). A goldapclient-driven
// typesOnly=true request is therefore rejected as a malformed LDAPMessage
// and silently dropped before it ever reaches handleSearch — the connection
// then just hangs until the server's 30s ReadTimeout closes it, which is
// not this test's concern: it proves handleSearch's typesOnly rendering is
// correct for any spec-compliant client, using the same raw-BER-over-TCP
// technique this package's controls_test.go already established for the
// same reason (rawBindRequest/rawEnvelope/readRawResponse, reused
// unchanged here).
func TestTypesOnly_WireSearchReturnsAttributeNamesWithoutValues(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_engineer"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	t.Cleanup(func() { rawConn.Close() })

	boundDN := protoBindDN("alice")
	if _, err := rawConn.Write(rawEnvelope(1, rawBindRequest(boundDN, "jwt-alice"), false)); err != nil {
		t.Fatalf("write raw Bind: %v", err)
	}
	if got := readRawResponse(t, rawConn, 5*time.Second, 1, 1); got != ldapserver.LDAPResultSuccess {
		t.Fatalf("raw Bind resultCode = %d, want %d (success)", got, ldapserver.LDAPResultSuccess)
	}

	requestedAttrs := []string{"cn", "member", "objectClass"}
	searchBytes := buildSearchRequestBytes(2, protoGroupBaseDN, boundDN, 0, 0, true, requestedAttrs)
	if _, err := rawConn.Write(searchBytes); err != nil {
		t.Fatalf("write raw typesOnly Search: %v", err)
	}

	entries, resultCode := readRawSearchResponses(t, rawConn, 5*time.Second)
	if resultCode != ldapserver.LDAPResultSuccess {
		t.Fatalf("final result = %d, want %d (success)", resultCode, ldapserver.LDAPResultSuccess)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	if entry.dn == "" {
		t.Fatalf("entry DN is empty")
	}
	if _, err := goldapclient.ParseDN(entry.dn); err != nil {
		t.Fatalf("entry DN %q does not parse as a valid DN: %v", entry.dn, err)
	}

	seen := make(map[string]bool, len(requestedAttrs))
	for _, attr := range entry.attrs {
		seen[attr.name] = true
		if len(attr.values) != 0 {
			t.Fatalf("attribute %q carried %d value(s), want none under typesOnly", attr.name, len(attr.values))
		}
	}
	for _, name := range requestedAttrs {
		if !seen[name] {
			t.Fatalf("requested attribute %q missing from typesOnly response (attribute descriptions must still be present)", name)
		}
	}
}

// ---- 6. telemetry log carries only safe numeric/bool fields ---------------

func TestSearchLimits_TelemetryLogIsNumericBoolOnlyAndOmitsSensitiveFields(t *testing.T) {
	roles := []string{"ch_engineer", "ch_analyst"}
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", roles)
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	conn := dialTest(t, addr)
	requireSuccess(t, "bind", bindAs(conn, protoBindDN("alice"), "jwt-alice"))

	stop := captureSearchLog(t)

	req := membershipSearchWithLimits(protoGroupBaseDN, protoBindDN("alice"), nil, 10, 5, false)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != len(roles) {
		t.Fatalf("entries = %d, want %d", len(res.Entries), len(roles))
	}

	logged := stop()
	line := findLogLine(t, logged, "search")

	numeric := map[string]float64{
		"size_limit": 10,
		"time_limit": 5,
		"entries":    float64(len(roles)),
		"result":     float64(ldapserver.LDAPResultSuccess),
	}
	for key, want := range numeric {
		got, ok := line[key].(float64)
		if !ok {
			t.Fatalf("log field %q missing or not numeric: %#v", key, line[key])
		}
		if got != want {
			t.Fatalf("log field %q = %v, want %v", key, got, want)
		}
	}
	if got, ok := line["types_only"].(bool); !ok || got != false {
		t.Fatalf("log field types_only = %#v, want false", line["types_only"])
	}

	forbidden := []string{"filter", "dn", "member", "controls", "role", "roles", "boundDN", "bound_dn", "bind_dn"}
	for _, key := range forbidden {
		if v, present := line[key]; present {
			t.Fatalf("log line unexpectedly contains forbidden key %q: %v", key, v)
		}
	}

	for _, role := range roles {
		if strings.Contains(logged, role) {
			t.Fatalf("captured log leaked role value %q:\n%s", role, logged)
		}
	}
	if strings.Contains(logged, protoBindDN("alice")) {
		t.Fatalf("captured log leaked the bound DN:\n%s", logged)
	}
	if strings.Contains(logged, protoGroupBaseDN) {
		t.Fatalf("captured log leaked the Search base DN:\n%s", logged)
	}
}
