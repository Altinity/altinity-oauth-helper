package profile

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// This file is the handler-level test suite for search.go: the field
// decode/malformed-range table (Amendment 2), the fixed authorization
// table, the fixed membership filter decoder (including its nonrecursive
// two-child walk and structural member comparison), sizeLimit/timeLimit
// execution, the response-PDU size cap, terminal-deadline correctness,
// and no-marker-leak. Every test drives handleSearch through a real
// net.Pipe, matching bind_test.go's handler-level approach.

// --- op-content builders ------------------------------------------------

func enumTLV(v int64) []byte { return tlv(0x0a, minimalIntegerContent(v)) }

func boolTLV(v bool) []byte {
	b := byte(0x00)
	if v {
		b = 0xff
	}
	return tlv(0x01, []byte{b})
}

func attrsTLV(attrs ...string) []byte {
	var content []byte
	for _, a := range attrs {
		content = append(content, tlv(0x04, []byte(a))...)
	}
	return tlv(0x30, content)
}

// searchOp assembles a complete, well-formed SearchRequest protocolOp
// content in field order: baseObject, scope, derefAliases, sizeLimit,
// timeLimit, typesOnly, filter (a complete, already-tagged TLV, e.g. from
// validMembershipFilter), attributes.
func searchOp(base string, scope, deref, sizeLimit, timeLimit int64, typesOnly bool, filterBytes []byte, attrs ...string) []byte {
	out := tlv(0x04, []byte(base))
	out = append(out, enumTLV(scope)...)
	out = append(out, enumTLV(deref)...)
	out = append(out, berInteger(sizeLimit)...)
	out = append(out, berInteger(timeLimit)...)
	out = append(out, boolTLV(typesOnly)...)
	out = append(out, filterBytes...)
	out = append(out, attrsTLV(attrs...)...)
	return out
}

func filterEquality(desc, value string) []byte {
	content := tlv(0x04, []byte(desc))
	content = append(content, tlv(0x04, []byte(value))...)
	return tlv(0xa3, content)
}

func filterAnd(children ...[]byte) []byte {
	var content []byte
	for _, c := range children {
		content = append(content, c...)
	}
	return tlv(0xa0, content)
}

func filterOr(children ...[]byte) []byte {
	var content []byte
	for _, c := range children {
		content = append(content, c...)
	}
	return tlv(0xa1, content)
}

func filterNot(child []byte) []byte { return tlv(0xa2, child) }

// filterSubstrings is a structurally minimal but recognizable substrings
// filter (attribute description + an empty substrings SEQUENCE) — enough
// to exercise "not an equalityMatch CHOICE tag" rejection; its internal
// substrings shape is never decoded.
func filterSubstrings(desc string) []byte {
	content := tlv(0x04, []byte(desc))
	content = append(content, tlv(0x30, nil)...)
	return tlv(0xa4, content)
}

func filterPresent(desc string) []byte { return tlv(0x87, []byte(desc)) }

const testBoundDN = "uid=alice,ou=users,dc=profile,dc=test"

func validMembershipFilter(memberDN string) []byte {
	return filterAnd(filterEquality("objectClass", "groupOfNames"), filterEquality("member", memberDN))
}

// --- connection/harness construction -------------------------------------

// newSearchTestConnection returns a connection pre-authenticated with
// boundDN/roles (per this sub-task's harness convention: set c.auth
// directly rather than driving a Bind first), wired to one end of a
// net.Pipe, using a real clock. The fakeVerifier/fakeResolver are
// accessible via c.verifier/c.roles type assertions for call-count
// assertions.
func newSearchTestConnection(t *testing.T, boundDN string, roles []string) (*connection, net.Conn, func()) {
	t.Helper()
	return newSearchTestConnectionWithClock(t, boundDN, roles, time.Now)
}

func newSearchTestConnectionWithClock(t *testing.T, boundDN string, roles []string, clock func() time.Time) (*connection, net.Conn, func()) {
	t.Helper()
	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig(newTestConfig()): %v", err)
	}
	parsedBoundDN, err := ParseDN(boundDN)
	if err != nil {
		t.Fatalf("ParseDN(boundDN) = %v", err)
	}
	clientConn, serverConn := net.Pipe()
	c := &connection{
		nc:           serverConn,
		ctx:          context.Background(),
		cfg:          &parsed,
		verifier:     newFakeVerifier(),
		roles:        newFakeResolver(),
		clock:        clock,
		writeTimeout: 2 * time.Second,
	}
	c.replaceAuth(authState{
		Username: "alice",
		BoundDN:  boundDN,
		boundDN:  parsedBoundDN,
		Roles:    roles,
	})
	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
	return c, clientConn, cleanup
}

// --- response reading -----------------------------------------------------

type searchReadResult struct {
	envs   []Envelope
	bodies [][]byte
	err    error
}

// collectSearchResponses reads frames off clientConn until one decodes as
// a SearchResultDone (the terminal PDU every Search ends with) or a
// read/decode error occurs, running concurrently with the (synchronously
// blocking-on-Write) handleSearch call under test.
func collectSearchResponses(clientConn net.Conn) <-chan searchReadResult {
	ch := make(chan searchReadResult, 1)
	go func() {
		var envs []Envelope
		var bodies [][]byte
		for {
			body, err := readFrame(clientConn)
			if err != nil {
				ch <- searchReadResult{envs, bodies, err}
				return
			}
			env, decErr := decodeEnvelope(body)
			if decErr != nil {
				ch <- searchReadResult{envs, bodies, decErr}
				return
			}
			envs = append(envs, env)
			bodies = append(bodies, body)
			if env.ProtocolOp == tagSearchResultDone {
				ch <- searchReadResult{envs, bodies, nil}
				return
			}
		}
	}()
	return ch
}

// doSearch calls c.handleSearch while concurrently draining every
// response frame it writes. If handleSearch returns a non-nil error
// (close), c.nc is closed to unblock the reader with EOF/closed-pipe,
// matching doBind's convention in bind_test.go.
func doSearch(t *testing.T, c *connection, clientConn net.Conn, msgID int32, op []byte, hasCritical bool) (searchErr error, envs []Envelope, bodies [][]byte, wrote bool) {
	t.Helper()
	ch := collectSearchResponses(clientConn)

	searchErr = c.handleSearch(msgID, cryptobyte.String(op), hasCritical)
	if searchErr != nil {
		_ = c.nc.Close()
	}

	select {
	case res := <-ch:
		if searchErr != nil {
			return searchErr, nil, nil, false
		}
		if res.err != nil {
			t.Fatalf("handleSearch returned nil but reading its responses failed: %v", res.err)
		}
		return nil, res.envs, res.bodies, true
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the Search response reader goroutine")
		return nil, nil, nil, false
	}
}

// readSearchResultDone decodes env.Content as SearchResultDone's
// LDAPResult fields.
func readSearchResultDone(t *testing.T, env Envelope) (result int, matchedDN, diagnosticMessage string) {
	t.Helper()
	if env.ProtocolOp != tagSearchResultDone {
		t.Fatalf("protocolOp = %#x, want SearchResultDone %#x", byte(env.ProtocolOp), byte(tagSearchResultDone))
	}
	content := env.Content
	var resultEnum int
	if !content.ReadASN1Enum(&resultEnum) {
		t.Fatal("SearchResultDone: failed to read resultCode")
	}
	var matchedDNBytes, diagBytes []byte
	if !content.ReadASN1Bytes(&matchedDNBytes, asn1.OCTET_STRING) {
		t.Fatal("SearchResultDone: failed to read matchedDN")
	}
	if !content.ReadASN1Bytes(&diagBytes, asn1.OCTET_STRING) {
		t.Fatal("SearchResultDone: failed to read diagnosticMessage")
	}
	if !content.Empty() {
		t.Fatal("SearchResultDone: trailing bytes after LDAPResult fields")
	}
	return resultEnum, string(matchedDNBytes), string(diagBytes)
}

// decodedEntry is a SearchResultEntry decoded down to its objectName and
// parallel attribute-type/values slices.
type decodedEntry struct {
	objectName string
	attrTypes  []string
	attrValues [][]string
}

func readSearchResultEntry(t *testing.T, env Envelope) decodedEntry {
	t.Helper()
	if env.ProtocolOp != tagSearchResultEntry {
		t.Fatalf("protocolOp = %#x, want SearchResultEntry %#x", byte(env.ProtocolOp), byte(tagSearchResultEntry))
	}
	content := env.Content
	var nameBytes []byte
	if !content.ReadASN1Bytes(&nameBytes, asn1.OCTET_STRING) {
		t.Fatal("SearchResultEntry: failed to read objectName")
	}
	var attrsSeq cryptobyte.String
	if !content.ReadASN1(&attrsSeq, asn1.SEQUENCE) {
		t.Fatal("SearchResultEntry: failed to read attributes")
	}
	if !content.Empty() {
		t.Fatal("SearchResultEntry: trailing bytes after attributes")
	}

	out := decodedEntry{objectName: string(nameBytes)}
	for !attrsSeq.Empty() {
		var attr cryptobyte.String
		if !attrsSeq.ReadASN1(&attr, asn1.SEQUENCE) {
			t.Fatal("SearchResultEntry: malformed PartialAttribute")
		}
		var typeBytes []byte
		if !attr.ReadASN1Bytes(&typeBytes, asn1.OCTET_STRING) {
			t.Fatal("SearchResultEntry: failed to read attribute type")
		}
		var valsSet cryptobyte.String
		if !attr.ReadASN1(&valsSet, asn1.SET) {
			t.Fatal("SearchResultEntry: failed to read attribute values")
		}
		if !attr.Empty() {
			t.Fatal("SearchResultEntry: trailing bytes inside PartialAttribute")
		}
		var vals []string
		for !valsSet.Empty() {
			var v []byte
			if !valsSet.ReadASN1Bytes(&v, asn1.OCTET_STRING) {
				t.Fatal("SearchResultEntry: malformed attribute value")
			}
			vals = append(vals, string(v))
		}
		out.attrTypes = append(out.attrTypes, string(typeBytes))
		out.attrValues = append(out.attrValues, vals)
	}
	return out
}

// --- deterministic clocks --------------------------------------------------

// sequenceClock returns times[i] for the i-th call to Now (0-indexed),
// clamping to the last entry once exhausted. Used to make consecutive
// c.clock() reads inside one synchronous handleSearch call advance
// deterministically without a real sleep. Every scripted value must still
// be a genuine near-future wall-clock instant (built from a real
// time.Now() base plus small offsets): the connection's entry/terminal
// write deadlines are set on a real net.Conn (net.Pipe), which enforces
// deadlines against real wall-clock time regardless of what this fake
// clock reports for business-logic comparisons.
type sequenceClock struct {
	mu    sync.Mutex
	times []time.Time
	next  int
}

func (s *sequenceClock) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.next
	if idx >= len(s.times) {
		idx = len(s.times) - 1
	} else {
		s.next++
	}
	return s.times[idx]
}

// --- deadline-recording connection ----------------------------------------

// deadlineRecordingConn wraps a net.Conn and records every
// SetWriteDeadline argument, so a test can assert the actual deadline
// value a terminal SearchResultDone write used.
type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (r *deadlineRecordingConn) SetWriteDeadline(t time.Time) error {
	r.mu.Lock()
	r.deadlines = append(r.deadlines, t)
	r.mu.Unlock()
	return r.Conn.SetWriteDeadline(t)
}

func (r *deadlineRecordingConn) lastDeadline() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.deadlines) == 0 {
		return time.Time{}
	}
	return r.deadlines[len(r.deadlines)-1]
}

// =========================================================================
// Critical control / unauthenticated / malformed
// =========================================================================

func TestHandleSearch_CriticalControlPreservesAuthAndReturns12(t *testing.T) {
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, []string{markerLegitimateRole})
	defer cleanup()

	op := searchOp(c.cfg.groupBaseText, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, true)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	if len(envs) != 1 {
		t.Fatalf("got %d response frames, want exactly 1 (SearchResultDone only)", len(envs))
	}
	code, _, diag := readSearchResultDone(t, envs[0])
	if code != int(resultUnavailableCriticalExtension) {
		t.Fatalf("result = %d, want %d", code, resultUnavailableCriticalExtension)
	}
	if diag != diagCriticalControl.text() {
		t.Fatalf("diagnostic = %q, want %q", diag, diagCriticalControl.text())
	}
	if !c.authenticated {
		t.Fatal("critical-control Search must not clear prior authentication")
	}
}

func TestHandleSearch_UnauthenticatedReturns50(t *testing.T) {
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, nil)
	defer cleanup()
	c.clearAuth()

	op := searchOp(c.cfg.groupBaseText, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	fields := captureLog(t, zerolog.InfoLevel, func() {
		err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
		if err != nil || !wrote {
			t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
		}
		code, _, diag := readSearchResultDone(t, envs[0])
		if code != int(resultInsufficientAccessRights) {
			t.Fatalf("result = %d, want 50", code)
		}
		if diag != diagInsufficientAccess.text() {
			t.Fatalf("diagnostic = %q, want %q", diag, diagInsufficientAccess.text())
		}
	})
	if fields["reason"] != reasonUnauthenticated.text() {
		t.Fatalf("logged reason = %v, want %q", fields["reason"], reasonUnauthenticated.text())
	}
}

func TestHandleSearch_EnumeratedOutOfRangeCloses(t *testing.T) {
	cases := []struct {
		name  string
		scope int64
		deref int64
	}{
		{"scope_5_out_of_range", 5, 0},
		{"deref_7_out_of_range", 2, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, []string{markerLegitimateRole})
			defer cleanup()
			op := searchOp(c.cfg.groupBaseText, tc.scope, tc.deref, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
			err, _, _, wrote := doSearch(t, c, clientConn, 1, op, false)
			if err == nil || wrote {
				t.Fatalf("out-of-range ENUMERATED must close, got err=%v wrote=%v", err, wrote)
			}
		})
	}
}

func TestHandleSearch_MalformedASN1Closes(t *testing.T) {
	base := "ou=groups,dc=profile,dc=test"
	validFilter := validMembershipFilter(testBoundDN)
	cases := []struct {
		name string
		op   []byte
	}{
		{"base_wrong_tag_integer", func() []byte {
			out := tlv(0x02, []byte{0x01}) // INTEGER instead of OCTET STRING
			out = append(out, enumTLV(2)...)
			out = append(out, enumTLV(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, boolTLV(false)...)
			out = append(out, validFilter...)
			out = append(out, attrsTLV("cn")...)
			return out
		}()},
		{"scope_wrong_tag_integer", func() []byte {
			out := tlv(0x04, []byte(base))
			out = append(out, berInteger(2)...) // INTEGER instead of ENUMERATED
			out = append(out, enumTLV(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, boolTLV(false)...)
			out = append(out, validFilter...)
			out = append(out, attrsTLV("cn")...)
			return out
		}()},
		{"sizelimit_negative", func() []byte {
			out := tlv(0x04, []byte(base))
			out = append(out, enumTLV(2)...)
			out = append(out, enumTLV(0)...)
			out = append(out, tlv(0x02, []byte{0xff})...) // -1
			out = append(out, berInteger(0)...)
			out = append(out, boolTLV(false)...)
			out = append(out, validFilter...)
			out = append(out, attrsTLV("cn")...)
			return out
		}()},
		{"timelimit_non_minimal", func() []byte {
			out := tlv(0x04, []byte(base))
			out = append(out, enumTLV(2)...)
			out = append(out, enumTLV(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, tlv(0x02, []byte{0x00, 0x01})...) // non-minimal encoding of 1
			out = append(out, boolTLV(false)...)
			out = append(out, validFilter...)
			out = append(out, attrsTLV("cn")...)
			return out
		}()},
		{"typesonly_non_canonical_boolean", func() []byte {
			out := tlv(0x04, []byte(base))
			out = append(out, enumTLV(2)...)
			out = append(out, enumTLV(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, tlv(0x01, []byte{0x01})...) // 0x01, not 0x00/0xff
			out = append(out, validFilter...)
			out = append(out, attrsTLV("cn")...)
			return out
		}()},
		{"truncated_missing_attributes", func() []byte {
			out := tlv(0x04, []byte(base))
			out = append(out, enumTLV(2)...)
			out = append(out, enumTLV(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, berInteger(0)...)
			out = append(out, boolTLV(false)...)
			out = append(out, validFilter...)
			return out // no attributes field at all
		}()},
		{"trailing_garbage_after_attributes", func() []byte {
			out := searchOp(base, 2, 0, 0, 0, false, validFilter, "cn")
			return append(out, 0x00, 0x00)
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, []string{markerLegitimateRole})
			defer cleanup()
			err, _, _, wrote := doSearch(t, c, clientConn, 1, tc.op, false)
			if err == nil || wrote {
				t.Fatalf("malformed SearchRequest must close, got err=%v wrote=%v", err, wrote)
			}
		})
	}
}

// =========================================================================
// Fixed field-policy table
// =========================================================================

func TestHandleSearch_FieldPolicyTable(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	cases := []struct {
		name       string
		base       string
		scope      int64
		deref      int64
		typesOnly  bool
		attrs      []string
		wantReject bool
		wantReason reason
	}{
		{"wrong_base", "ou=other,dc=profile,dc=test", 2, 0, false, []string{"cn"}, true, reasonWrongBase},
		{"scope_baseObject", groupBase, 0, 0, false, []string{"cn"}, true, reasonWrongScope},
		{"scope_singleLevel", groupBase, 1, 0, false, []string{"cn"}, true, reasonWrongScope},
		{"deref_1", groupBase, 2, 1, false, []string{"cn"}, true, reasonDerefAliasesOutOfProfile},
		{"deref_2", groupBase, 2, 2, false, []string{"cn"}, true, reasonDerefAliasesOutOfProfile},
		{"deref_3", groupBase, 2, 3, false, []string{"cn"}, true, reasonDerefAliasesOutOfProfile},
		{"typesOnly_true", groupBase, 2, 0, true, []string{"cn"}, true, reasonTypesOnlyOutOfProfile},
		{"attrs_empty", groupBase, 2, 0, false, nil, true, reasonAttributeSelectionOutOfProfile},
		{"attrs_star", groupBase, 2, 0, false, []string{"*"}, true, reasonAttributeSelectionOutOfProfile},
		{"attrs_1.1", groupBase, 2, 0, false, []string{"1.1"}, true, reasonAttributeSelectionOutOfProfile},
		{"attrs_member", groupBase, 2, 0, false, []string{"member"}, true, reasonAttributeSelectionOutOfProfile},
		{"attrs_cn_and_member", groupBase, 2, 0, false, []string{"cn", "member"}, true, reasonAttributeSelectionOutOfProfile},
		{"attrs_CN_uppercase_ok", groupBase, 2, 0, false, []string{"CN"}, false, 0},
		{"attrs_cN_mixed_ok", groupBase, 2, 0, false, []string{"cN"}, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, []string{markerLegitimateRole})
			defer cleanup()
			op := searchOp(tc.base, tc.scope, tc.deref, 0, 0, tc.typesOnly, validMembershipFilter(testBoundDN), tc.attrs...)

			if !tc.wantReject {
				err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
				if err != nil || !wrote {
					t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
				}
				done := envs[len(envs)-1]
				code, _, _ := readSearchResultDone(t, done)
				if code != int(resultSuccess) {
					t.Fatalf("result = %d, want success (0)", code)
				}
				return
			}

			fields := captureLog(t, zerolog.InfoLevel, func() {
				err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
				if err != nil || !wrote {
					t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
				}
				code, _, diag := readSearchResultDone(t, envs[0])
				if code != int(resultInsufficientAccessRights) {
					t.Fatalf("result = %d, want 50", code)
				}
				if diag != diagInsufficientAccess.text() {
					t.Fatalf("diagnostic = %q, want %q", diag, diagInsufficientAccess.text())
				}
			})
			if fields["reason"] != tc.wantReason.text() {
				t.Fatalf("logged reason = %v, want %q", fields["reason"], tc.wantReason.text())
			}
		})
	}
}

// =========================================================================
// Fixed filter decoder / mutation table
// =========================================================================

func TestHandleSearch_FilterMutationTable(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	cases := []struct {
		name       string
		filter     []byte
		wantReason reason
	}{
		{"or_instead_of_and", filterOr(filterEquality("objectClass", "groupOfNames"), filterEquality("member", testBoundDN)), reasonUnauthorizedFilterShape},
		{"not", filterNot(filterEquality("objectClass", "groupOfNames")), reasonUnauthorizedFilterShape},
		{"third_predicate", filterAnd(filterEquality("objectClass", "groupOfNames"), filterEquality("member", testBoundDN), filterEquality("cn", "extra")), reasonUnauthorizedFilterShape},
		{"duplicate_objectClass", filterAnd(filterEquality("objectClass", "groupOfNames"), filterEquality("objectClass", "groupOfNames")), reasonUnauthorizedFilterShape},
		{"duplicate_member", filterAnd(filterEquality("member", testBoundDN), filterEquality("member", testBoundDN)), reasonUnauthorizedFilterShape},
		{"missing_member", filterAnd(filterEquality("objectClass", "groupOfNames"), filterEquality("cn", "x")), reasonUnauthorizedFilterShape},
		{"nested_and", filterAnd(filterAnd(filterEquality("objectClass", "groupOfNames")), filterEquality("member", testBoundDN)), reasonUnauthorizedFilterShape},
		{"substrings_child", filterAnd(filterSubstrings("objectClass"), filterEquality("member", testBoundDN)), reasonUnauthorizedFilterShape},
		{"presence_child", filterAnd(filterPresent("objectClass"), filterEquality("member", testBoundDN)), reasonUnauthorizedFilterShape},
		{"objectclass_value_wrong_case_rejected", filterAnd(filterEquality("objectClass", "GroupOfNames"), filterEquality("member", testBoundDN)), reasonUnauthorizedFilterShape},
		{"descriptions_uppercase_accepted", filterAnd(filterEquality("OBJECTCLASS", "groupOfNames"), filterEquality("MEMBER", testBoundDN)), 0},
		{"member_escaped_spelling_accepted", filterAnd(filterEquality("objectClass", "groupOfNames"), filterEquality("member", "UID=alice,OU=users,DC=profile,DC=test")), 0},
		{"member_suffix_only_rejected", filterAnd(filterEquality("objectClass", "groupOfNames"), filterEquality("member", "cn=evil,"+testBoundDN)), reasonMemberDNMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, []string{markerLegitimateRole})
			defer cleanup()
			op := searchOp(groupBase, 2, 0, 0, 0, false, tc.filter, "cn")

			if tc.wantReason == 0 {
				err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
				if err != nil || !wrote {
					t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
				}
				done := envs[len(envs)-1]
				code, _, _ := readSearchResultDone(t, done)
				if code != int(resultSuccess) {
					t.Fatalf("result = %d, want success (0)", code)
				}
				return
			}

			fields := captureLog(t, zerolog.InfoLevel, func() {
				err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
				if err != nil || !wrote {
					t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
				}
				code, _, _ := readSearchResultDone(t, envs[0])
				if code != int(resultInsufficientAccessRights) {
					t.Fatalf("result = %d, want 50", code)
				}
			})
			if fields["reason"] != tc.wantReason.text() {
				t.Fatalf("logged reason = %v, want %q", fields["reason"], tc.wantReason.text())
			}
		})
	}
}

func TestDecodeMembershipFilter_NonRecursive(t *testing.T) {
	// A structural, not merely textual, guard: decodeEquality must never
	// itself decode another Filter CHOICE, so nesting an "and" inside
	// what decodeMembershipFilter treats as an equalityMatch child must
	// be rejected as an ordinary shape mismatch, not silently unwrapped.
	nested := filterAnd(filterAnd(filterEquality("objectClass", "groupOfNames")), filterEquality("member", testBoundDN))
	if got := decodeMembershipFilter(0xa0, cryptobyte.String(nested[2:]), DN{}); got != filterShapeInvalid {
		t.Fatalf("nested AND child: got %v, want filterShapeInvalid", got)
	}
}

// TestDecodeMembershipFilter_UnicodeFoldDescriptorRejected proves the
// objectClass/member descriptor match uses ASCII-only case folding, not
// strings.EqualFold's full Unicode folding. "objectClaſs" (U+017F LATIN
// SMALL LETTER LONG S in place of the final 's') is
// strings.EqualFold-equivalent to "objectClass" — Go's Unicode
// case-folding tables fold U+017F to 's' — but attribute-type descriptors
// are ASCII by grammar (see ValidAttributeDescriptor/asciiEqualFold), so
// this out-of-profile descriptor must be rejected as filterShapeInvalid,
// never silently accepted as the fixed objectClass predicate.
func TestDecodeMembershipFilter_UnicodeFoldDescriptorRejected(t *testing.T) {
	filter := filterAnd(filterEquality("objectClaſs", "groupOfNames"), filterEquality("member", testBoundDN))
	if got := decodeMembershipFilter(0xa0, cryptobyte.String(filter[2:]), DN{}); got != filterShapeInvalid {
		t.Fatalf("Unicode-fold-equivalent objectClass descriptor: got %v, want filterShapeInvalid", got)
	}
}

// =========================================================================
// sizeLimit / timeLimit execution
// =========================================================================

func rolesNamed(n int, prefix string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

func TestHandleSearch_SizeLimitBoundaries(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	cases := []struct {
		name        string
		sizeLimit   int64
		roleCount   int
		wantEntries int
		wantResult  int32
	}{
		{"sizeLimit_0_unlimited_256_roles", 0, 256, 256, resultSuccess},
		{"sizeLimit_1_of_256", 1, 256, 1, resultSizeLimitExceeded},
		{"sizeLimit_255_of_256", 255, 256, 255, resultSizeLimitExceeded},
		{"sizeLimit_256_of_256_exact_no_overflow", 256, 256, 256, resultSuccess},
		{"sizeLimit_257_of_256_more_room_than_roles", 257, 256, 256, resultSuccess},
		{"sizeLimit_256_of_257_N_plus_1", 256, 257, 256, resultSizeLimitExceeded},
		{"generic_N_of_N_plus_1", 5, 6, 5, resultSizeLimitExceeded},
		{"generic_N_of_N", 5, 5, 5, resultSuccess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roles := rolesNamed(tc.roleCount, "role")
			c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, roles)
			defer cleanup()
			op := searchOp(groupBase, 2, 0, tc.sizeLimit, 0, false, validMembershipFilter(testBoundDN), "cn")
			err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
			if err != nil || !wrote {
				t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
			}
			entries := envs[:len(envs)-1]
			if len(entries) != tc.wantEntries {
				t.Fatalf("emitted %d entries, want %d", len(entries), tc.wantEntries)
			}
			code, _, _ := readSearchResultDone(t, envs[len(envs)-1])
			if code != int(tc.wantResult) {
				t.Fatalf("result = %d, want %d", code, tc.wantResult)
			}
		})
	}
}

func TestHandleSearch_EmptyRoleSkippedWithoutConsumingLimit(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := []string{"", "role0", "", "role1", ""}
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, roles)
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 2, 0, false, validMembershipFilter(testBoundDN), "cn")
	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	entries := envs[:len(envs)-1]
	if len(entries) != 2 {
		t.Fatalf("emitted %d entries, want 2 (both non-empty roles, sizeLimit=2 never breached)", len(entries))
	}
	code, _, _ := readSearchResultDone(t, envs[len(envs)-1])
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success — empty roles must never consume sizeLimit budget", code)
	}
}

func TestHandleSearch_ZeroRolesSuccessWithZeroRolesMessage(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, nil)
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")

	var envs []Envelope
	fields := captureLog(t, zerolog.InfoLevel, func() {
		var err error
		var wrote bool
		err, envs, _, wrote = doSearch(t, c, clientConn, 1, op, false)
		if err != nil || !wrote {
			t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
		}
	})
	if len(envs) != 1 {
		t.Fatalf("got %d frames, want exactly 1 (Done only, zero entries)", len(envs))
	}
	code, _, _ := readSearchResultDone(t, envs[0])
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success (0) — zero roles must never become an authorization failure", code)
	}
	if fields["message"] != "ldap search succeeded (zero roles)" {
		t.Fatalf("message = %v, want %q", fields["message"], "ldap search succeeded (zero roles)")
	}
	if fields["entries"] != float64(0) {
		t.Fatalf("entries = %v, want 0", fields["entries"])
	}
}

// =========================================================================
// Fake-clock timeLimit
// =========================================================================

func TestHandleSearch_TimeLimitZeroNeverExpires(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(5, "role")
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, roles) // real clock, timeLimit=0
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	if len(envs)-1 != 5 {
		t.Fatalf("emitted %d entries, want 5", len(envs)-1)
	}
	code, _, _ := readSearchResultDone(t, envs[len(envs)-1])
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want success", code)
	}
}

func TestHandleSearch_TimeLimitExpiredBeforeFirstEntry(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(5, "role")
	now := time.Now()
	// Call 1 (searchStart) sees `now`; every later call (the first
	// entry's expiry check, and the terminal Done's deadline calc) sees
	// now+2s — already past now+1s (timeLimit=1), so the deadline is
	// discovered expired before any entry is rendered.
	clk := &sequenceClock{times: []time.Time{now, now.Add(2 * time.Second)}}
	c, clientConn, cleanup := newSearchTestConnectionWithClock(t, testBoundDN, roles, clk.Now)
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 1, false, validMembershipFilter(testBoundDN), "cn")

	fields := captureLog(t, zerolog.InfoLevel, func() {
		err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
		if err != nil || !wrote {
			t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
		}
		if len(envs) != 1 {
			t.Fatalf("got %d frames, want exactly 1 (Done only, zero entries emitted)", len(envs))
		}
		code, _, _ := readSearchResultDone(t, envs[0])
		if code != int(resultTimeLimitExceeded) {
			t.Fatalf("result = %d, want timeLimitExceeded (3)", code)
		}
	})
	if fields["message"] != "ldap search time limit exceeded" {
		t.Fatalf("message = %v", fields["message"])
	}
	if fields["entries"] != float64(0) {
		t.Fatalf("entries = %v, want 0", fields["entries"])
	}
}

func TestHandleSearch_TimeLimitExpiredMidLoopEmitsExactlyKThenResult3(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(5, "role") // >= k+1 = 4 so the break happens mid-loop
	now := time.Now()
	// Exact call sequence for k=3 successfully emitted entries (see
	// search.go's executeSearch): searchStart; then, per entry,
	// [expired()-check, write-deadline calc] not-expired for entries
	// 1..3; then the 4th entry's expired()-check reports expired; then
	// the terminal Done's own deadline calc. All values are small real
	// offsets from an actual time.Now() so every real net.Conn deadline
	// this produces stays a genuine near-future wall-clock instant.
	clk := &sequenceClock{times: []time.Time{
		now,                                                // searchStart (timeLimit=5s -> deadline = now+5s)
		now.Add(1 * time.Second), now.Add(1 * time.Second), // entry 1: not expired, write deadline
		now.Add(2 * time.Second), now.Add(2 * time.Second), // entry 2
		now.Add(3 * time.Second), now.Add(3 * time.Second), // entry 3
		now.Add(10 * time.Second), // entry 4's expired()-check: now+10s >= now+5s -> expired
		now.Add(10 * time.Second), // terminal Done write-deadline calc
	}}
	c, clientConn, cleanup := newSearchTestConnectionWithClock(t, testBoundDN, roles, clk.Now)
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 5, false, validMembershipFilter(testBoundDN), "cn")

	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	if len(envs)-1 != 3 {
		t.Fatalf("emitted %d entries, want exactly 3", len(envs)-1)
	}
	code, _, _ := readSearchResultDone(t, envs[len(envs)-1])
	if code != int(resultTimeLimitExceeded) {
		t.Fatalf("result = %d, want timeLimitExceeded (3)", code)
	}
}

func TestHandleSearch_TerminalResult3DeadlineIsFreshNotExpiredSearchDeadline(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(5, "role")
	now := time.Now()
	writeTimeout := 2 * time.Second
	clk := &sequenceClock{times: []time.Time{now, now.Add(2 * time.Second)}}

	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	boundDN, err := ParseDN(testBoundDN)
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	recorder := &deadlineRecordingConn{Conn: serverConn}
	c := &connection{
		nc: recorder, ctx: context.Background(), cfg: &parsed,
		verifier: newFakeVerifier(), roles: newFakeResolver(),
		clock: clk.Now, writeTimeout: writeTimeout,
	}
	c.replaceAuth(authState{Username: "alice", BoundDN: testBoundDN, boundDN: boundDN, Roles: roles})
	defer func() { _ = clientConn.Close(); _ = serverConn.Close() }()

	op := searchOp(groupBase, 2, 0, 0, 1, false, validMembershipFilter(testBoundDN), "cn")
	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	code, _, _ := readSearchResultDone(t, envs[len(envs)-1])
	if code != int(resultTimeLimitExceeded) {
		t.Fatalf("result = %d, want timeLimitExceeded", code)
	}

	// The expired search deadline was now+1s (already passed by the
	// clock's second value, now+2s). The terminal Done write must use a
	// fresh now+writeTimeout deadline instead: the last recorded
	// SetWriteDeadline call is at least writeTimeout beyond the clock
	// value used to detect expiry, never merely at/near the expired
	// search deadline.
	last := recorder.lastDeadline()
	expiredSearchDeadline := now.Add(1 * time.Second)
	if !last.After(expiredSearchDeadline.Add(500 * time.Millisecond)) {
		t.Fatalf("terminal Done deadline %v must not inherit the already-expired search deadline %v", last, expiredSearchDeadline)
	}
}

// =========================================================================
// Write-stall vs Search-deadline classification
// =========================================================================

// TestHandleSearch_WriteStallWithTimeLimitZeroClosesNotResult3 proves a
// plain zero-byte write timeout under the ordinary (non-Search) write
// deadline is classified as a transport write stall — the connection is
// closed — not misreported as timeLimitExceeded. timeLimit=0 means no
// Search deadline is ever operative, so the ordinary writeTimeout is the
// sole binding deadline on the stalled entry write: the client here never
// reads at all, so the first entry's Write blocks until that ordinary
// deadline fires with zero bytes on the wire.
func TestHandleSearch_WriteStallWithTimeLimitZeroClosesNotResult3(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(2, "role")

	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	boundDN, err := ParseDN(testBoundDN)
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	c := &connection{
		nc: serverConn, ctx: context.Background(), cfg: &parsed,
		verifier: newFakeVerifier(), roles: newFakeResolver(),
		clock: time.Now, writeTimeout: 200 * time.Millisecond,
	}
	c.replaceAuth(authState{Username: "alice", BoundDN: testBoundDN, boundDN: boundDN, Roles: roles})
	defer func() { _ = clientConn.Close() }()

	// timeLimit=0.
	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")

	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf).Level(zerolog.InfoLevel)
	var searchErr error
	done := make(chan struct{})
	go func() {
		searchErr = c.handleSearch(1, cryptobyte.String(op), false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for handleSearch to return")
	}
	log.Logger = orig

	if searchErr == nil {
		t.Fatal("a write stall with no operative Search deadline must close the connection (non-nil error), got nil")
	}
	if logged := strings.TrimSpace(buf.String()); logged != "" {
		t.Fatalf("write stall must not log anything (in particular no time-limit-exceeded terminal), got: %s", logged)
	}
}

// TestHandleSearch_WriteStallWithOperativeSearchDeadlineReturnsResult3
// proves the complementary case: when the Search deadline genuinely is the
// binding one (timeLimit small, ordinary writeTimeout larger), a zero-byte
// write timeout on the first entry still reports timeLimitExceeded (result
// 3) rather than closing — the entry write blocks with no reader present
// until the (shorter) Search deadline fires, then the terminal
// SearchResultDone is written under a fresh ordinary deadline once a
// reader appears.
func TestHandleSearch_WriteStallWithOperativeSearchDeadlineReturnsResult3(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(2, "role")

	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	boundDN, err := ParseDN(testBoundDN)
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	c := &connection{
		nc: serverConn, ctx: context.Background(), cfg: &parsed,
		verifier: newFakeVerifier(), roles: newFakeResolver(),
		clock: time.Now, writeTimeout: 3 * time.Second,
	}
	c.replaceAuth(authState{Username: "alice", BoundDN: testBoundDN, boundDN: boundDN, Roles: roles})

	// timeLimit=1s (searchDeadline), well inside the 3s ordinary
	// writeTimeout, so the Search deadline is the binding one.
	op := searchOp(groupBase, 2, 0, 0, 1, false, validMembershipFilter(testBoundDN), "cn")

	type readResult struct {
		env Envelope
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
		// Deliberately does not read at all until well after the 1s
		// Search deadline has fired, so the first entry's write
		// genuinely stalls (zero bytes on the wire) until that
		// deadline, rather than succeeding immediately against an
		// eager reader.
		time.Sleep(1300 * time.Millisecond)
		body, err := readFrame(clientConn)
		if err != nil {
			readCh <- readResult{err: err}
			return
		}
		env, decErr := decodeEnvelope(body)
		readCh <- readResult{env: env, err: decErr}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.handleSearch(1, cryptobyte.String(op), false)
	}()

	var searchErr error
	select {
	case searchErr = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleSearch to return")
	}
	if searchErr != nil {
		t.Fatalf("handleSearch: unexpected error: %v", searchErr)
	}

	var res readResult
	select {
	case res = <-readCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the terminal SearchResultDone")
	}
	if res.err != nil {
		t.Fatalf("reading terminal SearchResultDone: %v", res.err)
	}
	code, _, _ := readSearchResultDone(t, res.env)
	if code != int(resultTimeLimitExceeded) {
		t.Fatalf("result = %d, want timeLimitExceeded (3)", code)
	}
}

// =========================================================================
// Partial write / oversized entry
// =========================================================================

// closeAfterNWritesConn closes the underlying pipe after n Write calls
// have partially succeeded, simulating a peer that vanishes mid-PDU.
type closeAfterNWritesConn struct {
	net.Conn
	remaining int
}

func (cw *closeAfterNWritesConn) Write(b []byte) (int, error) {
	if cw.remaining <= 0 {
		_ = cw.Conn.Close()
		return 0, fmt.Errorf("closeAfterNWritesConn: connection closed")
	}
	cw.remaining--
	n, err := cw.Conn.Write(b)
	if cw.remaining == 0 {
		_ = cw.Conn.Close()
	}
	return n, err
}

func TestHandleSearch_PartialWriteClosesWithNoFurtherBytes(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(5, "role")

	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	boundDN, err := ParseDN(testBoundDN)
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	wrapped := &closeAfterNWritesConn{Conn: serverConn, remaining: 1}
	c := &connection{
		nc: wrapped, ctx: context.Background(), cfg: &parsed,
		verifier: newFakeVerifier(), roles: newFakeResolver(),
		clock: time.Now, writeTimeout: 2 * time.Second,
	}
	c.replaceAuth(authState{Username: "alice", BoundDN: testBoundDN, boundDN: boundDN, Roles: roles})
	defer func() { _ = clientConn.Close() }()

	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err == nil {
		t.Fatal("write failure after the first entry must close the connection (non-nil error), got nil")
	}
	if wrote {
		t.Fatal("no further response frames may follow a partial/failed write")
	}
	_ = envs
}

func TestHandleSearch_OversizedRoleReturns11EntriesPreservedNoMarkerLeak(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := []string{markerLegitimateRole, markerOversizedRole}
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, roles)
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")

	var envs []Envelope
	var bodies [][]byte
	fields := captureLog(t, zerolog.InfoLevel, func() {
		var err error
		var wrote bool
		err, envs, bodies, wrote = doSearch(t, c, clientConn, 1, op, false)
		if err != nil || !wrote {
			t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
		}
	})

	if len(envs) != 2 {
		t.Fatalf("got %d frames, want exactly 2 (one entry for the legitimate role, then Done(11))", len(envs))
	}
	entry := readSearchResultEntry(t, envs[0])
	wantCN := c.cfg.rolePrefix + markerLegitimateRole
	if len(entry.attrValues) != 1 || len(entry.attrValues[0]) != 1 || entry.attrValues[0][0] != wantCN {
		t.Fatalf("unexpected legitimate entry: %+v", entry)
	}
	code, _, diag := readSearchResultDone(t, envs[1])
	if code != int(resultAdminLimitExceeded) {
		t.Fatalf("result = %d, want adminLimitExceeded (11)", code)
	}
	if diag != diagEmpty.text() {
		t.Fatalf("diagnostic = %q, want empty", diag)
	}
	if fields["entries"] != float64(1) {
		t.Fatalf("logged entries = %v, want 1 (already-emitted count preserved)", fields["entries"])
	}
	if fields["message"] != "ldap search administrative limit exceeded" {
		t.Fatalf("message = %v", fields["message"])
	}

	var allBytes []byte
	for _, b := range bodies {
		allBytes = append(allBytes, b...)
	}
	assertNoMarkerLeak(t, fields, allBytes, markerOversizedRole)
}

// =========================================================================
// Response shape / telemetry / no Verify-Roles calls
// =========================================================================

func TestHandleSearch_EntryIsCNOnlyNeverObjectClassOrMember(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, []string{markerLegitimateRole})
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	err, envs, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	entry := readSearchResultEntry(t, envs[0])
	if len(entry.attrTypes) != 1 || entry.attrTypes[0] != "cn" {
		t.Fatalf("attribute types = %v, want exactly [\"cn\"]", entry.attrTypes)
	}
	if len(entry.attrValues[0]) != 1 || entry.attrValues[0][0] != "clickhouse_"+markerLegitimateRole {
		t.Fatalf("cn values = %v, want exactly one RoleCNPrefix+role value", entry.attrValues[0])
	}
	wantObjectName := "cn=clickhouse_" + markerLegitimateRole + "," + groupBase
	if entry.objectName != wantObjectName {
		t.Fatalf("objectName = %q, want %q", entry.objectName, wantObjectName)
	}
}

func TestHandleSearch_ExactTelemetrySuccess(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	roles := rolesNamed(3, "role")
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, roles)
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 10, 20, false, validMembershipFilter(testBoundDN), "cn")

	fields := captureLog(t, zerolog.InfoLevel, func() {
		err, _, _, wrote := doSearch(t, c, clientConn, 1, op, false)
		if err != nil || !wrote {
			t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
		}
	})

	want := map[string]any{
		"op": "search", "success": true, "result": float64(0), "username": "alice",
		"size_limit": float64(10), "time_limit": float64(20), "types_only": false,
		"entries": float64(3), "message": "ldap search succeeded",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Fatalf("field %q = %v, want %v (all fields: %v)", k, fields[k], v, fields)
		}
	}
}

func TestHandleSearch_NoVerifyOrRolesCalls(t *testing.T) {
	groupBase := "ou=groups,dc=profile,dc=test"
	c, clientConn, cleanup := newSearchTestConnection(t, testBoundDN, rolesNamed(3, "role"))
	defer cleanup()
	op := searchOp(groupBase, 2, 0, 0, 0, false, validMembershipFilter(testBoundDN), "cn")
	err, _, _, wrote := doSearch(t, c, clientConn, 1, op, false)
	if err != nil || !wrote {
		t.Fatalf("doSearch: err=%v wrote=%v", err, wrote)
	}
	if got := c.verifier.(*fakeVerifier).callCount(); got != 0 {
		t.Fatalf("Verify called %d times from Search, want 0", got)
	}
	if got := c.roles.(*fakeResolver).callCount(); got != 0 {
		t.Fatalf("Roles called %d times from Search, want 0", got)
	}
}
