package profile

// This file is sub-task p2-11's TCP-level port of the plan's "Restricted
// DN grammar" hostile-input coverage (disposition table's hostile_dn_test.go
// row) and the structural member-DN comparison it names: raw-BER Bind
// requests whose DN bytes are invalid UTF-8, carry an embedded NUL, use
// malformed/odd hex escapes or a trailing backslash, use dotted-decimal
// (OID) attribute types, an unescaped '+' (multi-valued RDN), a ';'
// separator, or a leading '#' (BER-hexstring) value, plus a large
// (60 KiB-class) but otherwise syntactically valid DN just under the 64 KiB
// frame cap — all reusing server_test.go's harness (newRunningServer/dial/
// sendAndReadEnvelope/readLDAPResultFields/bindRequestBytes),
// search_limits_test.go's newBoundSearchServer, and fakes_test.go's
// fakeVerifier/fakeResolver/newVerificationResult.
//
// Every case in the first table is well-formed ASN.1 at the wire level: a
// BindRequest name field is an OCTET STRING, and OCTET STRING never
// constrains its content to valid UTF-8, printable ASCII, or any DN
// grammar at all — cryptobyte's decoder happily reads any declared-length
// byte run. So none of these hostile DNs is "malformed ASN.1" in the
// sense frame.go/bind.go's own errMalformed (connection-closing) checks
// cover; every one reaches ParseBindDN (dn.go) as a fully decoded Go
// string, and is rejected there, at the DN-grammar-semantic layer, into
// the ordinary invalidCredentials (49) Bind failure — never a close. (A
// bad-tag/non-minimal-INTEGER/truncated-envelope kind of "ASN.1
// malformation" is a materially different failure class, already covered
// exhaustively by frame_test.go/adversarial_test.go; this file does not
// manufacture an artificial one just to exercise the "or close" clause in
// this sub-task's own description, since no real hostile-DN-shaped input
// actually produces that outcome in this package's implementation.)
//
// Legacy-only characterization NOT ported here (disposition table): old
// go-ldap/v3-specific DN sanitization quirks (e.g. silent U+FFFD
// substitution for invalid UTF-8 confined to an RDN value) — this
// package's own restricted grammar (dn.go) rejects invalid UTF-8
// unconditionally, in either the type or the value position, so there is
// no "sanitized, not rejected" case to characterize here.

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// ---- table 1: hostile Bind DNs, all well-formed ASN.1, all rejected at
// the DN-grammar layer into a fixed invalidCredentials (49) Bind failure,
// plus one large-but-valid DN just under the frame cap ------------------

func TestHostileDN_TableRejectedAsInvalidCredentials(t *testing.T) {
	cases := []struct {
		name string
		dn   string
	}{
		{
			name: "invalid_utf8_in_attribute_type",
			// 0xff is never a valid descriptor character (isDescriptorChar
			// only accepts ASCII letters/digits/hyphen) — rejected before
			// even one character of the type is consumed.
			dn: "u\xffid=alice,ou=users,dc=profile,dc=test",
		},
		{
			name: "invalid_utf8_in_attribute_value",
			// Raw 0xff 0xfe copies through decodeValue unchanged, then
			// fails ParseDN's utf8.Valid(value) check.
			dn: "uid=\xff\xfeghost,ou=users,dc=profile,dc=test",
		},
		{
			name: "embedded_nul_in_value",
			dn:   "uid=alice\x00trailing,ou=users,dc=profile,dc=test",
		},
		{
			name: "malformed_hex_escape_non_hex_digits",
			// '\' followed by neither a special-escape character nor two
			// hex digits ('z' is not a hex digit).
			dn: `uid=ali\zzce,ou=users,dc=profile,dc=test`,
		},
		{
			name: "odd_hex_escape_truncated_at_end_of_value",
			// A single trailing hex digit with no second digit to pair
			// with before the RDN separator.
			dn: `uid=alice\6,ou=users,dc=profile,dc=test`,
		},
		{
			name: "trailing_backslash_at_end_of_dn",
			// The backslash is the very last byte of the entire candidate
			// (no base suffix follows) — decodeValue's own
			// "trailing '\' with no following escape" case.
			dn: `uid=alice\`,
		},
		{
			name: "oid_dotted_decimal_attribute_type",
			// A leading digit never matches the descriptor grammar
			// (isDescriptorChar requires a letter first).
			dn: "2.5.4.3=alice,ou=users,dc=profile,dc=test",
		},
		{
			name: "unescaped_plus_multivalued_rdn",
			dn:   "uid=alice+description=hostile,ou=users,dc=profile,dc=test",
		},
		{
			name: "semicolon_rdn_separator",
			dn:   "uid=alice;ou=users,dc=profile,dc=test",
		},
		{
			name: "leading_hash_ber_hexstring_value",
			dn:   "uid=#414243,ou=users,dc=profile,dc=test",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			healthAcct := newVerificationResult("alice", "https://idp.example/", "sub-hostile-dn-health", time.Now().Add(time.Hour).Unix())
			fv := newFakeVerifier().withSuccess("s3cr3t-health", healthAcct)
			fr := newFakeResolver().withRoles("sub-hostile-dn-health", []string{"ch_engineer"})
			h := newRunningServer(t, fv, fr, nil)
			defer h.stopAndWait(t, 5*time.Second)

			conn := dial(t, h.addr)
			defer conn.Close()

			appLines := captureAllLog(t, zerolog.TraceLevel, func() {
				env := sendAndReadEnvelope(t, conn, bindRequestBytes(1, tc.dn, "whatever-password", false))
				result, matchedDN, diag := readLDAPResultFields(t, env.Content)
				if result != int(resultInvalidCredentials) {
					t.Fatalf("Bind result = %d, want %d (invalidCredentials)", result, resultInvalidCredentials)
				}
				if matchedDN != "" {
					t.Fatalf("matchedDN = %q, want empty", matchedDN)
				}
				if diag != diagInvalidCredentials.text() {
					t.Fatalf("diagnostic = %q, want %q", diag, diagInvalidCredentials.text())
				}
			})

			if fv.callCount() != 0 {
				t.Fatalf("verifier calls = %d, want 0 — a hostile DN must be rejected before Verify is ever called", fv.callCount())
			}

			for _, line := range appLines {
				for _, v := range line {
					if s, ok := v.(string); ok && strings.Contains(s, tc.dn) {
						t.Fatalf("hostile DN bytes leaked into a captured log line: %+v", line)
					}
				}
			}

			// The server must stay fully healthy: a fresh connection on
			// the same listener can still Bind with a real registered
			// credential and Search successfully afterward.
			fresh := dial(t, h.addr)
			defer fresh.Close()
			env := sendAndReadEnvelope(t, fresh, bindRequestBytes(99, testAliceDN, "s3cr3t-health", false))
			result, _, _ := readLDAPResultFields(t, env.Content)
			if result != int(resultSuccess) {
				t.Fatalf("post-hostile-DN fresh connection Bind result = %d, want success", result)
			}
			entries, done := sendSearchWithMember(t, fresh, 100, newTestConfig().GroupBaseDN, testAliceDN)
			doneCode, _, _ := readLDAPResultFields(t, done.Content)
			if doneCode != int(resultSuccess) || len(entries) != 1 {
				t.Fatalf("post-hostile-DN fresh connection Search: result=%d entries=%d, want success with 1 entry", doneCode, len(entries))
			}
		})
	}
}

// TestHostileDN_LargeValidDNJustUnderFrameCap drives a leading RDN value
// large enough (60 KiB-class) to approach, but a syntactically valid DN
// under, frame.go's 64 KiB (maxBodyBytes) LDAPMessage body cap — proving a
// large legitimate-shaped DN Binds normally rather than being rejected by
// some undocumented smaller size policy. declaredEnvelopeBodyLength
// below independently decodes the actual outer SEQUENCE length octets (as
// frame.go's readFrame does) to self-check the fixture really is under
// the cap, rather than trusting the arithmetic blindly.
func TestHostileDN_LargeValidDNJustUnderFrameCap(t *testing.T) {
	const largeValueLen = 60 * 1024 // 60 KiB, comfortably under the 64 KiB cap once wrapped
	largeUsername := strings.Repeat("a", largeValueLen)
	largeDN := "uid=" + largeUsername + ",ou=users,dc=profile,dc=test"

	acct := newVerificationResult("alice", "https://idp.example/", "sub-large-dn-alice", time.Now().Add(time.Hour).Unix())
	v := newFakeVerifier().withSuccess("s3cr3t", acct)
	r := newFakeResolver().withRoles("sub-large-dn-alice", []string{"ch_engineer"})
	h := newRunningServer(t, v, r, nil)
	defer h.stopAndWait(t, 5*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	msg := bindRequestBytes(1, largeDN, "s3cr3t", false)
	if bodyLen := declaredEnvelopeBodyLength(t, msg); bodyLen >= maxBodyBytes {
		t.Fatalf("test fixture bug: declared body length %d is not under the %d-byte cap — shrink largeValueLen", bodyLen, maxBodyBytes)
	}

	env := sendAndReadEnvelope(t, conn, msg)
	result, _, _ := readLDAPResultFields(t, env.Content)
	if result != int(resultSuccess) {
		t.Fatalf("Bind result = %d, want success — a syntactically valid, if large, DN must Bind normally", result)
	}
}

// declaredEnvelopeBodyLength decodes just the outer SEQUENCE tag+length
// header of a raw LDAPMessage encoding (as produced by bindRequestBytes)
// and returns the declared body length — the same quantity frame.go's
// readFrame compares against maxBodyBytes.
func declaredEnvelopeBodyLength(t *testing.T, raw []byte) int {
	t.Helper()
	if len(raw) < 2 {
		t.Fatalf("fixture too short to carry a SEQUENCE tag+length header: %d bytes", len(raw))
	}
	if raw[1]&0x80 == 0 {
		return int(raw[1])
	}
	numOctets := int(raw[1] & 0x7f)
	if len(raw) < 2+numOctets {
		t.Fatalf("fixture too short for its own declared long-form length octets")
	}
	length := 0
	for i := 0; i < numOctets; i++ {
		length = length<<8 | int(raw[2+i])
	}
	return length
}

// ---------------------------------------------------------------------
// Structural member-DN comparison (search authorization)
// ---------------------------------------------------------------------

// TestHostileDN_StructuralMemberComparison proves the fixed membership
// filter's member assertion is compared structurally (DN.Equal), never by
// rendered text or suffix: an escaped-but-equivalent spelling and a
// case-different attribute-type spelling of alice's own bound DN must
// both still authorize her Search, while a suffix-only match (missing her
// own leading RDN) and a same-shape RDN naming a different attribute type,
// and another user's real DN, must all three be rejected with result 50.
func TestHostileDN_StructuralMemberComparison(t *testing.T) {
	roles := []string{"ch_engineer"}
	h, conn := newBoundSearchServer(t, roles, nil)
	defer h.stopAndWait(t, 5*time.Second)
	defer conn.Close()

	groupBase := newTestConfig().GroupBaseDN

	cases := []struct {
		name       string
		memberDN   string
		wantResult int32
	}{
		{
			name:       "escaped_but_equivalent_spelling_of_own_dn_accepted",
			memberDN:   `uid=ali\63e,ou=users,dc=profile,dc=test`, // \63 = 'c'; decodes to "alice"
			wantResult: resultSuccess,
		},
		{
			name:       "case_variant_attribute_type_of_own_dn_accepted",
			memberDN:   "UID=alice,ou=users,dc=profile,dc=test",
			wantResult: resultSuccess,
		},
		{
			name:       "suffix_only_missing_own_leading_rdn_rejected",
			memberDN:   "ou=users,dc=profile,dc=test", // exactly the base, no identity RDN at all
			wantResult: resultInsufficientAccessRights,
		},
		{
			name:       "same_shape_different_attribute_type_rejected",
			memberDN:   "cn=alice,ou=users,dc=profile,dc=test", // "cn" instead of "uid"
			wantResult: resultInsufficientAccessRights,
		},
		{
			name:       "other_users_real_dn_rejected",
			memberDN:   testBobDN,
			wantResult: resultInsufficientAccessRights,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, done := sendSearchWithMember(t, conn, int64(10+i), groupBase, tc.memberDN)
			code, matchedDN, diag := readLDAPResultFields(t, done.Content)
			if code != int(tc.wantResult) {
				t.Fatalf("result = %d, want %d", code, tc.wantResult)
			}
			if matchedDN != "" {
				t.Fatalf("matchedDN = %q, want empty", matchedDN)
			}
			if tc.wantResult == resultSuccess {
				if diag != "" {
					t.Fatalf("diagnostic = %q, want empty", diag)
				}
				if len(entries) != 1 {
					t.Fatalf("entries = %d, want 1 (structural match must authorize the real Search)", len(entries))
				}
			} else {
				if diag != diagInsufficientAccess.text() {
					t.Fatalf("diagnostic = %q, want %q", diag, diagInsufficientAccess.text())
				}
				if len(entries) != 0 {
					t.Fatalf("entries = %d, want 0 (rejected authorization must never emit entries)", len(entries))
				}
			}
		})
	}
}

// sendSearchWithMember is sendSearch's (search_limits_test.go) sibling for
// tests that need to control the membership filter's base/member value
// directly rather than always naming this connection's own bound DN.
func sendSearchWithMember(t *testing.T, conn net.Conn, msgID int64, base, memberDN string) (entries []Envelope, done Envelope) {
	t.Helper()
	req := rawSearchRequestBytes(msgID, base, scopeWholeSubtree, derefNever, 0, 0, false, validMembershipFilter(memberDN), false, "cn")
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write search request: %v", err)
	}
	return collectSearchResult(t, conn)
}
