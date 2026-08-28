package ldap

import (
	"bytes"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers plan-19p5 §11/§6's remaining "hostile Bind-DN encodings"
// gap: raw-BER Bind requests whose DN bytes are not valid UTF-8, carry an
// embedded NUL, or are syntactically valid but very large. It reuses
// protocol_test.go's account/newFakeVerifier/newFakeRoles/startTestServer/
// dialTest/bindAs/requireSuccess fixtures and adversarial_test.go's
// rawSimpleBindMessage raw-BER Bind-request encoder; no existing file is
// modified.
//
// Every hostile Bind DN below is well-formed BER at the wire level: the
// goldap message decoder's OCTET STRING/LDAPString reader (see
// third_party/goldap/message/string.go's readLDAPString, which delegates to
// readTaggedOCTETSTRING) never validates UTF-8 — it just copies raw bytes
// into a Go string, and Go strings tolerate arbitrary byte sequences,
// including invalid UTF-8 and embedded NULs. So every case here reaches
// dn.go's UserBaseDN.ExtractUsername (via go-ldap/v3's RFC 4514 ParseDN) as
// a fully decoded LDAPMessage; the question this file answers is purely
// "what does that RFC 4514 parsing layer do with the resulting Go string,
// and is the outcome safe."

// readRawEnvelope reads and BER-decodes one complete raw LDAPMessage
// response from conn, failing the test if none arrives within timeout.
// Shared by this file, midsearch_test.go, and conncap_test.go.
func readRawEnvelope(t *testing.T, conn net.Conn, timeout time.Duration) *ber.Packet {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	pkt, err := ber.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read raw LDAP response: %v", err)
	}
	return pkt
}

// bindResponseFields decodes pkt as a BindResponse LDAPMessage, asserting
// its messageID matches wantMessageID, and returns the LDAPResult triple
// every Bind response carries (RFC 4511 §4.1.9: resultCode, matchedDN,
// diagnosticMessage). Shared by this file and conncap_test.go.
func bindResponseFields(t *testing.T, pkt *ber.Packet, wantMessageID int) (code int64, matchedDN, diagnostic string) {
	t.Helper()
	if len(pkt.Children) < 2 {
		t.Fatalf("malformed response envelope: %+v", pkt)
	}
	gotID, _ := pkt.Children[0].Value.(int64)
	if gotID != int64(wantMessageID) {
		t.Fatalf("response messageID = %d, want %d", gotID, wantMessageID)
	}
	op := pkt.Children[1]
	if op.Tag != ldapserver.ApplicationBindResponse {
		t.Fatalf("response op tag = %d, want %d (BindResponse)", op.Tag, ldapserver.ApplicationBindResponse)
	}
	if len(op.Children) < 3 {
		t.Fatalf("bind response: too few LDAPResult fields: %+v", op)
	}
	code, _ = op.Children[0].Value.(int64)
	matchedDN, _ = op.Children[1].Value.(string)
	diagnostic, _ = op.Children[2].Value.(string)
	return
}

// envelopeBodyLength decodes just the outer SEQUENCE tag+length header of a
// raw LDAPMessage encoding (as produced by rawSimpleBindMessage et al.) and
// returns the declared body length — the same quantity
// third_party/ldapserver/packet.go's readTagAndLength compares against
// maxMessageBodyLength (64 KiB). Used to self-check the large-RDN fixture
// below actually stays under that cap, rather than trusting arithmetic.
func envelopeBodyLength(raw []byte) int {
	if raw[1]&0x80 == 0 {
		return int(raw[1])
	}
	numBytes := int(raw[1] & 0x7f)
	length := 0
	for i := 0; i < numBytes; i++ {
		length <<= 8
		length |= int(raw[2+i])
	}
	return length
}

// swapAppLog redirects the package-level zerolog logger to a buffer for the
// duration of the calling test, restored via t.Cleanup. Mirrors the
// existing in-file capture pattern in adversarial_test.go's
// TestAdversarial_SentinelAbsentFromEveryCapturedOutputChannel.
func swapAppLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

// requireNoLeak fails the test if any of markers appears in appLog.
func requireNoLeak(t *testing.T, appLog *bytes.Buffer, markers ...string) {
	t.Helper()
	got := appLog.String()
	for _, m := range markers {
		if m == "" {
			continue
		}
		if strings.Contains(got, m) {
			t.Fatalf("marker %q leaked into captured application log:\n%s", m, got)
		}
	}
}

// requireFreshConnectionWorks dials a brand-new connection to addr, Binds as
// alice with the real registered token, and Searches for her one role,
// proving the server is still fully healthy after a hostile input.
func requireFreshConnectionWorks(t *testing.T, addr string) {
	t.Helper()
	fresh := dialTest(t, addr)
	requireSuccess(t, "bind on fresh connection after hostile DN", bindAs(fresh, protoBindDN("alice"), "jwt-alice"))
	res, err := fresh.Search(membershipSearch(protoGroupBaseDN, protoBindDN("alice"), nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("search on fresh connection after hostile DN: res=%+v, err=%v, want the one entry", res, err)
	}
}

// ---- non-UTF-8 Bind DN -----------------------------------------------------

// TestHostileDN_InvalidUTF8BindDNSafelyRejected drives raw-BER Bind requests
// whose DN bytes are not valid UTF-8.
func TestHostileDN_InvalidUTF8BindDNSafelyRejected(t *testing.T) {
	// 0xFF is never a valid UTF-8 leading byte in any position, so every
	// case below embeds it (or another invalid byte) directly, unescaped,
	// in the raw DN wire bytes.
	t.Run("InvalidByteInAttributeTypeRejectedBeforeVerify", func(t *testing.T) {
		acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
		fv := newFakeVerifier(acct)
		addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))
		appLog := swapAppLog(t)

		const sentinel = "HOSTILE-DN-UTF8-TYPE-SENTINEL"
		// go-ldap/v3's DN parser (dn.go's decodeString) converts the
		// attribute type substring through []rune, which replaces the
		// invalid byte with U+FFFD rather than failing outright — but the
		// resulting folded type ("u�id") then compares unequal to the
		// configured user_rdn_attribute "uid", so dn.go's ExtractUsername
		// rejects the DN before verifier.Verify is ever called. Verified
		// empirically against this exact go-ldap/v3 version during this
		// sub-task's investigation.
		hostileDN := "u\xffid=alice," + protoUserBaseDN

		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer raw.Close()

		if _, err := raw.Write(rawSimpleBindMessage(1, hostileDN, sentinel)); err != nil {
			t.Fatalf("write hostile bind: %v", err)
		}
		pkt := readRawEnvelope(t, raw, 5*time.Second)
		code, matchedDN, diagnostic := bindResponseFields(t, pkt, 1)

		if code != int64(ldapserver.LDAPResultInvalidCredentials) {
			t.Fatalf("resultCode = %d, want %d (invalidCredentials)", code, ldapserver.LDAPResultInvalidCredentials)
		}
		if matchedDN != "" {
			t.Fatalf("matchedDN = %q, want empty", matchedDN)
		}
		if diagnostic != invalidCredentialsDiagnostic {
			t.Fatalf("diagnostic = %q, want %q", diagnostic, invalidCredentialsDiagnostic)
		}
		if fv.callCount() != 0 {
			t.Fatalf("verifier calls = %d, want 0 — DN rejection must happen before Verify", fv.callCount())
		}

		requireNoLeak(t, appLog, sentinel, hostileDN)
		requireFreshConnectionWorks(t, addr)
	})

	// Empirical characterization (see this sub-task's investigation, and
	// the doc comment above): an invalid UTF-8 byte confined to the leading
	// RDN's attribute VALUE, rather than its type, is NOT rejected at the
	// DN-parsing layer. go-ldap/v3's decodeString silently substitutes
	// U+FFFD for the invalid byte during its []rune conversion (this is
	// standard Go/Unicode replacement behavior, not a defect specific to
	// this repository, and go-ldap/v3 is an external, unpatched dependency
	// — not something this sub-task's file scope could fix even if it were
	// a defect), so ExtractUsername succeeds with a garbled-but-non-empty
	// username and Bind proceeds to call verifier.Verify exactly as it
	// would for any other Bind attempt. This subtest exists to prove that
	// path is STILL safe even though it does not hit the "rejected before
	// Verify" bucket the sibling subtest above does: no panic, no
	// successful authentication with an unregistered token, no credential
	// leak, and the connection/server stay healthy afterward.
	t.Run("InvalidByteInAttributeValueIsSanitizedNotRejected", func(t *testing.T) {
		acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
		fv := newFakeVerifier(acct)
		addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))
		appLog := swapAppLog(t)

		const sentinel = "HOSTILE-DN-UTF8-VALUE-SENTINEL-not-a-real-token"
		hostileDN := "uid=\xff\xfeghost," + protoUserBaseDN

		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer raw.Close()

		if _, err := raw.Write(rawSimpleBindMessage(1, hostileDN, sentinel)); err != nil {
			t.Fatalf("write hostile bind: %v", err)
		}
		pkt := readRawEnvelope(t, raw, 5*time.Second)
		code, matchedDN, diagnostic := bindResponseFields(t, pkt, 1)

		if code != int64(ldapserver.LDAPResultInvalidCredentials) {
			t.Fatalf("resultCode = %d, want %d (invalidCredentials) — the garbled username must not authenticate with an unregistered token", code, ldapserver.LDAPResultInvalidCredentials)
		}
		if matchedDN != "" {
			t.Fatalf("matchedDN = %q, want empty", matchedDN)
		}
		if diagnostic != invalidCredentialsDiagnostic {
			t.Fatalf("diagnostic = %q, want %q", diagnostic, invalidCredentialsDiagnostic)
		}
		// Documented divergence from the sibling subtest: ExtractUsername
		// succeeds here (see the doc comment above this t.Run), so Verify
		// IS called exactly once — the safety property this subtest proves
		// is "still no successful auth / no leak / no panic", not "zero
		// verifier calls".
		if fv.callCount() != 1 {
			t.Fatalf("verifier calls = %d, want exactly 1 (characterization: DN parsing sanitizes rather than rejects invalid UTF-8 confined to the value)", fv.callCount())
		}

		requireNoLeak(t, appLog, sentinel)
		requireFreshConnectionWorks(t, addr)
	})
}

// ---- embedded NUL Bind DN --------------------------------------------------

// TestHostileDN_EmbeddedNULBindDNSafelyRejected drives a raw-BER Bind
// request whose DN value carries a raw, unescaped NUL byte. RFC 4514
// requires NUL to be escaped when present in a DN string; go-ldap/v3's
// decodeString explicitly rejects an unescaped NUL character ("got
// unescaped NULL character"), so — unlike the invalid-UTF8-in-value case
// above — this is rejected deterministically before verifier.Verify is ever
// called, regardless of which side of the leading RDN's "=" it appears on.
func TestHostileDN_EmbeddedNULBindDNSafelyRejected(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))
	appLog := swapAppLog(t)

	const sentinel = "HOSTILE-DN-NUL-SENTINEL"
	hostileDN := "uid=alice\x00trailing," + protoUserBaseDN

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	if _, err := raw.Write(rawSimpleBindMessage(1, hostileDN, sentinel)); err != nil {
		t.Fatalf("write hostile bind: %v", err)
	}
	pkt := readRawEnvelope(t, raw, 5*time.Second)
	code, matchedDN, diagnostic := bindResponseFields(t, pkt, 1)

	if code != int64(ldapserver.LDAPResultInvalidCredentials) {
		t.Fatalf("resultCode = %d, want %d (invalidCredentials)", code, ldapserver.LDAPResultInvalidCredentials)
	}
	if matchedDN != "" {
		t.Fatalf("matchedDN = %q, want empty", matchedDN)
	}
	if diagnostic != invalidCredentialsDiagnostic {
		t.Fatalf("diagnostic = %q, want %q", diagnostic, invalidCredentialsDiagnostic)
	}
	if fv.callCount() != 0 {
		t.Fatalf("verifier calls = %d, want 0 — embedded-NUL DN rejection must happen before Verify", fv.callCount())
	}

	requireNoLeak(t, appLog, sentinel, hostileDN)
	requireFreshConnectionWorks(t, addr)
}

// ---- large syntactically valid RDN -----------------------------------------

// TestHostileDN_LargeValidRDNBoundedTimeAndAllocation drives a raw-BER Bind
// request whose leading RDN value is very large but perfectly syntactically
// valid, sized (see the constant below) so the resulting LDAPMessage body is
// just under third_party/ldapserver/packet.go's 64 KiB maxMessageBodyLength
// cap. Per this sub-task's description, this measures elapsed time and
// allocation and asserts a generous bound; it must NOT introduce a new
// RDN-size policy unless the measurement actually demonstrates a real
// resource defect — it does not (see the results recorded in this
// sub-task's handoff).
func TestHostileDN_LargeValidRDNBoundedTimeAndAllocation(t *testing.T) {
	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	addr, _, _ := startTestServer(t, newFakeVerifier(acct), newFakeRoles(acct))

	// 65470 'a' characters in the leading RDN value, combined with this
	// fixture's fixed protoUserBaseDN suffix and the rest of the Bind
	// envelope (messageID, version, empty-ish password), was measured
	// (during this sub-task's implementation) to produce a 65525-byte
	// LDAPMessage body — 11 bytes under the 65536-byte (64 KiB) cap. The
	// exact value doesn't need to be pinned any tighter than "large and
	// under the cap"; the self-check immediately below fails loudly if a
	// future change to rawSimpleBindMessage's envelope shape ever pushes
	// this over the cap instead of silently testing something else.
	const largeRDNLen = 65470
	largeUsername := strings.Repeat("a", largeRDNLen)
	hostileDN := "uid=" + largeUsername + "," + protoUserBaseDN

	msg := rawSimpleBindMessage(1, hostileDN, "jwt-alice")
	if bodyLen := envelopeBodyLength(msg); bodyLen >= 64<<10 {
		t.Fatalf("test fixture bug: declared body length %d is not under the 64 KiB cap — adjust largeRDNLen", bodyLen)
	}

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()

	if _, err := raw.Write(msg); err != nil {
		t.Fatalf("write large-RDN bind: %v", err)
	}
	pkt := readRawEnvelope(t, raw, 5*time.Second)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	code, _, _ := bindResponseFields(t, pkt, 1)
	if code != int64(ldapserver.LDAPResultSuccess) {
		t.Fatalf("resultCode = %d, want success — a syntactically valid, if large, RDN must Bind normally", code)
	}

	// Generous bounds: this is ordinary well-formed input (unlike the
	// pathological ~2 GiB oversized-declared-length case in
	// TestAdversarial_OversizedDeclaredLengthRejectedWithoutBoundedAllocation),
	// so there is no reason to expect anything beyond a small constant
	// multiple of the ~64 KiB message itself.
	const elapsedBudget = 3 * time.Second
	const allocBudget = 4 << 20 // 4 MiB
	if elapsed > elapsedBudget {
		t.Fatalf("large valid RDN Bind took %v, want under %v — this would suggest a real resource defect worth reporting, not silently patching", elapsed, elapsedBudget)
	}
	if delta := after.TotalAlloc - before.TotalAlloc; delta > allocBudget {
		t.Fatalf("large valid RDN Bind allocated %d bytes, want under %d — this would suggest a real resource defect worth reporting, not silently patching", delta, allocBudget)
	}

	// A follow-on Search on this very same connection would itself need a
	// membership filter naming the exact (large) bound DN — see filter.go's
	// AuthorizeGroupMembershipFilter — which would push that second
	// message close to or over the same 64 KiB cap all over again; that is
	// not this test's concern (there is no requirement that a Search
	// naming a near-cap-sized DN also fit under the cap). What matters
	// here is that the large-RDN Bind itself is bounded and that the
	// server stays fully healthy afterward, which the ordinary
	// small-DN fresh connection below proves.
	requireFreshConnectionWorks(t, addr)
}
