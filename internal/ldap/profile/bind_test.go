package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"golang.org/x/crypto/cryptobyte"

	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// This file is the handler-level test suite for bind.go: the full Bind
// state/result policy table, Amendment 2's [3]->7 / other-tag->close
// narrowing, the LDAPv3-only version narrowing, clear-before-validate,
// the exclusive Verify/Roles call sites, replace-not-merge re-Bind, roles
// clone isolation, and no-marker-leak. Every test drives handleBind
// through a real net.Pipe, matching the plan's requirement to exercise
// this at handler level rather than by calling encode.go's functions
// directly.

// --- op-content builders ----------------------------------------------
//
// bind.go's handleBind receives op as the already-tag/length-stripped
// protocolOp content (an Envelope.Content), never a full LDAPMessage —
// so these builders produce exactly that: version + name + authentication
// CHOICE, nothing else, reusing frame_test.go's independent tlv/berInteger
// helpers (never encode.go's own code).

const (
	authTagSimple   = 0x80 // context [0] primitive
	authTagSASL     = 0xa3 // context [3] constructed
	authTagUnknown1 = 0x81 // context [1] primitive — never recognized
	authTagUnknown2 = 0x82 // context [2] primitive — never recognized
	authTagUnknown4 = 0x84 // context [4] primitive — never recognized
)

// bindOp assembles a complete, well-formed BindRequest protocolOp content:
// version (a complete minimal INTEGER TLV), name (OCTET STRING), then one
// authentication CHOICE TLV under authTag.
func bindOp(version int64, name string, authTag byte, authContent []byte) []byte {
	out := append([]byte{}, berInteger(version)...)
	out = append(out, tlv(0x04, []byte(name))...)
	out = append(out, tlv(authTag, authContent)...)
	return out
}

const (
	testAliceDN = "uid=alice,ou=users,dc=profile,dc=test"
	testBobDN   = "uid=bob,ou=users,dc=profile,dc=test"
)

// --- connection/harness construction -----------------------------------

// newBindTestConnection returns a connection wired to one end of a
// net.Pipe (the other end, clientConn, is the test's own read side) with
// the given verifier/resolver and the canonical newTestConfig() bases. The
// returned cleanup closes both pipe ends; call it once per test via
// t.Cleanup or defer.
func newBindTestConnection(t *testing.T, verifier Verifier, resolver RoleResolver) (*connection, net.Conn, func()) {
	t.Helper()
	parsed, err := parseConfig(newTestConfig())
	if err != nil {
		t.Fatalf("parseConfig(newTestConfig()): %v", err)
	}
	clientConn, serverConn := net.Pipe()
	c := &connection{
		nc:           serverConn,
		ctx:          context.Background(),
		cfg:          &parsed,
		verifier:     verifier,
		roles:        resolver,
		clock:        time.Now,
		writeTimeout: 2 * time.Second,
	}
	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
	return c, clientConn, cleanup
}

// bindReadResult is what the test-side reader goroutine hands back:
// either the raw LDAPMessage body readFrame produced, or the error
// reading it failed with (io.EOF/closed-pipe for the "nothing was ever
// written" case).
type bindReadResult struct {
	body []byte
	err  error
}

// doBind calls c.handleBind(msgID, op, hasCritical) while a background
// goroutine on clientConn (the test side) concurrently waits for exactly
// one response frame — required because net.Pipe's Write blocks until a
// matching Read consumes it, so the read must already be in flight before
// handleBind's write (if any) happens. If handleBind returns a non-nil
// error (the "close" outcome, nothing written), c.nc is closed to unblock
// the waiting reader with EOF/closed-pipe, matching what server.go would
// do with that error.
//
// It returns handleBind's own error, the raw response body bytes (nil if
// bindErr != nil), the response decoded as an Envelope (zero value if
// bindErr != nil), and whether a response was actually written.
func doBind(t *testing.T, c *connection, clientConn net.Conn, msgID int32, op []byte, hasCritical bool) (bindErr error, body []byte, env Envelope, wrote bool) {
	t.Helper()
	ch := make(chan bindReadResult, 1)
	go func() {
		b, err := readFrame(clientConn)
		ch <- bindReadResult{body: b, err: err}
	}()

	bindErr = c.handleBind(msgID, cryptobyte.String(op), hasCritical)
	if bindErr != nil {
		_ = c.nc.Close()
	}

	select {
	case res := <-ch:
		if bindErr != nil {
			return bindErr, nil, Envelope{}, false
		}
		if res.err != nil {
			t.Fatalf("handleBind returned nil but reading its response failed: %v", res.err)
		}
		decoded, decErr := decodeEnvelope(res.body)
		if decErr != nil {
			t.Fatalf("decodeEnvelope(response body): %v (% x)", decErr, res.body)
		}
		return nil, res.body, decoded, true
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the Bind response reader goroutine")
		return nil, nil, Envelope{}, false
	}
}

// readBindResultCode decodes env.Content (a BindResponse's LDAPResult
// fields: resultCode ENUMERATED, matchedDN OCTET STRING, diagnosticMessage
// OCTET STRING) and returns the result code and diagnostic text.
func readBindResultCode(t *testing.T, env Envelope) (result int, matchedDN, diagnosticMessage string) {
	t.Helper()
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("response protocolOp tag = %#x, want BindResponse %#x", byte(env.ProtocolOp), byte(tagBindResponse))
	}
	content := env.Content
	var resultEnum int
	if !content.ReadASN1Enum(&resultEnum) {
		t.Fatal("BindResponse: failed to read resultCode ENUMERATED")
	}
	var matchedDNBytes, diagBytes []byte
	if !content.ReadASN1Bytes(&matchedDNBytes, 0x04) {
		t.Fatal("BindResponse: failed to read matchedDN")
	}
	if !content.ReadASN1Bytes(&diagBytes, 0x04) {
		t.Fatal("BindResponse: failed to read diagnosticMessage")
	}
	if !content.Empty() {
		t.Fatal("BindResponse: trailing bytes after LDAPResult fields")
	}
	return resultEnum, string(matchedDNBytes), string(diagBytes)
}

// --- state/result policy table ------------------------------------------

func TestHandleBind_CriticalControlClearsAndReturns12(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 9999))
	resolver := newFakeResolver().withRoles("subj-alice", []string{markerLegitimateRole})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	// Authenticate first so there is state to clear.
	if _, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
		t.Fatal("setup Bind did not write a response")
	} else if code, _, _ := readBindResultCode(t, env); code != int(resultSuccess) {
		t.Fatalf("setup Bind result = %d, want success", code)
	}
	if !c.authenticated {
		t.Fatal("setup Bind did not authenticate")
	}

	bindErr, _, env, wrote := doBind(t, c, clientConn, 2, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), true)
	if bindErr != nil {
		t.Fatalf("critical-control Bind returned error %v, want a written response (connection stays open)", bindErr)
	}
	if !wrote {
		t.Fatal("critical-control Bind wrote no response")
	}
	code, matchedDN, diag := readBindResultCode(t, env)
	if code != int(resultUnavailableCriticalExtension) {
		t.Fatalf("result = %d, want %d", code, resultUnavailableCriticalExtension)
	}
	if matchedDN != "" {
		t.Fatalf("matchedDN = %q, want empty", matchedDN)
	}
	if diag != "critical control unavailable" {
		t.Fatalf("diagnostic = %q, want %q", diag, "critical control unavailable")
	}
	if c.authenticated {
		t.Fatal("authenticated == true after critical-control Bind, want false (prior state cleared)")
	}
	if !reflect.DeepEqual(c.auth, authState{}) {
		t.Fatalf("auth = %+v, want zero value", c.auth)
	}
	if calls := verifier.callCount(); calls != 1 {
		t.Fatalf("Verify called %d times, want 1 (only the setup Bind)", calls)
	}
}

func TestHandleBind_UnknownAuthenticationTagCloses(t *testing.T) {
	verifier := newFakeVerifier()
	resolver := newFakeResolver()
	for _, tag := range []byte{authTagUnknown1, authTagUnknown2, authTagUnknown4} {
		t.Run(fmt.Sprintf("tag_%#x", tag), func(t *testing.T) {
			c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
			defer cleanup()
			bindErr, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, tag, []byte("whatever")), false)
			if !errors.Is(bindErr, errMalformed) {
				t.Fatalf("handleBind error = %v, want errMalformed", bindErr)
			}
			if wrote {
				t.Fatal("a close outcome must not write a response")
			}
			if verifier.callCount() != 0 {
				t.Fatal("Verify called for an unrecognized authentication tag")
			}
		})
	}
}

func TestHandleBind_MalformedASN1Closes(t *testing.T) {
	valid := bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw"))
	cases := map[string][]byte{
		"truncated_mid_auth_content": valid[:len(valid)-2],
		"truncated_missing_auth":     bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw"))[:len(berInteger(3))+len(tlv(0x04, []byte(testAliceDN)))],
		"trailing_garbage":           append(append([]byte{}, valid...), 0x00),
		"version_wrong_tag_octetstring": append(
			tlv(0x04, []byte{0x03}),
			append(tlv(0x04, []byte(testAliceDN)), tlv(authTagSimple, []byte("alice-pw"))...)...,
		),
		"version_non_minimal": append(
			tlv(0x02, []byte{0x00, 0x03}),
			append(tlv(0x04, []byte(testAliceDN)), tlv(authTagSimple, []byte("alice-pw"))...)...,
		),
		"empty_input": {},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			verifier := newFakeVerifier()
			resolver := newFakeResolver()
			c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
			defer cleanup()
			bindErr, _, _, wrote := doBind(t, c, clientConn, 1, data, false)
			if !errors.Is(bindErr, errMalformed) {
				t.Fatalf("handleBind error = %v, want errMalformed", bindErr)
			}
			if wrote {
				t.Fatal("a close outcome must not write a response")
			}
			if verifier.callCount() != 0 {
				t.Fatal("Verify called on a malformed Bind")
			}
		})
	}
}

func TestHandleBind_SASLReturnsAuthMethodNotSupported(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 9999))
	resolver := newFakeResolver().withRoles("subj-alice", []string{markerLegitimateRole})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	bindErr, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSASL, []byte("sasl-credentials-ignored")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil (7, not close)", bindErr)
	}
	if !wrote {
		t.Fatal("SASL Bind wrote no response")
	}
	code, matchedDN, diag := readBindResultCode(t, env)
	if code != int(resultAuthMethodNotSupported) {
		t.Fatalf("result = %d, want %d", code, resultAuthMethodNotSupported)
	}
	if matchedDN != "" {
		t.Fatalf("matchedDN = %q, want empty", matchedDN)
	}
	if diag != "only simple authentication is supported" {
		t.Fatalf("diagnostic = %q, want %q", diag, "only simple authentication is supported")
	}
	if c.authenticated {
		t.Fatal("authenticated == true after SASL Bind, want false")
	}
	if verifier.callCount() != 0 {
		t.Fatal("Verify called for a SASL Bind")
	}
}

// TestHandleBind_SASLPrecedesVersionCheckForNonV3 is a regression test for
// the accepted "minor" review finding: bind.go decodes version first but
// only ever *acts* on it inside the authChoiceSimple case (the `if version
// != 3` check sits after the auth-tag switch's SASL case, which
// unconditionally returns before that check is ever reached — see
// bind.go). So a decodable SASL Bind at a non-3 version must still return
// authMethodNotSupported (7), never protocolError (2): this is the
// disputed cross-product pass 1's SASL/version rebuttal left untested —
// every existing SASL test used version 3
// (TestHandleBind_SASLReturnsAuthMethodNotSupported and
// TestHandleBind_ClearBeforeValidate_SASL) and every non-3-version test
// used authTagSimple (TestHandleBind_VersionOtherThan3ReturnsProtocolError),
// so the precedence between the two was never exercised together.
func TestHandleBind_SASLPrecedesVersionCheckForNonV3(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 9999))
	resolver := newFakeResolver().withRoles("subj-alice", []string{markerLegitimateRole})
	for _, version := range []int64{1, 2, 4} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
			defer cleanup()

			bindErr, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(version, testAliceDN, authTagSASL, []byte("sasl-credentials-ignored")), false)
			if bindErr != nil {
				t.Fatalf("handleBind error = %v, want nil (7, not close)", bindErr)
			}
			if !wrote {
				t.Fatal("SASL Bind wrote no response")
			}
			code, matchedDN, diag := readBindResultCode(t, env)
			if code != int(resultAuthMethodNotSupported) {
				t.Fatalf("version=%d: result = %d, want %d (authMethodNotSupported, not protocolError) — the SASL auth-tag switch must preempt the version check", version, code, resultAuthMethodNotSupported)
			}
			if matchedDN != "" {
				t.Fatalf("matchedDN = %q, want empty", matchedDN)
			}
			if diag != "only simple authentication is supported" {
				t.Fatalf("diagnostic = %q, want %q", diag, "only simple authentication is supported")
			}
			if c.authenticated {
				t.Fatal("authenticated == true after a non-v3 SASL Bind, want false")
			}
		})
	}
	if verifier.callCount() != 0 {
		t.Fatal("Verify called for a non-v3 SASL Bind")
	}
}

// TestHandleBind_VersionOtherThan3ReturnsProtocolError's version list
// includes 127 and 128 to close the reviewer-flagged gap in row 1a of
// docs/clickhouse-ldap-wire-profile.md §11.3: 127 is the largest value
// minimalPositiveInt32 accepts in a one-octet INTEGER content (bindOp's
// berInteger naturally emits the single byte 0x7f), while 128 is the
// smallest value that legitimately requires the two-octet minimal form
// (berInteger emits 0x00 0x80 — the leading 0x00 disambiguates the
// following high bit, per minimalPositiveInt32's own rule, so it is not
// itself a non-minimal encoding). Both are well-formed, decodable
// versions that are simply not 3, so both must land on protocolError via
// the same version-narrowing path as versions 1/2/4 below — proving the
// row 1a composite (minimally-encoded version >=128 decodes fine and
// then fails only the != 3 check) end-to-end rather than as an isolated
// claim.
//
// A NON-minimal version encoding (e.g. tag/length/content 02 02 00 07,
// or the 128-adjacent 02 03 00 00 80) is deliberately not exercised here:
// TestHandleBind_MalformedASN1Closes's "version_non_minimal" case
// already drives exactly that code path (minimalPositiveInt32's
// leading-0x00/0xff padding rule) with content 00 03, and a
// same-shape/different-digit repeat of that case would not add coverage.
func TestHandleBind_VersionOtherThan3ReturnsProtocolError(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 9999))
	resolver := newFakeResolver()
	for _, version := range []int64{1, 2, 4, 127, 128} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
			defer cleanup()
			bindErr, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(version, testAliceDN, authTagSimple, []byte("alice-pw")), false)
			if bindErr != nil {
				t.Fatalf("handleBind error = %v, want nil", bindErr)
			}
			if !wrote {
				t.Fatal("wrote no response")
			}
			code, matchedDN, diag := readBindResultCode(t, env)
			if code != int(resultProtocolError) {
				t.Fatalf("result = %d, want %d", code, resultProtocolError)
			}
			if matchedDN != "" {
				t.Fatalf("matchedDN = %q, want empty", matchedDN)
			}
			if diag != "LDAPv3 required" {
				t.Fatalf("diagnostic = %q, want %q", diag, "LDAPv3 required")
			}
			if c.authenticated {
				t.Fatal("authenticated == true, want false")
			}
		})
	}
	if verifier.callCount() != 0 {
		t.Fatal("Verify called for a non-v3 Bind")
	}
}

func assertInvalidCredentials(t *testing.T, env Envelope) {
	t.Helper()
	code, matchedDN, diag := readBindResultCode(t, env)
	if code != int(resultInvalidCredentials) {
		t.Fatalf("result = %d, want %d", code, resultInvalidCredentials)
	}
	if matchedDN != "" {
		t.Fatalf("matchedDN = %q, want empty", matchedDN)
	}
	if diag != "invalid credentials" {
		t.Fatalf("diagnostic = %q, want %q", diag, "invalid credentials")
	}
}

func TestHandleBind_EmptyDNOrPasswordReturns49(t *testing.T) {
	cases := map[string]struct {
		dn       string
		password string
	}{
		"empty_dn":       {"", "alice-pw"},
		"empty_password": {testAliceDN, ""},
		"both_empty":     {"", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			verifier := newFakeVerifier()
			resolver := newFakeResolver()
			c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
			defer cleanup()
			bindErr, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, tc.dn, authTagSimple, []byte(tc.password)), false)
			if bindErr != nil {
				t.Fatalf("handleBind error = %v, want nil", bindErr)
			}
			if !wrote {
				t.Fatal("wrote no response")
			}
			assertInvalidCredentials(t, env)
			if verifier.callCount() != 0 {
				t.Fatal("Verify called for an empty DN/password Bind")
			}
		})
	}
}

func TestHandleBind_RejectedBindDNReturns49(t *testing.T) {
	verifier := newFakeVerifier()
	resolver := newFakeResolver()
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()
	bindErr, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, markerHostileDN, authTagSimple, []byte("whatever")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil", bindErr)
	}
	if !wrote {
		t.Fatal("wrote no response")
	}
	assertInvalidCredentials(t, env)
	if verifier.callCount() != 0 {
		t.Fatal("Verify called for a rejected Bind DN")
	}
}

func TestHandleBind_VerifierFailureReturns49AndSkipsRoles(t *testing.T) {
	verifier := newFakeVerifier().withFailure("alice-pw", fmt.Errorf("%s", markerVerifierError))
	resolver := newFakeResolver()
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	bindErr, body, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil", bindErr)
	}
	if !wrote {
		t.Fatal("wrote no response")
	}
	assertInvalidCredentials(t, env)
	if verifier.callCount() != 1 {
		t.Fatalf("Verify called %d times, want 1", verifier.callCount())
	}
	if resolver.callCount() != 0 {
		t.Fatal("Roles called despite Verify failing")
	}
	if bytes.Contains(body, []byte(markerVerifierError)) {
		t.Fatalf("response leaked the verifier error marker: % x", body)
	}
}

func TestHandleBind_ResolverFailureReturns49(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 9999))
	resolver := newFakeResolver().withError(fmt.Errorf("%s", markerResolverError))
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	bindErr, body, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil", bindErr)
	}
	if !wrote {
		t.Fatal("wrote no response")
	}
	assertInvalidCredentials(t, env)
	if verifier.callCount() != 1 {
		t.Fatalf("Verify called %d times, want 1", verifier.callCount())
	}
	if resolver.callCount() != 1 {
		t.Fatalf("Roles called %d times, want 1", resolver.callCount())
	}
	if c.authenticated {
		t.Fatal("authenticated == true after a role-resolver failure")
	}
	if bytes.Contains(body, []byte(markerResolverError)) {
		t.Fatalf("response leaked the resolver error marker: % x", body)
	}
}

func TestHandleBind_SuccessReplacesStateAndReturns0(t *testing.T) {
	const issuer = "https://idp.example.com/"
	const subject = "subj-alice"
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", issuer, subject, 9999))
	resolver := newFakeResolver().withRoles(subject, []string{markerLegitimateRole, "clickhouse_writer"})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	bindErr, _, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil", bindErr)
	}
	if !wrote {
		t.Fatal("wrote no response")
	}
	code, matchedDN, diag := readBindResultCode(t, env)
	if code != int(resultSuccess) {
		t.Fatalf("result = %d, want %d", code, resultSuccess)
	}
	if matchedDN != "" || diag != "" {
		t.Fatalf("matchedDN/diagnostic = %q/%q, want empty/empty", matchedDN, diag)
	}

	if !c.authenticated {
		t.Fatal("authenticated == false after a successful Bind")
	}
	wantBoundDN, err := ParseDN(testAliceDN)
	if err != nil {
		t.Fatalf("ParseDN(testAliceDN): %v", err)
	}
	want := authState{
		Username:  "alice",
		Issuer:    issuer,
		Subject:   subject,
		BoundDN:   testAliceDN,
		boundDN:   wantBoundDN,
		ExpiresAt: 9999,
		Roles:     []string{markerLegitimateRole, "clickhouse_writer"},
	}
	if !reflect.DeepEqual(c.auth, want) {
		t.Fatalf("auth = %+v, want %+v", c.auth, want)
	}
	if verifier.callCount() != 1 {
		t.Fatalf("Verify called %d times, want 1", verifier.callCount())
	}
	if resolver.callCount() != 1 {
		t.Fatalf("Roles called %d times, want 1", resolver.callCount())
	}
}

// TestHandleBind_RolesCloneIsolation proves the stored Roles snapshot is
// immune to the caller (fakeResolver) mutating the slice it returned —
// exercised through the real Bind flow, not session.go's replaceAuth in
// isolation.
func TestHandleBind_RolesCloneIsolation(t *testing.T) {
	const subject = "subj-alice"
	roles := []string{markerLegitimateRole, "clickhouse_writer"}
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", subject, 9999))
	resolver := newFakeResolver().withRoles(subject, roles)
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	if _, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
		t.Fatal("Bind did not write a response")
	}

	stored := append([]string{}, c.auth.Roles...)
	roles[0] = "mutated-after-bind"
	if !reflect.DeepEqual(c.auth.Roles, stored) {
		t.Fatalf("c.auth.Roles changed after mutating fakeResolver's returned slice: %v, want %v", c.auth.Roles, stored)
	}
}

// --- re-Bind: failed-clear-first, successful-replace-not-merge ---------

func TestHandleBind_RebindReplacesSnapshotAliceThenBob(t *testing.T) {
	verifier := newFakeVerifier().
		withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 1000)).
		withSuccess("bob-pw", newVerificationResult("bob", "https://idp.example.com/", "subj-bob", 2000))
	resolver := newFakeResolver().
		withRoles("subj-alice", []string{"clickhouse_alice_role"}).
		withRoles("subj-bob", []string{"clickhouse_bob_role"})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	if _, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
		t.Fatal("Alice Bind did not write a response")
	}
	if _, _, _, wrote := doBind(t, c, clientConn, 2, bindOp(3, testBobDN, authTagSimple, []byte("bob-pw")), false); !wrote {
		t.Fatal("Bob Bind did not write a response")
	}

	wantBoundDN, err := ParseDN(testBobDN)
	if err != nil {
		t.Fatalf("ParseDN(testBobDN): %v", err)
	}
	want := authState{
		Username:  "bob",
		Issuer:    "https://idp.example.com/",
		Subject:   "subj-bob",
		BoundDN:   testBobDN,
		boundDN:   wantBoundDN,
		ExpiresAt: 2000,
		Roles:     []string{"clickhouse_bob_role"},
	}
	if !reflect.DeepEqual(c.auth, want) {
		t.Fatalf("auth after Alice then Bob = %+v, want exactly Bob's state (no merge): %+v", c.auth, want)
	}
	if verifier.callCount() != 2 {
		t.Fatalf("Verify called %d times, want 2", verifier.callCount())
	}
	if resolver.callCount() != 2 {
		t.Fatalf("Roles called %d times, want 2", resolver.callCount())
	}
}

// --- clear-before-validate --------------------------------------------

func TestHandleBind_ClearBeforeValidate_Version2(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 1000))
	resolver := newFakeResolver().withRoles("subj-alice", []string{markerLegitimateRole})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	if _, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
		t.Fatal("setup Bind did not write a response")
	}
	if !c.authenticated {
		t.Fatal("setup Bind did not authenticate")
	}
	callsBefore := verifier.callCount()

	bindErr, _, env, wrote := doBind(t, c, clientConn, 2, bindOp(2, testAliceDN, authTagSimple, []byte("alice-pw")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil", bindErr)
	}
	if !wrote {
		t.Fatal("v2 Bind wrote no response")
	}
	if code, _, _ := readBindResultCode(t, env); code != int(resultProtocolError) {
		t.Fatalf("result = %d, want %d", code, resultProtocolError)
	}
	if c.authenticated {
		t.Fatal("authenticated == true after v2 Bind, want false (cleared before the version check)")
	}
	if verifier.callCount() != callsBefore {
		t.Fatalf("Verify called again for a v2 Bind: calls = %d, want %d (unchanged)", verifier.callCount(), callsBefore)
	}
}

func TestHandleBind_ClearBeforeValidate_SASL(t *testing.T) {
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 1000))
	resolver := newFakeResolver().withRoles("subj-alice", []string{markerLegitimateRole})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	if _, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
		t.Fatal("setup Bind did not write a response")
	}
	callsBefore := verifier.callCount()

	_, _, env, wrote := doBind(t, c, clientConn, 2, bindOp(3, testAliceDN, authTagSASL, []byte("sasl-bytes")), false)
	if !wrote {
		t.Fatal("SASL Bind wrote no response")
	}
	if code, _, _ := readBindResultCode(t, env); code != int(resultAuthMethodNotSupported) {
		t.Fatalf("result = %d, want %d", code, resultAuthMethodNotSupported)
	}
	if c.authenticated {
		t.Fatal("authenticated == true after SASL Bind, want false")
	}
	if verifier.callCount() != callsBefore {
		t.Fatalf("Verify called again for a SASL Bind: calls = %d, want %d (unchanged)", verifier.callCount(), callsBefore)
	}
}

// TestHandleBind_ClearBeforeValidate_FailingVerify proves that, for a Bind
// whose auth choice IS simple and whose version IS 3 but whose Verify call
// fails, prior authentication state was already cleared by the time Verify
// itself runs — not merely by the time handleBind returns. It uses a
// verifier wrapper that snapshots c.authenticated at call time.
func TestHandleBind_ClearBeforeValidate_FailingVerify(t *testing.T) {
	backing := newFakeVerifier().
		withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 1000)).
		withFailure("wrong-pw", fmt.Errorf("%s", markerVerifierError))
	resolver := newFakeResolver().withRoles("subj-alice", []string{markerLegitimateRole})

	var authAtCallTime *bool
	wrapped := &callTimeObservingVerifier{
		fakeVerifier: backing,
		onCall: func(c *connection) {
			v := c.authenticated
			authAtCallTime = &v
		},
	}

	c, clientConn, cleanup := newBindTestConnection(t, wrapped, resolver)
	defer cleanup()
	wrapped.conn = c

	if _, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
		t.Fatal("setup Bind did not write a response")
	}
	if !c.authenticated {
		t.Fatal("setup Bind did not authenticate")
	}

	bindErr, _, env, wrote := doBind(t, c, clientConn, 2, bindOp(3, testAliceDN, authTagSimple, []byte("wrong-pw")), false)
	if bindErr != nil {
		t.Fatalf("handleBind error = %v, want nil", bindErr)
	}
	if !wrote {
		t.Fatal("failing Bind wrote no response")
	}
	assertInvalidCredentials(t, env)

	if authAtCallTime == nil {
		t.Fatal("Verify was never called")
	}
	if *authAtCallTime {
		t.Fatal("c.authenticated was still true at the moment Verify was called, want false (clear-before-validate)")
	}
	if c.authenticated {
		t.Fatal("authenticated == true after the failing Bind, want false")
	}
}

// callTimeObservingVerifier wraps *fakeVerifier, invoking onCall(conn)
// immediately before delegating — used only by
// TestHandleBind_ClearBeforeValidate_FailingVerify above.
type callTimeObservingVerifier struct {
	*fakeVerifier
	conn   *connection
	onCall func(*connection)
}

func (v *callTimeObservingVerifier) Verify(ctx context.Context, username, password string) (*verification.Result, error) {
	if v.onCall != nil {
		v.onCall(v.conn)
	}
	return v.fakeVerifier.Verify(ctx, username, password)
}

// --- exact success log line / no-marker-leak ----------------------------

func TestHandleBind_ExactSuccessLogLine(t *testing.T) {
	const issuer = "https://idp.example.com/"
	const subject = "subj-alice"
	verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", issuer, subject, 9999))
	resolver := newFakeResolver().withRoles(subject, []string{markerLegitimateRole, "clickhouse_writer"})
	c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
	defer cleanup()

	fields := captureLog(t, zerolog.InfoLevel, func() {
		if _, _, _, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false); !wrote {
			t.Fatal("Bind did not write a response")
		}
	})

	want := map[string]any{
		"op":             "bind",
		"success":        true,
		"result":         float64(resultSuccess),
		"username":       "alice",
		"correlation_id": correlationID(issuer, subject),
		"roles":          float64(2),
		"message":        "ldap bind succeeded",
	}
	// zerolog also includes a "level" and "time" field we don't pin here.
	for k, wantV := range want {
		gotV, ok := fields[k]
		if !ok {
			t.Fatalf("log line missing field %q; got %+v", k, fields)
		}
		if gotV != wantV {
			t.Fatalf("log field %q = %v (%T), want %v (%T)", k, gotV, gotV, wantV, wantV)
		}
	}
}

// TestHandleBind_NoMarkerLeak proves that neither the raw JWT-shaped
// password, the hostile Bind DN, nor either injected dependency error
// marker ever reaches the response bytes or the log line, across four
// distinct failure paths that each actually handle that marker value.
func TestHandleBind_NoMarkerLeak(t *testing.T) {
	t.Run("jwt_shaped_password", func(t *testing.T) {
		verifier := newFakeVerifier() // markerJWTPassword is deliberately unregistered
		resolver := newFakeResolver()
		c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
		defer cleanup()

		var body []byte
		fields := captureLog(t, zerolog.InfoLevel, func() {
			_, b, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte(markerJWTPassword)), false)
			if !wrote {
				t.Fatal("wrote no response")
			}
			assertInvalidCredentials(t, env)
			body = b
		})
		assertNoMarkerLeak(t, fields, body, markerJWTPassword)
	})

	t.Run("hostile_dn", func(t *testing.T) {
		verifier := newFakeVerifier()
		resolver := newFakeResolver()
		c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
		defer cleanup()

		var body []byte
		fields := captureLog(t, zerolog.InfoLevel, func() {
			_, b, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, markerHostileDN, authTagSimple, []byte("whatever")), false)
			if !wrote {
				t.Fatal("wrote no response")
			}
			assertInvalidCredentials(t, env)
			body = b
		})
		assertNoMarkerLeak(t, fields, body, markerHostileDN)
	})

	t.Run("verifier_error", func(t *testing.T) {
		verifier := newFakeVerifier().withFailure("alice-pw", fmt.Errorf("%s", markerVerifierError))
		resolver := newFakeResolver()
		c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
		defer cleanup()

		var body []byte
		fields := captureLog(t, zerolog.InfoLevel, func() {
			_, b, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false)
			if !wrote {
				t.Fatal("wrote no response")
			}
			assertInvalidCredentials(t, env)
			body = b
		})
		assertNoMarkerLeak(t, fields, body, markerVerifierError)
	})

	t.Run("resolver_error", func(t *testing.T) {
		verifier := newFakeVerifier().withSuccess("alice-pw", newVerificationResult("alice", "https://idp.example.com/", "subj-alice", 9999))
		resolver := newFakeResolver().withError(fmt.Errorf("%s", markerResolverError))
		c, clientConn, cleanup := newBindTestConnection(t, verifier, resolver)
		defer cleanup()

		var body []byte
		fields := captureLog(t, zerolog.InfoLevel, func() {
			_, b, env, wrote := doBind(t, c, clientConn, 1, bindOp(3, testAliceDN, authTagSimple, []byte("alice-pw")), false)
			if !wrote {
				t.Fatal("wrote no response")
			}
			assertInvalidCredentials(t, env)
			body = b
		})
		assertNoMarkerLeak(t, fields, body, markerResolverError)
	})
}

func assertNoMarkerLeak(t *testing.T, fields map[string]any, body []byte, marker string) {
	t.Helper()
	if bytes.Contains(body, []byte(marker)) {
		t.Fatalf("response bytes leaked marker %q: % x", marker, body)
	}
	serialized, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal captured log fields: %v", err)
	}
	if bytes.Contains(serialized, []byte(marker)) {
		t.Fatalf("log line leaked marker %q: %s", marker, serialized)
	}
}
