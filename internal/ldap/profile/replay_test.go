package profile

// This file implements the Phase 2 plan's "Captured-wire replay" section
// (sub-task p2-12-wire-replay): TestProfileReplay drives the REAL profile
// server, over a real loopback TCP connection, with the exact committed
// bytes under internal/ldap/testdata/clickhouse-wire/**, consumed only
// through internal/wirefixture (a test-only import — see
// internal/securitytest/profile_dependency_contract_test.go, which proves
// it never reaches this package's production dependency closure).
//
// It complements, rather than duplicates, this package's other fixture
// consumers:
//
//   - bind_fuzz_test.go/frame_fuzz_test.go/search_fuzz_test.go feed the
//     committed PDUs to native fuzz targets seeded from (not asserting
//     end-to-end behavior for) the corpus;
//   - the Phase 4 differential oracle (per the plan's "Phase 1
//     independent decoder" section, not yet written) proves the fixture
//     bytes are well-formed against an independent decoder — this file
//     never plays that role; it only proves the shipped server produces
//     the documented ClickHouse-compatible responses for real captured
//     traffic.
//
// # Role-pipeline scope
//
// Every session below uses a fake RoleResolver returning a fixed,
// deterministic pair of already-mapped ClickHouse role names. This is
// NOT a production role-pipeline test: it does not exercise
// internal/roles' actual idp-readers/idp-unprovisioned -> ClickHouse
// role-name mapping (see wirefixture.FixedTokenClaimRecipe for the real
// JWT claim shape those fixtures were minted against) — it only proves
// that whatever roles a Bind-time snapshot holds are rendered correctly
// as synthetic groupOfNames entries by the real Search handler.
//
// # Config provenance
//
// The profile.Config used to run the server is derived mechanically from
// the real ClickHouse LDAP configuration file named by a captured
// fixture's own profile.json (CanonicalConfigPath) — never a
// second, independently maintained literal DN/attribute/prefix copy in
// this test file.

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// replayCase is one discovered fixture session ready to replay: its
// stable display name (e.g. "24.8/success", "constructed/message-id-
// boundary"), the on-disk directory holding its .ber files and
// session.json, the decoded Session metadata itself, and whether it is
// the constructed MessageID-boundary session (which gets the additional
// exact-response-byte assertion the plan names explicitly).
type replayCase struct {
	name          string
	dir           string
	session       wirefixture.Session
	isConstructed bool
}

// discoverReplayCases walks the whole committed wire-evidence corpus
// through internal/wirefixture only (ModuleRoot, ClickHouseWireFixtureRoot,
// LineDir, SessionDir, ReadSession, ReadProfile — the same helpers this
// package's fuzz seed-loaders already use), and cross-checks the result
// against an independent, wirefixture-schema-agnostic filesystem walk: if
// a session directory exists on disk but profile.json's session_paths (or
// any other wirefixture-based enumeration bug) silently fails to surface
// it, independentTotal and len(cases) diverge and this fails loudly
// instead of a fixture quietly never being replayed.
func discoverReplayCases(t *testing.T) (cases []replayCase, moduleRoot string) {
	t.Helper()

	var err error
	moduleRoot, err = wirefixture.ModuleRoot()
	if err != nil {
		t.Fatalf("wirefixture.ModuleRoot: %v", err)
	}
	fixtureRoot := wirefixture.ClickHouseWireFixtureRoot(moduleRoot)

	lines, err := wirefixture.ValidateFixtureRoot(fixtureRoot)
	if err != nil {
		t.Fatalf("wirefixture.ValidateFixtureRoot(%s): %v", fixtureRoot, err)
	}
	if len(lines) == 0 {
		t.Fatal("discoverReplayCases: no tracked ClickHouse lines found under the wire fixture root")
	}

	independentTotal := 0
	for _, line := range lines {
		lineDir := wirefixture.LineDir(fixtureRoot, line)

		profile, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
		if err != nil {
			t.Fatalf("read profile.json for line %s: %v", line, err)
		}
		if len(profile.SessionPaths) == 0 {
			t.Fatalf("line %s: profile.json lists no session_paths", line)
		}
		for _, sessionName := range profile.SessionPaths {
			sessionDir := wirefixture.SessionDir(lineDir, sessionName)
			session, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessionDir))
			if err != nil {
				t.Fatalf("read session.json for %s: %v", sessionDir, err)
			}
			cases = append(cases, replayCase{
				name:    line + "/" + sessionName,
				dir:     sessionDir,
				session: session,
			})
		}

		entries, err := os.ReadDir(lineDir)
		if err != nil {
			t.Fatalf("read line dir %s: %v", lineDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				independentTotal++
			}
		}
	}

	constructedDir := wirefixture.ConstructedDir(fixtureRoot)
	constructedEntries, err := os.ReadDir(constructedDir)
	if err != nil {
		t.Fatalf("read constructed fixture dir %s: %v", constructedDir, err)
	}
	for _, e := range constructedEntries {
		if !e.IsDir() {
			t.Fatalf("constructed fixture dir %s: unexpected non-directory entry %q", constructedDir, e.Name())
		}
		sessionDir := wirefixture.SessionDir(constructedDir, e.Name())
		session, err := wirefixture.ReadSession(wirefixture.SessionMetadataPath(sessionDir))
		if err != nil {
			t.Fatalf("read session.json for %s: %v", sessionDir, err)
		}
		cases = append(cases, replayCase{
			name:          "constructed/" + e.Name(),
			dir:           sessionDir,
			session:       session,
			isConstructed: true,
		})
		independentTotal++
	}

	if independentTotal != len(cases) {
		t.Fatalf(
			"wirefixture-based discovery produced %d replay session(s), but an independent filesystem walk over the same fixture root found %d director(y/ies) -- a fixture session may have been silently skipped (e.g. missing from a profile.json's session_paths)",
			len(cases), independentTotal,
		)
	}

	return cases, moduleRoot
}

// extractXMLTag returns the trimmed text content of the first <tag>...
// </tag> occurrence in xmlContent. It is a deliberately minimal,
// single-purpose extractor (not a general XML parser) for the three
// fixed, unambiguous tags this file reads out of the real committed
// ClickHouse LDAP config (bind_dn, base_dn, prefix) -- see
// loadProfileConfigFromCanonicalXML.
func extractXMLTag(t *testing.T, xmlContent []byte, tag string) string {
	t.Helper()
	open := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	s := string(xmlContent)
	start := strings.Index(s, open)
	if start < 0 {
		t.Fatalf("canonical ClickHouse LDAP config: tag <%s> not found", tag)
	}
	start += len(open)
	rest := s[start:]
	end := strings.Index(rest, closeTag)
	if end < 0 {
		t.Fatalf("canonical ClickHouse LDAP config: closing </%s> not found", tag)
	}
	return strings.TrimSpace(rest[:end])
}

// loadProfileConfigFromCanonicalXML derives this replay run's profile.Config
// from the real ClickHouse LDAP configuration file named by a captured
// fixture's own profile.json (CanonicalConfigPath): the user base DN and
// user_rdn_attribute from <bind_dn>, and the group base DN and role-CN
// prefix from <role_mapping>'s <base_dn>/<prefix> (see
// integration/clickhouse/clickhouse/common/config.d/ldap.xml). This
// mirrors the sub-task description's "configure profile.Config from the
// fixture's profile.json/ClickHouse ldap.xml values" instruction exactly:
// nothing here is a second, independently maintained copy of those
// literal DN/attribute/prefix strings.
func loadProfileConfigFromCanonicalXML(t *testing.T, moduleRoot string, cases []replayCase) Config {
	t.Helper()

	var lineDir string
	for _, tc := range cases {
		if !tc.isConstructed {
			lineDir = filepath.Dir(tc.dir)
			break
		}
	}
	if lineDir == "" {
		t.Fatal("loadProfileConfigFromCanonicalXML: no captured (non-constructed) fixture session found")
	}

	profile, err := wirefixture.ReadProfile(wirefixture.ProfilePath(lineDir))
	if err != nil {
		t.Fatalf("read profile.json for %s: %v", lineDir, err)
	}

	xmlPath := filepath.Join(moduleRoot, filepath.FromSlash(profile.CanonicalConfigPath))
	xmlBytes, err := os.ReadFile(xmlPath)
	if err != nil {
		t.Fatalf("read canonical ClickHouse LDAP config %s: %v", xmlPath, err)
	}

	bindDNPattern := extractXMLTag(t, xmlBytes, "bind_dn")
	rdnAttribute, userBaseDN, ok := strings.Cut(bindDNPattern, "={user_name},")
	if !ok {
		t.Fatalf("canonical config %s: bind_dn %q does not match the expected \"<attr>={user_name},<base>\" shape", xmlPath, bindDNPattern)
	}

	groupBaseDN := extractXMLTag(t, xmlBytes, "base_dn")
	rolePrefix := extractXMLTag(t, xmlBytes, "prefix")

	return Config{
		UserBaseDN:       userBaseDN,
		GroupBaseDN:      groupBaseDN,
		UserRDNAttribute: rdnAttribute,
		RoleCNPrefix:     rolePrefix,
	}
}

// readFixturePDU reads one committed .ber file's exact bytes, unmodified.
func readFixturePDU(t *testing.T, dir, filename string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		t.Fatalf("read fixture PDU %s/%s: %v", dir, filename, err)
	}
	return raw
}

// decodeFixtureBindCredentials decodes one committed BindRequest .ber
// file's exact Bind DN and password bytes -- using this package's own
// readFrame/decodeEnvelope (the file carries the whole wire-identical
// LDAPMessage, outer SEQUENCE tag/length included, exactly like the
// existing fuzz-seed loaders' fixtures) plus the same three-field
// (version, name, authentication CHOICE) decode bind.go's own handleBind
// performs. This is read-only fixture introspection to configure the fake
// verifier -- the bytes actually sent to the server later are always the
// untouched raw file content, never a re-encoding of what this function
// decoded.
func decodeFixtureBindCredentials(t *testing.T, raw []byte) (bindDN, password string) {
	t.Helper()
	body, err := readFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readFrame(fixture bind PDU): %v", err)
	}
	env, err := decodeEnvelope(body)
	if err != nil {
		t.Fatalf("decodeEnvelope(fixture bind PDU): %v", err)
	}
	if env.ProtocolOp != tagBindRequest {
		t.Fatalf("fixture PDU recorded as a bindRequest is not one on the wire: tag=%v", env.ProtocolOp)
	}

	content := env.Content
	var versionContent cryptobyte.String
	if !content.ReadASN1(&versionContent, asn1.INTEGER) {
		t.Fatal("decode fixture bind PDU: version")
	}
	var nameBytes []byte
	if !content.ReadASN1Bytes(&nameBytes, asn1.OCTET_STRING) {
		t.Fatal("decode fixture bind PDU: name")
	}
	var authContent cryptobyte.String
	var authTag asn1.Tag
	if !content.ReadAnyASN1(&authContent, &authTag) {
		t.Fatal("decode fixture bind PDU: authentication choice")
	}
	return string(nameBytes), string(authContent)
}

// newRunningServerWithConfig starts a real profile.Server, Serve-ing a
// real loopback TCP listener, using cfg (server_test.go's own
// newRunningServer always uses newTestConfig() and cannot be reused here,
// nor edited from this file's scope).
func newRunningServerWithConfig(t *testing.T, cfg Config, v Verifier, r RoleResolver) *testServerHandle {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s, err := New(context.Background(), cfg, v, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	return &testServerHandle{server: s, addr: ln.Addr().String(), done: done}
}

// readEnvelopeRaw reads and decodes one bounded LDAPMessage response,
// returning both the raw SEQUENCE-content bytes (readFrame's own return
// shape) and its decoded Envelope -- unlike server_test.go's readEnvelope,
// which discards the raw bytes this file needs for the constructed
// session's exact-MessageID-byte assertion.
func readEnvelopeRaw(t *testing.T, conn net.Conn) (raw []byte, env Envelope) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	raw, err := readFrame(conn)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	env, err = decodeEnvelope(raw)
	if err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}
	return raw, env
}

// wantMappedCNValues is the fixed pair of already-mapped ClickHouse role
// names every captured session's Search is expected to return, per the
// sub-task description: idp-readers/idp-unprovisioned (the fixture
// token's real "roles" claim, see wirefixture.FixedTokenClaimRecipe)
// mapped, with the fixture profile's RoleCNPrefix ("clickhouse_"), to
// these two rendered cn values.
var wantMappedCNValues = []string{"clickhouse_ch_readonly", "clickhouse_ch_unprovisioned"}

// TestProfileReplay is the Phase 2 plan's "Captured-wire replay": every
// committed ClickHouse wire fixture session, fed byte-for-byte to a real
// profile.Server over real TCP, one PASS subtest per discovered session.
func TestProfileReplay(t *testing.T) {
	cases, moduleRoot := discoverReplayCases(t)
	cfg := loadProfileConfigFromCanonicalXML(t, moduleRoot, cases)
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("profile.Config derived from the canonical ClickHouse LDAP XML is invalid: %v", err)
	}

	ran := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran++
			runReplaySession(t, cfg, tc)
		})
	}
	if ran != len(cases) {
		t.Fatalf("ran %d replay subtest(s), want %d (one per discovered fixture session)", ran, len(cases))
	}
}

// runReplaySession replays one fixture session's PDUs, in Sequence order,
// against a freshly started real profile.Server over one real TCP
// connection.
func runReplaySession(t *testing.T, cfg Config, tc replayCase) {
	t.Helper()

	pdus := append([]wirefixture.PDU(nil), tc.session.PDUs...)
	sort.Slice(pdus, func(i, j int) bool { return pdus[i].Sequence < pdus[j].Sequence })
	if len(pdus) == 0 {
		t.Fatalf("session %s: session.json lists zero PDUs", tc.name)
	}

	verifier := newFakeVerifier()
	resolver := newFakeResolver()

	base, err := ParseDN(cfg.UserBaseDN)
	if err != nil {
		t.Fatalf("session %s: parse configured UserBaseDN %q: %v", tc.name, cfg.UserBaseDN, err)
	}

	// Register every Bind PDU's exact sanitized/constructed password
	// (never re-derived or re-encoded) as the one recipe the fake
	// verifier accepts, and a fixed deterministic mapped-role pair for
	// the fake resolver -- NOT a production role-pipeline test (see this
	// file's top-of-file doc comment): the real idp-readers/
	// idp-unprovisioned -> ClickHouse role-name mapping lives in
	// internal/roles and is exercised elsewhere, never here.
	for _, pdu := range pdus {
		if pdu.Direction != wirefixture.DirectionClientToServer || pdu.Operation != wirefixture.OperationBindRequest {
			continue
		}
		raw := readFixturePDU(t, tc.dir, pdu.Filename)
		bindDN, password := decodeFixtureBindCredentials(t, raw)

		username, err := ParseBindDN(bindDN, base, cfg.UserRDNAttribute)
		if err != nil {
			t.Fatalf("session %s: fixture Bind DN %q does not parse under the configured profile: %v", tc.name, bindDN, err)
		}

		const issuer = "https://idp.example.com/"
		verifier.withSuccess(password, newVerificationResult(username, issuer, username, time.Now().Add(time.Hour).Unix()))
		resolver.withRoles(username, []string{"ch_readonly", "ch_unprovisioned"})
	}

	h := newRunningServerWithConfig(t, cfg, verifier, resolver)
	defer h.stopAndWait(t, 10*time.Second)

	conn := dial(t, h.addr)
	defer conn.Close()

	for _, pdu := range pdus {
		if pdu.Direction != wirefixture.DirectionClientToServer {
			t.Fatalf("session %s: PDU %d has unexpected direction %q (fixtures are client-to-server only)", tc.name, pdu.Sequence, pdu.Direction)
		}
		raw := readFixturePDU(t, tc.dir, pdu.Filename)

		switch pdu.Operation {
		case wirefixture.OperationBindRequest:
			replayBind(t, tc, conn, pdu, raw)
		case wirefixture.OperationSearchRequest:
			replaySearch(t, tc, conn, pdu, raw)
		case wirefixture.OperationAbandonRequest:
			replayAbandon(t, tc, conn, verifier, resolver, raw)
		case wirefixture.OperationUnbindRequest:
			if _, err := conn.Write(raw); err != nil {
				t.Fatalf("session %s: write Unbind PDU: %v", tc.name, err)
			}
			expectNoResponseThenClosed(t, conn)
		default:
			t.Fatalf("session %s: PDU %d has unrecognized operation %q", tc.name, pdu.Sequence, pdu.Operation)
		}
	}
}

// replayBind feeds one raw Bind PDU and asserts a successful BindResponse
// carrying the identical MessageID (plan L30/L34); for the constructed
// MessageID-boundary session it additionally asserts the response's raw
// MessageID bytes are exactly the DER-minimal encoding of the request's
// MessageID (127 -> 02 01 7f, 128 -> 02 02 00 80).
func replayBind(t *testing.T, tc replayCase, conn net.Conn, pdu wirefixture.PDU, raw []byte) {
	t.Helper()
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("session %s: write Bind PDU: %v", tc.name, err)
	}
	body, env := readEnvelopeRaw(t, conn)
	if env.ProtocolOp != tagBindResponse {
		t.Fatalf("session %s: expected BindResponse, got protocolOp tag %v", tc.name, env.ProtocolOp)
	}
	result, _, _ := readLDAPResultFields(t, env.Content)
	if result != int(resultSuccess) {
		t.Fatalf("session %s: Bind result = %d, want success (0)", tc.name, result)
	}
	if env.MessageID != int32(pdu.MessageID) {
		t.Fatalf("session %s: BindResponse MessageID = %d, want %d (identical to the request)", tc.name, env.MessageID, pdu.MessageID)
	}

	if tc.isConstructed {
		want := berInteger(int64(pdu.MessageID))
		if len(body) < len(want) || !bytes.Equal(body[:len(want)], want) {
			got := body
			if len(got) > len(want) {
				got = got[:len(want)]
			}
			t.Fatalf("session %s: BindResponse MessageID bytes = % x, want exactly % x (MessageID %d)", tc.name, got, want, pdu.MessageID)
		}
	}
}

// replaySearch feeds one raw Search PDU and asserts the fixed
// ClickHouse-compatible Search shape: exactly the two expected
// clickhouse_ch_readonly/clickhouse_ch_unprovisioned entries, each with
// exactly one "cn" attribute holding exactly one value (never
// objectClass/member -- enforced structurally by decodeSearchResultEntry
// itself, which fails on a second PartialAttribute or a second value),
// then a successful SearchResultDone carrying the identical MessageID.
func replaySearch(t *testing.T, tc replayCase, conn net.Conn, pdu wirefixture.PDU, raw []byte) {
	t.Helper()
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("session %s: write Search PDU: %v", tc.name, err)
	}
	entries, done := collectSearchResult(t, conn)

	doneResult, _, _ := readLDAPResultFields(t, done.Content)
	if doneResult != int(resultSuccess) {
		t.Fatalf("session %s: SearchResultDone result = %d, want success (0)", tc.name, doneResult)
	}
	if done.MessageID != int32(pdu.MessageID) {
		t.Fatalf("session %s: SearchResultDone MessageID = %d, want %d (identical to the request)", tc.name, done.MessageID, pdu.MessageID)
	}

	wantCN := make(map[string]bool, len(wantMappedCNValues))
	for _, cn := range wantMappedCNValues {
		wantCN[cn] = false
	}
	if len(entries) != len(wantCN) {
		t.Fatalf("session %s: Search returned %d entries, want exactly %d", tc.name, len(entries), len(wantCN))
	}
	for _, entry := range entries {
		if entry.ProtocolOp != tagSearchResultEntry {
			t.Fatalf("session %s: expected SearchResultEntry, got protocolOp tag %v", tc.name, entry.ProtocolOp)
		}
		if entry.MessageID != int32(pdu.MessageID) {
			t.Fatalf("session %s: SearchResultEntry MessageID = %d, want %d (identical to the request)", tc.name, entry.MessageID, pdu.MessageID)
		}
		_, attrType, attrValue := decodeSearchResultEntry(t, entry.Content)
		if attrType != cnAttributeType {
			t.Fatalf("session %s: entry attribute type = %q, want exactly %q (never objectClass/member)", tc.name, attrType, cnAttributeType)
		}
		seen, expected := wantCN[attrValue]
		if !expected {
			t.Fatalf("session %s: unexpected cn value %q, want one of %v", tc.name, attrValue, wantMappedCNValues)
		}
		if seen {
			t.Fatalf("session %s: cn value %q returned more than once", tc.name, attrValue)
		}
		wantCN[attrValue] = true
	}
	for _, cn := range wantMappedCNValues {
		if !wantCN[cn] {
			t.Fatalf("session %s: expected cn value %q was never returned", tc.name, cn)
		}
	}
}

// replayAbandon feeds one raw Abandon PDU, captured (per the fixture's
// timeout-abandon mode) after its session's Search already ran to
// SearchResultDone. Asserts no response bytes arrive and neither the fake
// verifier nor the fake resolver was called as a side effect (plan
// L1566-1568): Abandon's target is recognized and dropped, never looked
// up or acted on.
func replayAbandon(t *testing.T, tc replayCase, conn net.Conn, verifier *fakeVerifier, resolver *fakeResolver, raw []byte) {
	t.Helper()
	verifierCallsBefore := verifier.callCount()
	resolverCallsBefore := resolver.callCount()

	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("session %s: write Abandon PDU: %v", tc.name, err)
	}
	assertNoBytesWithin(t, conn, 500*time.Millisecond)

	if got := verifier.callCount(); got != verifierCallsBefore {
		t.Fatalf("session %s: Verify called after Abandon (count %d -> %d), want unchanged", tc.name, verifierCallsBefore, got)
	}
	if got := resolver.callCount(); got != resolverCallsBefore {
		t.Fatalf("session %s: Roles called after Abandon (count %d -> %d), want unchanged", tc.name, resolverCallsBefore, got)
	}
}
