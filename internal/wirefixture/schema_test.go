package wirefixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sampleProfile() Profile {
	return Profile{
		SchemaVersion:        SchemaVersion,
		Line:                 "24.8",
		TrackedImage:         "altinity/clickhouse-server:24.8.11.51285.altinitystable",
		ClickHouseRepository: "Altinity/ClickHouse",
		ClickHouseTag:        "v24.8.11.51285.altinitystable",
		ClickHouseCommit:     "351edb1a2ec26940aee4c2d1d332fd280c232964",
		ClickHouseSourceBlobs: map[string]string{
			BlobKeyLDAPClientCPP:             "3a0b82b9a760e8c0e4f37f422e673a1c5a2228e0",
			BlobKeyLDAPClientH:               "0bbd2c6e9c4662d3d31f83bd8ed457647d436cc6",
			BlobKeyLDAPAccessStorageCPP:      "917ad7cbb922083ab82f85ab25c120a17fd009c7",
			BlobKeyExternalAuthenticatorsCPP: "77812ac5eb5d0027f081ac43dccc6b89110aeb73",
		},
		OpenLDAPRepository:            "ClickHouse/openldap",
		OpenLDAPPin:                   "5671b80e369df2caf5f34e02924316205a43c895",
		OpenLDAPVersion:               "2.5.16",
		CanonicalConfigPath:           "integration/clickhouse/clickhouse/common/config.d/ldap.xml",
		ClickHouseConfigElementSHA256: strings.Repeat("ab", 32),
		CaptureToolSchemaVersion:      1,
		SessionPaths:                  []string{"success", "timeout-abandon"},
	}
}

func abandonTarget(v int) *int { return &v }

func sampleSession() Session {
	return Session{
		SchemaVersion:     SchemaVersion,
		Line:              "24.8",
		Applicability:     []string{"24.8"},
		ProvenanceClass:   ProvenanceCapturedRedacted,
		Mode:              "success",
		ConnectionCount:   1,
		SQL:               "SELECT currentUser()",
		TokenClaimRecipe:  "sub=alice@example.com; roles=idp-readers,idp-unprovisioned; fixed-digit iat/exp; no jti",
		PlaceholderLength: 512,
		PDUs: []PDU{
			{
				Sequence:          1,
				Filename:          "001-bind-request.ber",
				Direction:         DirectionClientToServer,
				Operation:         OperationBindRequest,
				MessageID:         1,
				SanitizedSHA256:   strings.Repeat("11", 32),
				RedactionStatus:   RedactionRedacted,
				ExpectedSemantics: "simple Bind, version 3",
			},
			{
				Sequence:          2,
				Filename:          "002-search-request.ber",
				Direction:         DirectionClientToServer,
				Operation:         OperationSearchRequest,
				MessageID:         2,
				SanitizedSHA256:   strings.Repeat("22", 32),
				RedactionStatus:   RedactionRedacted,
				ExpectedSemantics: "role Search, subtree scope",
			},
			{
				Sequence:          3,
				Filename:          "003-abandon-request.ber",
				Direction:         DirectionClientToServer,
				Operation:         OperationAbandonRequest,
				MessageID:         3,
				AbandonTarget:     abandonTarget(2),
				SanitizedSHA256:   strings.Repeat("33", 32),
				RedactionStatus:   RedactionRedacted,
				ExpectedSemantics: "Abandon targeting the Search MessageID",
			},
		},
	}
}

func TestWriteReadProfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ProfileFileName)
	want := sampleProfile()

	if err := WriteProfile(path, want); err != nil {
		t.Fatalf("WriteProfile: %v", err)
	}
	got, err := ReadProfile(path)
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip mismatch:\n want=%+v\n  got=%+v", want, got)
	}
}

func TestWriteReadSessionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SessionFileName)
	want := sampleSession()

	if err := WriteSession(path, want); err != nil {
		t.Fatalf("WriteSession: %v", err)
	}
	got, err := ReadSession(path)
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip mismatch:\n want=%+v\n  got=%+v", want, got)
	}
}

// TestEncodingIsDeterministic proves two encodings of an equal Profile (and
// an equal Session) value are byte-identical, as WriteProfile/WriteSession
// promise.
func TestEncodingIsDeterministic(t *testing.T) {
	p := sampleProfile()
	a, err := encodeJSON(p)
	if err != nil {
		t.Fatalf("encodeJSON profile #1: %v", err)
	}
	b, err := encodeJSON(sampleProfile())
	if err != nil {
		t.Fatalf("encodeJSON profile #2: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("profile encoding not deterministic:\n a=%s\n b=%s", a, b)
	}

	s := sampleSession()
	sa, err := encodeJSON(s)
	if err != nil {
		t.Fatalf("encodeJSON session #1: %v", err)
	}
	sb, err := encodeJSON(sampleSession())
	if err != nil {
		t.Fatalf("encodeJSON session #2: %v", err)
	}
	if string(sa) != string(sb) {
		t.Fatalf("session encoding not deterministic:\n a=%s\n b=%s", sa, sb)
	}

	// Writing the same Profile to disk twice must also be byte-identical.
	dir := t.TempDir()
	path := filepath.Join(dir, ProfileFileName)
	if err := WriteProfile(path, p); err != nil {
		t.Fatalf("WriteProfile #1: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read #1: %v", err)
	}
	if err := WriteProfile(path, sampleProfile()); err != nil {
		t.Fatalf("WriteProfile #2: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read #2: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("written profile bytes differ between identical-value writes")
	}
}

func TestReadProfileStrictDecodeRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ProfileFileName)

	raw, err := json.Marshal(sampleProfile())
	if err != nil {
		t.Fatalf("marshal base profile: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	m["unexpected_field"] = "surprise"
	tainted, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal tainted map: %v", err)
	}
	if err := os.WriteFile(path, tainted, 0o644); err != nil {
		t.Fatalf("write tainted profile: %v", err)
	}

	if _, err := ReadProfile(path); err == nil {
		t.Fatal("ReadProfile: expected error for unknown field, got nil")
	}
}

func TestReadSessionStrictDecodeRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SessionFileName)

	raw, err := json.Marshal(sampleSession())
	if err != nil {
		t.Fatalf("marshal base session: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	m["unexpected_field"] = "surprise"
	tainted, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal tainted map: %v", err)
	}
	if err := os.WriteFile(path, tainted, 0o644); err != nil {
		t.Fatalf("write tainted session: %v", err)
	}

	if _, err := ReadSession(path); err == nil {
		t.Fatal("ReadSession: expected error for unknown field, got nil")
	}
}

func TestReadSessionStrictDecodeRejectsUnknownPDUField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SessionFileName)

	raw, err := json.Marshal(sampleSession())
	if err != nil {
		t.Fatalf("marshal base session: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	pdus, ok := m["pdus"].([]any)
	if !ok || len(pdus) == 0 {
		t.Fatalf("unexpected pdus shape: %#v", m["pdus"])
	}
	firstPDU, ok := pdus[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected pdu[0] shape: %#v", pdus[0])
	}
	firstPDU["unexpected_field"] = "surprise"
	tainted, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal tainted session: %v", err)
	}
	if err := os.WriteFile(path, tainted, 0o644); err != nil {
		t.Fatalf("write tainted session: %v", err)
	}

	if _, err := ReadSession(path); err == nil {
		t.Fatal("ReadSession: expected error for unknown PDU field, got nil")
	}
}

// TestStableSessionExcludesObservedElapsedMS proves that ObservedElapsedMS
// (the sole diagnostic/run-varying field on PDU) never affects the stable
// projection used for verify-mode equality, even though it does make the
// raw Session values themselves unequal.
func TestStableSessionExcludesObservedElapsedMS(t *testing.T) {
	a := sampleSession()
	b := sampleSession()

	elapsedA := int64(120)
	elapsedB := int64(45000)
	a.PDUs[0].ObservedElapsedMS = &elapsedA
	b.PDUs[0].ObservedElapsedMS = &elapsedB

	if reflect.DeepEqual(a, b) {
		t.Fatal("test setup invalid: raw sessions must differ by ObservedElapsedMS")
	}

	stableA := StableSession(a)
	stableB := StableSession(b)
	if !reflect.DeepEqual(stableA, stableB) {
		t.Fatalf("StableSession must ignore ObservedElapsedMS:\n a=%+v\n b=%+v", stableA, stableB)
	}
}

func TestStableProfileProjectsSampleProfile(t *testing.T) {
	p := sampleProfile()
	sp := StableProfile(p)
	if sp.Line != p.Line || sp.ClickHouseCommit != p.ClickHouseCommit {
		t.Fatalf("StableProfile did not carry through core fields: %+v", sp)
	}
	if !reflect.DeepEqual(sp.ClickHouseSourceBlobs, p.ClickHouseSourceBlobs) {
		t.Fatalf("StableProfile blob map mismatch: %+v vs %+v", sp.ClickHouseSourceBlobs, p.ClickHouseSourceBlobs)
	}
	// The projection must be a defensive copy, not an alias, of mutable
	// fields, so mutating the source Profile after projecting cannot
	// retroactively change a previously computed stable view.
	p.ClickHouseSourceBlobs[BlobKeyLDAPClientCPP] = "mutated"
	if sp.ClickHouseSourceBlobs[BlobKeyLDAPClientCPP] == "mutated" {
		t.Fatal("StableProfile aliased the source ClickHouseSourceBlobs map")
	}
}

func TestValidateFixtureRootAcceptsLinesAndConstructed(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"24.8", "25.8", ConstructedDirName} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}

	lines, err := ValidateFixtureRoot(dir)
	if err != nil {
		t.Fatalf("ValidateFixtureRoot: unexpected error: %v", err)
	}
	want := []string{"24.8", "25.8"}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("ValidateFixtureRoot lines = %v, want %v", lines, want)
	}
}

func TestValidateFixtureRootRejectsStrayFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "24.8"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write stray file: %v", err)
	}

	if _, err := ValidateFixtureRoot(dir); err == nil {
		t.Fatal("ValidateFixtureRoot: expected error for stray root file, got nil")
	}
}

func TestValidateFixtureRootRejectsMalformedLineName(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "26.3.1"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if _, err := ValidateFixtureRoot(dir); err == nil {
		t.Fatal("ValidateFixtureRoot: expected error for malformed line directory name, got nil")
	}
}

func TestValidateFixtureRootRejectsUnrelatedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "not-a-line"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if _, err := ValidateFixtureRoot(dir); err == nil {
		t.Fatal("ValidateFixtureRoot: expected error for unrelated directory name, got nil")
	}
}
