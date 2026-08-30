package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

func writeFixtureDir(t *testing.T, dir string, session *wirefixture.Session, pduContent map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, content := range pduContent {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := wirefixture.WriteSession(filepath.Join(dir, "session.json"), session); err != nil {
		t.Fatalf("WriteSession: %v", err)
	}
}

func baseSession(placeholderLen int, observedElapsedMS int64) (*wirefixture.Session, map[string][]byte) {
	bind := buildBindRequest(1, "uid=alice,dc=test", "xxxxxxxxxxxxxxxxxxxx")
	search := buildSearchRequest(2)
	pdus := map[string][]byte{
		"001-bind-request.ber":   bind,
		"002-search-request.ber": search,
	}
	session := &wirefixture.Session{
		SchemaVersion:     wirefixture.SchemaVersion,
		Line:              "24.8",
		Provenance:        wirefixture.ProvenanceCapturedRedacted,
		Mode:              "success",
		ConnectionCount:   1,
		PlaceholderLength: placeholderLen,
		PDUs: []wirefixture.PDU{
			{Sequence: 1, Filename: "001-bind-request.ber", Direction: "client-to-server", Operation: "bind", MessageID: 1, SanitizedSHA256: wirefixture.SHA256Hex(bind), RedactionStatus: "redacted"},
			{Sequence: 2, Filename: "002-search-request.ber", Direction: "client-to-server", Operation: "search", MessageID: 2, SanitizedSHA256: wirefixture.SHA256Hex(search), RedactionStatus: "no-credential-present", ObservedElapsedMS: observedElapsedMS},
		},
	}
	return session, pdus
}

func TestCompare_IdenticalFixturesMatch(t *testing.T) {
	dir := t.TempDir()
	committedDir := filepath.Join(dir, "committed")
	freshDir := filepath.Join(dir, "fresh")

	cSession, cPDUs := baseSession(20, 0)
	writeFixtureDir(t, committedDir, cSession, cPDUs)

	// Fresh run: identical bytes/metadata except a run-varying diagnostic
	// timestamp field, which must NOT affect equality.
	fSession, fPDUs := baseSession(20, 4321)
	writeFixtureDir(t, freshDir, fSession, fPDUs)

	result, err := Compare(CompareInput{CommittedDir: committedDir, FreshDir: freshDir})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if result.CredentialLengthMismatch {
		t.Fatal("unexpected credential-length mismatch")
	}
	if !result.Equal {
		t.Fatalf("expected Equal, got diffs: %v", result.Diffs)
	}
}

func TestCompare_CredentialLengthMismatchIsDistinctFromWireDrift(t *testing.T) {
	dir := t.TempDir()
	committedDir := filepath.Join(dir, "committed")
	freshDir := filepath.Join(dir, "fresh")

	cSession, cPDUs := baseSession(20, 0)
	writeFixtureDir(t, committedDir, cSession, cPDUs)

	fSession, fPDUs := baseSession(999, 0) // different placeholder length
	writeFixtureDir(t, freshDir, fSession, fPDUs)

	result, err := Compare(CompareInput{CommittedDir: committedDir, FreshDir: freshDir})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !result.CredentialLengthMismatch {
		t.Fatal("expected a credential-length mismatch to be reported")
	}
	if len(result.Diffs) != 0 {
		t.Fatalf("credential-length mismatch must not also report wire-drift diffs, got %v", result.Diffs)
	}
}

func TestCompare_PDUByteDriftDetected(t *testing.T) {
	dir := t.TempDir()
	committedDir := filepath.Join(dir, "committed")
	freshDir := filepath.Join(dir, "fresh")

	cSession, cPDUs := baseSession(20, 0)
	writeFixtureDir(t, committedDir, cSession, cPDUs)

	fSession, fPDUs := baseSession(20, 0)
	// Corrupt one byte of the fresh Search PDU to simulate wire drift.
	drifted := make([]byte, len(fPDUs["002-search-request.ber"]))
	copy(drifted, fPDUs["002-search-request.ber"])
	drifted[len(drifted)-1] ^= 0xFF
	fPDUs["002-search-request.ber"] = drifted
	writeFixtureDir(t, freshDir, fSession, fPDUs)

	result, err := Compare(CompareInput{CommittedDir: committedDir, FreshDir: freshDir})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if result.CredentialLengthMismatch {
		t.Fatal("unexpected credential-length mismatch")
	}
	if result.Equal {
		t.Fatal("expected drift to be detected")
	}
	found := false
	for _, d := range result.Diffs {
		if d == "PDU 002-search-request.ber is not byte-equal to committed fixture" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a byte-equality diff for the drifted PDU, got %v", result.Diffs)
	}
}

func TestCompare_TimeoutModeDiagnostics(t *testing.T) {
	dir := t.TempDir()
	committedDir := filepath.Join(dir, "committed")
	freshDir := filepath.Join(dir, "fresh")

	bind := buildBindRequest(1, "uid=alice,dc=test", "xxxxxxxxxxxxxxxxxxxx")
	search := buildSearchRequest(2)
	abandon := buildAbandonRequest(3, 2)
	pdus := map[string][]byte{
		"001-bind-request.ber":    bind,
		"002-search-request.ber":  search,
		"003-abandon-request.ber": abandon,
	}
	mk := func(elapsed int64) *wirefixture.Session {
		return &wirefixture.Session{
			SchemaVersion:     wirefixture.SchemaVersion,
			Line:              "24.8",
			Provenance:        wirefixture.ProvenanceCapturedRedacted,
			Mode:              "timeout-abandon",
			ConnectionCount:   1,
			PlaceholderLength: 20,
			PDUs: []wirefixture.PDU{
				{Sequence: 1, Filename: "001-bind-request.ber", Operation: "bind", MessageID: 1, SanitizedSHA256: wirefixture.SHA256Hex(bind), RedactionStatus: "redacted"},
				{Sequence: 2, Filename: "002-search-request.ber", Operation: "search", MessageID: 2, SanitizedSHA256: wirefixture.SHA256Hex(search), RedactionStatus: "no-credential-present"},
				{Sequence: 3, Filename: "003-abandon-request.ber", Operation: "abandon", MessageID: 3, SanitizedSHA256: wirefixture.SHA256Hex(abandon), RedactionStatus: "no-credential-present", ObservedElapsedMS: elapsed},
			},
		}
	}

	writeFixtureDir(t, committedDir, mk(0), pdus)
	writeFixtureDir(t, freshDir, mk(20123), pdus)

	result, err := Compare(CompareInput{CommittedDir: committedDir, FreshDir: freshDir})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !result.Equal {
		t.Fatalf("expected Equal (elapsed-ms must not affect equality), diffs: %v", result.Diffs)
	}
	if !result.TimeoutElapsedMSPositive {
		t.Fatal("expected TimeoutElapsedMSPositive diagnostic to be true")
	}
	if !result.SearchBeforeAbandon {
		t.Fatal("expected SearchBeforeAbandon diagnostic to be true")
	}
}
