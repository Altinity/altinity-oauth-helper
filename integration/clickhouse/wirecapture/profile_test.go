package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

func baseProfileInput(t *testing.T, outDir string) ProfileInput {
	t.Helper()
	return ProfileInput{
		OutDir:                         outDir,
		Line:                           "24.8",
		TrackedImage:                   "altinity/clickhouse-server:24.8",
		ClickHouseRepository:           "Altinity/ClickHouse",
		ClickHouseTag:                  "24.8",
		ClickHouseCommit:               "351edb1a00000000000000000000000000000000",
		BlobLDAPClientCPP:              "aaaa000000000000000000000000000000aaaa1",
		BlobLDAPClientH:                "aaaa000000000000000000000000000000aaaa2",
		BlobLDAPAccessStorageCPP:       "aaaa000000000000000000000000000000aaaa3",
		BlobExternalAuthenticatorsCPP:  "aaaa000000000000000000000000000000aaaa4",
		OpenLDAPRepository:             "openldap/openldap",
		OpenLDAPPin:                    "OPENLDAP_REL_ENG_2_6_7",
		OpenLDAPVersion:                "2.6.7",
		ConfigPath:                     "integration/clickhouse/clickhouse/common/config.d/ldap.xml",
		ConfigSHA256:                   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		SessionPaths:                   []string{"timeout-abandon", "success"}, // deliberately unsorted
	}
}

func TestWriteProfileFromInput_WritesReadableProfile(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "24.8")
	in := baseProfileInput(t, outDir)

	profile, err := WriteProfileFromInput(in)
	if err != nil {
		t.Fatalf("WriteProfileFromInput: %v", err)
	}
	if profile.CaptureToolSchemaVersion != CaptureToolSchemaVersion {
		t.Fatalf("CaptureToolSchemaVersion = %d, want %d", profile.CaptureToolSchemaVersion, CaptureToolSchemaVersion)
	}
	// SessionPaths must come back sorted regardless of input order (plan:
	// "populate Profile.SessionPaths deterministically sorted").
	if got, want := profile.SessionPaths, []string{"success", "timeout-abandon"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("SessionPaths = %v, want %v", got, want)
	}

	read, err := wirefixture.ReadProfile(wirefixture.ProfilePath(outDir))
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	if read.ClickHouseConfigElementSHA256 != in.ConfigSHA256 {
		t.Fatalf("ClickHouseConfigElementSHA256 = %q, want %q", read.ClickHouseConfigElementSHA256, in.ConfigSHA256)
	}
	if read.ClickHouseSourceBlobs[wirefixture.BlobKeyLDAPClientCPP] != in.BlobLDAPClientCPP {
		t.Fatalf("ClickHouseSourceBlobs[%s] = %q, want %q",
			wirefixture.BlobKeyLDAPClientCPP, read.ClickHouseSourceBlobs[wirefixture.BlobKeyLDAPClientCPP], in.BlobLDAPClientCPP)
	}
}

func TestWriteProfileFromInput_ConfigFileHashedInContainer(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "24.8")
	configFile := filepath.Join(dir, "ldap.xml")
	configContent := "<!-- comment -->\n<clickhouse><a>1</a></clickhouse>\n"
	if err := os.WriteFile(configFile, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	wantHash, err := wirefixture.ClickHouseConfigElementSHA256([]byte(configContent))
	if err != nil {
		t.Fatalf("ClickHouseConfigElementSHA256: %v", err)
	}

	in := baseProfileInput(t, outDir)
	in.ConfigSHA256 = ""
	in.ConfigFile = configFile

	profile, err := WriteProfileFromInput(in)
	if err != nil {
		t.Fatalf("WriteProfileFromInput: %v", err)
	}
	if profile.ClickHouseConfigElementSHA256 != wantHash {
		t.Fatalf("ClickHouseConfigElementSHA256 = %q, want %q", profile.ClickHouseConfigElementSHA256, wantHash)
	}
}

func TestWriteProfileFromInput_SecondSessionSameLineIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "24.8")
	in := baseProfileInput(t, outDir)

	first, err := WriteProfileFromInput(in)
	if err != nil {
		t.Fatalf("first WriteProfileFromInput: %v", err)
	}
	// A "second session" invocation reuses the identical ProfileInput
	// (this is what a real second sanitize call for the same line, e.g.
	// timeout-abandon after success, is expected to pass).
	second, err := WriteProfileFromInput(in)
	if err != nil {
		t.Fatalf("second WriteProfileFromInput (same inputs) should succeed idempotently: %v", err)
	}
	if first.ClickHouseConfigElementSHA256 != second.ClickHouseConfigElementSHA256 {
		t.Fatalf("profile drifted across idempotent re-write")
	}

	// The file on disk must still be exactly what ReadProfile decodes.
	read, err := wirefixture.ReadProfile(wirefixture.ProfilePath(outDir))
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	if read.ClickHouseCommit != in.ClickHouseCommit {
		t.Fatalf("ClickHouseCommit = %q, want %q", read.ClickHouseCommit, in.ClickHouseCommit)
	}
}

func TestWriteProfileFromInput_SecondSessionDriftIsRejected(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "24.8")
	in := baseProfileInput(t, outDir)
	if _, err := WriteProfileFromInput(in); err != nil {
		t.Fatalf("first WriteProfileFromInput: %v", err)
	}

	drifted := in
	drifted.ClickHouseCommit = "bbbb000000000000000000000000000000bbbb1" // different commit, same line
	if _, err := WriteProfileFromInput(drifted); err == nil {
		t.Fatal("expected an error when a second session's profile inputs disagree with the committed profile.json")
	}
}

func TestWriteProfileFromInput_MissingRequiredFlag(t *testing.T) {
	dir := t.TempDir()
	in := baseProfileInput(t, filepath.Join(dir, "24.8"))
	in.ClickHouseCommit = ""
	if _, err := WriteProfileFromInput(in); err == nil {
		t.Fatal("expected an error for a missing required field")
	}
}

func TestWriteProfileFromInput_BothConfigSourcesRejected(t *testing.T) {
	dir := t.TempDir()
	in := baseProfileInput(t, filepath.Join(dir, "24.8"))
	in.ConfigFile = filepath.Join(dir, "does-not-need-to-exist.xml")
	// ConfigSHA256 is already set by baseProfileInput.
	if _, err := WriteProfileFromInput(in); err == nil {
		t.Fatal("expected an error when both --config-file and --config-sha256 are supplied")
	}
}

func TestWriteProfileFromInput_NeitherConfigSourceRejected(t *testing.T) {
	dir := t.TempDir()
	in := baseProfileInput(t, filepath.Join(dir, "24.8"))
	in.ConfigSHA256 = ""
	if _, err := WriteProfileFromInput(in); err == nil {
		t.Fatal("expected an error when neither --config-file nor --config-sha256 is supplied")
	}
}

func TestWriteProfileFromInput_MissingSessionPaths(t *testing.T) {
	dir := t.TempDir()
	in := baseProfileInput(t, filepath.Join(dir, "24.8"))
	in.SessionPaths = nil
	if _, err := WriteProfileFromInput(in); err == nil {
		t.Fatal("expected an error when --session-paths is empty")
	}
}

// TestRun_Sanitize_WritesProfileEndToEnd is the doneWhen's "an end-to-end
// test writes a profile.json via the tool and reads it back with
// wirefixture.ReadProfile strict decode": it drives the real `sanitize`
// subcommand through run() (the same CLI entrypoint main() uses) with the
// full set of --profile-out/... flags, then reads the resulting
// profile.json back through wirefixture.ReadProfile.
func TestRun_Sanitize_WritesProfileEndToEnd(t *testing.T) {
	dir := t.TempDir()
	rawDir := filepath.Join(dir, "raw")
	sanitizedDir := filepath.Join(dir, "sanitized")
	profileOutDir := filepath.Join(dir, "clickhouse-wire", "24.8")
	configFile := filepath.Join(dir, "ldap.xml")
	credential := "stdin-supplied-credential-for-profile-e2e"

	writeRawConn(t, rawDir, "conn-0001", [][]byte{
		buildBindRequest(1, "uid=alice,dc=test", credential),
	})
	if err := os.WriteFile(configFile, []byte("<clickhouse><a>1</a></clickhouse>"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		_, _ = stdinW.WriteString(credential)
		stdinW.Close()
	}()

	stdout, stderr, cleanup := pipeFiles(t)
	defer cleanup()

	code := run([]string{
		"sanitize",
		"--raw-dir", rawDir,
		"--sanitized-dir", sanitizedDir,
		"--line", "24.8",
		"--mode", "success",
		"--sql", "SELECT currentUser()",
		"--profile-out", profileOutDir,
		"--tracked-image", "altinity/clickhouse-server:24.8",
		"--clickhouse-repository", "Altinity/ClickHouse",
		"--clickhouse-tag", "24.8",
		"--clickhouse-commit", "351edb1a00000000000000000000000000000000",
		"--blob-ldapclient-cpp", "aaaa000000000000000000000000000000aaaa1",
		"--blob-ldapclient-h", "aaaa000000000000000000000000000000aaaa2",
		"--blob-ldapaccessstorage-cpp", "aaaa000000000000000000000000000000aaaa3",
		"--blob-externalauthenticators-cpp", "aaaa000000000000000000000000000000aaaa4",
		"--openldap-repository", "openldap/openldap",
		"--openldap-pin", "OPENLDAP_REL_ENG_2_6_7",
		"--openldap-version", "2.6.7",
		"--config-path", "integration/clickhouse/clickhouse/common/config.d/ldap.xml",
		"--config-file", configFile,
		"--session-paths", "success,timeout-abandon",
	}, stdinR, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	profile, err := wirefixture.ReadProfile(wirefixture.ProfilePath(profileOutDir))
	if err != nil {
		t.Fatalf("ReadProfile: %v", err)
	}
	if profile.Line != "24.8" {
		t.Fatalf("Line = %q, want 24.8", profile.Line)
	}
	if len(profile.SessionPaths) != 2 || profile.SessionPaths[0] != "success" || profile.SessionPaths[1] != "timeout-abandon" {
		t.Fatalf("SessionPaths = %v, want sorted [success timeout-abandon]", profile.SessionPaths)
	}
	if profile.ClickHouseConfigElementSHA256 == "" {
		t.Fatal("ClickHouseConfigElementSHA256 is empty")
	}
}
