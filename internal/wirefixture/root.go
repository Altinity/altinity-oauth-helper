package wirefixture

import (
	"fmt"
	"os"
	"path/filepath"
)

// Canonical filenames for the documents this package owns.
const (
	ProfileFileName = "profile.json"
	SessionFileName = "session.json"
)

// ModuleRoot locates the repository root by walking upward from the
// current working directory until a go.mod file is found.
//
// This is intentionally a separate helper from
// internal/securitytest's own in-package moduleRoot()/findModuleRoot
// (coordinator amendment 7): internal/securitytest's contract tests keep
// using their existing in-package helper, while ModuleRoot here exists
// for the two consumers outside internal/securitytest that need a
// module-root-relative fixture path — internal/ldap's cryptobyte decision
// test (internal_ldap/clickhouse_wire_cryptobyte_test.go) and the
// integration/clickhouse/wirecapture recorder tool. Neither of those
// packages should reach into internal/securitytest for this.
func ModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("wirefixture: determine working directory: %w", err)
	}
	return moduleRootFrom(dir)
}

// moduleRootFrom walks upward from start looking for a go.mod file.
func moduleRootFrom(start string) (string, error) {
	dir := start
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("wirefixture: no go.mod found above %s", start)
		}
		dir = parent
	}
}

// ClickHouseWireFixtureRoot returns the committed ClickHouse wire-evidence
// corpus root, internal/ldap/testdata/clickhouse-wire, under moduleRoot.
func ClickHouseWireFixtureRoot(moduleRoot string) string {
	return filepath.Join(moduleRoot, "internal", "ldap", "testdata", "clickhouse-wire")
}

// LineDir returns the fixture directory for a tracked line (e.g. "24.8")
// under a corpus root such as ClickHouseWireFixtureRoot's return value.
func LineDir(fixtureRoot, line string) string {
	return filepath.Join(fixtureRoot, line)
}

// ConstructedDir returns the constructed-fixture directory under a corpus
// root.
func ConstructedDir(fixtureRoot string) string {
	return filepath.Join(fixtureRoot, ConstructedDirName)
}

// SessionDir returns the named session directory (e.g. "success",
// "timeout-abandon", "message-id-boundary") under a line or constructed
// directory.
func SessionDir(parent, session string) string {
	return filepath.Join(parent, session)
}

// ProfilePath returns the profile.json path within a line directory.
func ProfilePath(lineDir string) string {
	return filepath.Join(lineDir, ProfileFileName)
}

// SessionMetadataPath returns the session.json path within a session
// directory.
func SessionMetadataPath(sessionDir string) string {
	return filepath.Join(sessionDir, SessionFileName)
}
