package wirefixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleRootFromFindsGoMod(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	got, err := moduleRootFrom(nested)
	if err != nil {
		t.Fatalf("moduleRootFrom: %v", err)
	}
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("EvalSymlinks(got): %v", err)
	}
	wantResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks(root): %v", err)
	}
	if gotResolved != wantResolved {
		t.Fatalf("moduleRootFrom(%s) = %s, want %s", nested, got, root)
	}
}

func TestModuleRootFromFailsWithoutGoMod(t *testing.T) {
	// A tree rooted at a fresh temp directory with nothing above it (up
	// to the filesystem root) named go.mod should fail rather than
	// silently walking out to some unrelated go.mod.
	root := t.TempDir()
	nested := filepath.Join(root, "x", "y")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	if _, err := moduleRootFrom(nested); err == nil {
		t.Fatal("moduleRootFrom: expected error when no go.mod exists above start, got nil")
	}
}

// TestModuleRootFindsRepositoryRoot exercises the exported ModuleRoot
// against this package's real working directory (internal/wirefixture,
// two levels below the repository root during `go test`), and confirms it
// lands on this repository's own go.mod rather than some unrelated one.
func TestModuleRootFindsRepositoryRoot(t *testing.T) {
	root, err := ModuleRoot()
	if err != nil {
		t.Fatalf("ModuleRoot: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod at discovered root %s: %v", root, err)
	}
	if !strings.Contains(string(data), "module github.com/altinity/altinity-oauth-helper") {
		t.Fatalf("go.mod at discovered root %s does not look like this repository's module file", root)
	}
}

func TestFixturePathHelpers(t *testing.T) {
	moduleRoot := filepath.FromSlash("/repo")
	fixtureRoot := ClickHouseWireFixtureRoot(moduleRoot)
	want := filepath.Join(moduleRoot, "internal", "ldap", "testdata", "clickhouse-wire")
	if fixtureRoot != want {
		t.Fatalf("ClickHouseWireFixtureRoot = %s, want %s", fixtureRoot, want)
	}

	lineDir := LineDir(fixtureRoot, "24.8")
	if lineDir != filepath.Join(fixtureRoot, "24.8") {
		t.Fatalf("LineDir = %s", lineDir)
	}

	constructedDir := ConstructedDir(fixtureRoot)
	if constructedDir != filepath.Join(fixtureRoot, ConstructedDirName) {
		t.Fatalf("ConstructedDir = %s", constructedDir)
	}

	sessionDir := SessionDir(lineDir, "success")
	if sessionDir != filepath.Join(lineDir, "success") {
		t.Fatalf("SessionDir = %s", sessionDir)
	}

	if got, want := ProfilePath(lineDir), filepath.Join(lineDir, ProfileFileName); got != want {
		t.Fatalf("ProfilePath = %s, want %s", got, want)
	}
	if got, want := SessionMetadataPath(sessionDir), filepath.Join(sessionDir, SessionFileName); got != want {
		t.Fatalf("SessionMetadataPath = %s, want %s", got, want)
	}
}
