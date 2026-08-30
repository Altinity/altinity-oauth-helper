package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_MissingSubcommand(t *testing.T) {
	stdout, stderr, cleanup := pipeFiles(t)
	defer cleanup()
	code := run(nil, devNullStdin(t), stdout, stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	stdout, stderr, cleanup := pipeFiles(t)
	defer cleanup()
	code := run([]string{"frobnicate"}, devNullStdin(t), stdout, stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRun_ConstructMessageIDBoundary_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "constructed")
	stdout, stderr, cleanup := pipeFiles(t)
	defer cleanup()

	code := run([]string{"construct-message-id-boundary", "--output-dir", out, "--lines", "24.8,25.8"}, devNullStdin(t), stdout, stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(out, "session.json")); err != nil {
		t.Fatalf("session.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "001-bind-messageid-127.ber")); err != nil {
		t.Fatalf("127 fixture missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "002-bind-messageid-128.ber")); err != nil {
		t.Fatalf("128 fixture missing: %v", err)
	}
}

func TestRun_Sanitize_ReadsCredentialFromStdin(t *testing.T) {
	dir := t.TempDir()
	rawDir := filepath.Join(dir, "raw")
	sanitizedDir := filepath.Join(dir, "sanitized")
	credential := "stdin-supplied-credential-value"
	writeRawConn(t, rawDir, "conn-0001", [][]byte{
		buildBindRequest(1, "uid=alice,dc=test", credential),
	})

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
	}, stdinR, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(sanitizedDir, "session.json")); err != nil {
		t.Fatalf("session.json missing: %v", err)
	}
}

func TestRun_Compare_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	committedDir := filepath.Join(dir, "committed")
	freshDir := filepath.Join(dir, "fresh")
	cSession, cPDUs := baseSession(20, 0)
	writeFixtureDir(t, committedDir, cSession, cPDUs)
	fSession, fPDUs := baseSession(20, 55)
	writeFixtureDir(t, freshDir, fSession, fPDUs)

	stdout, stderr, cleanup := pipeFiles(t)
	defer cleanup()
	code := run([]string{"compare", "--committed-dir", committedDir, "--fresh-dir", freshDir}, devNullStdin(t), stdout, stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

// ---- test plumbing ---------------------------------------------------

func pipeFiles(t *testing.T) (stdout, stderr *os.File, cleanup func()) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	// Drain both pipes in the background so a full OS pipe buffer never
	// blocks the code under test.
	go drain(outR)
	go drain(errR)
	return outW, errW, func() {
		outW.Close()
		errW.Close()
	}
}

func drain(f *os.File) {
	buf := make([]byte, 4096)
	for {
		if _, err := f.Read(buf); err != nil {
			return
		}
	}
}

func devNullStdin(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
