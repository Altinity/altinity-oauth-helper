package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

func TestConstructMessageIDBoundary_WritesReproducibleBundle(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "constructed", "message-id-boundary")

	session, err := ConstructMessageIDBoundary(ConstructInput{
		OutputDir:       out,
		ApplicableLines: []string{"24.8", "25.8"},
	})
	if err != nil {
		t.Fatalf("ConstructMessageIDBoundary: %v", err)
	}
	if len(session.PDUs) != 2 {
		t.Fatalf("got %d PDUs, want 2", len(session.PDUs))
	}
	if session.Provenance != wirefixture.ProvenanceConstructed {
		t.Fatalf("Provenance = %q, want constructed", session.Provenance)
	}

	want127, err := wirefixture.BuildConstructedSimpleBind(127)
	if err != nil {
		t.Fatalf("BuildConstructedSimpleBind(127): %v", err)
	}
	want128, err := wirefixture.BuildConstructedSimpleBind(128)
	if err != nil {
		t.Fatalf("BuildConstructedSimpleBind(128): %v", err)
	}

	got127, err := os.ReadFile(filepath.Join(out, session.PDUs[0].Filename))
	if err != nil {
		t.Fatalf("read %s: %v", session.PDUs[0].Filename, err)
	}
	if !bytes.Equal(got127, want127) {
		t.Fatalf("127 fixture bytes mismatch")
	}
	got128, err := os.ReadFile(filepath.Join(out, session.PDUs[1].Filename))
	if err != nil {
		t.Fatalf("read %s: %v", session.PDUs[1].Filename, err)
	}
	if !bytes.Equal(got128, want128) {
		t.Fatalf("128 fixture bytes mismatch")
	}

	// Regenerating must be byte-identical (deterministic).
	session2, err := ConstructMessageIDBoundary(ConstructInput{
		OutputDir:       filepath.Join(dir, "second-run"),
		ApplicableLines: []string{"24.8", "25.8"},
	})
	if err != nil {
		t.Fatalf("second ConstructMessageIDBoundary: %v", err)
	}
	if session.PDUs[0].SanitizedSHA256 != session2.PDUs[0].SanitizedSHA256 {
		t.Fatalf("regeneration is not deterministic: hash mismatch")
	}

	if _, err := os.Stat(filepath.Join(out, "session.json")); err != nil {
		t.Fatalf("session.json not written: %v", err)
	}
}
